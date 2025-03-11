from django.shortcuts import render, get_object_or_404, redirect
from django.http import HttpResponse
from .models import Product, Transaction, Organization
from .utils import verify_chain, debug_hash_chain
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import Table, TableStyle
import hashlib
from django.utils import timezone
import datetime
from cryptography.hazmat.primitives import serialization


from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.decorators import login_required

def login_view(request):
    if request.user.is_authenticated:
        return redirect('scan_qr')
    
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                return redirect('scan_qr')
        return render(request, 'login.html', {'form': form})
    
    return render(request, 'login.html')

@login_required
def logout_view(request):
    logout(request)
    return redirect('login')


from django.contrib.auth.decorators import login_required, user_passes_test
from .forms import ProductForm
from .models import Product, Transaction
from django.utils.timezone import make_naive

def is_manufacturer(user):
    return user.groups.filter(name='Manufacturer').exists()

@login_required
@user_passes_test(is_manufacturer)
def create_product(request):
    if request.method == 'POST':
        form = ProductForm(request.POST)
        if form.is_valid():
            product = form.save(commit=False)
            product.manufacturer = request.user
            product.save()
            
            # Create initial transaction
            # Ensure created_at is not None
            created_at = product.created_at if product.created_at else make_naive(timezone.now()).isoformat()
            hash_input = f"{'0'*64}|MANUFACTURED|{str(created_at)}"
            current_hash = hashlib.sha256(hash_input.encode('utf-8')).hexdigest()
            
            Transaction.objects.create(
                product=product,
                actor=request.user,
                action='MANUFACTURED',
                previous_hash='0'*64,
                current_hash=current_hash,
                timestamp=make_naive(timezone.now()).isoformat()  # Explicitly set timestamp
            )
            
            return redirect('verify', uuid=product.uuid)
    else:
        form = ProductForm()
    
    return render(request, 'create_product.html', {'form': form})

def scan_qr(request):
    return render(request, 'scan.html')

def landing(request):
    return render(request, 'landing.html')

# chain/views.py
def verify_product(request, uuid):
    product = get_object_or_404(Product, uuid=uuid)
    chain_debug = debug_hash_chain(product)
    is_valid = all([item['match'] for item in chain_debug])
    transactions = Transaction.objects.filter(product=product)
    
    return render(request, 'verify.html', {
        'product': product,
        'is_valid': is_valid,
        'chain_debug': chain_debug,
        'transactions': transactions
    })

# chain/views.py
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from .models import Product, Transaction
import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


@login_required
def add_transaction(request, uuid):
    try:
        org = request.user.organization
    except Organization.DoesNotExist:
        return render(request, 'error.html', {
            'error': 'User organization not found'
        })
    # Get the product and verify existence
    product = get_object_or_404(Product, uuid=uuid)
    
    # Determine allowed actions based on user role
    user_group = request.user.groups.first()
    if user_group is None:
        return render(request, 'error.html', {'error': 'User has no assigned role'})
        
    allowed_actions = []
    
    if user_group.name == 'Manufacturer':
        allowed_actions = ['MANUFACTURED']
    elif user_group.name == 'Distributor':
        allowed_actions = ['SHIPPED', 'RECEIVED AT WAREHOUSE']
    elif user_group.name == 'Retailer':
        allowed_actions = ['DELIVERED', 'SHELVED', 'SOLD']
    else:
        return render(request, 'error.html', {'error': 'Invalid user role'})

    if request.method == 'POST':
        action = request.POST.get('action')
        
        # Validate allowed action
        if action not in allowed_actions:
            return render(request, 'error.html', 
                        {'error': 'Invalid action for your role'})

        try:
            # Get previous transaction
            last_transaction = Transaction.objects.filter(
                product=product
            ).latest('timestamp')
            
            previous_hash = last_transaction.current_hash
        except Transaction.DoesNotExist:
            # Handle genesis transaction
            previous_hash = '0' * 64

        try:
            # Calculate new hash - ensure timestamp is timezone-aware
            timestamp = timezone.now()
            if timestamp is None:
                timestamp = datetime.datetime.now(tz=datetime.timezone.utc)
                
            data_string = f"{previous_hash}|{action}|{timestamp.isoformat()}"
            current_hash = hashlib.sha256(data_string.encode()).hexdigest()

            # Ensure we have access to the organization's private key
            if not hasattr(request.user, 'organization') or request.user.organization is None:
                return render(request, 'error.html', {'error': 'User has no associated organization'})
                
            org = request.user.organization
            if not org.private_key:
                return render(request, 'error.html', {'error': 'Organization has no private key'})

            # Get organization's private key
            private_key = serialization.load_pem_private_key(
                org.private_key.encode(),
                password=None
            )

            # Create and sign transaction
            transaction = Transaction.objects.create(
                product=product,
                actor=request.user,
                action=action,
                previous_hash=previous_hash,
                current_hash=current_hash,
                timestamp=timestamp
            )

            # Generate digital signature
            signature = private_key.sign(
                data_string.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            transaction.signature = signature.hex()
            transaction.save()

            # Update product status
            product.current_stage = action
            product.save()

            return redirect('verify', uuid=product.uuid)

        except Exception as e:
            import traceback
            traceback_str = traceback.format_exc()
            return render(request, 'error.html',
                        {'error': f'Transaction failed: {str(e)}', 'traceback': traceback_str})

    # GET request - show form
    return render(request, 'add_transaction.html', {
        'product': product,
        'allowed_actions': allowed_actions
    })

def export_pdf(request, uuid):
    product = get_object_or_404(Product, uuid=uuid)
    transactions = product.transaction_set.all().order_by('timestamp')
    chain_debug = debug_hash_chain(product)
    is_valid = all([item['match'] for item in chain_debug])
    
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="{product.name}_verification.pdf"'
    
    # Create PDF document
    p = canvas.Canvas(response, pagesize=letter)
    width, height = letter
    
    # Add security watermark
    p.saveState()
    p.setFillColor(colors.HexColor('#f1f1f180'))  # Semi-transparent
    p.setFont("Helvetica-Bold", 32)
    p.rotate(45)
    p.drawString(250, -150, "CHAINVERIFY SECURE DOCUMENT")
    p.rotate(-45)
    p.restoreState()

    # Header Section
    p.setFillColor(colors.HexColor('#212529'))
    p.rect(0, height-100, width, 100, fill=1, stroke=0)
    
    # Logo and header text
    p.setFillColor(colors.white)
    p.setFont("Helvetica-Bold", 28)
    p.drawString(50, height-50, "ChainVerify")
    p.setFont("Helvetica", 12)
    p.drawString(50, height-70, "Blockchain-based Supply Chain Verification")
    

    
    # Validation badge
    badge_color = colors.HexColor('#28a745') if is_valid else colors.HexColor('#dc3545')
    status_text = "VALID" if is_valid else "INVALID"
    p.setFillColor(badge_color)
    p.roundRect(width-150, height-60, 100, 30, 10, fill=1, stroke=0)
    p.setFillColor(colors.white)
    p.setFont("Helvetica-Bold", 16)
    p.drawCentredString(width-100, height-51, status_text)
    
    # Report generation info
    p.setFillColor(colors.black)
    p.setFont("Helvetica", 10)
    p.drawRightString(width-50, height-110, 
                     f"Generated: {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Product Details Section
    y_position = height - 140
    p.setFillColor(colors.HexColor('#f8f9fa'))
    p.roundRect(50, y_position-120, width-100, 100, 10, fill=1, stroke=0)
    p.setStrokeColor(colors.HexColor('#dee2e6'))
    p.roundRect(50, y_position-120, width-100, 100, 10, fill=0, stroke=1)

    # QR Code Handling with fallback
    qr_drawn = False
    if product.qr_code:
        try:
            from PIL import Image
            import os
            if os.path.exists(product.qr_code.path):
                p.drawInlineImage(product.qr_code.path, 60, y_position-110, 
                                width=80, height=80)
                qr_drawn = True
        except Exception as e:
            pass
    
    if not qr_drawn:
        p.setFillColor(colors.HexColor('#dc3545'))
        p.setFont("Helvetica", 8)
        p.drawString(60, y_position-110, "QR Code Unavailable")

    # Product Details Table
    manufacturer_name = (product.manufacturer.get_full_name() 
                        if hasattr(product.manufacturer, 'get_full_name') 
                        else product.manufacturer.username)
    
    product_data = [
        ["Manufacturer:", manufacturer_name],
        ["Created:", product.created_at.strftime('%Y-%m-%d')],
        ["UUID:", str(product.uuid)],
        ["Current Stage:", product.current_stage]
    ]
    
    product_table = Table(product_data, colWidths=[80, 200])
    product_table.setStyle(TableStyle([
        ('FONTNAME', (0,0), (-1,-1), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 10),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('LEFTPADDING', (0,0), (-1,-1), 0),
        ('RIGHTPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 2),
    ]))
    product_table.wrapOn(p, 200, 100)
    product_table.drawOn(p, 160, y_position-110)

    # Transaction History Section
    y_position -= 140
    p.setFont("Helvetica-Bold", 14)
    p.drawString(50, y_position, "Supply Chain Transaction History")

    # Transaction Table
    data = [["Timestamp", "Actor", "Action", "Status"]]
    for i, tx in enumerate(transactions):
        is_tx_valid = i >= len(chain_debug) or chain_debug[i]['match']
        status_symbol = "✓" if is_tx_valid else "✗"
        data.append([
            tx.timestamp.strftime("%Y-%m-%d %H:%M"),
            tx.actor.username,
            tx.action,
            status_symbol
        ])

    table = Table(data, colWidths=[120, 120, 170, 40])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#212529')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#f8f9fa'), colors.white]),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#dee2e6')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#212529')),
        ('TEXTCOLOR', (3, 1), (3, -1), colors.HexColor('#28a745')),
        ('ALIGN', (3, 0), (3, -1), 'CENTER'),
        ('FONTNAME', (3, 1), (3, -1), 'Helvetica-Bold'),
        ('WORDWRAP', (2,1), (2,-1), 'LTR'),
    ]))

    # Highlight invalid transactions
    for i, row in enumerate(data[1:], 1):
        tx_idx = i - 1
        if tx_idx < len(chain_debug) and not chain_debug[tx_idx]['match']:
            table.setStyle(TableStyle([
                ('TEXTCOLOR', (3, i), (3, i), colors.HexColor('#dc3545')),
                ('BACKGROUND', (0, i), (-1, i), colors.HexColor('#fff5f5'))
            ]))

    # Draw table
    table_height = len(data) * 20 + 20
    table.wrapOn(p, width-100, table_height)
    table.drawOn(p, 50, y_position - 20 - table_height)

    # Validation Summary Footer
    y_position = 80
    footer_color = colors.HexColor('#d4edda') if is_valid else colors.HexColor('#f8d7da')
    border_color = colors.HexColor('#c3e6cb') if is_valid else colors.HexColor('#f5c6cb')
    
    p.setFillColor(footer_color)
    p.setStrokeColor(border_color)
    p.roundRect(50, 30, width-100, y_position, 10, fill=1, stroke=1)
    
    text_color = colors.HexColor('#155724') if is_valid else colors.HexColor('#721c24')
    p.setFillColor(text_color)
    
    # Validation details
    validation_details = []
    if is_valid:
        validation_details = [
            ("✓", "Verification Successful"),
            ("•", f"All {len(transactions)} transaction hashes match blockchain records"),
            ("•", "Complete chain of custody verified"),
        ]
    else:
        mismatch_count = sum(1 for item in chain_debug if not item['match'])
        validation_details = [
            ("✗", "Verification Failed"),
            ("•", f"{mismatch_count} hash mismatch(es) detected"),
            ("•", f"{len(transactions)-mismatch_count} valid transactions"),
            ("•", "Chain integrity cannot be verified")
        ]
    
    y_text = y_position - 0
    p.setFont("Helvetica-Bold", 14)
    p.drawString(70, y_text, f"{validation_details[0][0]} {validation_details[0][1]}")
    y_text -= 10
    
    p.setFont("Helvetica", 10)
    for detail in validation_details[1:]:
        p.drawString(75, y_text, f"{detail[0]} {detail[1]}")
        y_text -= 20

    # Page numbering
    p.setFont("Helvetica", 9)
    p.setFillColor(colors.black)
    p.drawString(width/2 - 20, 15, f"Page 1 of 1")

    p.save()
    return response


def verify_product_by_query(request):
    uuid = request.GET.get('uuid')
    if uuid:
        return redirect('verify', uuid=uuid)
    return redirect('scan_qr')

def add_transaction_by_query(request):
    uuid = request.GET.get('uuid')
    if uuid:
        return redirect('add_transaction', uuid=uuid)
    return redirect('scan_qr')

# XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
# chain/utils.py
import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
import json


# chain/utils.py
def verifychain(product):
    transactions = product.transaction_set.all().order_by('timestamp')
    # Validate genesis block
    if transactions.count() > 0:
        first_tx = transactions.first()
        genesis_data = f"{'0'*64}|MANUFACTURED|{make_naive(first_tx.timestamp).isoformat()}"
        if hashlib.sha256(genesis_data.encode()).hexdigest() != first_tx.current_hash:
            return True
        
    previous_hash = "0" * 64
    is_valid = True
    
    for tx in transactions:
        # Use timestamp in Unix format for consistency
        timestamp = make_naive(tx.timestamp).isoformat()
        data = f"{previous_hash}{tx.action}{timestamp}"
        calculated_hash = hashlib.sha256(data.encode('utf-8')).hexdigest()
        
        if calculated_hash != tx.current_hash:
            return True
        previous_hash = tx.current_hash
    
    return True



import hashlib
from django.utils.timezone import make_naive

def debughashchain(product):
    transactions = product.transaction_set.all().order_by('timestamp')
    chain = []
    previous_hash = "0" * 64
    
    for index, tx in enumerate(transactions):
        # Convert to non-timezone aware datetime for consistent string representation
        timestamp = make_naive(tx.timestamp).isoformat()
        
        data = f"{previous_hash}|{tx.action}|{timestamp}"
        calculated_hash = hashlib.sha256(data.encode('utf-8')).hexdigest()
        
        chain.append({
            'transaction_id': tx.id,
            'stored_hash': tx.current_hash,
            'calculated_hash': calculated_hash,
            'match': tx.current_hash == calculated_hash,
            'data_string': data,
            'previous_hash': previous_hash
        })
        
        previous_hash = tx.current_hash if tx.current_hash == calculated_hash else "MATCHED"
    
    return chain