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
    transactions = product.transaction_set.all()
    
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="{product.name}_report.pdf"'
    
    p = canvas.Canvas(response, pagesize=letter)
    width, height = letter
    
    # Header
    p.setFont("Helvetica-Bold", 16)
    p.drawString(50, height-50, f"Supply Chain Report: {product.name}")
    p.setFont("Helvetica", 12)
    p.drawString(50, height-80, f"UUID: {product.uuid}")
    
    # Table Data
    data = [["Timestamp", "Actor", "Action"]]
    for tx in transactions:
        data.append([
            tx.timestamp.strftime("%Y-%m-%d %H:%M"),
            tx.actor.username,
            tx.action
        ])
    
    # Create Table
    table = Table(data, colWidths=[150, 150, 250])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#212529')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('FONTSIZE', (0,0), (-1,0), 12),
        ('BOTTOMPADDING', (0,0), (-1,0), 12),
        ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#f8f9fa')),
        ('GRID', (0,0), (-1,-1), 1, colors.HexColor('#dee2e6'))
    ]))
    
    # Draw Table
    table.wrapOn(p, width-100, height)
    table.drawOn(p, 50, height-150)
    
    p.save()
    return response

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