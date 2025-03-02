from django.shortcuts import render, get_object_or_404, redirect
from django.http import HttpResponse
from .models import Product, Transaction
from .utils import verify_chain
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import Table, TableStyle
import hashlib
from django.utils import timezone


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
            Transaction.objects.create(
                product=product,
                actor=request.user,
                action='MANUFACTURED',
                previous_hash='0'*64,
                current_hash=hashlib.sha256(f'GENESIS{product.uuid}'.encode()).hexdigest()
            )
            
            return redirect('verify', uuid=product.uuid)
    else:
        form = ProductForm()
    
    return render(request, 'create_product.html', {'form': form})

def scan_qr(request):
    return render(request, 'scan.html')

def verify_product(request, uuid=None):
    if request.method == "GET" and 'uuid' in request.GET:
        uuid = request.GET['uuid']
    
    product = get_object_or_404(Product, uuid=uuid)
    is_valid = verify_chain(product)
    
    return render(request, 'verify.html', {
        'product': product,
        'is_valid': is_valid,
        'transactions': product.transaction_set.all().order_by('timestamp'),
        'is_authenticated': request.user.is_authenticated
    })


from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import Group
from django.shortcuts import redirect

@login_required
def add_transaction(request, uuid):
    product = get_object_or_404(Product, uuid=uuid)
    allowed_actions = []
    
    if request.user.groups.filter(name='Manufacturer').exists():
        allowed_actions = ['MANUFACTURED', 'SHIPPED']
    elif request.user.groups.filter(name='Distributor').exists():
        allowed_actions = ['IN_TRANSIT', 'RECEIVED_WAREHOUSE']
    elif request.user.groups.filter(name='Retailer').exists():
        allowed_actions = ['DELIVERED', 'SHELVED', 'SOLD']

    if request.method == 'POST':
        action = request.POST.get('action')
        if action in allowed_actions:
            # Update product stage
            product.update_stage(action)
            
            # Create transaction
            last_transaction = product.transaction_set.last()
            new_hash = hashlib.sha256(
                f"{last_transaction.current_hash}{action}{timezone.now()}".encode()
            ).hexdigest()
            
            Transaction.objects.create(
                product=product,
                actor=request.user,
                action=action,
                previous_hash=last_transaction.current_hash,
                current_hash=new_hash
            )
            
            return redirect('verify', uuid=product.uuid)

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