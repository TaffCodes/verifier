from django.shortcuts import render, get_object_or_404, redirect
from django.http import HttpResponse
from .models import Product, Transaction
from .utils import verify_chain
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import Table, TableStyle


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
    
    # Get allowed actions based on user role
    allowed_actions = []
    if request.user.groups.filter(name='Manufacturer').exists():
        allowed_actions = ['MANUFACTURED']
    elif request.user.groups.filter(name='Distributor').exists():
        allowed_actions = ['SHIPPED', 'RECEIVED_AT_WAREHOUSE']
    elif request.user.groups.filter(name='Retailer').exists():
        allowed_actions = ['DELIVERED', 'SHELVED']
    
    if request.method == 'POST':
        action = request.POST.get('action')
        if action in allowed_actions:
            Transaction.objects.create(
                product=product,
                actor=request.user,
                action=action
            )
            return redirect('verify', uuid=product.uuid)
    
    return render(request, 'add_transaction.html', {
        'product': product,
        'allowed_actions': Transaction.ACTION_CHOICES,  # Or filtered choices
        'recent_transactions': Transaction.objects.filter(actor=request.user)[:5]
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