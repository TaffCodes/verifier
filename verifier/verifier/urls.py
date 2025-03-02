from django.contrib import admin
from django.urls import path
from chain import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('accounts/login/', views.login_view, name='login'),
    path('accounts/logout/', views.logout_view, name='logout'),
    path('scan/', views.scan_qr, name='scan_qr'),
    path('verify/<uuid:uuid>', views.verify_product, name='verify'),
    path('verify/', views.verify_product, name='verify_manual'),
    path('export-pdf/<uuid:uuid>', views.export_pdf, name='export_pdf'),
    path('', views.scan_qr, name='home'),
    path('transaction/<uuid:uuid>/add', views.add_transaction, name='add_transaction'),
    path('add_transaction/', views.add_transaction, name='add_transaction'),
]