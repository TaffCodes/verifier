from django.db import models
from django.contrib.auth.models import User
import uuid
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from django.utils.timezone import make_naive

from django.db import models
from django.contrib.auth.models import User
import uuid

class Product(models.Model):
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    manufacturer = models.ForeignKey(User, on_delete=models.CASCADE, related_name='products_created')
    created_at = models.DateTimeField(auto_now_add=True)
    current_stage = models.CharField(max_length=50, default='MANUFACTURED')
    qr_code = models.ImageField(upload_to='qrcodes/', blank=True)

    STAGE_CHOICES = [
        ('MANUFACTURED', 'Manufactured'),
        ('IN_TRANSIT', 'In Transit'),
        ('RECEIVED_WAREHOUSE', 'Received at Warehouse'),
        ('DELIVERED', 'Delivered to Retailer'),
        ('SHELVED', 'Shelved for Sale'),
        ('SOLD', 'Sold'),
    ]

    def update_stage(self, new_stage):
        if new_stage in dict(self.STAGE_CHOICES):
            self.current_stage = new_stage
            self.save()
            return True
        return False

class Organization(models.Model):
    user = models.OneToOneField(
        User, 
        on_delete=models.CASCADE,
        related_name='organization'  # Access via user.organization
    )
    public_key = models.TextField()
    private_key = models.TextField()
class Transaction(models.Model):
    ACTION_CHOICES = [
    ('MANUFACTURED', 'Manufactured'),
    ('SHIPPED', 'Shipped'),
    ('RECEIVED_AT_WAREHOUSE', 'Received at Warehouse'),
    ('DELIVERED', 'Delivered to Store'),
    ('SHELVED', 'Shelved for Sale'),
    ]
    actor = models.ForeignKey(
        User, 
        on_delete=models.CASCADE,
        related_name='transactions'  # Access via user.transactions
    )
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    action = models.CharField(max_length=50, choices=ACTION_CHOICES)
    timestamp = models.DateTimeField(auto_now_add=True)
    previous_hash = models.CharField(max_length=64)
    current_hash = models.CharField(max_length=64)
    signature = models.TextField()

    def clean(self):
        from django.core.exceptions import ValidationError
        
        # Validate hash consistency
        if self.pk:  # Existing instance
            previous = Transaction.objects.get(pk=self.pk)
            if self.current_hash != previous.current_hash:
                raise ValidationError("Immutable field: current_hash")

    def save(self, *args, **kwargs):
        # Prevent manual hash modification
        if self.pk:
            original = Transaction.objects.get(pk=self.pk)
            if self.current_hash != original.current_hash:
                raise ValueError("Hash modification prohibited")
        super().save(*args, **kwargs)