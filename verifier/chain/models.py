from django.db import models
from django.contrib.auth.models import User
import uuid
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

class Product(models.Model):
    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100)
    manufacturer = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    qr_code = models.ImageField(upload_to='qrcodes/', blank=True)
    is_recalled = models.BooleanField(default=False)
    recall_reason = models.TextField(blank=True)
    recall_date = models.DateTimeField(null=True, blank=True)

class Organization(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
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
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    actor = models.ForeignKey(User, on_delete=models.CASCADE)
    action = models.CharField(max_length=50, choices=ACTION_CHOICES)
    timestamp = models.DateTimeField(auto_now_add=True)
    previous_hash = models.CharField(max_length=64)
    current_hash = models.CharField(max_length=64)
    signature = models.TextField()

    def save(self, *args, **kwargs):
        if not self.pk:
            last_tx = Transaction.objects.filter(product=self.product).last()
            self.previous_hash = last_tx.current_hash if last_tx else '0'*64
            data = f"{self.previous_hash}{self.action}{self.timestamp}"
            self.current_hash = hashlib.sha256(data.encode()).hexdigest()
        super().save(*args, **kwargs)

    def sign_transaction(self, private_key):
        data = f"{self.previous_hash}{self.action}{self.timestamp}".encode()
        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        self.signature = signature.hex()