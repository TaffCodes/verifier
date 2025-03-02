import hashlib
from django.test import TestCase
from chain.models import Product, Transaction

class VerificationTests(TestCase):
    def test_valid_chain(self):
        product = Product.objects.create(name="Test Product")
        
        # Create valid transaction chain
        tx1 = Transaction.objects.create(
            product=product,
            action="MANUFACTURED",
            previous_hash="0"*64,
            current_hash=hashlib.sha256(
                f"{'0'*64}MANUFACTURED{product.created_at}"
            ).hexdigest()
        )
        
        tx2 = Transaction.objects.create(
            product=product,
            action="SHIPPED",
            previous_hash=tx1.current_hash,
            current_hash=hashlib.sha256(
                f"{tx1.current_hash}SHIPPED{tx2.timestamp}"
            ).hexdigest()
        )
        
        self.assertTrue(product.verify_chain())