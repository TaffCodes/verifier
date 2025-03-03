from django.db.models.signals import post_save
from django.dispatch import receiver
from django.core.files.base import ContentFile
from .models import Product
import qrcode
import io
from django.conf import settings

@receiver(post_save, sender=Product)
def generate_qrcode(sender, instance, created, **kwargs):
    if created:
        # Generate QR code data
        verification_url = f"{settings.BASE_URL}/verify/{instance.uuid}"
        
        # Create QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(verification_url)
        qr.make(fit=True)
        
        # Create in-memory image
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        
        # Save to model
        filename = f"qr_{instance.uuid}.png"
        instance.qr_code.save(filename, ContentFile(buffer.getvalue()), save=False)
        instance.save()
    print(f"Generating QR code for {instance.uuid}")  # Check server logs