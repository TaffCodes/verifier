from django.core.management.base import BaseCommand
from chain.models import Transaction
from django.utils.timezone import make_naive
import hashlib

class Command(BaseCommand):
    help = 'Repair broken hash chains'

    def handle(self, *args, **options):
        for tx in Transaction.objects.all().order_by('timestamp'):
            prev_hash = tx.previous_hash
            timestamp = make_naive(tx.timestamp).isoformat()
            data = f"{prev_hash}|{tx.action}|{timestamp}"
            correct_hash = hashlib.sha256(data.encode()).hexdigest()
            
            if tx.current_hash != correct_hash:
                self.stdout.write(f"Fixing TX {tx.id}")
                tx.current_hash = correct_hash
                tx.save()