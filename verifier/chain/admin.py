from django.contrib.auth.models import User, Group
from chain.models import Organization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def create_user_with_org(username, password, group_name):
    user = User.objects.create_user(username=username, password=password)
    group = Group.objects.get(name=group_name)
    user.groups.add(group)
    
    # Generate cryptographic keys
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pem_public = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    Organization.objects.create(
        user=user,
        public_key=pem_public.decode(),
        private_key=pem_private.decode()
    )

# Example usage
# create_user_with_org('distributor1', 'iamcalvo44', 'Distributor')
# create_user_with_org('retailer1', 'iamcalvo44', 'Retailer')