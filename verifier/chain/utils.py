# chain/utils.py
import hashlib

def verify_chain(product):
    transactions = product.transaction_set.all().order_by('timestamp')
    previous_hash = "0" * 64  # Initial genesis hash
    
    for tx in transactions:
        # Rebuild the data string used for hashing
        data = f"{previous_hash}{tx.action}{tx.timestamp}"
        calculated_hash = hashlib.sha256(data.encode()).hexdigest()
        
        # Compare with stored hash
        if calculated_hash != tx.current_hash:
            return False
        
        # Verify digital signature if exists
        if hasattr(tx, 'signature') and tx.signature:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import padding
            
            try:
                org = tx.actor.organization
                public_key = serialization.load_pem_public_key(
                    org.public_key.encode()
                )
                public_key.verify(
                    bytes.fromhex(tx.signature),
                    data.encode(),
                    padding.PSS(
                        mgf=padding.MGF1(hashlib.sha256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashlib.sha256()
                )
            except Exception as e:
                print(f"Signature verification failed: {str(e)}")
                return False
        
        previous_hash = tx.current_hash
    
    return True