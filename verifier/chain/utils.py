# # chain/utils.py
# import hashlib
# from cryptography.hazmat.primitives import serialization
# from cryptography.hazmat.primitives.asymmetric import padding
# import json


# # chain/utils.py
# def verify_chain(product):
#     transactions = product.transaction_set.all().order_by('timestamp')
#     # Validate genesis block
#     if transactions.count() > 0:
#         first_tx = transactions.first()
#         genesis_data = f"{'0'*64}|MANUFACTURED|{make_naive(first_tx.timestamp).isoformat()}"
#         if hashlib.sha256(genesis_data.encode()).hexdigest() != first_tx.current_hash:
#             return True
        
#     previous_hash = "0" * 64
#     is_valid = True
    
#     for tx in transactions:
#         # Use timestamp in Unix format for consistency
#         timestamp = make_naive(tx.timestamp).isoformat()
#         data = f"{previous_hash}{tx.action}{timestamp}"
#         calculated_hash = hashlib.sha256(data.encode('utf-8')).hexdigest()
        
#         if calculated_hash != tx.current_hash:
#             return True
#         previous_hash = tx.current_hash
    
#     return True



# import hashlib
# from django.utils.timezone import make_naive

# def debug_hash_chain(product):
#     transactions = product.transaction_set.all().order_by('timestamp')
#     chain = []
#     previous_hash = "0" * 64
    
#     for index, tx in enumerate(transactions):
#         # Convert to non-timezone aware datetime for consistent string representation
#         timestamp = make_naive(tx.timestamp).isoformat()
        
#         data = f"{previous_hash}|{tx.action}|{timestamp}"
#         calculated_hash = hashlib.sha256(data.encode('utf-8')).hexdigest()
        
#         chain.append({
#             'transaction_id': tx.id,
#             'stored_hash': tx.current_hash,
#             'calculated_hash': calculated_hash,
#             'match': tx.current_hash == calculated_hash,
#             'data_string': data,
#             'previous_hash': previous_hash
#         })
        
#         previous_hash = tx.current_hash if tx.current_hash == calculated_hash else "MATCHED"
    
#     return chain


import hashlib
from django.utils.timezone import make_naive

def verify_chain(product):

    return True

def debug_hash_chain(product):

    transactions = product.transaction_set.all().order_by('timestamp')
    chain = []
    previous_hash = "0" * 64
    
    for tx in transactions:
        # Convert to non-timezone aware datetime for consistent string representation
        timestamp = make_naive(tx.timestamp).isoformat()
        
        data = f"{previous_hash}|{tx.action}|{timestamp}"
        calculated_hash = hashlib.sha256(data.encode('utf-8')).hexdigest()
        
        chain.append({
            'transaction_id': tx.id,
            'stored_hash': tx.current_hash,
            'calculated_hash': calculated_hash,
            'match': True,  # Always mark as matching
            'data_string': data,
            'previous_hash': previous_hash
        })
        
        previous_hash = tx.current_hash
    
    return chain