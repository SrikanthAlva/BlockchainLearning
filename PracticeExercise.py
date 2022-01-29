from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Generating the private/public key pair
private_key_alice = rsa.generate_private_key(public_exponent=65537, key_size=2048)
# Assigning the public key from the pair
public_key_alice = private_key_alice.public_key()

# Generating the private/public key pair
private_key_bob = rsa.generate_private_key(public_exponent=65537, key_size=2048)
# Assigning the public key from the pair
public_key_bob = private_key_bob.public_key()

orig_message = b"The quick brown fox jumps over the lazy dog"
false_message = b"The quick brown fox jumps over the lazy dog!"
print(f"Original Message: {orig_message}\n\n")

# Encrypting the original message using the public key
signature_alice = private_key_alice.sign(
    orig_message,
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
    hashes.SHA256(),
)
print(f"Alice Signature: {signature_alice}\n\n")

encrypted_message = public_key_bob.encrypt(
    orig_message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    ),
)
print(f"Encrypted message: {encrypted_message}\n\n")


# Decrypting the original message using the private key
decrypted_message = private_key_bob.decrypt(
    encrypted_message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    ),
)
print(f"Decrypted Message: {decrypted_message}\n\n")

# Decrypting the original message using the private key
public_key_alice.verify(
    signature_alice,
    decrypted_message,
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
    hashes.SHA256(),
)
# print(f'Decrypted message: {decrypted_message}\n\n')
