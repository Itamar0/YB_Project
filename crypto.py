# crypto.py
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
import os
import logging

logger = logging.getLogger('VPN-Crypto')

class VPNCrypto:
    """Handles cryptographic operations for the VPN"""
    
    def __init__(self):
        """Initialize crypto module with no active keys"""
        self.private_key = None
        self.public_key = None
        self.peer_public_key = None
        self.shared_key = None
        self.encryption_key = None
        self.session_id = None
        
    def generate_keypair(self):
        """Generate a new ECDH key pair"""
        # Use P-256 curve for good security-performance balance
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()
        return self.get_public_bytes()
        
    def get_public_bytes(self):
        """Get the public key in serialized form"""
        if not self.public_key:
            return None
            
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
    def set_peer_public_key(self, public_key_bytes):
        """Set the peer's public key from serialized form"""
        try:
            self.peer_public_key = serialization.load_pem_public_key(public_key_bytes)
            return True
        except Exception as e:
            logger.error(f"Error loading peer public key: {e}")
            return False
            
    def generate_shared_key(self):
        """Generate shared key using ECDH"""
        if not self.private_key or not self.peer_public_key:
            logger.error("Cannot generate shared key: Missing keys")
            return False
            
        try:
            # Perform the key exchange
            shared_secret = self.private_key.exchange(ec.ECDH(), self.peer_public_key)
            
            # Generate a session ID for identifying this session
            self.session_id = os.urandom(8).hex()
            
            # Derive encryption keys using HKDF
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,  # 256-bit key for AES-256-GCM
                salt=None,
                info=b'vpn_encryption_key'
            )
            self.encryption_key = hkdf.derive(shared_secret)
            
            logger.info(f"Generated shared encryption key for session {self.session_id}")
            return True
        except Exception as e:
            logger.error(f"Error generating shared key: {e}")
            return False
            
    def encrypt(self, plaintext):
        """Encrypt data using AES-GCM"""
        if not self.encryption_key:
            logger.error("Cannot encrypt: No encryption key available")
            return None
            
        try:
            # Create a unique nonce for each message
            nonce = os.urandom(12)  # 96 bits as recommended for GCM
            
            # Encrypt the plaintext
            aesgcm = AESGCM(self.encryption_key)
            ciphertext = aesgcm.encrypt(nonce, plaintext, None)
            
            # Return nonce + ciphertext
            return nonce + ciphertext
        except Exception as e:
            logger.error(f"Encryption error: {e}")
            return None
            
    def decrypt(self, ciphertext):
        """Decrypt data using AES-GCM"""
        if not self.encryption_key:
            logger.error("Cannot decrypt: No encryption key available")
            return None
            
        if len(ciphertext) < 12:  # Minimum length for nonce
            logger.error("Ciphertext too short")
            return None
            
        try:
            # Extract nonce and actual ciphertext
            nonce = ciphertext[:12]
            actual_ciphertext = ciphertext[12:]
            
            # Decrypt the ciphertext
            aesgcm = AESGCM(self.encryption_key)
            plaintext = aesgcm.decrypt(nonce, actual_ciphertext, None)
            
            return plaintext
        except InvalidTag:
            logger.error("Decryption failed: Message authentication failed")
            return None
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            return None
    
    def create_auth_response(self, challenge):
        """Create an authentication response using the shared key"""
        if not self.encryption_key:
            logger.error("Cannot create auth response: No encryption key")
            return None
            
        try:
            # Use HMAC-SHA256 with our encryption key
            from cryptography.hazmat.primitives import hmac
            h = hmac.HMAC(self.encryption_key, hashes.SHA256())
            h.update(challenge)
            return h.finalize()
        except Exception as e:
            logger.error(f"Error creating auth response: {e}")
            return None
            
    def verify_auth_response(self, challenge, response):
        """Verify an authentication response"""
        if not self.encryption_key:
            logger.error("Cannot verify auth response: No encryption key")
            return False
            
        try:
            # Calculate expected response
            from cryptography.hazmat.primitives import hmac
            h = hmac.HMAC(self.encryption_key, hashes.SHA256())
            h.update(challenge)
            expected = h.finalize()
            
            # Compare in constant time to prevent timing attacks
            from cryptography.hazmat.primitives.constant_time import bytes_eq
            return bytes_eq(expected, response)
        except Exception as e:
            logger.error(f"Error verifying auth response: {e}")
            return False