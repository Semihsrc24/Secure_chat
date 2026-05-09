"""
End-to-End Encryption Module
Handles RSA key management and message encryption/decryption for E2E security.
"""

import os
import json
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend


class E2EEncryption:
    """RSA-based End-to-End encryption manager."""
    
    KEY_SIZE = 2048
    PUBLIC_EXPONENT = 65537
    
    def __init__(self, user_id: str, keys_dir: str = "keys"):
        """Initialize E2E encryption manager for a user.
        
        Args:
            user_id: Unique identifier for the user
            keys_dir: Directory to store public/private keys
        """
        self.user_id = user_id
        self.keys_dir = keys_dir
        self.private_key = None
        self.public_key = None
        self.public_keys_cache = {}  # {user_id: public_key}
        
        os.makedirs(keys_dir, exist_ok=True)
        self._load_or_generate_keys()
    
    def _get_private_key_path(self) -> str:
        """Get path to user's private key file."""
        return os.path.join(self.keys_dir, f"{self.user_id}_private.pem")
    
    def _get_public_key_path(self) -> str:
        """Get path to user's public key file."""
        return os.path.join(self.keys_dir, f"{self.user_id}_public.pem")
    
    def _load_or_generate_keys(self) -> None:
        """Load existing keys or generate new ones."""
        private_key_path = self._get_private_key_path()
        public_key_path = self._get_public_key_path()
        
        # Try loading existing keys
        if os.path.exists(private_key_path) and os.path.exists(public_key_path):
            try:
                self._load_keys()
                return
            except Exception as e:
                print(f"[E2E] Error loading keys for {self.user_id}: {e}")
        
        # Generate new key pair if not found
        self._generate_key_pair()
    
    def _generate_key_pair(self) -> None:
        """Generate new RSA key pair."""
        try:
            private_key = rsa.generate_private_key(
                public_exponent=self.PUBLIC_EXPONENT,
                key_size=self.KEY_SIZE,
                backend=default_backend()
            )
            self.private_key = private_key
            self.public_key = private_key.public_key()
            self._save_keys()
            print(f"[E2E] Generated new RSA key pair for {self.user_id}")
        except Exception as e:
            print(f"[E2E] Error generating key pair for {self.user_id}: {e}")
            raise
    
    def _save_keys(self) -> None:
        """Save private and public keys to files."""
        try:
            # Save private key
            private_pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            with open(self._get_private_key_path(), "wb") as f:
                f.write(private_pem)
            
            # Save public key
            public_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            with open(self._get_public_key_path(), "wb") as f:
                f.write(public_pem)
            
            print(f"[E2E] Keys saved for {self.user_id}")
        except Exception as e:
            print(f"[E2E] Error saving keys for {self.user_id}: {e}")
            raise
    
    def _load_keys(self) -> None:
        """Load private and public keys from files."""
        try:
            # Load private key
            with open(self._get_private_key_path(), "rb") as f:
                private_pem = f.read()
            self.private_key = serialization.load_pem_private_key(
                private_pem,
                password=None,
                backend=default_backend()
            )
            
            # Load public key
            with open(self._get_public_key_path(), "rb") as f:
                public_pem = f.read()
            self.public_key = serialization.load_pem_public_key(
                public_pem,
                backend=default_backend()
            )
            
            print(f"[E2E] Keys loaded for {self.user_id}")
        except Exception as e:
            print(f"[E2E] Error loading keys for {self.user_id}: {e}")
            raise
    
    def get_public_key_pem(self) -> str:
        """Get public key as PEM-encoded string (for sharing with server/other users)."""
        if not self.public_key:
            return ""
        
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return public_pem.decode("utf-8")
    
    @staticmethod
    def load_public_key_from_pem(pem_str: str):
        """Load a public key from PEM string."""
        try:
            public_key = serialization.load_pem_public_key(
                pem_str.encode("utf-8"),
                backend=default_backend()
            )
            return public_key
        except Exception as e:
            print(f"[E2E] Error loading public key from PEM: {e}")
            return None
    
    def cache_public_key(self, user_id: str, public_key_pem: str) -> bool:
        """Cache another user's public key."""
        try:
            public_key = self.load_public_key_from_pem(public_key_pem)
            if public_key:
                self.public_keys_cache[user_id] = public_key
                return True
        except Exception as e:
            print(f"[E2E] Error caching public key for {user_id}: {e}")
        return False
    
    def get_cached_public_key(self, user_id: str):
        """Get a cached public key."""
        return self.public_keys_cache.get(user_id)
    
    def encrypt_message(self, message: str, recipient_public_key) -> str:
        """Encrypt a message with recipient's public key.
        
        Args:
            message: Plain text message to encrypt
            recipient_public_key: Recipient's public key object
        
        Returns:
            Base64-encoded encrypted message with 'e2e:' prefix
        """
        try:
            ciphertext = recipient_public_key.encrypt(
                message.encode("utf-8"),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            # Encode to base64 for JSON transport
            encrypted_b64 = base64.b64encode(ciphertext).decode("utf-8")
            return f"e2e:v1:{encrypted_b64}"
        except Exception as e:
            print(f"[E2E] Error encrypting message: {e}")
            return message
    
    def decrypt_message(self, encrypted_msg: str) -> str:
        """Decrypt a message with user's private key.
        
        Args:
            encrypted_msg: Encrypted message with 'e2e:v1:' prefix
        
        Returns:
            Decrypted message or error message if decryption fails
        """
        if not isinstance(encrypted_msg, str):
            return encrypted_msg
        
        if not encrypted_msg.startswith("e2e:v1:"):
            return encrypted_msg
        
        if not self.private_key:
            return "[E2E message - no private key available]"
        
        try:
            # Extract base64-encoded ciphertext
            encrypted_b64 = encrypted_msg.split(":", 2)[2]
            ciphertext = base64.b64decode(encrypted_b64)
            
            # Decrypt with private key
            plaintext = self.private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return plaintext.decode("utf-8")
        except Exception:
            # Silently fail for cross-recipient or corrupted E2E messages
            # This is normal when receiving messages encrypted for other users
            return "[E2E message could not be decrypted]"
    
    def create_key_exchange_payload(self) -> dict:
        """Create a payload for public key exchange with server/other users."""
        return {
            "type": "key_exchange",
            "user_id": self.user_id,
            "public_key": self.get_public_key_pem(),
            "key_format": "RSA-2048-PKCS8",
        }
    
    def get_public_keys_cache_dump(self) -> dict:
        """Export cached public keys for persistence."""
        dump = {}
        for user_id, public_key in self.public_keys_cache.items():
            try:
                public_pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                dump[user_id] = public_pem.decode("utf-8")
            except:
                pass
        return dump
    
    def restore_public_keys_cache(self, dump: dict) -> None:
        """Restore cached public keys from persistence."""
        for user_id, public_pem in dump.items():
            self.cache_public_key(user_id, public_pem)
