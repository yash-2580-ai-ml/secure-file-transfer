from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import hashlib
from typing import Tuple, Dict, Any, Union


class HybridCrypto:
    """
    Hybrid cryptosystem implementing RSA-4096 asymmetric encryption
    for secure AES key exchange and AES-256-GCM symmetric authenticated
    encryption for payload integrity and confidentiality.
    """

    def generate_rsa_keys(self) -> Tuple[bytes, bytes]:
        """
        Generate a 4096-bit RSA keypair.

        Returns:
            Tuple[bytes, bytes]: (private_key, public_key) as PEM bytes.
        """
        try:
            key = RSA.generate(4096)
            private_key = key.export_key(format='PEM')
            public_key = key.publickey().export_key(format='PEM')
            return private_key, public_key
        except Exception as e:
            raise RuntimeError(f"Failed to generate 4096-bit RSA key pair: {e}") from e

    def encrypt_hybrid(self, file_data: Union[bytes, str], recipient_public_key: Union[bytes, str]) -> Dict[str, bytes]:
        """
        Encrypt file_data using hybrid encryption:
        1. Generates a random 32-byte AES-256 key.
        2. Encrypts file_data with AES-256-GCM, obtaining ciphertext and authentication tag.
        3. Encrypts the AES key with RSA-OAEP using recipient_public_key.
        4. Returns dictionary containing encrypted_key, nonce, tag, and ciphertext.

        Args:
            file_data: Payload data as bytes or string.
            recipient_public_key: Recipient's RSA public key (PEM bytes or string).

        Returns:
            Dict[str, bytes]: Dictionary containing:
                - 'encrypted_key': RSA-OAEP encrypted AES key
                - 'nonce': AES-GCM nonce (IV)
                - 'tag': AES-GCM authentication tag
                - 'ciphertext': AES-GCM encrypted payload
        """
        try:
            if isinstance(file_data, str):
                file_data = file_data.encode('utf-8')
            elif not isinstance(file_data, (bytes, bytearray)):
                raise TypeError(f"file_data must be bytes or str, got {type(file_data).__name__}")

            if isinstance(recipient_public_key, str):
                recipient_public_key = recipient_public_key.encode('utf-8')

            # 1. Generate random 32-byte AES key
            aes_key = get_random_bytes(32)

            # 2. Encrypt file_data with AES-256-GCM
            cipher_aes = AES.new(aes_key, AES.MODE_GCM)
            ciphertext, tag = cipher_aes.encrypt_and_digest(file_data)
            nonce = cipher_aes.nonce

            # 3. Encrypt AES key with RSA-OAEP using recipient_public_key
            try:
                rsa_key = RSA.import_key(recipient_public_key)
            except Exception as e:
                raise ValueError(f"Invalid recipient RSA public key: {e}") from e

            cipher_rsa = PKCS1_OAEP.new(rsa_key)
            encrypted_aes_key = cipher_rsa.encrypt(aes_key)

            # 4. Return package dict
            return {
                'encrypted_key': encrypted_aes_key,
                'nonce': nonce,
                'tag': tag,
                'ciphertext': ciphertext
            }
        except (TypeError, ValueError):
            raise
        except Exception as e:
            raise RuntimeError(f"Hybrid encryption failed: {e}") from e

    def decrypt_hybrid(self, encrypted_package: Dict[str, bytes], private_key: Union[bytes, str]) -> bytes:
        """
        Decrypt encrypted_package using hybrid decryption:
        1. Decrypts AES key using RSA private key via RSA-OAEP.
        2. Decrypts file payload using AES-256-GCM with nonce and tag.
        3. Returns decrypted bytes.

        Args:
            encrypted_package: Dict with 'encrypted_key', 'nonce', 'tag', 'ciphertext'.
            private_key: RSA private key (PEM bytes or string).

        Returns:
            bytes: Decrypted payload bytes.
        """
        try:
            if not isinstance(encrypted_package, dict):
                raise TypeError(f"encrypted_package must be a dict, got {type(encrypted_package).__name__}")

            required_fields = ('encrypted_key', 'nonce', 'tag', 'ciphertext')
            for field in required_fields:
                if field not in encrypted_package:
                    raise ValueError(f"Missing required field '{field}' in encrypted_package")

            if isinstance(private_key, str):
                private_key = private_key.encode('utf-8')

            # 1. Decrypt AES key with RSA-OAEP
            try:
                rsa_key = RSA.import_key(private_key)
            except Exception as e:
                raise ValueError(f"Invalid RSA private key: {e}") from e

            cipher_rsa = PKCS1_OAEP.new(rsa_key)
            try:
                aes_key = cipher_rsa.decrypt(encrypted_package['encrypted_key'])
            except Exception as e:
                raise ValueError(f"Failed to decrypt AES key with RSA private key: {e}") from e

            # 2. Decrypt file using AES-GCM with nonce and tag
            try:
                cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=encrypted_package['nonce'])
                decrypted_data = cipher_aes.decrypt_and_verify(
                    encrypted_package['ciphertext'],
                    encrypted_package['tag']
                )
            except ValueError as e:
                raise ValueError(f"Integrity check failed: AES-GCM tag verification failed ({e})") from e

            return decrypted_data
        except (TypeError, ValueError):
            raise
        except Exception as e:
            raise RuntimeError(f"Hybrid decryption failed: {e}") from e

    def hash_sha256(self, data: Union[bytes, str]) -> str:
        """
        Calculate SHA-256 hex digest of data.

        Args:
            data: Data to hash (bytes or str).

        Returns:
            str: Hexadecimal SHA-256 digest string.
        """
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            elif not isinstance(data, (bytes, bytearray)):
                raise TypeError(f"data must be bytes or str, got {type(data).__name__}")

            return hashlib.sha256(data).hexdigest()
        except TypeError:
            raise
        except Exception as e:
            raise RuntimeError(f"SHA-256 hashing failed: {e}") from e


if __name__ == "__main__":
    print("=" * 60)
    print("Testing HybridCrypto (RSA-4096 + AES-256-GCM)")
    print("=" * 60)

    crypto = HybridCrypto()

    # 1. Key Generation
    print("\n[1] Generating 4096-bit RSA key pair...")
    priv_key, pub_key = crypto.generate_rsa_keys()
    print(f"    Private key size: {len(priv_key)} bytes")
    print(f"    Public key size:  {len(pub_key)} bytes")

    # 2. Test Data & Hashing
    test_message = b"Top secret payload protected by Hybrid AES-256-GCM + RSA-4096."
    print(f"\n[2] Original message: {test_message.decode('utf-8')}")
    original_hash = crypto.hash_sha256(test_message)
    print(f"    SHA-256 Hash: {original_hash}")

    # 3. Hybrid Encryption
    print("\n[3] Encrypting with HybridCrypto...")
    pkg = crypto.encrypt_hybrid(test_message, pub_key)
    print(f"    Encrypted AES Key: {len(pkg['encrypted_key'])} bytes")
    print(f"    AES Nonce:         {pkg['nonce'].hex()}")
    print(f"    AES Tag:           {pkg['tag'].hex()}")
    print(f"    Ciphertext:        {pkg['ciphertext'].hex()[:32]}...")

    # 4. Hybrid Decryption
    print("\n[4] Decrypting with HybridCrypto...")
    decrypted = crypto.decrypt_hybrid(pkg, priv_key)
    print(f"    Decrypted payload: {decrypted.decode('utf-8')}")
    decrypted_hash = crypto.hash_sha256(decrypted)
    print(f"    Decrypted SHA-256: {decrypted_hash}")

    # 5. Validation
    assert decrypted == test_message, "Decrypted message mismatch!"
    assert original_hash == decrypted_hash, "Hash mismatch!"
    print("\n[SUCCESS] Verification successful: Hybrid encryption & decryption verified.")
    print("=" * 60)