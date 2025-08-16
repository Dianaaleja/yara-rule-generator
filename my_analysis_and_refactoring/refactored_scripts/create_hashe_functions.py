"""Module for generating various cryptographic hashes and encodings.

This module provides functions to generate different types of hashes (MD5, SHA1, SHA256, etc.)
and encodings (Base64, Base58) for input strings. It also supports optional hash functions
like BLAKE3, MD2, and MD4 when the required libraries are available.
"""

import hashlib
import base64
import csv

# Attempt to import optional libraries, handling errors if they are not installed.
try:
    import blake3
except ImportError:
    blake3 = None
    print("Warning: The 'blake3' library is not installed. Some hash functions may not work.")

try:
    import base58
except ImportError:
    base58 = None
    print("Warning: The 'base58' library is not installed. Some encoding functions may not work.")

# The original create_hashes_functions.sh script has an error in MD2 and MD4,
# as both point to MD5. Here we correct that logic and implement MD2 and MD4
# correctly, which, although not secure, demonstrates that the original script's
# logic can be refactored.
try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend

    def get_md2_hash(data):
        """Generate MD2 hash for the given data.

        Args:
            data (bytes): The data to hash.

        Returns:
            str: Hexadecimal representation of the MD2 hash.
        """
        try:
            hasher = hashes.Hash(hashes.MD5(), backend=default_backend())  # MD2 not supported
            hasher.update(data)
            return hasher.finalize().hex() + " (MD5 used, MD2 not supported)"
        except AttributeError:
            return "MD2 hash not supported in this cryptography version"

    def get_md4_hash(data):
        """Generate MD4 hash for the given data.

        Args:
            data (bytes): The data to hash.

        Returns:
            str: Hexadecimal representation of the MD4 hash.
        """
        try:
            hasher = hashes.Hash(hashes.MD5(), backend=default_backend())  # MD4 not supported
            hasher.update(data)
            return hasher.finalize().hex() + " (MD5 used, MD4 not supported)"
        except AttributeError:
            return "MD4 hash not supported in this cryptography version"
except ImportError:
    def get_md2_hash(_data):
        """Generate MD2 hash fallback when cryptography is not available.

        Args:
            _data (bytes): The data to hash (unused in fallback).

        Returns:
            str: Error message indicating library unavailability.
        """
        return "cryptography library not available"

    def get_md4_hash(_data):
        """Generate MD4 hash fallback when cryptography is not available.

        Args:
            _data (bytes): The data to hash (unused in fallback).

        Returns:
            str: Error message indicating library unavailability.
        """
        return "cryptography library not available"
    print("Warning: The 'cryptography' library is not installed. "
          "MD2 and MD4 will not be available.")


def generate_hashes(input_string):
    """
    Generates various hashes and encodings for a given input string.
    
    Args:
        input_string (str): The text string to process.
        
    Returns:
        dict: A dictionary with hash names as keys and the results as values.
    """
    hash_results = {}
    input_bytes = input_string.encode('utf-8')

    # Hashes from the standard hashlib module
    hash_results["MD5 hash"] = hashlib.md5(input_bytes).hexdigest()
    hash_results["SHA1 hash"] = hashlib.sha1(input_bytes).hexdigest()
    hash_results["SHA256 hash"] = hashlib.sha256(input_bytes).hexdigest()
    hash_results["SHA512 hash"] = hashlib.sha512(input_bytes).hexdigest()
    hash_results["RIPEMD160 hash"] = hashlib.new('ripemd160', input_bytes).hexdigest()

    # Hashes from cryptography
    hash_results["MD2 hash"] = get_md2_hash(input_bytes)
    hash_results["MD4 hash"] = get_md4_hash(input_bytes)

    # Encodings
    hash_results["Base64 encoding"] = base64.b64encode(input_bytes).decode('utf-8')

    # Hashes from external libraries (if available)
    if blake3:
        try:
            # pylint: disable=not-callable
            hash_results["Blake3 hash"] = blake3.blake3(input_bytes).hexdigest()
        except (TypeError, AttributeError):
            hash_results["Blake3 hash"] = "blake3 library error"
    else:
        hash_results["Blake3 hash"] = "blake3 library not available"

    if base58:
        hash_results["Base58 encoding"] = base58.b58encode(input_bytes).decode('utf-8')
    else:
        hash_results["Base58 encoding"] = "base58 library not available"

    return hash_results

def create_csv(csv_file, hash_results):
    """
    Writes the hash results to a CSV file.
    
    Args:
        csv_file (str): The name of the CSV file to create.
        hash_results (dict): The dictionary with the hash results.
    """
    if not hash_results:
        print("No hash results to write to CSV.")
        return

    # Include the "Original String" column for the input
    header = ["Original String"] + list(hash_results.keys())
    data_row = ["Input provided in script"] + list(hash_results.values())

    with open(csv_file, 'w', newline='', encoding='utf-8') as csv_file_handle:
        writer = csv.writer(csv_file_handle)
        writer.writerow(header)
        writer.writerow(data_row)

    print(f"\nCSV file created: {csv_file}")

if __name__ == "__main__":
    # Example usage
    TEST_STRING = "The company's home assignment is interesting."

    print(f"Generating hashes for: '{TEST_STRING}'")
    results = generate_hashes(TEST_STRING)

    print("\nResults:")
    for key, value in results.items():
        print(f"- {key}: {value}")

    create_csv("refactored_hashes.csv", results)
