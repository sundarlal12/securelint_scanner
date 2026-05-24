# # crypto.py
# import base64
# import json
# from Crypto.Cipher import AES
# from Crypto.Util.Padding import pad, unpad

# # Crypto constants (EXACT match from JS)
# KEY = b"w9reLCgzPQBsNJ6dRjH9qUwUGbqvToUY"
# IV = b"PHnuDrqYysUi0cI5"
# TOKEN = "tMn1LoCwTQoIo1406x5YYfYSRoSzeSSWzU4QyS8TS2TuGBwtHFPcR92ec8X25zVCu74Xl28zXwrCI02AJfmonU5Rlf5trYvmFLRTEMWSrCuTVtbw8C4n9WBQnd4iag3Y"
# REAL_API_URL = "https://ext.fortect.com/v1/cloud"

# # Headers exactly matching the real request
# HEADERS = {
#     "Content-Type": "application/json",
#     "authorizationToken": TOKEN,
#     "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
#     "Origin": "chrome-extension://dplojpoeafjlpdpbokcpnojleddffaco",
#     "Accept": "*/*",
#     "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
#     "Cache-Control": "no-cache",
#     "Pragma": "no-cache",
#     "Sec-Fetch-Dest": "empty",
#     "Sec-Fetch-Mode": "cors",
#     "Sec-Fetch-Site": "none",
# }

# def encrypt(plaintext: str) -> str:
#     """Exact match of the JS encrypt function"""
#     cipher = AES.new(KEY, AES.MODE_CBC, IV)
#     padded_data = pad(plaintext.encode('utf-8'), AES.block_size)
#     encrypted = cipher.encrypt(padded_data)
#     return base64.b64encode(encrypted).decode('utf-8')

# def decrypt(encrypted_b64: str) -> str:
#     """Exact match of the JS decrypt function"""
#     encrypted_data = base64.b64decode(encrypted_b64)
#     cipher = AES.new(KEY, AES.MODE_CBC, IV)
#     decrypted_padded = cipher.decrypt(encrypted_data)
#     decrypted = unpad(decrypted_padded, AES.block_size)
#     return decrypted.decode('utf-8')

# def extract_domain_from_url(url: str) -> str:
#     """Extract domain from URL"""
#     from urllib.parse import urlparse
#     domain = urlparse(url).netloc or url
#     domain = domain.replace("www.", "").split(":")[0]
#     return domain
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from urllib.parse import urlparse

KEY = b"w9reLCgzPQBsNJ6dRjH9qUwUGbqvToUY"
IV = b"PHnuDrqYysUi0cI5"
TOKEN = "tMn1LoCwTQoIo1406x5YYfYSRoSzeSSWzU4QyS8TS2TuGBwtHFPcR92ec8X25zVCu74Xl28zXwrCI02AJfmonU5Rlf5trYvmFLRTEMWSrCuTVtbw8C4n9WBQnd4iag3Y"
REAL_API_URL = "https://ext.fortect.com/v1/cloud"

HEADERS = {
    "Content-Type": "application/json",
    "authorizationToken": TOKEN,
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Origin": "chrome-extension://dplojpoeafjlpdpbokcpnojleddffaco",
}

def encrypt(plaintext: str) -> str:
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    padded_data = pad(plaintext.encode('utf-8'), AES.block_size)
    encrypted = cipher.encrypt(padded_data)
    return base64.b64encode(encrypted).decode('utf-8')

def decrypt(encrypted_b64: str) -> str:
    encrypted_data = base64.b64decode(encrypted_b64)
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    decrypted_padded = cipher.decrypt(encrypted_data)
    decrypted = unpad(decrypted_padded, AES.block_size)
    return decrypted.decode('utf-8')

def extract_domain(url: str) -> str:
    """Extract domain from URL"""
    parsed = urlparse(url)
    domain = parsed.netloc or url
    domain = domain.replace("www.", "").split(":")[0]
    return domain