# import ssl
# import socket
# import json
# from OpenSSL import crypto
# from datetime import datetime

# hostname = "google.com"

# result = {
#     "domain": hostname,
#     "ssl": False
# }

# try:
#     # Get certificate
#     cert_pem = ssl.get_server_certificate((hostname, 443))

#     # Load cert
#     cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)

#     valid_from = cert.get_notBefore().decode()
#     valid_to = cert.get_notAfter().decode()

#     # Convert dates
#     start_date = datetime.strptime(valid_from, "%Y%m%d%H%M%SZ")
#     expiry_date = datetime.strptime(valid_to, "%Y%m%d%H%M%SZ")

#     result = {
#         "domain": hostname,
#         "ssl": True,
#         "issuer": cert.get_issuer().CN,
#         "common_name": cert.get_subject().CN,
#         "organization": getattr(cert.get_subject(), "O", ""),
#         "serial_number": str(cert.get_serial_number()),
#         "valid_from": start_date.strftime("%Y-%m-%d %H:%M:%S"),
#         "valid_until": expiry_date.strftime("%Y-%m-%d %H:%M:%S"),
#         "expired": expiry_date < datetime.utcnow(),
#         "days_left": (expiry_date - datetime.utcnow()).days
#     }

# except Exception as e:
#     result["error"] = str(e)

# # Print JSON
# print(json.dumps(result, indent=4))


import ssl
import socket
import json
import hashlib
import requests

from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec

# =========================
# DOMAIN
# =========================
hostname = "google.com"

result = {
    "domain": hostname,
    "ssl": False
}

try:

    # =========================
    # SSL SOCKET
    # =========================
    context = ssl._create_unverified_context()

    with socket.create_connection((hostname, 443), timeout=10) as sock:

        with context.wrap_socket(
            sock,
            server_hostname=hostname
        ) as ssock:

            # RAW CERT
            der_cert = ssock.getpeercert(True)

            # LOAD CERT
            cert = x509.load_der_x509_certificate(
                der_cert,
                default_backend()
            )

            # =========================
            # DATES
            # =========================
            valid_from = cert.not_valid_before_utc
            valid_until = cert.not_valid_after_utc

            expired = valid_until < datetime.utcnow().astimezone()

            days_left = (
                valid_until - datetime.utcnow().astimezone()
            ).days

            # =========================
            # ISSUER
            # =========================
            issuer = {}

            for attr in cert.issuer:
                issuer[attr.oid._name] = attr.value

            # =========================
            # SUBJECT
            # =========================
            subject = {}

            for attr in cert.subject:
                subject[attr.oid._name] = attr.value

            # =========================
            # SIGNATURE ALGORITHM
            # =========================
            signature_algorithm = (
                cert.signature_hash_algorithm.name
            )

            weak_signature = (
                signature_algorithm.lower() in [
                    "md5",
                    "sha1"
                ]
            )

            # =========================
            # PUBLIC KEY
            # =========================
            public_key = cert.public_key()

            public_key_bits = None
            public_key_type = None

            if isinstance(public_key, rsa.RSAPublicKey):

                public_key_bits = public_key.key_size
                public_key_type = "RSA"

            elif isinstance(public_key, ec.EllipticCurvePublicKey):

                public_key_bits = public_key.key_size
                public_key_type = "ECC"

            weak_key = (
                public_key_bits is not None
                and
                public_key_bits < 2048
            )

            # =========================
            # SELF SIGNED
            # =========================
            self_signed = (
                cert.issuer == cert.subject
            )

            # =========================
            # WILDCARD
            # =========================
            common_name = subject.get(
                "commonName",
                ""
            )

            wildcard = "*" in common_name

            # =========================
            # TLS INFO
            # =========================
            tls_version = ssock.version()

            cipher = ssock.cipher()[0]

            # =========================
            # FINGERPRINTS
            # =========================
            sha1_fingerprint = hashlib.sha1(
                der_cert
            ).hexdigest()

            sha256_fingerprint = hashlib.sha256(
                der_cert
            ).hexdigest()

            # =========================
            # SAN DOMAINS
            # =========================
            # san_domains = []

            try:

                ext = cert.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                )

                # san_domains = ext.value.get_values_for_type(
                #     x509.DNSName
                # )

            except:
                pass

            # =========================
            # HSTS
            # =========================
            supports_hsts = False
            hsts_header = ""

            try:

                response = requests.get(
                    f"https://{hostname}",
                    timeout=10
                )

                hsts_header = response.headers.get(
                    "Strict-Transport-Security",
                    ""
                )

                supports_hsts = bool(hsts_header)

            except:
                pass

            # =========================
            # FINAL JSON
            # =========================
            result = {

                "domain": hostname,

                "ssl": True,

                "certificate_valid": not expired,

                "expired": expired,

                "days_left": days_left,

                "valid_from": str(valid_from),

                "valid_until": str(valid_until),

                "issuer": issuer,

                "subject": subject,

                "serial_number": str(
                    cert.serial_number
                ),

                "signature_algorithm": signature_algorithm,

                "weak_signature": weak_signature,

                "public_key_type": public_key_type,

                "public_key_bits": public_key_bits,

                "weak_key": weak_key,

                "self_signed": self_signed,

                "wildcard": wildcard,

                "tls_version": tls_version,

                "cipher": cipher,

                "sha1_fingerprint": sha1_fingerprint,

                "sha256_fingerprint": sha256_fingerprint,

                # "san_domains": san_domains,

                "supports_hsts": supports_hsts,

                "hsts_header": hsts_header,

                # "hostname_match": (
                #     hostname in san_domains
                # )
            }

except Exception as e:

    result["error"] = str(e)

# =========================
# PRINT JSON
# =========================
print(
    json.dumps(
        result,
        indent=4
    )
)