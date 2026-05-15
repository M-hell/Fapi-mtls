import argparse
import base64
import json
import socket
import ssl
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from mtls_client import build_ssl_context, get_tls_details


def encrypt_payload(public_key_path: str, payload: dict) -> str:
    """Encrypt payload using PUBLIC KEY (OAEP)"""
    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read(), backend=None)

    payload_bytes = json.dumps(payload).encode()

    encrypted = public_key.encrypt(
        payload_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    encrypted_base64 = base64.b64encode(encrypted).decode()
    return encrypted_base64


def call_peds_endpoint(host: str, port: int, path: str, context: ssl.SSLContext, encrypted_payload: str):
    """Send encrypted PEDS request via mTLS"""
    
    body = json.dumps({"encrypted_data": encrypted_payload}).encode("utf-8")
    
    request = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Accept: application/json\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("utf-8")

    print(f"POST https://{host}:{port}{path}")
    print(f"\n--- Encrypted Payload (Base64) ---")
    print(encrypted_payload[:100] + "..." if len(encrypted_payload) > 100 else encrypted_payload)

    with socket.create_connection((host, port), timeout=10) as raw_sock:
        with context.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
            tls_version, cipher = get_tls_details_from_socket(tls_sock)
            
            print(f"\n--- TLS Details ---")
            print(f"TLS version: {tls_version}")
            print(f"Negotiated cipher: {cipher[0]}")
            print(f"Cipher strength: {cipher[2]} bits")
            
            tls_sock.sendall(request + body)
            
            response = b""
            while True:
                chunk = tls_sock.recv(4096)
                if not chunk:
                    break
                response += chunk

    response_str = response.decode("utf-8", errors="ignore")
    headers, payload = response_str.split("\r\n\r\n", 1)
    status = headers.split("\r\n")[0]

    print(f"\n--- Response ---")
    print(f"Status: {status}")
    
    try:
        response_json = json.loads(payload)
        print(f"\n--- Decrypted Response ---")
        print(json.dumps(response_json, indent=2))
    except json.JSONDecodeError:
        print(payload)


def get_tls_details_from_socket(sock):
    """Extract TLS version and cipher from socket"""
    return sock.version(), sock.cipher()


def main():
    parser = argparse.ArgumentParser(description="PEDS client for encrypted requests via mTLS")
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=8081)
    parser.add_argument("--path", default="/api/receive-peds-request/")
    parser.add_argument("--ciphers", default="ECDHE+AESGCM")
    args = parser.parse_args()

    server1_dir = Path(__file__).resolve().parent
    fapi_dir = server1_dir.parent

    ca_cert = fapi_dir / "ca.crt"
    client_cert = fapi_dir / "server1.crt"
    client_key = fapi_dir / "server1.key"
    server2_public_key = fapi_dir / "public_key.pem"  # Generated public key

    # Build mTLS context
    context = build_ssl_context(ca_cert=str(ca_cert), client_cert=str(client_cert), client_key=str(client_key), ciphers=args.ciphers)

    # Payload to encrypt
    payload = {
        "card_number": "4111111111111111",
        "amount": 5000,
        "currency": "INR"
    }

    print(f"\n--- Original Payload ---")
    print(json.dumps(payload, indent=2))

    # Encrypt payload
    encrypted_payload = encrypt_payload(str(server2_public_key), payload)

    # Send via mTLS
    call_peds_endpoint(host=args.host, port=args.port, path=args.path, context=context, encrypted_payload=encrypted_payload)


if __name__ == "__main__":
    main()