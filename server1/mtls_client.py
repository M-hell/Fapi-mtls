import argparse
import http.client
import json
import ssl
import socket
from pathlib import Path


def build_ssl_context(ca_cert: Path, client_cert: Path, client_key: Path, ciphers: str | None):
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca_cert))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if ciphers:
        context.set_ciphers(ciphers)
    context.load_cert_chain(certfile=str(client_cert), keyfile=str(client_key))
    return context


def get_tls_details(connection: http.client.HTTPSConnection):
    sock = getattr(connection, "sock", None)
    if sock is not None:
        return sock.version(), sock.cipher()

    response = getattr(connection, "response", None)
    if response is not None:
        raw = getattr(getattr(response, "fp", None), "raw", None)
        sock = getattr(raw, "_sock", None)
        if sock is not None:
            return sock.version(), sock.cipher()

    return "unknown", ("unknown", "", 0)


def call_endpoint(host: str, port: int, path: str, context: ssl.SSLContext):
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Accept: application/json\r\n"
        "Connection: close\r\n\r\n"
    ).encode("utf-8")

    with socket.create_connection((host, port), timeout=10) as raw_sock:
        with context.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
            tls_sock.sendall(request)
            tls_version = tls_sock.version() or "unknown"
            cipher = tls_sock.cipher() or ("unknown", "", 0)
            response = http.client.HTTPResponse(tls_sock)
            response.begin()
            payload = response.read().decode("utf-8")
            status = response.status

    print(f"GET https://{host}:{port}{path}")
    print(f"Status: {status}")
    print(f"TLS version: {tls_version}")
    print(f"Negotiated cipher: {cipher[0]}")

    try:
        print(json.dumps(json.loads(payload), indent=2))
    except json.JSONDecodeError:
        print(payload)

def main():
    parser = argparse.ArgumentParser(description="mTLS client for server1 -> server2")
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=8081)
    parser.add_argument("--path", default="/api/mtls-status/")
    parser.add_argument("--ciphers", default="ECDHE+AESGCM")
    args = parser.parse_args()

    server1_dir = Path(__file__).resolve().parent
    fapi_dir = server1_dir.parent

    ca_cert = fapi_dir / "ca.crt"
    client_cert = fapi_dir / "server1.crt"
    client_key = fapi_dir / "server1.key"

    context = build_ssl_context(ca_cert=ca_cert, client_cert=client_cert, client_key=client_key, ciphers=args.ciphers)
    call_endpoint(host=args.host, port=args.port, path=args.path, context=context)


if __name__ == "__main__":
    main()