import argparse
import ssl
import http.client
from pathlib import Path


def build_ssl_context(ca_cert: Path, client_cert: Path, client_key: Path) -> ssl.SSLContext:
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca_cert))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=str(client_cert), keyfile=str(client_key))
    return ctx


def call_endpoint(host: str, port: int, path: str, context: ssl.SSLContext) -> None:
    conn = http.client.HTTPSConnection(host, port=port, context=context, timeout=10)
    conn.request("GET", path, headers={"Connection": "close"})
    resp = conn.getresponse()
    body = resp.read()
    conn.close()

    try:
        print(body.decode("utf-8"), end="")
    except Exception:
        import sys

        sys.stdout.buffer.write(body)


def main() -> None:
    parser = argparse.ArgumentParser(description="Minimal mTLS client")
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=8081)
    parser.add_argument("--path", default="/api/mtls-status/")
    args = parser.parse_args()

    base_dir = Path(__file__).resolve().parent.parent
    ca_cert = base_dir / "ca.crt"
    client_cert = base_dir / "server1.crt"
    client_key = base_dir / "server1.key"

    context = build_ssl_context(ca_cert=ca_cert, client_cert=client_cert, client_key=client_key)
    call_endpoint(host=args.host, port=args.port, path=args.path, context=context)


if __name__ == "__main__":
    main()
