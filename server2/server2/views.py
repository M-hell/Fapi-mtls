from datetime import datetime, timezone
import socket
from pathlib import Path

from django.http import JsonResponse
from django.views.decorators.http import require_GET, require_POST
from django.views.decorators.csrf import csrf_exempt

import json
import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key



@require_GET
def mtls_status(request):
    return JsonResponse(
        {
            "service": "server2",
            "status": "ok",
            "message": "mTLS protected endpoint reached",
        }
    )


@require_GET
def server_time(request):
    return JsonResponse(
        {
            "service": "server2",
            "hostname": socket.gethostname(),
            "server_time_utc": datetime.now(timezone.utc).isoformat(),
        }
    )


# LOAD PRIVATE KEY - use Path for consistency
server2_dir = Path(__file__).resolve().parent.parent
fapi_dir = server2_dir.parent
private_key_path = fapi_dir / "private_key.pem"

with open(private_key_path, "rb") as f:
    private_key = load_pem_private_key(
        f.read(),
        password=None
    )

@require_POST
@csrf_exempt
def receive_PEDS_request(request):
    """
    Decrypt payload using PRIVATE KEY
    """

    body = json.loads(request.body)

    encrypted_data = body.get("encrypted_data")

    encrypted_bytes = base64.b64decode(encrypted_data)

    decrypted = private_key.decrypt(
        encrypted_bytes,
        padding.OAEP(
            mgf=padding.MGF1(
                algorithm=hashes.SHA256()
            ),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    decrypted_payload = json.loads(
        decrypted.decode()
    )

    return JsonResponse({
        "decrypted_payload": decrypted_payload
    })