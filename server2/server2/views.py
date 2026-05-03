from datetime import datetime, timezone
import socket

from django.http import JsonResponse
from django.views.decorators.http import require_GET


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