# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import json
import logging

from django.db import IntegrityError
from django_q.tasks import async_task
from rest_framework import status
from rest_framework.decorators import (
    api_view,
    authentication_classes,
    permission_classes,
    throttle_classes,
)
from rest_framework.response import Response

from api.authentication import EventSourceAuthentication
from api.permissions import IsActiveEventSource
from api.serializers import EventDataSerializer
from api.throttles import EventSourceThrottle
from greedybear.models import InjectedEvent

logger = logging.getLogger(__name__)


@api_view(["POST"])
@authentication_classes([EventSourceAuthentication])
@permission_classes([IsActiveEventSource])
@throttle_classes([EventSourceThrottle])
def inject_event(request):
    serializer = EventDataSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)

    payload = json.loads(json.dumps(serializer.data))
    source = request.auth
    external_event_id = payload.get("external_event_id")

    if external_event_id:
        existing = InjectedEvent.objects.filter(
            source=source,
            external_event_id=external_event_id,
        ).first()
        if existing is not None:
            return Response(
                {
                    "status": "already_exists",
                    "current_status": existing.status,
                    "injected_event_id": str(existing.pk),
                    "message": "Event already queued or processed.",
                },
                status=status.HTTP_200_OK,
            )

    try:
        injected_event = InjectedEvent.objects.create(
            source=source,
            observable_value=payload["observable"]["value"],
            observable_type=payload["observable"]["type"],
            payload_json=payload,
            external_event_id=external_event_id,
        )
    except IntegrityError:
        existing = InjectedEvent.objects.get(
            source=source,
            external_event_id=external_event_id,
        )
        return Response(
            {
                "status": "already_exists",
                "current_status": existing.status,
                "injected_event_id": str(existing.pk),
                "message": "Event already queued or processed.",
            },
            status=status.HTTP_200_OK,
        )

    async_task("greedybear.tasks.process_injected_event", str(injected_event.pk))
    logger.info(f"Accepted injected event {injected_event.pk} from source {source.pk}")
    return Response(
        {
            "status": "accepted",
            "injected_event_id": str(injected_event.pk),
            "message": "Event queued for processing.",
        },
        status=status.HTTP_202_ACCEPTED,
    )
