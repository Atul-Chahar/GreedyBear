from datetime import datetime
from unittest.mock import patch

from django.core.cache import cache
from rest_framework import status
from rest_framework.test import APIClient

from greedybear.models import EventSource, InjectedEvent
from tests import CustomTestCase


class InjectedEventViewTestCase(CustomTestCase):
    def setUp(self):
        super().setUp()
        cache.clear()
        self.client = APIClient()
        self.source = EventSource(owner=self.superuser, name="cowrie-ingest", rate_limit=5)
        self.raw_token = self.source.issue_token()
        self.source.save()
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.raw_token}")
        self.payload = {
            "observable": {"value": "8.8.8.8", "type": "ip"},
            "attack_type": "scanner",
            "honeypot": "Cowrie",
            "sensor": "1.1.1.1",
            "event_time": datetime.now().isoformat(),
            "destination_ports": [22],
            "interaction_count": 1,
            "login_attempts": 2,
            "related_urls": ["https://example.com/dropper"],
            "external_event_id": "evt-1",
            "raw_event": {"username": "root", "password": "toor"},
        }

    @patch("api.views.injected_event.async_task")
    def test_inject_event_accepts_valid_payload(self, mock_async_task):
        response = self.client.post("/api/events/inject/", self.payload, format="json")

        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
        self.assertEqual(InjectedEvent.objects.count(), 1)
        injected_event = InjectedEvent.objects.get()
        self.assertEqual(injected_event.status, InjectedEvent.Status.QUEUED)
        self.assertEqual(injected_event.observable_value, "8.8.8.8")
        mock_async_task.assert_called_once_with("greedybear.tasks.process_injected_event", str(injected_event.pk))

    def test_inject_event_requires_authentication(self):
        client = APIClient()
        response = client.post("/api/events/inject/", self.payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_inject_event_rejects_invalid_token(self):
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION="Bearer invalid-token")
        response = client.post("/api/events/inject/", self.payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_inject_event_rejects_inactive_source(self):
        self.source.is_active = False
        self.source.save(update_fields=["is_active"])

        response = self.client.post("/api/events/inject/", self.payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data["detail"], "Inactive event source.")

    @patch("api.views.injected_event.async_task")
    def test_inject_event_is_idempotent(self, mock_async_task):
        first_response = self.client.post("/api/events/inject/", self.payload, format="json")
        second_response = self.client.post("/api/events/inject/", self.payload, format="json")

        self.assertEqual(first_response.status_code, status.HTTP_202_ACCEPTED)
        self.assertEqual(second_response.status_code, status.HTTP_200_OK)
        self.assertEqual(second_response.data["status"], "already_exists")
        self.assertEqual(second_response.data["current_status"], InjectedEvent.Status.QUEUED)
        self.assertEqual(InjectedEvent.objects.count(), 1)
        mock_async_task.assert_called_once()

    @patch("api.views.injected_event.async_task")
    def test_inject_event_is_throttled_per_source(self, mock_async_task):
        self.source.rate_limit = 1
        self.source.save(update_fields=["rate_limit"])

        first_payload = dict(self.payload, external_event_id="evt-throttle-1")
        second_payload = dict(self.payload, external_event_id="evt-throttle-2")

        first_response = self.client.post("/api/events/inject/", first_payload, format="json")
        second_response = self.client.post("/api/events/inject/", second_payload, format="json")

        self.assertEqual(first_response.status_code, status.HTTP_202_ACCEPTED)
        self.assertEqual(second_response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)

    @patch("api.views.injected_event.async_task")
    def test_inject_event_rejects_non_global_ip(self, mock_async_task):
        payload = dict(self.payload)
        payload["observable"] = {"value": "192.168.1.10", "type": "ip"}

        response = self.client.post("/api/events/inject/", payload, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(InjectedEvent.objects.count(), 0)
        mock_async_task.assert_not_called()
