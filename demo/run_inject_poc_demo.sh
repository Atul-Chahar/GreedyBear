#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE_URL="${BASE_URL:-http://localhost}"
API_URL="${BASE_URL}/api/events/inject/"
RUN_ID="${RUN_ID:-$(date +%s)}"
DEMO_SOURCE_NAME="${DEMO_SOURCE_NAME:-demo-source-${RUN_ID}}"
THROTTLE_SOURCE_NAME="${THROTTLE_SOURCE_NAME:-${DEMO_SOURCE_NAME}-throttle-${RUN_ID}}"
DEMO_EVENT_ID="${DEMO_EVENT_ID:-demo-event-1-${RUN_ID}}"
THROTTLE_EVENT_ID_1="${THROTTLE_EVENT_ID_1:-demo-event-2-${RUN_ID}}"
THROTTLE_EVENT_ID_2="${THROTTLE_EVENT_ID_2:-demo-event-3-${RUN_ID}}"
INACTIVE_EVENT_ID="${INACTIVE_EVENT_ID:-demo-event-4-${RUN_ID}}"

echo "[1/7] Applying migrations"
docker exec greedybear_uwsgi sh -lc "cd /opt/deploy/greedybear && python manage.py migrate --noinput >/dev/null"

echo "[2/7] Creating or updating demo event source"
RAW_TOKEN="$(
  docker exec greedybear_uwsgi sh -lc "cd /opt/deploy/greedybear && python manage.py shell -c \"
from django.contrib.auth import get_user_model
from greedybear.models import EventSource

User = get_user_model()
user = User.objects.filter(is_superuser=True).first()
if user is None:
    user = User.objects.create_superuser(username='demo-admin', email='demo@example.com', password='demo-admin')
source, _ = EventSource.objects.get_or_create(owner=user, name='${DEMO_SOURCE_NAME}')
source.rate_limit = 5
source.is_active = True
token = source.issue_token()
source.save()
print(token)
\"" | tail -n 1 | tr -d '\r'
)"

echo "Issued demo token:"
echo "${RAW_TOKEN}"
echo

echo "[3/7] Sending a valid event"
curl -sS -X POST "${API_URL}" \
  -H "Authorization: Bearer ${RAW_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "observable": {"value": "8.8.8.8", "type": "ip"},
    "attack_type": "scanner",
    "honeypot": "Cowrie",
    "sensor": "1.1.1.1",
    "event_time": "2026-03-21T10:15:00",
    "destination_ports": [22],
    "interaction_count": 1,
    "login_attempts": 2,
    "related_urls": ["https://example.com/dropper"],
    "external_event_id": "'"${DEMO_EVENT_ID}"'",
    "raw_event": {"username": "root", "password": "toor"}
  }' | jq .

echo
echo "[4/7] Sending the same event again to show idempotency"
curl -sS -X POST "${API_URL}" \
  -H "Authorization: Bearer ${RAW_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "observable": {"value": "8.8.8.8", "type": "ip"},
    "attack_type": "scanner",
    "honeypot": "Cowrie",
    "sensor": "1.1.1.1",
    "event_time": "2026-03-21T10:15:00",
    "destination_ports": [22],
    "interaction_count": 1,
    "login_attempts": 2,
    "related_urls": ["https://example.com/dropper"],
    "external_event_id": "'"${DEMO_EVENT_ID}"'",
    "raw_event": {"username": "root", "password": "toor"}
  }' | jq .

echo
echo "[5/7] Creating a fresh source with rate_limit=1"
THROTTLE_TOKEN="$(
  docker exec greedybear_uwsgi sh -lc "cd /opt/deploy/greedybear && python manage.py shell -c \"
from django.contrib.auth import get_user_model
from greedybear.models import EventSource

User = get_user_model()
user = User.objects.filter(is_superuser=True).first()
if user is None:
    user = User.objects.create_superuser(username='demo-admin', email='demo@example.com', password='demo-admin')
source, _ = EventSource.objects.get_or_create(owner=user, name='${THROTTLE_SOURCE_NAME}')
source.rate_limit = 1
source.is_active = True
token = source.issue_token()
source.save()
print(token)
\"" | tail -n 1 | tr -d '\r'
)"
echo "Issued throttle demo token:"
echo "${THROTTLE_TOKEN}"
echo

echo "[6/7] Sending two new requests to trigger 429"
curl -sS -o /tmp/gb-demo-1.json -w 'first_status=%{http_code}\n' -X POST "${API_URL}" \
  -H "Authorization: Bearer ${THROTTLE_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "observable": {"value": "9.9.9.9", "type": "ip"},
    "attack_type": "scanner",
    "honeypot": "Cowrie",
    "event_time": "2026-03-21T10:20:00",
    "external_event_id": "'"${THROTTLE_EVENT_ID_1}"'"
  }'
cat /tmp/gb-demo-1.json | jq .

curl -sS -o /tmp/gb-demo-2.json -w 'second_status=%{http_code}\n' -X POST "${API_URL}" \
  -H "Authorization: Bearer ${THROTTLE_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "observable": {"value": "9.9.9.10", "type": "ip"},
    "attack_type": "scanner",
    "honeypot": "Cowrie",
    "event_time": "2026-03-21T10:21:00",
    "external_event_id": "'"${THROTTLE_EVENT_ID_2}"'"
  }'
cat /tmp/gb-demo-2.json | jq .

echo
echo "[7/7] Disabling the source to trigger 403"
docker exec greedybear_uwsgi sh -lc "cd /opt/deploy/greedybear && python manage.py shell -c \"
from greedybear.models import EventSource
source = EventSource.objects.get(name='${THROTTLE_SOURCE_NAME}')
source.is_active = False
source.save(update_fields=['is_active'])
print('source disabled')
\""

curl -sS -o /tmp/gb-demo-3.json -w 'inactive_status=%{http_code}\n' -X POST "${API_URL}" \
  -H "Authorization: Bearer ${THROTTLE_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "observable": {"value": "9.9.9.11", "type": "ip"},
    "attack_type": "scanner",
    "honeypot": "Cowrie",
    "event_time": "2026-03-21T10:22:00",
    "external_event_id": "'"${INACTIVE_EVENT_ID}"'"
  }'
cat /tmp/gb-demo-3.json | jq .

echo
echo "Demo complete."
