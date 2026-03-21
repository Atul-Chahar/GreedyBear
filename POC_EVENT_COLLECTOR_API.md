# GreedyBear PoC: Injection / Event Collector API

This branch contains two linked PoCs for the GSoC idea "Injection / Event Collector API". The goal of the branch is to show a realistic end-to-end path for accepting external honeypot events and routing them through GreedyBear's existing IOC ingestion logic without turning this into a production-complete feature.

## What This PoC Covers

### PoC 1: Source identity and token auth

- Adds an `EventSource` model owned by a GreedyBear user
- Stores only a hashed source token
- Authenticates the inject endpoint with `Authorization: Bearer <token>`
- Supports source activation and per-source rate limiting

### PoC 2: Event injection pipeline

- Adds an `InjectedEvent` audit model
- Accepts one event per request at `POST /api/events/inject/`
- Queues work through Django Q
- Processes the event through GreedyBear's existing `IocProcessor` path
- Persists success or failure on the audit row

## Architecture At A Glance

1. A GreedyBear admin creates an `EventSource` in Django admin.
2. The admin receives a raw bearer token once and shares it with the external producer.
3. The external producer calls `POST /api/events/inject/`.
4. The API validates the payload and stores an `InjectedEvent` audit row.
5. A Django Q task loads that row and converts the payload into an unsaved `IOC`.
6. The worker uses `IocProcessor.add_ioc(...)` so the new path stays aligned with the existing extraction flow.
7. The audit row is marked `processed` or `failed`.

## Main Files

- `greedybear/models.py`
- `greedybear/tasks.py`
- `greedybear/admin.py`
- `api/authentication.py`
- `api/permissions.py`
- `api/throttles.py`
- `api/serializers.py`
- `api/views/injected_event.py`
- `tests/api/views/test_injected_event_view.py`
- `tests/test_tasks.py`
- `tests/test_models.py`

## Design Choices In This PoC

- One event per request
- Separate source auth instead of reusing Durin user tokens
- `event_time` maps to both `IOC.first_seen` and `IOC.last_seen`
- `sensor` is attached using the same temporary `_sensors_to_add` pattern used by extraction
- Unknown honeypot names follow GreedyBear's existing extraction behavior and are created through repository flow
- `raw_event` is stored only on the audit event payload, not on `IOC`
- Idempotency is scoped by `(source, external_event_id)`

## How To Run

### 1. Start the local stack

```bash
docker compose -f docker/default.yml -f docker/local.override.yml up -d
```

### 2. Apply migrations

```bash
docker exec greedybear_uwsgi sh -lc 'cd /opt/deploy/greedybear && python manage.py migrate'
```

### 3. Create a superuser if needed

```bash
docker exec greedybear_uwsgi sh -lc 'cd /opt/deploy/greedybear && python manage.py createsuperuser'
```

### 4. Open Django admin

- Visit `http://localhost/admin`
- Log in as the superuser

## How To Use The PoC

### 1. Create an EventSource

In Django admin:

- Open `Event Sources`
- Add a new source
- Choose the owner user
- Set a source name
- Optionally change `rate_limit`
- Save

On first save, the admin shows the raw token once. Copy it immediately.

If you need a new token later, use the `Rotate selected source tokens` admin action.

### 2. Send an event

```bash
curl -X POST http://localhost/api/events/inject/ \
  -H 'Authorization: Bearer <source-token>' \
  -H 'Content-Type: application/json' \
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
    "external_event_id": "demo-event-1",
    "raw_event": {"username": "root", "password": "toor"}
  }'
```

Expected success response:

```json
{
  "status": "accepted",
  "injected_event_id": "<uuid>",
  "message": "Event queued for processing."
}
```

Expected duplicate response for the same `external_event_id` from the same source:

```json
{
  "status": "already_exists",
  "current_status": "queued",
  "injected_event_id": "<uuid>",
  "message": "Event already queued or processed."
}
```

Common error cases:

```json
{"detail": "Authentication credentials were not provided."}
```

```json
{"detail": "Inactive event source."}
```

```json
{"detail": "Request was throttled."}
```

### 3. Inspect what happened

In Django admin:

- Open `Injected Events`
- Check the new row
- Watch `status` move from `queued` to `processed` or `failed`
- Open `IOCs`
- Confirm the IOC now exists and has the expected timestamps, honeypot, and sensor relationship

If successful, the IOC will also appear in the regular `IOC` admin table.

### 4. Reproduce the full demo quickly

This branch includes a scripted walkthrough:

```bash
./demo/run_inject_poc_demo.sh
```

The script:

- applies migrations
- creates or refreshes a demo source
- prints the raw token
- sends a valid request
- repeats the request to show idempotency
- lowers the source rate limit to trigger `429`
- disables the source to trigger `403`

## Validation Rules In This PoC

- IPs must be globally routable
- Domains must match GreedyBear's existing domain validation style
- `attack_type` is limited to `scanner` or `payload_request`
- `event_time` cannot be older than 30 days or in the future
- `destination_ports` must be `1-65535`
- `interaction_count` must be at least `1`
- `login_attempts` must be non-negative
- `related_urls` accepts up to 20 URLs
- `raw_event` is limited to 10 KB

## Worker Behavior

The queued task:

- loads the `InjectedEvent`
- ensures the honeypot is ready using repository logic
- builds an unsaved `IOC`
- maps `sensor` into `_sensors_to_add`
- calls `IocProcessor.add_ioc(...)`
- runs `UpdateScores().score_only(...)`
- marks the audit row as `processed` or `failed`

Field mapping used in this PoC:

- `observable.value` -> `IOC.name`
- `observable.type` -> `IOC.type`
- `event_time` -> `IOC.first_seen` and `IOC.last_seen`
- `sensor` -> temporary `_sensors_to_add`
- `honeypot` -> `general_honeypot_name`
- `raw_event` -> `InjectedEvent.payload_json`

## Idempotency

If the same `external_event_id` is sent again by the same source:

- the second request returns `200`
- the existing `InjectedEvent` is returned
- no second audit row is created

## Rate Limiting

Each `EventSource` has a `rate_limit` field interpreted as requests per minute.

Example:

- `rate_limit = 1` means the second request inside the same minute gets `429`

## Files To Read First

If you want to understand the branch quickly, start with:

- `greedybear/models.py`
- `api/views/injected_event.py`
- `greedybear/tasks.py`
- `tests/api/views/test_injected_event_view.py`
- `tests/test_tasks.py`

## Focused Test Command

```bash
docker exec greedybear_uwsgi sh -lc 'cd /opt/deploy/greedybear && python manage.py test tests.test_models tests.api.views.test_injected_event_view tests.test_tasks'
```

## Current PoC Limits

- No batch endpoint
- No stats endpoint for injected sources yet
- No source management UI outside Django admin
- No retry API for failed `external_event_id` values
- No OpenAPI / Swagger integration yet

## Suggested Demo Flow

1. Show the new models in Django admin
2. Create an `EventSource`
3. Copy the issued token
4. Send one valid event with `curl`
5. Show the `InjectedEvent` row
6. Show the created `IOC`
7. Send the same payload again to show idempotency
8. Lower `rate_limit` and show a `429`
9. Disable the source and show a `403`
