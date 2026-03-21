#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO_DIR="${ROOT_DIR}/demo"
WORK_DIR="${DEMO_DIR}/.video-build"
OUTPUT_FILE="${DEMO_DIR}/greedybear-injection-poc-demo.mp4"
FONT_TITLE="/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
FONT_BODY="/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"

rm -rf "${WORK_DIR}"
mkdir -p "${WORK_DIR}"

cat > "${WORK_DIR}/01.txt" <<'EOF'
GreedyBear GSoC PoC

Injection / Event Collector API

This demo covers:
- EventSource token auth
- InjectedEvent audit model
- POST /api/events/inject/
- Django Q worker processing
- Idempotency + throttling
- Focused automated tests
EOF

cat > "${WORK_DIR}/02.txt" <<'EOF'
PoC 1: Source Identity

What was added:
- EventSource model
- owner, is_active, rate_limit
- hashed source token
- admin issue / rotate flow

Auth style:
Authorization: Bearer <source-token>
EOF

cat > "${WORK_DIR}/03.txt" <<'EOF'
How Source Setup Works

1. Open Django admin
2. Create an EventSource
3. Pick an owner user
4. Save once to issue the raw token
5. Reuse that token from the external producer
6. Rotate it later from admin if needed
EOF

cat > "${WORK_DIR}/04.txt" <<'EOF'
PoC 2: Inject Endpoint

Request path:
POST /api/events/inject/

Request fields:
- observable.value / observable.type
- attack_type
- honeypot
- sensor
- event_time
- external_event_id
- raw_event
EOF

cat > "${WORK_DIR}/05.txt" <<'EOF'
Example Request

curl -X POST http://localhost/api/events/inject/ \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  -d '{
    "observable": {"value": "8.8.8.8", "type": "ip"},
    "attack_type": "scanner",
    "honeypot": "Cowrie",
    "external_event_id": "demo-event-1"
  }'
EOF

cat > "${WORK_DIR}/06.txt" <<'EOF'
Worker Path

Accepted events are not written through a fake side path.
The worker:
- loads InjectedEvent
- builds an unsaved IOC
- maps sensor via _sensors_to_add
- calls IocProcessor.add_ioc(...)
- updates scores
- marks audit status processed / failed
EOF

cat > "${WORK_DIR}/07.txt" <<'EOF'
Field Mapping

- observable.value -> IOC.name
- observable.type -> IOC.type
- event_time -> first_seen + last_seen
- sensor -> _sensors_to_add
- honeypot -> general_honeypot_name
- raw_event -> payload_json on InjectedEvent
EOF

cat > "${WORK_DIR}/08.txt" <<'EOF'
Behavior Demonstrated

Idempotency:
- same source + same external_event_id
- second request returns existing event

Throttling:
- per-source requests/minute
- second request can return 429

Source control:
- inactive source returns 403
EOF

cat > "${WORK_DIR}/09.txt" <<'EOF'
How To Run

1. docker compose -f docker/default.yml -f docker/local.override.yml up -d
2. python manage.py migrate
3. create EventSource in Django admin
4. copy the issued token
5. send curl request to /api/events/inject/
6. inspect InjectedEvent + IOC rows
EOF

cat > "${WORK_DIR}/10.txt" <<'EOF'
Demo Script Included

Run:
./demo/run_inject_poc_demo.sh

It shows:
- successful queueing
- duplicate idempotency
- throttling with 429
- inactive source with 403
EOF

cat > "${WORK_DIR}/11.txt" <<'EOF'
Verification

Focused test command:
python manage.py test \
  tests.test_models \
  tests.api.views.test_injected_event_view \
  tests.test_tasks

Result used for this repo state:
35 tests
OK
EOF

for index in 01 02 03 04 05 06 07 08 09 10 11; do
  ffmpeg -y \
    -f lavfi -i "color=c=0x0f172a:s=1280x720:d=1" \
    -vf "drawtext=fontfile=${FONT_TITLE}:text='GreedyBear Injection API PoC':fontsize=38:fontcolor=white:x=80:y=60,\
drawtext=fontfile=${FONT_BODY}:textfile=${WORK_DIR}/${index}.txt:fontsize=24:fontcolor=white:x=80:y=170:line_spacing=14" \
    -frames:v 1 "${WORK_DIR}/slide_${index}.png" >/dev/null 2>&1
done

ffmpeg -y \
  -framerate 1/6 \
  -i "${WORK_DIR}/slide_%02d.png" \
  -c:v libx264 \
  -pix_fmt yuv420p \
  -r 30 \
  "${OUTPUT_FILE}" >/dev/null 2>&1

rm -rf "${WORK_DIR}"

echo "Created ${OUTPUT_FILE}"
