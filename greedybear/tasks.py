# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.


from datetime import datetime, timezone

from django.utils.dateparse import parse_datetime
from greedybear.settings import CLUSTER_COWRIE_COMMAND_SEQUENCES, EXTRACTION_INTERVAL


def extract_all():
    from greedybear.cronjobs.extract import ExtractionJob

    # Check if this is the extraction run immediately after midnight
    midnight_extraction = datetime.now().hour == 0 and datetime.now().minute < EXTRACTION_INTERVAL

    ExtractionJob().execute()

    # If so, execute the training task
    if midnight_extraction:
        train_and_update()


def monitor_honeypots():
    from greedybear.cronjobs.monitor_honeypots import MonitorHoneypots

    MonitorHoneypots().execute()


def monitor_logs():
    from greedybear.cronjobs.monitor_logs import MonitorLogs

    MonitorLogs().execute()


# SCORING
def train_and_update():
    from greedybear.cronjobs.scoring.scoring_jobs import TrainModels, UpdateScores

    trainer = TrainModels()
    trainer.execute()

    updater = UpdateScores()
    updater.data = trainer.current_data
    updater.execute()


# COMMANDS
def cluster_commands():
    from greedybear.cronjobs.commands.cluster import ClusterCommandSequences

    if CLUSTER_COWRIE_COMMAND_SEQUENCES:
        ClusterCommandSequences().execute()


# CLEAN UP
def clean_up_db():
    from greedybear.cronjobs.cleanup import CleanUp

    CleanUp().execute()


def get_mass_scanners():
    from greedybear.cronjobs.mass_scanners import MassScannersCron

    MassScannersCron().execute()


def get_whatsmyip():
    from greedybear.cronjobs.whatsmyip import WhatsMyIPCron

    WhatsMyIPCron().execute()


def extract_firehol_lists():
    from greedybear.cronjobs.firehol import FireHolCron

    FireHolCron().execute()


def get_tor_exit_nodes():
    from greedybear.cronjobs.tor_exit_nodes import TorExitNodesCron

    TorExitNodesCron().execute()


def enrich_threatfox():
    from greedybear.cronjobs.threatfox_feed import ThreatFoxCron

    ThreatFoxCron().execute()


def enrich_abuseipdb():
    from greedybear.cronjobs.abuseipdb_feed import AbuseIPDBCron

    AbuseIPDBCron().execute()


def process_injected_event(event_id: str):
    from greedybear.cronjobs.extraction.ioc_processor import IocProcessor
    from greedybear.cronjobs.repositories import IocRepository, SensorRepository
    from greedybear.cronjobs.scoring.scoring_jobs import UpdateScores
    from greedybear.models import IOC, InjectedEvent

    event = InjectedEvent.objects.select_related("source").get(pk=event_id)
    payload = event.payload_json

    try:
        ioc_repo = IocRepository()
        sensor_repo = SensorRepository()
        honeypot_name = payload["honeypot"]

        if not ioc_repo.is_ready_for_extraction(honeypot_name):
            raise ValueError(f"Honeypot '{honeypot_name}' is disabled.")

        event_time = parse_datetime(payload["event_time"])
        if event_time is None:
            raise ValueError("Invalid event_time value.")
        if event_time.tzinfo is not None:
            event_time = event_time.astimezone(timezone.utc).replace(tzinfo=None)

        ioc = IOC(
            name=payload["observable"]["value"],
            type=payload["observable"]["type"],
            first_seen=event_time,
            last_seen=event_time,
            interaction_count=payload.get("interaction_count", 1),
            destination_ports=payload.get("destination_ports", []),
            login_attempts=payload.get("login_attempts", 0),
            related_urls=payload.get("related_urls", []),
        )

        sensor_ip = payload.get("sensor")
        if sensor_ip:
            sensor = sensor_repo.get_or_create_sensor(sensor_ip)
            if sensor is not None:
                ioc._sensors_to_add = [sensor]

        processor = IocProcessor(
            ioc_repo=ioc_repo,
            sensor_repo=sensor_repo,
        )
        ioc_record = processor.add_ioc(
            ioc,
            attack_type=payload["attack_type"],
            general_honeypot_name=honeypot_name,
        )

        if ioc_record is not None:
            UpdateScores(ioc_repo=ioc_repo).score_only([ioc_record])

        event.status = InjectedEvent.Status.PROCESSED
        event.error_text = ""
    except Exception as exc:
        event.status = InjectedEvent.Status.FAILED
        event.error_text = str(exc)
    finally:
        event.save(update_fields=["status", "error_text"])
