# This file is a part of GreedyBear https://github.com/honeynet/GreedyBear
# See the file 'LICENSE' for copying permission.
import hashlib
import hmac
import secrets
import uuid

from django.conf import settings
from django.contrib.postgres import fields as pg_fields
from django.db import models
from django.db.models import Q
from django.db.models.functions import Lower, Now


class ViewType(models.TextChoices):
    FEEDS_VIEW = "feeds"
    ENRICHMENT_VIEW = "enrichment"
    COMMAND_SEQUENCE_VIEW = "command sequence"
    COWRIE_SESSION_VIEW = "cowrie session"


class IocType(models.TextChoices):
    IP = "ip"
    DOMAIN = "domain"


class Sensor(models.Model):
    address = models.GenericIPAddressField(unique=True)
    country = models.CharField(
        max_length=64,
        blank=True,
        default="",
    )

    def __str__(self):
        return self.address


class GeneralHoneypot(models.Model):
    name = models.CharField(max_length=15)
    active = models.BooleanField(default=True)

    class Meta:
        constraints = [models.UniqueConstraint(Lower("name"), name="unique_generalhoneypot_name_ci")]

    def __str__(self):
        return self.name


class FireHolList(models.Model):
    ip_address = models.CharField(max_length=256)
    added = models.DateTimeField(db_default=Now())
    source = models.CharField(max_length=64, blank=True, default="")

    class Meta:
        indexes = [
            models.Index(fields=["ip_address"]),
        ]

    def __str__(self):
        return f"{self.ip_address} ({self.source or 'unknown'})"


class IOC(models.Model):
    name = models.CharField(max_length=256)
    type = models.CharField(max_length=32, choices=IocType.choices)
    first_seen = models.DateTimeField(db_default=Now())
    last_seen = models.DateTimeField(db_default=Now())
    days_seen = pg_fields.ArrayField(models.DateField(), blank=True, default=list)
    number_of_days_seen = models.IntegerField(default=1)
    attack_count = models.IntegerField(default=1)
    interaction_count = models.IntegerField(default=1)
    attacker_country = models.CharField(
        max_length=64,
        blank=True,
        default="",
    )
    # FEEDS - list of honeypots from general list, from which the IOC was detected
    general_honeypot = models.ManyToManyField(GeneralHoneypot, blank=True)
    # SENSORS - list of T-Pot sensors that detected this IOC
    sensors = models.ManyToManyField(Sensor, blank=True)
    scanner = models.BooleanField(default=False)
    payload_request = models.BooleanField(default=False)
    related_ioc = models.ManyToManyField("self", blank=True, symmetrical=True)
    related_urls = pg_fields.ArrayField(models.CharField(max_length=900, blank=True), blank=True, default=list)
    ip_reputation = models.CharField(max_length=32, blank=True)
    firehol_categories = pg_fields.ArrayField(models.CharField(max_length=64, blank=True), blank=True, default=list)
    asn = models.IntegerField(blank=True, null=True)
    destination_ports = pg_fields.ArrayField(models.IntegerField(), default=list)
    login_attempts = models.IntegerField(default=0)
    # SCORES
    recurrence_probability = models.FloatField(null=True, default=0)
    expected_interactions = models.FloatField(null=True, default=0)

    class Meta:
        indexes = [
            models.Index(fields=["name"]),
            models.Index(fields=["attacker_country"]),
        ]

    def __str__(self):
        return self.name


class CommandSequence(models.Model):
    first_seen = models.DateTimeField(db_default=Now())
    last_seen = models.DateTimeField(db_default=Now())
    commands = pg_fields.ArrayField(
        models.CharField(max_length=1024, blank=True),
        default=list,
    )
    commands_hash = models.CharField(max_length=64, unique=True, blank=True, null=True)
    cluster = models.IntegerField(blank=True, null=True)

    def __str__(self):
        cmd_string = "; ".join(self.commands)
        return cmd_string[:29] + "..." if len(cmd_string) > 32 else cmd_string


class CowrieSession(models.Model):
    session_id = models.BigIntegerField(primary_key=True)
    start_time = models.DateTimeField(blank=True, null=True)
    duration = models.FloatField(blank=True, null=True)
    login_attempt = models.BooleanField(default=False)
    credentials = pg_fields.ArrayField(
        models.CharField(max_length=256, blank=True),
        default=list,
    )
    command_execution = models.BooleanField(default=False)
    interaction_count = models.IntegerField(default=0)
    source = models.ForeignKey(IOC, on_delete=models.CASCADE)
    commands = models.ForeignKey(CommandSequence, on_delete=models.SET_NULL, blank=True, null=True)

    class Meta:
        indexes = [
            models.Index(fields=["source"]),
        ]

    def __str__(self):
        return f"Session {hex(self.session_id)[2:]} from {self.source.name}"


class Statistics(models.Model):
    source = models.CharField(max_length=15)
    view = models.CharField(
        max_length=32,
        choices=ViewType.choices,
        default=ViewType.FEEDS_VIEW.value,
    )
    request_date = models.DateTimeField(db_default=Now())

    def __str__(self):
        return f"{self.source} - {self.view} ({self.request_date.strftime('%Y-%m-%d %H:%M')})"


class MassScanner(models.Model):
    ip_address = models.GenericIPAddressField()
    added = models.DateTimeField(db_default=Now())
    reason = models.CharField(max_length=64, blank=True, default="")

    class Meta:
        indexes = [
            models.Index(fields=["ip_address"]),
        ]

    def __str__(self):
        return f"{self.ip_address}{f' ({self.reason})' if self.reason else ''}"


class TorExitNode(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    added = models.DateTimeField(db_default=Now())
    reason = models.CharField(max_length=64, blank=True, default="tor exit node")

    class Meta:
        indexes = [
            models.Index(fields=["ip_address"]),
        ]

    def __str__(self):
        return f"{self.ip_address} (tor exit node)"


class WhatsMyIPDomain(models.Model):
    domain = models.CharField(max_length=256)
    added = models.DateTimeField(db_default=Now())

    class Meta:
        indexes = [
            models.Index(fields=["domain"]),
        ]

    def __str__(self):
        return self.domain


class Tag(models.Model):
    """Tags for IOCs from enrichment sources like ThreatFox and AbuseIPDB."""

    ioc = models.ForeignKey(IOC, on_delete=models.CASCADE, related_name="tags")
    key = models.CharField(max_length=128, db_index=True)
    value = models.CharField(max_length=256)
    source = models.CharField(max_length=64)  # e.g., "threatfox", "abuseipdb"
    added = models.DateTimeField(db_default=Now())

    class Meta:
        indexes = [
            models.Index(fields=["source", "ioc"]),
        ]

    def __str__(self):
        return f"{self.ioc.name} - {self.key}: {self.value} ({self.source})"


class EventSource(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="event_sources",
    )
    name = models.CharField(max_length=64)
    token_hash = models.CharField(max_length=64, unique=True, db_index=True)
    is_active = models.BooleanField(default=True)
    rate_limit = models.PositiveIntegerField(default=100)
    created_at = models.DateTimeField(auto_now_add=True)

    @staticmethod
    def generate_token() -> str:
        return secrets.token_urlsafe(32)

    @classmethod
    def hash_token(cls, raw_token: str) -> str:
        return hmac.new(
            settings.SECRET_KEY.encode(),
            raw_token.encode(),
            hashlib.sha256,
        ).hexdigest()

    def issue_token(self) -> str:
        raw_token = self.generate_token()
        self.token_hash = self.hash_token(raw_token)
        return raw_token

    def check_token(self, raw_token: str) -> bool:
        return hmac.compare_digest(self.token_hash, self.hash_token(raw_token))

    def __str__(self):
        return f"{self.name} ({self.owner})"


class InjectedEvent(models.Model):
    class Status(models.TextChoices):
        QUEUED = "queued"
        PROCESSED = "processed"
        FAILED = "failed"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    source = models.ForeignKey(
        EventSource,
        on_delete=models.CASCADE,
        related_name="injected_events",
    )
    received_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=32, choices=Status.choices, default=Status.QUEUED)
    error_text = models.TextField(blank=True, default="")
    observable_value = models.CharField(max_length=256)
    observable_type = models.CharField(max_length=32, choices=IocType.choices)
    payload_json = models.JSONField(default=dict)
    external_event_id = models.CharField(max_length=128, null=True, blank=True, db_index=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["source", "external_event_id"],
                condition=Q(external_event_id__isnull=False),
                name="unique_injected_event_external_id_per_source",
            )
        ]

    def __str__(self):
        return f"{self.observable_value} [{self.status}]"


class ShareToken(models.Model):
    """
    Tracks shared feed tokens issued via the ``/api/feeds/share`` endpoint.

    The raw token is never persisted; only its SHA-256 hash is stored so that
    a leaked database cannot be used to reconstruct valid tokens.
    A ``revoked`` flag allows tokens to be invalidated without deleting the record,
    making it easy to build an admin view for token management in the future.
    Only the user who created the token can revoke it.
    """

    user = models.ForeignKey(
        "certego_saas_user.User",
        on_delete=models.CASCADE,
        related_name="share_tokens",
    )
    token_hash = models.CharField(
        max_length=64,
        unique=True,
        db_index=True,
        help_text="SHA-256 hex digest of the raw signed token.",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    revoked = models.BooleanField(default=False)
    revoked_at = models.DateTimeField(null=True, blank=True)
    reason = models.CharField(max_length=256, blank=True, default="")

    def __str__(self):
        status = "revoked" if self.revoked else "active"
        return f"ShareToken({self.token_hash[:12]}… [{status}])"
