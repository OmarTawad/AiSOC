"""Map supported dataset event families to canonical AiSOC ingest events."""

from datetime import datetime, timezone
import math

CONNECTOR_ID = "hf-datasets"
AUTH_TYPES = {"auth_success", "auth_failure", "auth_event", "pam_event"}
WINDOWS_AUTH_ACTIONS = {"logon", "logoff", "credential validation", "kerberos authentication service"}
WINDOWS_STREAMS = {"windows_security_audit", "microsoft-windows-security-auditing"}


def key(row, field):
    return str(row.get(field) or "").strip().casefold()


def timestamp(value):
    if isinstance(value, datetime):
        return value.replace(tzinfo=value.tzinfo or timezone.utc).isoformat()
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, timezone.utc).isoformat() if math.isfinite(value) else None
    if not value:
        return None
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return parsed.replace(tzinfo=parsed.tzinfo or timezone.utc).isoformat()


def json_value(value):
    if isinstance(value, datetime):
        return timestamp(value)
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if isinstance(value, list):
        return [json_value(item) for item in value]
    if isinstance(value, dict):
        return {name: json_value(item) for name, item in value.items()}
    return value


def envelope(dataset, stable_id, connector_type, row, *, when, username, hostname, family):
    raw = {
        name if name.startswith("hf_") else f"hf_{name}": json_value(value)
        for name, value in row.items()
    }
    raw["hf_dataset"] = dataset
    external_id = f"{dataset}:{stable_id}"
    event = {
        "source": CONNECTOR_ID,
        "external_id": external_id,
        "title": f"HF {dataset}: {family}",
        "event_type": f"hf.{dataset}.{family}",
        "severity": "low",
        "raw_event": raw,
    }
    optional = {
        "timestamp": timestamp(when),
        "username": username,
        "hostname": hostname,
        "src_ip": row.get("src_ip"),
        "dst_ip": row.get("dst_ip"),
    }
    event.update({name: value for name, value in optional.items() if value})
    return connector_type, event


def map_precinct6(row):
    kind, stream, action = (key(row, name) for name in ("message_type", "stream_name", "action"))
    if kind in AUTH_TYPES or (stream in WINDOWS_STREAMS and action in WINDOWS_AUTH_ACTIONS):
        connector_type = "hf_auth"
    elif (
        (kind == "communication" and stream == "network_communication")
        or (kind == "network_flow_data" and stream == "aws_vpc_flow_log")
        or (kind == "firewall_action" and stream == "cisco_asa")
        or (stream in WINDOWS_STREAMS and action == "filtering platform connection")
    ):
        connector_type = "hf_network"
    else:
        return None
    mapped = envelope(
        "precinct6", row["hf_row_index"], connector_type, row,
        when=row.get("timestamp"),
        username=row.get("username"), hostname=row.get("src_host"), family=kind,
    )
    outcome = {"auth_success": "success", "auth_failure": "failure"}.get(kind)
    if outcome:
        mapped[1]["outcome"] = outcome
    return mapped


def map_advanced_siem(row):
    kind = key(row, "event_type")
    if kind == "auth":
        connector_type = "hf_auth"
    elif kind in {"network", "firewall", "ids_alert"}:
        connector_type = "hf_network"
    else:
        return None
    return envelope(
        "advanced-siem", row["event_id"], connector_type, row,
        when=row.get("timestamp"), username=row.get("user"), hostname=None, family=kind,
    )


MAPPERS = {"precinct6": map_precinct6, "advanced-siem": map_advanced_siem}
