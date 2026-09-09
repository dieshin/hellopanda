import ipaddress
import json
import os
import subprocess
from contextlib import nullcontext
from datetime import datetime, timezone
from threading import Lock
from urllib.parse import urlsplit

import httpx
import pandas as pd
from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator

from .context import fetch

CAPTURE_LOCK = Lock()


class EndpointEvent(BaseModel):
    model_config = ConfigDict(extra='forbid')
    event_id: str = Field(min_length=1, max_length=256)
    timestamp: datetime
    host: str = Field(min_length=1, max_length=256)
    source: str = Field(min_length=1, max_length=128)
    src_ip: IPvAnyAddress
    dst_ip: IPvAnyAddress
    src_port: int = Field(ge=0, le=65535)
    dst_port: int = Field(ge=0, le=65535)
    protocol: str
    process_name: str = Field(max_length=1024)
    process_id: int | None = Field(default=None, ge=0)
    process_hash: str | None = Field(default=None, max_length=128)

    @field_validator('timestamp')
    @classmethod
    def aware_timestamp(cls, value):
        if value.tzinfo is None:
            raise ValueError('Endpoint timestamps require an explicit timezone')
        return value.astimezone(timezone.utc)

    @field_validator('protocol')
    @classmethod
    def transport(cls, value):
        if value.lower() not in ('tcp', 'udp'):
            raise ValueError('Endpoint protocol must be tcp or udp')
        return value.lower()


class EndpointBatch(BaseModel):
    model_config = ConfigDict(extra='forbid')
    events: list[EndpointEvent] = Field(min_length=1, max_length=1000)


def correlate(frame, store, policy):
    required = {'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'timestamp', 'end_timestamp'}
    if not required <= set(frame):
        return {}
    results = {}
    tolerance = policy['match_tolerance_seconds']
    for index, flow in frame.iterrows():
        try:
            start, end = float(flow.timestamp), float(flow.end_timestamp)
            if not pd.notna(start) or not pd.notna(end):
                continue
            transport = 'udp' if flow.protocol == 'quic' else flow.protocol
            key = [str(ipaddress.ip_address(flow.src_ip)), str(ipaddress.ip_address(flow.dst_ip)),
                   int(flow.src_port), int(flow.dst_port), transport]
        except (ValueError, TypeError):
            continue
        records = store.endpoint_matches(key, start - tolerance, end + tolerance, policy['max_correlated_events'])
        if records:
            results[index] = [{**item, 'correlation_basis': 'directed 5-tuple and observed time interval',
                               'limitation': 'sensor-reported process association; not a malware verdict'} for item in records]
    return results


def capture_network(path, interface, seconds, policy):
    if not policy['enabled'] or interface not in policy['interfaces']:
        raise ValueError('Live capture requires an enabled, explicitly configured interface')
    if not 1 <= seconds <= policy['max_seconds']:
        raise ValueError('Capture duration exceeds the configured limit')
    if not CAPTURE_LOCK.acquire(blocking=False):
        raise ValueError('A live capture is already in progress')
    try:
        result = subprocess.run(['dumpcap', '-q', '-i', interface, '-a', f'duration:{seconds}',
                                 '-a', f"filesize:{policy['max_kib']}", '-c', str(policy['max_packets']),
                                 '-w', str(path)], capture_output=True, timeout=seconds + 15, check=False)
        if result.returncode:
            raise ValueError('Capture failed; check interface availability and dumpcap permissions on the host')
    except FileNotFoundError as error:
        raise ValueError('Live capture requires dumpcap on the application host') from error
    except subprocess.TimeoutExpired as error:
        raise ValueError('Live capture timed out; partial capture was rejected') from error
    finally:
        CAPTURE_LOCK.release()


def export_event(finding):
    return {'event_id': finding['id'], 'event_type': 'network_evidence', 'created_at': finding['created_at'],
            'flow_id': finding['flow_id'], 'features': finding['features'], 'risk': finding['risk'],
            'scores': finding['scores'], 'model_version': finding['model_version'],
            'triggered_rules': finding['triggered_rules'], 'evidence': finding['evidence'],
            'raw_reference': finding['raw_reference'], 'limitations': finding['limitations']}


def send_siem(findings, policy, client=None):
    if not policy['enabled']:
        raise ValueError('SIEM forwarding is disabled')
    endpoint = urlsplit(policy['url'] or '')
    if endpoint.scheme != 'https' or not endpoint.hostname or endpoint.username or endpoint.password or endpoint.query or endpoint.fragment:
        raise ValueError('SIEM endpoint must be an administrator-configured HTTPS URL without embedded credentials')
    token = os.getenv(policy['token_env'])
    if not token:
        raise ValueError('SIEM credential is missing')
    if len(findings) > policy['max_findings']:
        raise ValueError('Too many findings in one SIEM request')
    events = [export_event(finding) for finding in findings]
    if policy['format'] == 'splunk_hec':
        body = '\n'.join(json.dumps({'event': event, 'sourcetype': 'hellopanda:evidence'}) for event in events)
        headers = {'Authorization': f'Splunk {token}', 'Content-Type': 'application/json'}
    elif policy['format'] == 'ndjson':
        body = '\n'.join(json.dumps(event) for event in events) + '\n'
        headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/x-ndjson'}
    else:
        raise ValueError('Unknown SIEM format')
    try:
        with (nullcontext(client) if client is not None else httpx.Client(timeout=policy['timeout_seconds'], follow_redirects=False, trust_env=False)) as connection:
            raw = fetch(connection, 'POST', policy['url'], 65536, content=body.encode(), headers=headers)
        if policy['format'] == 'splunk_hec':
            acknowledgement = json.loads(raw)
            if not isinstance(acknowledgement, dict) or type(acknowledgement.get('code')) is not int or acknowledgement['code'] != 0:
                raise ValueError('Splunk did not accept the events')
    except (httpx.HTTPError, json.JSONDecodeError) as error:
        raise ValueError('SIEM delivery failed or is unconfirmed; inspect the receiver before retrying') from error
    return {'status': 'accepted_by_receiver', 'count': len(events),
            'message': 'HTTP acknowledgement received; indexing is not independently verified. Repeated sends may duplicate events.'}
