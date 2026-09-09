"""Import ECS or Wazuh Sysmon network-event JSONL through the authenticated sensor API."""
import argparse
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit

import httpx

APP = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(APP))

from backend.app.integrations import EndpointEvent  # noqa: E402


def normalize(record, format_name):
    if format_name == 'ecs':
        return EndpointEvent(event_id=record['event']['id'], timestamp=record['@timestamp'],
            host=record['host']['name'], source='ecs', src_ip=record['source']['ip'], dst_ip=record['destination']['ip'],
            src_port=record['source']['port'], dst_port=record['destination']['port'],
            protocol=record['network']['transport'], process_name=record['process']['name'],
            process_id=record['process'].get('pid'), process_hash=record['process'].get('hash', {}).get('sha256'))
    win = record['data']['win']
    if str(win['system']['eventID']) != '3':
        return None
    data = win['eventdata']
    timestamp = data['utcTime']
    if not timestamp.endswith('Z') and '+' not in timestamp:
        timestamp += '+00:00'
    return EndpointEvent(event_id=str(record['id']), timestamp=timestamp, host=record['agent']['name'],
        source='wazuh-sysmon', src_ip=data['sourceIp'], dst_ip=data['destinationIp'],
        src_port=data['sourcePort'], dst_port=data['destinationPort'], protocol=data['protocol'],
        process_name=data['image'], process_id=data.get('processId'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('file', type=Path)
    parser.add_argument('--format', choices=['ecs', 'wazuh'], required=True)
    parser.add_argument('--base-url', default='http://127.0.0.1:8000')
    parser.add_argument('--token-env', default='PANDA_SENSOR_TOKEN')
    args = parser.parse_args()
    url = urlsplit(args.base_url)
    if url.scheme != 'https' and not (url.scheme == 'http' and url.hostname in ('localhost', '127.0.0.1', '::1')):
        parser.error('Use HTTPS for a remote server')
    if url.username or url.password or url.query or url.fragment:
        parser.error('Base URL must not contain credentials, query or fragment')
    token = os.getenv(args.token_env)
    if not token:
        parser.error('Sensor token is missing from the specified environment variable')
    sent = 0
    with httpx.Client(timeout=30, follow_redirects=False, trust_env=False,
                      headers={'Authorization': f'Bearer {token}'}) as client, args.file.open() as source:
        for line_number, line in enumerate(source, 1):
            if not line.strip():
                continue
            try:
                event = normalize(json.loads(line), args.format)
            except (ValueError, KeyError, TypeError) as error:
                raise ValueError(f'Invalid network event on line {line_number}; earlier events remain imported') from error
            if event is None:
                continue
            response = client.post(args.base_url.rstrip('/') + '/api/endpoint-events',
                                   json={'events': [event.model_dump(mode='json')]})
            response.raise_for_status()
            sent += 1
    print(f'Imported {sent} endpoint network events. Reanalyse captures to correlate them.')


if __name__ == '__main__':
    main()
