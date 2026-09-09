import copy
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import httpx
import pandas as pd
import pytest
from fastapi import BackgroundTasks
from fastapi.testclient import TestClient

from backend.app.config import ROOT, file_hash, settings
from backend.app.context import enrich, lookup, refresh_ranges
from backend.app.data.capture import extract_flows
from backend.app.detection import dns_tunnel, rare_destination, similar_flows
from backend.app.integrations import capture_network, correlate, send_siem
from backend.app.main import analyse_dataset, app, inspect_upload, resources
from backend.app.model import feature_frame
from backend.app.storage import Store

WORKSPACE = ROOT.parents[1]


@pytest.fixture
def state(tmp_path, monkeypatch):
    config = copy.deepcopy(settings())
    config['app']['app']['database_url'] = 'sqlite:///' + str(tmp_path / 'store.db')
    config['app']['app']['upload_directory'] = str(tmp_path / 'uploads')
    monkeypatch.setenv('DATABASE_URL', config['app']['app']['database_url'])
    store = Store(config['app']['app'])
    return config, store


def test_udp_dns_quic_are_measured_without_tcp_model_scores(state):
    config, _ = state
    capture = extract_flows(WORKSPACE / 'c2db/pcaps/acbackdoor.pcap', config['model']['capture'])
    assert capture.protocol.value_counts().to_dict() == {'udp': 37, 'tcp': 10}
    assert capture.dns_queries.sum() == 336
    assert len(feature_frame(capture)) == 10
    results = dns_tunnel(capture, config['detection']['rules']['dns_tunnel']['parameters'])
    assert results and not any(hit for hit, _ in results.values())
    assert sum(len(json.loads(value)) for value in capture.dns_requests) == 336
    quic = extract_flows(WORKSPACE / 'datasets/validation/quic-double-retry.pcapng', config['model']['capture'])
    assert 'quic' in set(quic.protocol)
    assert quic.quic_version.ne('').any()
    assert feature_frame(quic).empty


def test_behaviour_rules_use_observed_scope_and_actual_query_times(state):
    config, _ = state
    capture = extract_flows(WORKSPACE / 'c2db/pcaps/acbackdoor.pcap', config['model']['capture'])
    params = config['detection']['rules']['similar_flows']['parameters']
    results = similar_flows(capture, params)
    assert any(hit for hit, _ in results.values())
    assert rare_destination(capture, config['detection']['rules']['rare_destination']['parameters']) == {}
    # Thresholds lowered only to exercise branches on real DNS observations, not benchmark detector accuracy.
    params = {**config['detection']['rules']['dns_tunnel']['parameters'], 'minimum_queries': 1,
              'minimum_unique_names': 1, 'minimum_name_length': 1, 'minimum_label_entropy': 0}
    results = dns_tunnel(capture, params)
    assert all(hit for hit, _ in results.values())
    for index, (_, measured) in results.items():
        times = [row[0] for row in json.loads(capture.loc[index, 'dns_requests'])]
        start = measured['window_start_epoch']
        assert any(start <= value < start + params['window_seconds'] for value in times)


@pytest.mark.parametrize('name,payload,expected', [
    ('virustotal', {'data': {'attributes': {'last_analysis_stats': {'malicious': 2, 'harmless': 8}}}}, 70),
    ('abuseipdb', {'data': {'ipAddress': '8.8.8.8', 'abuseConfidenceScore': 42, 'totalReports': 3}}, 42),
    ('urlhaus', {'query_status': 'ok', 'url_count': 2}, 70),
    ('greynoise', {'classification': 'malicious', 'noise': True, 'riot': False}, 70),
])
def test_provider_contracts_and_failures(state, monkeypatch, name, payload, expected):
    policy = state[0]['providers']['threat_intelligence']['sources'][name]
    monkeypatch.setenv(policy['api_key_env'], 'contract-fixture-key')
    calls = []

    def respond(request):
        calls.append(request)
        assert request.headers[policy['key_header']] == 'contract-fixture-key'
        if name == 'urlhaus':
            assert request.method == 'POST' and request.content == b'host=8.8.8.8'
        if name == 'abuseipdb':
            assert request.url.params['ipAddress'] == '8.8.8.8'
        return httpx.Response(200, json=payload)

    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        result = lookup(name, '8.8.8.8', policy, client)
    assert result['score'] == expected and result['status'] == 'observed' and len(calls) == 1
    for code, status in [(429, 'rate_limited'), (404, 'no_record'), (500, 'provider_error')]:
        with httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(code))) as client:
            assert lookup(name, '8.8.8.8', policy, client) == {'status': status, 'http_status': code, 'score': None}
    with httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200, json={}))) as client:
        assert lookup(name, '8.8.8.8', policy, client)['score'] is None


def test_hosting_cache_private_ips_and_shared_reputation_cap(state, monkeypatch):
    config, store = state
    policy = config['providers']
    policy['hosting']['feeds'] = [policy['hosting']['feeds'][0]]
    # Mock range/provider payloads are API contract fixtures, not real reputation assertions.
    with httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200, text='8.8.8.0/24\n'))) as client:
        refresh_ranges(policy['hosting'], store, client)
    policy['threat_intelligence']['enabled'] = True
    for name, source in policy['threat_intelligence']['sources'].items():
        source['enabled'] = name == 'abuseipdb'
    monkeypatch.setenv('ABUSEIPDB_API_KEY', 'contract-fixture-key')
    calls = []

    def respond(request):
        calls.append(request)
        return httpx.Response(200, json={'data': {'ipAddress': '8.8.8.8', 'abuseConfidenceScore': 95, 'totalReports': 2}})

    frame = pd.DataFrame({'dst_ip': ['8.8.8.8', '127.0.0.1']})
    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        first = enrich(frame, policy, store, client)
    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        second = enrich(frame, policy, store, client)
    assert first == second and len(calls) == 1
    assert first['8.8.8.8'][-1]['score'] == 30
    assert first['8.8.8.8'][-1]['uncapped_score'] == 95
    assert first['127.0.0.1'][-1]['status'] == 'non_public_address'


def test_auth_roles_and_atomic_endpoint_ingest(state, monkeypatch):
    config, store = state
    config['integrations']['auth']['enabled'] = True
    tokens = {role: role + '-contract-token-' + 'a' * 32 for role in ('admin', 'viewer', 'sensor')}
    for role, token in tokens.items():
        monkeypatch.setenv(f'PANDA_{role.upper()}_TOKEN', token)
    monkeypatch.setattr('backend.app.main.settings', lambda: config)
    app.dependency_overrides[resources] = lambda: state
    try:
        with TestClient(app, base_url='https://testserver') as client:
            assert client.get('/api/status').status_code == 401
            viewer = {'Authorization': 'Bearer ' + tokens['viewer']}
            sensor = {'Authorization': 'Bearer ' + tokens['sensor']}
            assert client.get('/api/status', headers=viewer).status_code == 200
            assert client.get('http://testserver/api/status', headers=viewer).status_code == 400
            assert client.post('/api/train', headers=viewer).status_code == 403
            assert client.get('/api/findings', headers=sensor).status_code == 403
            frame = extract_flows(WORKSPACE / 'c2db/pcaps/backstage.pcap', config['model']['capture'])
            flow = frame.loc[frame.protocol.eq('tcp')].iloc[0]
            event = {'event_id': 'contract-event', 'timestamp': pd.Timestamp(flow.timestamp, unit='s', tz='UTC').isoformat(),
                     'host': 'contract-host', 'source': 'contract-fixture', 'src_ip': flow.src_ip, 'dst_ip': flow.dst_ip,
                     'src_port': int(flow.src_port), 'dst_port': int(flow.dst_port), 'protocol': 'tcp', 'process_name': 'contract-fixture.exe'}
            assert client.post('/api/endpoint-events', json={'events': [event]}, headers=sensor).status_code == 201
            assert client.post('/api/endpoint-events', json={'events': [event]}, headers=sensor).status_code == 201
            conflict = {**event, 'process_name': 'changed.exe'}
            response = client.post('/api/endpoint-events', json={'events': [{**event, 'event_id': 'new'}, conflict]}, headers=sensor)
            assert response.status_code == 422 and store.count('endpoint') == 1
            matched = correlate(frame, store, config['integrations']['endpoint'])
            assert len(matched) == 1
            assert next(iter(matched.values()))[0]['process_name'] == 'contract-fixture.exe'
    finally:
        app.dependency_overrides.clear()


def test_capture_limits_and_siem_acknowledgement(state, tmp_path, monkeypatch):
    config, store = state
    path = tmp_path / 'capture.pcapng'
    with pytest.raises(ValueError, match='configured interface'):
        capture_network(path, 'unapproved', 2, config['integrations']['live_capture'])
    assert not path.exists()
    policy = {**config['integrations']['siem'], 'enabled': True, 'url': 'https://siem.example/services/collector/event'}
    monkeypatch.setenv('SIEM_TOKEN', 'contract-fixture-key')
    source = WORKSPACE / 'c2db/pcaps/backstage.pcap'
    calls = []

    def capture(command, **options):
        calls.append(command)
        assert command[0] == 'dumpcap' and command[command.index('-i') + 1] == 'lo'
        assert 'duration:2' in command and 'filesize:16384' in command
        assert options['timeout'] == 17 and not options.get('shell')
        Path(command[command.index('-w') + 1]).write_bytes(source.read_bytes())
        return SimpleNamespace(returncode=0)

    with monkeypatch.context() as patch:
        patch.setattr('backend.app.integrations.subprocess.run', capture)
        capture_network(path, 'lo', 2, {**config['integrations']['live_capture'], 'enabled': True, 'interfaces': ['lo']})
    assert file_hash(path) == file_hash(source) and len(calls) == 1
    local = tmp_path / source.name
    local.write_bytes(source.read_bytes())
    dataset = inspect_upload(local, local.name, file_hash(local), local.stat().st_size, 'capture', config, store)
    confirmation = store.confirmations(dataset['id'], 1)[0]
    analyse_dataset(confirmation['id'], BackgroundTasks(), state)
    findings = store.list('finding', 1)
    assert findings

    def receive(request):
        assert request.headers['authorization'] == 'Splunk contract-fixture-key'
        body = json.loads(request.content)
        assert body['event']['raw_reference']['sha256'] == file_hash(source)
        assert body['event']['event_id'] == findings[0]['id']
        return httpx.Response(200, json={'code': 0})

    with httpx.Client(transport=httpx.MockTransport(receive)) as client:
        assert send_siem(findings, policy, client)['status'] == 'accepted_by_receiver'
    with httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200, json={'code': 6}))) as client:
        with pytest.raises(ValueError, match='did not accept'):
            send_siem(findings, policy, client)


@pytest.mark.parametrize('stats', [None, [], 'unavailable'])
def test_malformed_vendor_statistics_remain_unknown(state, monkeypatch, stats):
    policy = state[0]['providers']['threat_intelligence']['sources']['virustotal']
    monkeypatch.setenv(policy['api_key_env'], 'contract-fixture-key')
    payload = {'data': {'attributes': {'last_analysis_stats': stats}}}
    with httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200, json=payload))) as client:
        assert lookup('virustotal', '8.8.8.8', policy, client) == {'status': 'invalid_or_unavailable', 'score': None}


@pytest.mark.parametrize('payload', [[], None, {'code': False}])
def test_invalid_siem_acknowledgement_is_not_success(state, monkeypatch, payload):
    policy = {**state[0]['integrations']['siem'], 'enabled': True, 'url': 'https://siem.example/events'}
    monkeypatch.setenv(policy['token_env'], 'contract-fixture-key')
    with httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200, content=json.dumps(payload)))) as client:
        with pytest.raises(ValueError, match='did not accept'):
            send_siem([], policy, client)


def test_failed_range_refresh_preserves_previous_snapshot(state):
    policy, store = state[0]['providers']['hosting'], state[1]
    policy['feeds'] = policy['feeds'][:2]
    with httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200, text='8.8.8.0/24\n'))) as client:
        original = refresh_ranges(policy, store, client)

    def respond(request):
        return httpx.Response(200, text='1.1.1.0/24\n' if str(request.url) == policy['feeds'][0]['url'] else 'invalid-cidr')

    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        with pytest.raises(ValueError):
            refresh_ranges(policy, store, client)
    assert store.list('hosting_ranges', 10) == [original]


@pytest.mark.parametrize('failure', ['exit', 'timeout'])
def test_failed_live_capture_cleans_partial_files_and_releases_lock(state, monkeypatch, failure):
    config, store = state
    config['integrations']['live_capture'].update(enabled=True, interfaces=['lo'])
    monkeypatch.setattr('backend.app.main.settings', lambda: config)

    def capture(command, **options):
        Path(command[command.index('-w') + 1]).write_bytes(b'partial contract fixture')
        if failure == 'timeout':
            raise subprocess.TimeoutExpired(command, options['timeout'])
        return SimpleNamespace(returncode=1)

    monkeypatch.setattr('backend.app.integrations.subprocess.run', capture)
    app.dependency_overrides[resources] = lambda: state
    try:
        with TestClient(app) as client:
            for _ in range(2):
                response = client.post('/api/capture', json={'interface': 'lo', 'seconds': 1})
                assert response.status_code == 422
                assert 'already in progress' not in response.text
                assert not list(Path(config['app']['app']['upload_directory']).iterdir())
        assert store.count('dataset') == store.count('finding') == 0
    finally:
        app.dependency_overrides.clear()
