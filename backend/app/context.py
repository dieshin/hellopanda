import ipaddress
import json
import math
import os
from contextlib import nullcontext
from datetime import datetime, timezone
from functools import lru_cache

import httpx

from .config import fingerprint
from .storage import now


def fetch(client, method, url, limit, **kwargs):
    with client.stream(method, url, **kwargs) as response:
        response.raise_for_status()
        data = bytearray()
        for chunk in response.iter_bytes():
            data.extend(chunk)
            if len(data) > limit:
                raise ValueError('Provider response exceeds the configured size limit')
        return bytes(data)


def lookup(name, address, policy, client):
    key = os.getenv(policy['api_key_env'])
    if not key:
        return {'status': 'missing_key', 'score': None}
    if name == 'greynoise' and ipaddress.ip_address(address).version != 4:
        return {'status': 'unsupported_ipv6', 'score': None}
    options = {'headers': {'Accept': 'application/json', policy['key_header']: key}}
    url = policy['url'].format(ip=address)
    if name == 'abuseipdb':
        options['params'] = {'ipAddress': address, 'maxAgeInDays': policy['max_age_days']}
    elif name == 'urlhaus':
        options['data'] = {'host': address}
    try:
        raw = fetch(client, 'POST' if name == 'urlhaus' else 'GET', url, policy['max_response_bytes'], **options)
        payload = json.loads(raw)
        if name == 'virustotal':
            stats = payload['data']['attributes']['last_analysis_stats']
            if not isinstance(stats, dict) or any(type(value) is not int or value < 0 for value in stats.values()) or not sum(stats.values()):
                raise ValueError('No measured vendor results')
            malicious = stats['malicious']
            score = policy['positive_score'] if malicious else 0
            measured = {'malicious_vendors': malicious, 'total_vendor_results': sum(stats.values())}
        elif name == 'abuseipdb':
            data = payload['data']
            if data['ipAddress'] != address:
                raise ValueError('Mismatched IP response')
            score = data['abuseConfidenceScore']
            measured = {'abuse_confidence_score': score, 'reports': data['totalReports'],
                        'max_age_days': policy['max_age_days']}
        elif name == 'urlhaus':
            status = payload['query_status']
            if status == 'no_results':
                return {'status': 'no_record', 'score': None}
            if status != 'ok':
                raise ValueError('URLhaus lookup was not successful')
            count = int(payload['url_count'])
            score = policy['positive_score'] if count > 0 else 0
            measured = {'associated_url_count': count, 'scope': 'host-associated URLs; not proof of C2'}
        elif name == 'greynoise':
            classification = payload['classification']
            if classification not in ('malicious', 'benign', 'unknown'):
                raise ValueError('Unknown classification')
            score = policy['positive_score'] if classification == 'malicious' else None
            measured = {field: payload[field] for field in ('noise', 'riot', 'classification')}
        else:
            raise ValueError('Unknown provider')
        if score is not None and (isinstance(score, bool) or not isinstance(score, (float, int)) or not math.isfinite(score) or not 0 <= score <= 100):
            raise ValueError('Provider returned an invalid score')
        return {'status': 'observed', 'score': score, 'measurements': measured,
                'response_sha256': fingerprint(payload)}
    except httpx.HTTPStatusError as error:
        code = error.response.status_code
        return {'status': 'no_record' if code == 404 else 'rate_limited' if code == 429 else 'provider_error',
                'http_status': code, 'score': None}
    except (httpx.HTTPError, ValueError, KeyError, TypeError):
        return {'status': 'invalid_or_unavailable', 'score': None}


def refresh_ranges(policy, store, client=None):
    if not policy['enabled']:
        raise ValueError('Hosting context is disabled in providers.yaml')
    entries = []
    with (nullcontext(client) if client is not None else httpx.Client(timeout=policy['timeout_seconds'], follow_redirects=False, trust_env=False)) as connection:
        for provider in policy['feeds']:
            raw = fetch(connection, 'GET', provider['url'], policy['max_response_bytes'])
            if provider['format'] == 'cidr':
                networks = raw.decode().splitlines()
            elif provider['format'] == 'aws':
                data = json.loads(raw)
                networks = [item['ip_prefix'] for item in data['prefixes']]
                networks += [item['ipv6_prefix'] for item in data['ipv6_prefixes']]
            else:
                raise ValueError('Unknown hosting feed format')
            for network in set(networks):
                entries.append({'network': str(ipaddress.ip_network(network)), 'provider': provider['name'],
                                'shared_infrastructure': provider['shared_infrastructure'], 'source': provider['url']})
    if not entries:
        raise ValueError('Hosting feeds returned no valid ranges')
    return store.save('hosting_ranges', {'entries': entries, 'observed_at': now()})


@lru_cache(maxsize=4)
def parsed_ranges(serialized):
    return [(ipaddress.ip_network(entry['network']), entry) for entry in json.loads(serialized)]


def enrich(frame, config, store, client=None):
    policy, hosting = config['threat_intelligence'], config['hosting']
    output = {}
    if 'dst_ip' not in frame or not (policy['enabled'] or hosting['enabled']):
        return output
    snapshots = store.list('hosting_ranges', 1) if hosting['enabled'] else []
    current = datetime.now(timezone.utc)
    snapshot = snapshots[0] if snapshots and (current - datetime.fromisoformat(snapshots[0]['observed_at'])).total_seconds() <= hosting['max_age_seconds'] else None
    ranges = parsed_ranges(json.dumps(snapshot['entries'], sort_keys=True)) if snapshot else []
    queried = 0
    with (nullcontext(client) if client is not None else httpx.Client(timeout=policy['timeout_seconds'], follow_redirects=False, trust_env=False)) as connection:
        for value in frame.dst_ip.dropna().astype(str).unique():
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                continue
            observations = []
            if hosting['enabled']:
                matches = [entry for network, entry in ranges if address.version == network.version and address in network]
                observations.append({'source': 'hosting_ranges', 'status': 'matched' if matches else 'no_match' if snapshot else 'missing_or_stale',
                                     'observed_at': snapshot['observed_at'] if snapshot else None,
                                     'score': None, 'shared_infrastructure': any(entry['shared_infrastructure'] for entry in matches) or None,
                                     'ranges': matches, 'scope': 'network ownership; origin operator and tenancy unverified'})
            shared = any(item['shared_infrastructure'] for item in observations)
            if policy['enabled']:
                for name, provider in policy['sources'].items():
                    if not provider['enabled']:
                        continue
                    observation = {'source': name, 'observed_at': None, 'shared_infrastructure': shared or None,
                                   'lookup_time_scope': 'current lookup; does not establish reputation at capture time'}
                    cache_key = fingerprint([name, value, provider])
                    cached = store.observation(cache_key, policy['cache_seconds'])
                    if not address.is_global:
                        result = {'status': 'non_public_address', 'score': None}
                    elif not os.getenv(provider['api_key_env']):
                        result = {'status': 'missing_key', 'score': None}
                    elif cached:
                        result = cached['result']
                        observation['observed_at'] = cached['created_at']
                    elif queried >= policy['max_queries_per_analysis']:
                        result = {'status': 'query_budget_exhausted', 'score': None}
                    else:
                        queried += 1
                        result = lookup(name, str(address), provider, connection)
                        if result['status'] in ('observed', 'no_record'):
                            cached = store.save('observation', {'cache_key': cache_key, 'result': result})
                            observation['observed_at'] = cached['created_at']
                    observation.update(result)
                    if shared and observation['score'] is not None:
                        observation['uncapped_score'] = observation['score']
                        observation['score'] = min(observation['score'], policy['shared_reputation_cap'])
                    observations.append(observation)
            output[value] = observations
    return output
