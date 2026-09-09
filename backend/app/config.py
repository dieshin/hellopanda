import hashlib
import json
import os
from pathlib import Path
from urllib.parse import urlsplit

import yaml
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[2]
load_dotenv(ROOT / '.env')
CONFIG_NAMES = ('app', 'dataset', 'features', 'detection', 'risk', 'providers', 'ai', 'model', 'integrations')


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, allow_nan=False).encode()).hexdigest()


def file_hash(path):
    with Path(path).open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def project_path(value):
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def settings():
    directory = project_path(os.getenv('HELLO_PANDA_CONFIG', 'config'))
    result = {name: yaml.safe_load((directory / f'{name}.yaml').read_text(encoding='utf-8')) for name in CONFIG_NAMES}
    app = result['app']['app']
    for key in ('max_upload_bytes', 'max_rows', 'max_columns', 'page_size', 'max_page_size', 'upload_chunk_bytes', 'category_preview_limit'):
        if not isinstance(app[key], int) or app[key] <= 0:
            raise ValueError(f'app.{key} must be a positive integer')
    auth = result['integrations']['auth']
    if app['host'] not in ('127.0.0.1', 'localhost', '::1') and not auth['enabled']:
        raise ValueError('Authentication must be enabled before binding beyond loopback')
    if any(user['role'] not in ('admin', 'analyst', 'viewer', 'sensor') for user in auth['users']):
        raise ValueError('Unknown access role')
    if auth['enabled'] and not any(len(os.getenv(user['token_env'], '')) >= 32 for user in auth['users'] if user['role'] == 'admin'):
        raise ValueError('Authentication requires an admin token of at least 32 characters')
    for provider in [*result['providers']['threat_intelligence']['sources'].values(), *result['providers']['hosting']['feeds']]:
        endpoint = urlsplit(provider['url'])
        if endpoint.scheme != 'https' or not endpoint.hostname or endpoint.username or endpoint.password or endpoint.query or endpoint.fragment:
            raise ValueError('Provider and hosting endpoints require HTTPS without embedded credentials, query or fragment')
    live = result['integrations']['live_capture']
    if live['max_kib'] * 1024 > app['max_upload_bytes'] or live['max_packets'] > result['model']['capture']['max_packets']:
        raise ValueError('Live capture limits must fit the import/extraction limits')
    risk = result['risk']['risk']
    if risk['formula'] != 'weighted_mean' or risk['scale'] <= 0:
        raise ValueError('Unsupported risk formula or scale')
    if any(not isinstance(v, (int, float)) or v <= 0 for v in risk['weights'].values()):
        raise ValueError('Risk weights must be positive')
    if set(risk['weights']) != set(risk['required_components']):
        raise ValueError('Risk weights must match required components')
    levels = risk['levels']
    if not levels or levels[0]['minimum'] != 0 or any(a['minimum'] >= b['minimum'] for a, b in zip(levels, levels[1:])):
        raise ValueError('Risk levels must begin at zero and increase strictly')
    if len({x['name'] for x in levels}) != len(levels) or levels[-1]['minimum'] > risk['scale']:
        raise ValueError('Invalid risk levels')
    ai = result['ai']['analyst']
    ai['model'] = os.getenv('ANALYST_MODEL') or ai['model']
    ai['base_url'] = os.getenv('ANALYST_BASE_URL') or ai['base_url']
    endpoint = urlsplit(ai['base_url'])
    if endpoint.scheme not in ('http', 'https') or not endpoint.hostname or endpoint.username or endpoint.password or endpoint.query or endpoint.fragment:
        raise ValueError('Analyst endpoint must be an HTTP(S) URL without credentials, query or fragment')
    if ai['api'] not in ('chat_completions', 'responses'):
        raise ValueError('Analyst API must be chat_completions or responses')
    if ai['response_format'] not in ('json_schema', 'json_object'):
        raise ValueError('Analyst response format must be json_schema or json_object')
    if ai['completion_token_parameter'] not in ('max_tokens', 'max_completion_tokens'):
        raise ValueError('Unsupported analyst completion token parameter')
    for key in ('max_examples', 'max_examples_bytes', 'max_output_tokens', 'max_evidence_items'):
        if not isinstance(ai[key], int) or ai[key] <= 0:
            raise ValueError(f'analyst.{key} must be a positive integer')
    if ai['automatic_analysis']['minimum_risk_level'] not in {x['name'] for x in levels}:
        raise ValueError('Unknown automatic analysis risk level')
    return result
