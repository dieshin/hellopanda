import copy
import os
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from backend.app.analyst import Assessment, Claim, availability, evidence_package, investigate, validate_assessment
from backend.app.config import settings
from backend.app.data.dataset_adapter import DatasetAdapter
from backend.app.data.schema_detector import inspect_schema
from backend.app.detection import fuse
from backend.app.main import app, resources
from backend.app.storage import Store


@pytest.fixture
def state(tmp_path, monkeypatch):
    monkeypatch.delenv('DATABASE_URL', raising=False)
    monkeypatch.delenv('ANALYST_API_KEY', raising=False)
    config = copy.deepcopy(settings())
    config['app']['app']['database_url'] = 'sqlite:///' + str(tmp_path / 'records.db')
    config['app']['app']['upload_directory'] = str(tmp_path / 'uploads')
    config['model']['model']['corpus'] = str(tmp_path / 'missing-corpus.csv')
    config['model']['model']['directory'] = str(tmp_path / 'models')
    monkeypatch.setenv('DATABASE_URL', config['app']['app']['database_url'])
    return config, Store(config['app']['app'])


@pytest.fixture
def client(state):
    app.dependency_overrides[resources] = lambda: state
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()


def test_empty_workspace_never_reports_model_results(client):
    response = client.get('/api/status')
    assert response.status_code == 200
    result = response.json()
    assert result['datasets'] == 0 and result['findings'] == 0
    assert result['model']['metrics'] is None
    assert not result['ai']['available']
    assert client.get('/api/findings').json() == {'items': [], 'total': 0}
    assert client.post('/api/train').status_code == 422


def test_unknown_record_does_not_create_evidence(client):
    assert client.get('/api/findings/missing').status_code == 404
    assert client.post('/api/findings/missing/investigate').status_code == 404
    assert client.get('/api/status').json()['findings'] == 0


def test_empty_import_leaves_no_dataset_or_file(client, state):
    response = client.post('/api/datasets', files={'file': ('empty.csv', b'', 'text/csv')})
    assert response.status_code == 422
    assert state[1].count('dataset') == 0
    assert not list(Path(state[0]['app']['app']['upload_directory']).iterdir())


def test_unsupported_file_cannot_be_imported(client):
    assert client.post('/api/datasets', files={'file': ('empty.exe', b'')}).status_code == 415


def test_cross_origin_write_is_rejected(client):
    assert client.post('/api/train', headers={'Origin': 'null'}).status_code == 403


def test_untrusted_host_is_rejected(client):
    assert client.get('/api/status', headers={'Host': 'untrusted'}).status_code == 400


def test_missing_components_never_become_zero_risk(state):
    config = copy.deepcopy(state[0]['risk'])
    config['risk']['enabled'] = True
    result = fuse({}, config)
    assert result['score'] is None
    assert result['level'] == 'unavailable'
    assert set(result['missing_components']) == set(config['risk']['required_components'])


def test_missing_key_disables_only_analyst(state):
    config = copy.deepcopy(state[0]['ai']['analyst'])
    config['enabled'] = True
    config['model'] = 'test-model'
    config['api_key_env'] = 'ANALYST_API_KEY'
    assert not availability(config)['available']
    assert not investigate([], 'investigation', config, state[1])['available']
    assert state[1].count('finding') == 0


def test_original_records_are_immutable(state):
    store = state[1]
    record = store.save('audit', {'configuration': state[0]['risk']})
    with pytest.raises(sqlite3.IntegrityError):
        store.save('audit', {'configuration': {}}, record['id'])
    assert store.get('audit', record['id']) == record


def test_failed_batch_is_atomic(state):
    store = state[1]

    def records():
        yield {'configuration': state[0]['risk']}
        raise ValueError('Abort incomplete write')

    with pytest.raises(ValueError):
        store.analysis_run('aborted', records())
    assert store.count('finding') == 0
    assert store.count('run') == 0


def test_completed_analysis_is_reused_without_consuming_input(state):
    store = state[1]
    original, reused = store.analysis_run('empty-run', iter(()))
    assert not reused

    def must_not_recompute():
        raise AssertionError('Previously analysed input must not be consumed again')
        yield

    cached, reused = store.analysis_run('empty-run', must_not_recompute())
    assert reused and cached == original


def test_ai_schema_rejects_unstructured_or_extra_content():
    with pytest.raises(ValidationError):
        Assessment.model_validate({'summary': 'Unsupported free-form response', 'engine_score': None})


def test_empty_assessment_is_rejected(state):
    assessment = Assessment(summary=[], triage='needs_review', confidence=0.0,
                            supporting_evidence=[], counter_evidence=[], risk=[],
                            recommended_actions=[], limitations=['limited_evidence'])
    with pytest.raises(ValueError, match='no cited summary'):
        validate_assessment(assessment, [], state[0]['ai']['analyst'], True)


def test_unknown_evidence_reference_is_rejected(state):
    assessment = Assessment(summary=[Claim(evidence_id='absent', quote='unsupported', interpretation='')],
                            triage='needs_review', confidence=0.0, supporting_evidence=[], counter_evidence=[],
                            risk=[], recommended_actions=[], limitations=['limited_evidence'])
    with pytest.raises(ValueError, match='unknown evidence ID'):
        validate_assessment(assessment, [], state[0]['ai']['analyst'], True)


def test_no_findings_means_no_ai_evidence(state):
    assert evidence_package([], state[0]['ai']['analyst']) == []


def test_ai_storage_cannot_overwrite_original_records(state):
    store = state[1]
    original = store.save('audit', {'configuration': state[0]['risk']})
    store.save_analysis('audit-cache', {'configuration': state[0]['ai']})
    assert store.get('audit', original['id']) == original
    assert store.cached('audit-cache') == {'configuration': state[0]['ai']}


def test_dashboard_and_assets_are_served(client):
    for path in ('/', '/app.js', '/styles.css'):
        response = client.get(path)
        assert response.status_code == 200
        assert response.headers['x-content-type-options'] == 'nosniff'
        assert "frame-ancestors 'none'" in response.headers['content-security-policy']


@pytest.mark.skipif(not os.getenv('HELLO_PANDA_DATASET'), reason='No real dataset supplied; synthetic data is prohibited')
def test_provided_dataset_schema_is_measured(state):
    config = state[0]
    path = Path(os.environ['HELLO_PANDA_DATASET'])
    adapter = DatasetAdapter(config['app']['app'], config['dataset']['dataset'])
    frame = adapter.read(path, config['app']['app']['formats'][path.suffix.lower()])
    profile = inspect_schema(frame, config['app']['app'], config['dataset']['dataset'])
    assert profile['row_count'] == len(frame)
    assert profile['label_column'] is None
    assert {column['name'] for column in profile['columns']} == set(frame.columns)
    assert sum(column['null_count'] for column in profile['columns']) == int(frame.isna().sum().sum())
