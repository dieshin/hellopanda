import copy
from pathlib import Path

import pandas as pd
import pytest
from fastapi import BackgroundTasks

from backend.app.config import ROOT, file_hash, settings
from backend.app.data.capture import extract_flows
from backend.app.main import analyse_dataset, inspect_upload, read_dataset
from backend.app.model import FEATURES, feature_frame, load_artifact, predict, train_model
from backend.app.storage import Store

WORKSPACE = ROOT.parents[1]


@pytest.fixture
def model_state(tmp_path, monkeypatch):
    monkeypatch.delenv('DATABASE_URL', raising=False)
    config = copy.deepcopy(settings())
    config['app']['app']['database_url'] = 'sqlite:///' + str(tmp_path / 'store.db')
    config['providers']['hosting']['enabled'] = False
    config['model']['model']['directory'] = str(tmp_path / 'models')
    return config, Store(config['app']['app'])


def test_real_capture_extraction_direction_and_limits():
    path = WORKSPACE / 'c2db/pcaps/backstage.pcap'
    limits = settings()['model']['capture']
    frame = extract_flows(path, limits)
    assert len(frame) == 3
    assert set(frame.protocol) == {'tcp', 'udp'}
    flow = frame.loc[frame.protocol.eq('tcp')].iloc[0]
    assert flow.packets == flow.src_packets + flow.dst_packets
    assert flow.initial_syn and flow.dst_ip == '139.180.202.218'
    assert flow.dst_port == 80 and flow.src_bytes > 0 and flow.dst_bytes > 0
    assert len(feature_frame(frame)) == 1
    with pytest.raises(ValueError, match='packet limit'):
        extract_flows(path, {**limits, 'max_packets': 2})


def test_labels_preserve_unknowns_and_external_incident_holdouts():
    audit = pd.read_csv(WORKSPACE / 'datasets/training/label-audit.csv')
    corpus = pd.read_csv(WORKSPACE / 'datasets/training/labelled-flows.csv')
    assert corpus.groupby('group').split.nunique().max() == 1
    assert not corpus.duplicated(['capture_sha256', 'stream_id']).any()
    assert audit.label.isna().sum() > 0
    assert audit.loc[audit.label.isna(), 'split'].eq('excluded').all()
    assert corpus.loc[~corpus.source_path.str.contains('ctu13'), 'split'].eq('test').all()
    assert corpus.loc[corpus.split.eq('train'), 'label'].value_counts().to_dict() == {0: 1117, 1: 24}
    assert len(corpus.loc[corpus.group.eq('acbackdoor')]) == 8
    assert len(corpus.loc[corpus.group.eq('backstage')]) == 1
    assert set(FEATURES).isdisjoint({'src_ip', 'dst_ip', 'label', 'timestamp', 'group', 'src_port', 'dst_port'})


def test_real_training_prediction_analysis_and_tamper_rejection(model_state, tmp_path):
    config, store = model_state
    record = train_model(config, store)
    assert record['training_c2'] == 24
    assert record['metrics']['acbackdoor']['precision'] is None
    assert record['metrics']['ctu5-normal-host-164']['recall'] is None
    source = WORKSPACE / 'c2db/pcaps/acbackdoor.pcap'
    capture = tmp_path / source.name
    capture.write_bytes(source.read_bytes())
    dataset = inspect_upload(capture, capture.name, file_hash(capture), capture.stat().st_size,
                             'capture', config, store)
    confirmation = store.confirmations(dataset['id'], 1)[0]
    first = analyse_dataset(confirmation['id'], BackgroundTasks(), model_state)
    second = analyse_dataset(confirmation['id'], BackgroundTasks(), model_state)
    assert first['ml_scored_records'] == 10 and second['reused']
    findings = store.list('finding', 100)
    assert any('regular_connections' in finding['triggered_rules'] for finding in findings)
    assert all(finding['model_version'] == record['version'] for finding in findings if finding['ml_score'] is not None)
    assert all(finding['ml_probability'] is None and finding['risk']['score'] is None for finding in findings)
    filtered, total = store.findings(100, 0, destination='193.29.15.147')
    assert total == 8
    assert [item['ml_score'] for item in filtered] == sorted((item['ml_score'] for item in filtered), reverse=True)
    adapter, raw = read_dataset(dataset, config)
    frame = adapter.map(raw, confirmation['mapping']['field_mapping'])
    assert len(predict(frame, record)) == 10
    frame['initial_syn'] = False
    assert predict(frame, record) == {}
    Path(dataset['extracted_path']).write_text('changed evidence')
    with pytest.raises(ValueError, match='evidence changed'):
        read_dataset(dataset, config)
    load_artifact.cache_clear()
    Path(record['artifact_path']).write_bytes(b'corrupted artifact')
    with pytest.raises(ValueError, match='missing or changed'):
        load_artifact(record['artifact_path'], record['artifact_sha256'])


def test_training_rejects_leaking_groups(model_state, tmp_path):
    config, store = model_state
    frame = pd.read_csv(WORKSPACE / 'datasets/training/labelled-flows.csv')
    frame.loc[frame.split.eq('test'), 'group'] = 'ctu5-training-hosts'
    path = tmp_path / 'leaking.csv'
    frame.to_csv(path, index=False)
    config['model']['model']['corpus'] = str(path)
    with pytest.raises(ValueError, match='crosses the train/test'):
        train_model(config, store)
    assert store.count('model') == 0
