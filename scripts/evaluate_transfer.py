"""Exploratory transfer check: leave each positive incident out; keep normal test host out throughout."""
import json
import sys
from pathlib import Path

import pandas as pd
from sklearn.base import clone

APP = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(APP))

from backend.app.config import file_hash, project_path, settings  # noqa: E402
from backend.app.model import evaluate, feature_frame, load_artifact, model_status  # noqa: E402
from backend.app.storage import Store  # noqa: E402


def evaluate_transfer():
    config = settings()
    record = model_status(Store(config['app']['app']))
    if record['status'] != 'trained':
        raise ValueError('Train the baseline model first')
    path = project_path(config['model']['model']['corpus'])
    frame = pd.read_csv(path)
    values = feature_frame(frame)
    if len(values) != len(frame) or frame.duplicated(['capture_sha256', 'stream_id']).any():
        raise ValueError('Invalid or duplicate flow features')
    baseline = load_artifact(record['artifact_path'], record['artifact_sha256'])['estimator']
    normal_test = frame.split.eq('test') & frame.label.eq(0)
    results = {}
    for group in frame.loc[frame.label.eq(1), 'group'].unique():
        held = frame.group.eq(group) & frame.label.eq(1)
        training = ~(held | normal_test)
        estimator = clone(baseline).fit(values.loc[training], frame.loc[training, 'label'])
        results[group] = {
            'c2_holdout': evaluate(frame.loc[held, 'label'], estimator.predict_proba(values.loc[held])[:, 1], record['threshold']),
            'normal_holdout': evaluate(frame.loc[normal_test, 'label'], estimator.predict_proba(values.loc[normal_test])[:, 1], record['threshold']),
            'training_records': int(training.sum()), 'training_c2': int(frame.loc[training, 'label'].sum()),
        }
    report = {'corpus_sha256': file_hash(path), 'baseline_version': record['version'],
              'threshold': record['threshold'], 'groups': results,
              'limitations': ['Exploratory follow-up after viewing the failed baseline, not a fresh final test.',
                  'External C2 incidents stay intact within each fold; CTU positive holdout shares its capture with normal training hosts.',
                  'The same 539 normal-host streams are held out in every fold; do not sum them as independent samples.',
                  'No tuning or model promotion follows this experiment. The active baseline remains unchanged.']}
    (path.parent / 'transfer-evaluation.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    evaluate_transfer()
