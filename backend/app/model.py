import os
import tempfile
from functools import lru_cache
from pathlib import Path
from threading import Lock

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, precision_score, recall_score

from .config import file_hash, fingerprint, project_path
from .data.capture import CONTRACT

FEATURES = ['duration', 'packets', 'src_bytes', 'dst_bytes', 'mean_packet_bytes',
            'src_packet_fraction', 'src_byte_fraction']
LIMITATIONS = [
    'Experimental TCP metadata model; score is not a calibrated C2 probability.',
    'Training positives come from one historical CTU Virut incident; unseen families may evade it.',
    'External C2 labels are source-attributed, not independent ground truth.',
    'Normal-host holdout shares the training capture; it is not an independent benign deployment test.',
    'Positive-only external tests cannot measure precision or false-positive rate.',
    'Incomplete captures, UDP, DNS-only channels and non-SYN-started streams are not modelled.',
]
TRAINING_LOCK = Lock()


def feature_frame(frame):
    required = ['duration', 'packets', 'src_bytes', 'dst_bytes', 'src_packets', 'dst_packets']
    if not set(required + ['initial_syn', 'feature_contract']) <= set(frame):
        raise ValueError('ML requires TCP flows extracted by the registered packet pipeline')
    values = frame[required].apply(pd.to_numeric, errors='coerce')
    valid = np.isfinite(values).all(axis=1) & (values >= 0).all(axis=1)
    valid &= frame['feature_contract'].eq(CONTRACT)
    valid &= frame['initial_syn'].astype(str).str.lower().isin(['true', '1'])
    valid &= values['packets'].eq(values.src_packets + values.dst_packets) & values.packets.gt(0)
    total_bytes = values.src_bytes + values.dst_bytes
    valid &= total_bytes.gt(0)
    values['mean_packet_bytes'] = total_bytes / values.packets
    values['src_packet_fraction'] = values.src_packets / values.packets
    values['src_byte_fraction'] = values.src_bytes / total_bytes
    return values.loc[valid, FEATURES]


def model_status(store):
    records = store.list('model', 1)
    return records[0] if records else {'status': 'not_trained', 'metrics': None,
                                     'message': 'Prepare the labelled corpus, then train the local model.'}


@lru_cache(maxsize=2)
def load_artifact(path, digest):
    if not Path(path).is_file() or file_hash(path) != digest:
        raise ValueError('Trained model is missing or changed; retrain before analysis')
    # Only application-created artifacts are accepted; there is no model upload endpoint.
    artifact = joblib.load(path)
    if artifact['contract'] != CONTRACT or artifact['sklearn_version'] != sklearn.__version__:
        raise ValueError('Model extraction/library version changed; retrain before analysis')
    return artifact


def predict(frame, record):
    if record['status'] != 'trained':
        return {}
    try:
        values = feature_frame(frame)
    except ValueError:
        return {}
    if values.empty:
        return {}
    artifact = load_artifact(record['artifact_path'], record['artifact_sha256'])
    scores = artifact['estimator'].predict_proba(values)[:, 1]
    return {index: {'score': float(score), 'prediction': 'c2_like' if score >= record['threshold'] else 'below_threshold',
                    'features': {key: float(value) for key, value in values.loc[index].items()}}
            for index, score in zip(values.index, scores)}


def evaluate(labels, scores, threshold):
    predicted = np.asarray(scores) >= threshold
    truth = np.asarray(labels, dtype=int)
    tn, fp, fn, tp = confusion_matrix(truth, predicted, labels=[0, 1]).ravel()
    both = set(truth) == {0, 1}
    return {'records': len(truth), 'c2': int(sum(truth)), 'normal': int(sum(truth == 0)),
            'confusion_matrix': {'tn': int(tn), 'fp': int(fp), 'fn': int(fn), 'tp': int(tp)},
            'recall': float(recall_score(truth, predicted, zero_division=0)) if sum(truth) else None,
            'precision': float(precision_score(truth, predicted, zero_division=0)) if both else None,
            'false_positive_rate': float(fp / (fp + tn)) if fp + tn else None}


def train_model(config, store):
    if not TRAINING_LOCK.acquire(blocking=False):
        raise ValueError('A model training run is already in progress')
    try:
        policy = config['model']['model']
        corpus = project_path(policy['corpus'])
        if not corpus.is_file():
            raise ValueError('Labelled corpus missing; run scripts/prepare_corpus.py first')
        frame = pd.read_csv(corpus)
        required = {'label', 'split', 'group', 'label_basis', 'capture_sha256', 'stream_id'}
        if not required <= set(frame) or frame[list(required)].isna().any().any():
            raise ValueError('Corpus requires labels, split groups, attribution and capture provenance')
        if not set(frame.label) <= {0, 1} or not set(frame.split) <= {'train', 'test'}:
            raise ValueError('Only explicit binary labels and train/test splits are accepted')
        if frame.groupby('group').split.nunique().max() != 1:
            raise ValueError('A split group crosses the train/test boundary')
        if frame.duplicated(['capture_sha256', 'stream_id']).any():
            raise ValueError('Duplicate capture streams would leak into evaluation')
        values = feature_frame(frame)
        if len(values) != len(frame):
            raise ValueError('Corpus contains unsupported or incomplete model features')
        training = frame.split.eq('train')
        if set(frame.loc[training, 'label']) != {0, 1} or not (~training).any():
            raise ValueError('Training requires both classes and a held-out evaluation set')
        threshold = policy['threshold']
        if not 0 < threshold < 1:
            raise ValueError('Model threshold must be between zero and one')
        estimator = RandomForestClassifier(n_estimators=policy['n_estimators'], max_depth=policy['max_depth'],
                                           min_samples_leaf=policy['min_samples_leaf'], class_weight='balanced',
                                           random_state=policy['random_state'], n_jobs=1)
        estimator.fit(values.loc[training], frame.loc[training, 'label'])
        metrics = {}
        for group, rows in frame.loc[~training].groupby('group'):
            metrics[group] = evaluate(rows.label, estimator.predict_proba(values.loc[rows.index])[:, 1], threshold)
        digest = file_hash(corpus)
        version = fingerprint([digest, policy, CONTRACT, sklearn.__version__])
        directory = project_path(policy['directory'])
        directory.mkdir(parents=True, exist_ok=True)
        artifact = {'estimator': estimator, 'contract': CONTRACT, 'sklearn_version': sklearn.__version__}
        path = directory / f'{version}.joblib'
        with tempfile.NamedTemporaryFile(dir=directory, delete=False) as handle:
            temporary = Path(handle.name)
        try:
            joblib.dump(artifact, temporary)
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)
        record = {'status': 'trained', 'version': version, 'threshold': threshold, 'metrics': metrics,
                  'artifact_path': str(path), 'artifact_sha256': file_hash(path), 'corpus_sha256': digest,
                  'contract': CONTRACT, 'sklearn_version': sklearn.__version__, 'limitations': LIMITATIONS,
                  'training_records': int(training.sum()), 'training_c2': int(frame.loc[training, 'label'].sum()),
                  'training_groups': sorted(frame.loc[training, 'group'].unique()),
                  'feature_importance': dict(zip(FEATURES, estimator.feature_importances_.tolist())),
                  'message': 'Local Random Forest trained. Review per-group tests before relying on its scores.'}
        return store.save('model', record)
    finally:
        TRAINING_LOCK.release()
