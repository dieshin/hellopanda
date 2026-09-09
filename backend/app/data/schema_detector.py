import numpy as np
import pandas as pd


def inspect_schema(frame, config, dataset_config):
    columns = []
    for name in frame.columns:
        values = frame[name]
        present = values.dropna()
        numeric = pd.to_numeric(present, errors='coerce')
        is_numeric = len(present) > 0 and numeric.notna().all() and np.isfinite(numeric).all()
        counts = present.astype(str).value_counts()
        columns.append({
            'name': str(name), 'inferred_type': 'numeric' if is_numeric else 'categorical',
            'storage_type': str(values.dtype), 'null_count': int(values.isna().sum()),
            'null_percentage': float(values.isna().mean() * 100),
            'unique_count': int(len(counts)),
            'minimum': float(numeric.min()) if is_numeric else None,
            'maximum': float(numeric.max()) if is_numeric else None,
            'values': [{'value': str(key), 'count': int(count)} for key, count in counts.head(config['category_preview_limit']).items()],
            'values_truncated': len(counts) > config['category_preview_limit'],
            'possible_label': str(name).lower() in dataset_config['label_hints'],
        })
    return {'row_count': len(frame), 'column_count': len(columns), 'columns': columns,
            'label_column': None, 'class_distribution': None,
            'assumptions': ['Data types are inferred, not feature semantics.',
                            'Candidate labels are hints only; label confirmation is required.',
                            'Whether rows represent flows requires user confirmation.']}


def confirm_schema(frame, mapping, feature_config):
    label = mapping.get('label_column')
    positive = mapping.get('positive_labels', [])
    negative = mapping.get('negative_labels', [])
    distribution = None
    if label:
        if label not in frame:
            raise ValueError('The label column is absent from this dataset')
        if not positive or not negative or set(positive) & set(negative):
            raise ValueError('Provide nonempty, disjoint positive and negative label values')
        values = frame[label].dropna().astype(str)
        observed = set(values)
        if set(positive + negative) != observed:
            raise ValueError('Configured labels must exactly cover the observed non-null values')
        distribution = {str(k): int(v) for k, v in values.value_counts().items()}
    elif positive or negative:
        raise ValueError('Confirm a label column before specifying label values')
    selected, disabled = [], []
    for name, feature in feature_config['features'].items():
        if not feature.get('enabled', False):
            continue
        source = mapping['field_mapping'].get(name)
        if source == label and label:
            raise ValueError('The label column cannot be an ML feature')
        if source not in frame:
            if feature_config['missing_feature_policy'] != 'disable':
                raise ValueError(f'Configured feature {name} is missing')
            disabled.append(name)
        else:
            selected.append(name)
    return {'class_distribution': distribution, 'selected_features': selected, 'disabled_features': disabled}
