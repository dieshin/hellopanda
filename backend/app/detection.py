import json
import math
from collections import Counter

import numpy as np
import pandas as pd

from .config import fingerprint
from .model import LIMITATIONS


def numeric(series):
    values = pd.to_numeric(series, errors='coerce')
    return values.where(np.isfinite(values))


def periodicity(frame, parameters, baseline=None):
    fields = parameters['group_fields']
    required = fields + [parameters['time_field']]
    if not fields or any(name not in frame for name in required):
        raise ValueError('Periodicity requires configured grouping fields and a mapped timestamp')
    if parameters['minimum_connections'] < 3 or parameters['maximum_coefficient_variation'] < 0:
        raise ValueError('Periodicity requires at least three connections and a nonnegative tolerance')
    times = pd.to_datetime(frame[parameters['time_field']], errors='coerce', utc=True) if parameters['time_unit'] == 'iso' else pd.to_datetime(numeric(frame[parameters['time_field']]), unit=parameters['time_unit'], errors='coerce', utc=True)
    results = {}
    for _, group in frame.groupby(fields, dropna=True):
        measured = times.loc[group.index].dropna().sort_values()
        if len(measured) < parameters['minimum_connections']:
            continue
        intervals = measured.diff().dt.total_seconds().dropna()
        mean = float(intervals.mean())
        if mean <= 0:
            continue
        deviation = float(intervals.std(ddof=0) / mean)
        data = {'connection_count': len(measured), 'mean_interval_seconds': mean,
                'coefficient_of_variation': deviation,
                'maximum_coefficient_variation': parameters['maximum_coefficient_variation'],
                'related_record_numbers': [int(i) + 1 for i in measured.index],
                'excluded_timestamp_count': int(len(group) - len(measured))}
        for index in measured.index:
            results[index] = (deviation <= parameters['maximum_coefficient_variation'], data)
    return results


def ratio_outlier(frame, parameters, baseline):
    numerator, denominator = parameters['numerator'], parameters['denominator']
    if baseline is None or baseline.empty:
        raise ValueError('A confirmed benign baseline dataset is required for ratio analysis')
    if any(field not in frame or field not in baseline for field in (numerator, denominator)):
        raise ValueError('Ratio fields must exist in both mapped datasets')
    if not 0 < parameters['percentile'] < 100:
        raise ValueError('Ratio percentile must be between zero and one hundred')
    baseline_denominator = numeric(baseline[denominator])
    baseline_numerator = numeric(baseline[numerator])
    ratios = (baseline_numerator.where(baseline_numerator >= 0) / baseline_denominator.where(baseline_denominator > 0)).dropna()
    if ratios.empty:
        raise ValueError('The supplied benign baseline contains no valid ratios')
    threshold = float(ratios.quantile(parameters['percentile'] / 100))
    denominator_values, numerator_values = numeric(frame[denominator]), numeric(frame[numerator])
    values = numerator_values.where(numerator_values >= 0) / denominator_values.where(denominator_values > 0)
    return {index: (float(value) > threshold, {'ratio': float(value), 'baseline_threshold': threshold,
            'baseline_count': len(ratios), 'baseline_confirmation_id': parameters['baseline_confirmation_id'],
            'percentile': parameters['percentile']}) for index, value in values.dropna().items() if math.isfinite(value)}


def rare_destination(frame, parameters, baseline=None):
    if parameters['minimum_hosts'] < 1 or not 0 <= parameters['maximum_host_fraction'] <= 1:
        raise ValueError('Rarity requires a positive host minimum and a fraction between zero and one')
    required = {'src_ip', 'dst_ip'}
    if not required <= set(frame):
        return {}
    hosts = frame.src_ip.nunique()
    if hosts < parameters['minimum_hosts']:
        return {}
    results = {}
    for _, group in frame.groupby('dst_ip'):
        prevalence = group.src_ip.nunique() / hosts
        measured = {'destination_host_count': int(group.src_ip.nunique()), 'observed_host_count': hosts,
                    'host_prevalence': prevalence, 'connection_count': len(group),
                    'maximum_host_fraction': parameters['maximum_host_fraction'],
                    'scope': 'this dataset only; not an internet reputation result'}
        for index in group.index:
            results[index] = (prevalence <= parameters['maximum_host_fraction'], measured)
    return results


def similar_flows(frame, parameters, baseline=None):
    if parameters['minimum_connections'] < 3 or parameters['maximum_coefficient_variation'] < 0:
        raise ValueError('Similarity requires at least three connections and a nonnegative tolerance')
    fields = parameters['group_fields']
    if not set(fields + parameters['measure_fields']) <= set(frame):
        return {}
    results = {}
    for _, group in frame.groupby(fields):
        values = group[parameters['measure_fields']].apply(numeric).dropna()
        if len(values) < parameters['minimum_connections'] or (values < 0).any().any():
            continue
        means = values.mean()
        if (means <= 0).any():
            continue
        coefficients = values.std(ddof=0) / means
        hit = bool((coefficients <= parameters['maximum_coefficient_variation']).all())
        measured = {'connection_count': len(values), 'coefficients_of_variation': coefficients.to_dict(),
                    'maximum_coefficient_variation': parameters['maximum_coefficient_variation']}
        for index in values.index:
            results[index] = (hit, measured)
    return results


def dns_tunnel(frame, parameters, baseline=None):
    if any(parameters[key] <= 0 for key in ('window_seconds', 'minimum_queries', 'minimum_unique_names', 'minimum_name_length')) or parameters['minimum_label_entropy'] < 0:
        raise ValueError('DNS thresholds require positive windows/counts/lengths and nonnegative entropy')
    if 'dns_requests' not in frame:
        return {}
    results, requests = {}, []
    for index, value in frame.dns_requests.items():
        try:
            for timestamp, source, destination, name in json.loads(value):
                if not isinstance(name, str) or not name or not math.isfinite(float(timestamp)):
                    raise ValueError('Invalid DNS observation')
                requests.append((index, float(timestamp), source, destination, name))
        except (ValueError, TypeError):
            raise ValueError('DNS analysis requires valid extracted query timestamps and names') from None
    if not requests:
        return results
    queries = pd.DataFrame(requests, columns=['flow_index', 'timestamp', 'source', 'destination', 'name'])
    queries['window'] = queries.timestamp // parameters['window_seconds']
    for (_, _, window), group in queries.groupby(['source', 'destination', 'window']):
        names = set(group.name)
        entropies = []
        for name in names:
            label = max(name.split('.'), key=len)
            entropies.append(-sum((count / len(label)) * math.log2(count / len(label))
                                 for count in Counter(label).values()) if label else 0)
        count, length, entropy = len(group), max(map(len, names)), max(entropies)
        hit = (count >= parameters['minimum_queries'] and len(names) >= parameters['minimum_unique_names']
               and length >= parameters['minimum_name_length'] and entropy >= parameters['minimum_label_entropy'])
        measured = {'query_count': count, 'unique_names': len(names), 'maximum_name_length': length,
                    'maximum_label_entropy': entropy, 'window_seconds': parameters['window_seconds'],
                    'window_start_epoch': window * parameters['window_seconds'], 'thresholds': parameters,
                    'visibility': 'visible DNS only; first question per query message; strongest observed window'}
        for index in group.flow_index.unique():
            previous = results.get(index)
            if previous is None or hit > previous[0] or (hit == previous[0] and count > previous[1]['query_count']):
                results[index] = (hit, measured)
    return results


DETECTORS = {'periodicity': periodicity, 'ratio_outlier': ratio_outlier,
             'rare_destination': rare_destination, 'similar_flows': similar_flows, 'dns_tunnel': dns_tunnel}
AGGREGATIONS = {'maximum': max, 'mean': lambda values: sum(values) / len(values)}


def aggregate(values, method):
    if method not in AGGREGATIONS:
        raise ValueError(f'Unknown score aggregation: {method}')
    return AGGREGATIONS[method](values) if values else None


def fuse(scores, config):
    risk = config['risk']
    missing = [name for name in risk['required_components'] if scores.get(name) is None]
    if not risk['enabled'] or missing:
        return {'score': None, 'level': 'unavailable', 'missing_components': missing,
                'formula': risk['formula'], 'weights': risk['weights'], 'policy_enabled': risk['enabled']}
    if any(not math.isfinite(scores[name]) or not 0 <= scores[name] <= risk['scale'] for name in risk['weights']):
        raise ValueError('Component scores must be finite and within the configured risk scale')
    score = sum(scores[name] * weight for name, weight in risk['weights'].items()) / sum(risk['weights'].values())
    level = next(level['name'] for level in reversed(risk['levels']) if score >= level['minimum'])
    return {'score': score, 'level': level, 'missing_components': [], 'formula': risk['formula'],
            'weights': risk['weights'], 'policy_enabled': True}


def context_evidence(row, config, scale):
    if not config['context']['enabled']:
        return [], None
    matched = []
    for entry in config['context']['entries']:
        required = {'field', 'value', 'source', 'observed_at', 'score', 'shared_infrastructure'}
        if not required <= entry.keys() or not entry['source'] or not entry['observed_at']:
            raise ValueError('Context entries require supplied attribution, observation time, and policy score')
        if not 0 <= entry['score'] <= scale:
            raise ValueError('Context score is outside the configured risk scale')
        if entry['field'] in row and str(row[entry['field']]) == str(entry['value']):
            matched.append(entry)
    return matched, aggregate([entry['score'] for entry in matched], config['context']['aggregation'])


def analyse(frame, dataset, confirmation, config, baseline_loader, predictions=None, model_record=None, contextual=None, endpoint_events=None):
    predictions = predictions or {}
    rule_results = {}
    rules = {name: rule for name, rule in config['detection']['rules'].items() if rule.get('enabled')}
    scale = config['risk']['risk']['scale']
    for name, rule in rules.items():
        detector = rule['detector']
        if detector not in DETECTORS:
            raise ValueError(f'Unknown detector: {detector}')
        parameters = rule['parameters']
        required = config['detection']['detectors'][detector]['required_parameters']
        if not set(required) <= parameters.keys():
            raise ValueError(f'Rule {name} is missing required parameters')
        if not 0 <= rule['score'] <= scale or not rule['severity']:
            raise ValueError(f'Invalid score or severity for rule {name}')
        baseline = baseline_loader(parameters['baseline_confirmation_id']) if detector == 'ratio_outlier' else None
        rule_results[name] = DETECTORS[detector](frame, parameters, baseline)
    if not rules and not config['providers']['context']['enabled'] and not predictions:
        raise ValueError('Configure justified behaviour rules or context evidence before analysis. No detector is enabled.')
    config_version = fingerprint(config)
    for index, row in frame.iterrows():
        flow_id = f"{dataset['id']}:{int(index) + 1}"
        evidence, triggered, measured_scores = [], [], []

        def add(kind, data):
            evidence.append({'id': f'EV-{fingerprint([flow_id, kind, data])}', 'type': kind, 'data': data})

        prediction = predictions.get(index)
        if prediction:
            add('ml', {**prediction, 'model_version': model_record['version'],
                       'threshold': model_record['threshold'], 'calibrated': False})

        for name, results in rule_results.items():
            if index not in results:
                continue
            hit, data = results[index]
            rule = rules[name]
            add('behaviour', {'rule': name, 'detector': rule['detector'], 'triggered': bool(hit),
                              'severity': rule['severity'], 'measurements': data})
            measured_scores.append(rule['score'] if hit else 0)
            if hit:
                triggered.append(name)
        context, context_score = context_evidence(row, config['providers'], scale)
        context += (contextual or {}).get(str(row.get('dst_ip')), [])
        context_score = aggregate([entry['score'] for entry in context if entry['score'] is not None], config['providers']['context']['aggregation'])
        for entry in context:
            add('context', entry)
        for entry in (endpoint_events or {}).get(index, []):
            add('endpoint', entry)
        if not evidence:
            continue
        scores = {'ml': prediction['score'] * scale if prediction else None,
                  'behaviour': aggregate(measured_scores, config['detection']['behaviour_aggregation']), 'context': context_score}
        risk = fuse(scores, config['risk'])
        add('engine', {'scores': scores, 'risk': risk})
        yield {'flow_id': flow_id, 'dataset_id': dataset['id'], 'raw_reference': {'sha256': dataset['sha256'],
               'record_number': int(index) + 1}, 'features': {k: None if pd.isna(v) else str(v) for k, v in row.items()},
               'model_version': model_record['version'] if prediction else None,
               'prediction': prediction['prediction'] if prediction else None,
               'ml_score': prediction['score'] if prediction else None, 'ml_probability': None,
               'scores': scores, 'risk': risk, 'triggered_rules': triggered, 'evidence': evidence,
               'configuration_version': config_version, 'configuration': config,
               'confirmation_id': confirmation['id'],
               'limitations': [*(LIMITATIONS if prediction else ['No supported trained-model features for this record.']),
                               'Behavioural deviation is not a malicious classification.',
                               'No context match means unknown context, not benign traffic.']}
