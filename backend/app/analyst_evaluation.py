"""Compare saved analyst outputs with human-reviewed held-out cases; makes no API calls."""

import argparse
import json
from pathlib import Path

from .analyst import Assessment, Example, reviewed_examples, validate_assessment
from .config import fingerprint, settings


def read_cases(path):
    cases = {}
    for line in Path(path).read_text(encoding='utf-8').splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        identifier = item.pop('case_id')
        if not isinstance(identifier, str) or not identifier.strip() or identifier in cases:
            raise ValueError('Case IDs must be nonempty, unique strings')
        cases[identifier] = item
    if not cases:
        raise ValueError('Provide actual cases; no evaluation can be computed from an empty file')
    return cases


def evaluate(reference_path, prediction_path, config):
    references, predictions = read_cases(reference_path), read_cases(prediction_path)
    if predictions.keys() - references.keys():
        raise ValueError('Predictions include unknown case IDs')
    demonstration_evidence = {
        fingerprint(example['evidence'])
        for task in ('alert_summary', 'investigation', 'triage')
        for example in reviewed_examples(task, config)
    }
    valid, agreed, matched, extra, missed = 0, 0, 0, 0, 0
    failures = []
    confusion = {}
    for identifier, record in references.items():
        reference = Example.model_validate(record)
        reference.validate_review(config)
        if fingerprint(reference.evidence) in demonstration_evidence:
            raise ValueError('Evaluation cases must be held out from prompt examples')
        engines = [item['data'] for item in reference.evidence if item['type'] == 'engine']
        incomplete = not engines or any(item['final_score'] is None for item in engines)
        expected = {(section, claim.evidence_id) for section in ('supporting_evidence', 'counter_evidence')
                    for claim in getattr(reference.assessment, section)}
        selected, predicted = set(), 'unavailable'
        try:
            candidate = Assessment.model_validate(predictions[identifier]['assessment'])
            validate_assessment(candidate, reference.evidence, config, incomplete)
        except (ValueError, KeyError, TypeError) as error:
            failures.append({'case_id': identifier, 'error': type(error).__name__})
        else:
            valid += 1
            predicted = candidate.triage
            agreed += predicted == reference.assessment.triage
            selected = {(section, claim.evidence_id) for section in ('supporting_evidence', 'counter_evidence')
                        for claim in getattr(candidate, section)}
        matched += len(expected & selected)
        extra += len(selected - expected)
        missed += len(expected - selected)
        row = confusion.setdefault(reference.assessment.triage, {})
        row[predicted] = row.get(predicted, 0) + 1
    return {
        'cases': len(references), 'valid_assessments': valid, 'triage_matches': agreed,
        'triage_agreement': agreed / len(references),
        'evidence_precision': matched / (matched + extra) if matched + extra else None,
        'evidence_recall': matched / (matched + missed) if matched + missed else None,
        'confusion': confusion, 'failures': failures,
        'reference_hash': fingerprint(references), 'prediction_hash': fingerprint(predictions),
        'limitation': 'Measures triage agreement and evidence selection, not semantic correctness or C2 detection accuracy.',
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('references', help='Human-reviewed JSONL cases, kept out of prompt examples')
    parser.add_argument('predictions', help='JSONL records with case_id and saved assessment (null for failed requests)')
    args = parser.parse_args()
    print(json.dumps(evaluate(args.references, args.predictions, settings()['ai']['analyst']), indent=2))
