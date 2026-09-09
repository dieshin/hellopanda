import json
import logging
import math
import os
from typing import Literal

from openai import OpenAI, OpenAIError
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .config import fingerprint, project_path
from .storage import now

LOGGER = logging.getLogger(__name__)
LIMITATIONS = ('incomplete_engine', 'limited_evidence', 'ownership_unverified', 'human_review_required')


class StrictModel(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)


class Claim(StrictModel):
    evidence_id: str
    quote: str
    interpretation: str


class Assessment(StrictModel):
    summary: list[Claim]
    triage: Literal['likely_benign', 'needs_review', 'high_priority']
    confidence: float = Field(ge=0, le=1)
    supporting_evidence: list[Claim]
    counter_evidence: list[Claim]
    risk: list[Claim]
    recommended_actions: list[str]
    limitations: list[Literal['incomplete_engine', 'limited_evidence', 'ownership_unverified', 'human_review_required']]


class Example(StrictModel):
    task: Literal['alert_summary', 'investigation', 'triage']
    reviewed_by: str = Field(min_length=1)
    evidence: list[dict] = Field(min_length=1)
    assessment: Assessment

    def validate_review(self, config):
        if not self.reviewed_by.strip():
            raise ValueError('Examples require a named reviewer')
        engines = [item['data'] for item in self.evidence if item['type'] == 'engine']
        incomplete = not engines or any(item['final_score'] is None for item in engines)
        validate_assessment(self.assessment, self.evidence, config, incomplete)


def availability(config):
    key_missing = config['api_key_env'] and not os.getenv(config['api_key_env'])
    if not config['enabled'] or key_missing or not config['model']:
        return {'available': False, 'message': 'AI Analyst unavailable — core detection remains operational.'}
    return {'available': True, 'message': 'AI Analyst configured; live service availability is checked on request.'}


def evidence_package(findings, config):
    evidence = []
    for finding in findings:
        for item in finding['evidence']:
            kind, source = item['type'], item['data']
            data = None
            if kind == 'engine':
                data = {'scores': source['scores'], 'final_score': source['risk']['score'],
                        'risk_level': source['risk']['level'], 'missing_components': source['risk']['missing_components']}
            elif kind == 'ml':
                data = {key: source[key] for key in ('score', 'prediction', 'threshold', 'calibrated')}
            elif kind == 'behaviour':
                measurements = {k: v for k, v in source['measurements'].items()
                                if isinstance(v, (int, float)) and not isinstance(v, bool)}
                data = {'detector': source['detector'], 'triggered': source['triggered'], 'measurements': measurements}
            elif kind == 'context':
                data = {'score': source['score'], 'shared_infrastructure': source['shared_infrastructure']}
                for field in ('status', 'lookup_time_scope', 'uncapped_score'):
                    if field in source:
                        data[field] = source[field]
            elif kind == 'endpoint':
                data = {'association': 'sensor-reported process matched by connection tuple and time',
                        'maliciousness': 'not established'}
            if data is not None:
                evidence.append({'id': item['id'], 'type': kind, 'data': data})
        approved = {field: value for field, value in finding['features'].items()
                    if (config['include_ip_addresses'] and field in config['ip_fields'])
                    or (config['include_domains'] and field in config['domain_fields'])}
        for field in config['safe_numeric_fields']:
            value = finding['features'].get(field)
            if value is not None:
                try:
                    number = float(value)
                    if math.isfinite(number):
                        approved[field] = number
                except (ValueError, TypeError):
                    pass
        if approved:
            evidence.append({'id': f"EV-{fingerprint([finding['id'], approved])}", 'type': 'approved_metadata', 'data': approved})
    if len(findings) > 1:
        relation = {'relationship': 'same measured periodicity group', 'finding_ids': [f['id'] for f in findings]}
        evidence.insert(0, {'id': f'EV-{fingerprint(relation)}', 'type': 'correlation', 'data': relation})
    return evidence[:config['max_evidence_items']]


def validate_assessment(assessment, evidence, config, incomplete):
    supplied = {item['id']: json.dumps(item['data'], sort_keys=True, allow_nan=False) for item in evidence}
    claims = assessment.summary + assessment.supporting_evidence + assessment.counter_evidence + assessment.risk
    if not assessment.summary or not claims:
        raise ValueError('AI returned no cited summary')
    for claim in claims:
        if claim.evidence_id not in supplied or not claim.quote.strip() or claim.quote not in supplied[claim.evidence_id]:
            raise ValueError('AI returned an unknown evidence ID or unsupported evidence quote')
    if not set(assessment.recommended_actions) <= set(config['recommended_actions']):
        raise ValueError('AI returned an action outside the defensive action policy')
    if incomplete and assessment.triage != 'needs_review':
        raise ValueError('Incomplete engine results require needs_review triage')
    return assessment


def reviewed_examples(task, config):
    if not config['examples_file']:
        return []
    with project_path(config['examples_file']).open('rb') as handle:
        data = handle.read(config['max_examples_bytes'] + 1)
    if len(data) > config['max_examples_bytes']:
        raise ValueError('Reviewed examples exceed the configured size limit')
    examples = []
    for line in data.splitlines():
        if not line.strip():
            continue
        example = Example.model_validate_json(line)
        example.validate_review(config)
        if example.task == task:
            examples.append(example.model_dump(exclude={'reviewed_by', 'task'}))
    return examples[:config['max_examples']]


def investigate(findings, task, config, store, client=None):
    status = availability(config)
    if not status['available']:
        return status
    if task not in ('alert_summary', 'investigation', 'triage'):
        raise ValueError('Unknown analyst task')
    package = evidence_package(findings, config)
    if not package:
        return {'available': False, 'message': 'No measured evidence is available for analysis.'}
    try:
        prompts = {name: project_path(config['prompts'][name]).read_text(encoding='utf-8') for name in ('system', task)}
        examples = reviewed_examples(task, config)
    except (OSError, UnicodeError, ValueError, KeyError, TypeError):
        return {'available': False, 'message': 'Analyst instructions or reviewed examples are invalid. Check the configuration.'}
    prompt_version = fingerprint({'prompts': prompts, 'examples': examples})
    key = fingerprint({'evidence': package, 'prompt_version': prompt_version, 'model': config['model'],
                       'policy': config, 'schema': Assessment.model_json_schema()})
    cached = store.cached(key)
    if cached:
        return {**cached, 'cached': True}
    try:
        instructions = prompts['system'] + '\n' + prompts[task]
        if examples:
            instructions += '\nReviewed examples (never cite their IDs for the current case):\n' + json.dumps(examples)
        messages = [{'role': 'system', 'content': instructions},
                    {'role': 'user', 'content': json.dumps({'evidence': package,
                     'allowed_actions': config['recommended_actions'], 'limitation_codes': LIMITATIONS})}]
        api_key = os.getenv(config['api_key_env']) if config['api_key_env'] else 'local'
        with (client or OpenAI(base_url=config['base_url'], api_key=api_key,
                               timeout=config['timeout_seconds'], max_retries=config['max_retries'])) as connection:
            if config['api'] == 'responses':
                options = {'reasoning': {'effort': config['reasoning_effort']}} if config['reasoning_effort'] else {}
                response = connection.responses.parse(
                    model=config['model'], store=False, max_output_tokens=config['max_output_tokens'],
                    input=messages, text_format=Assessment, **options)
                if response.status != 'completed' or response.output_parsed is None:
                    raise ValueError('AI response was incomplete or refused')
                assessment = response.output_parsed
            else:
                schema = Assessment.model_json_schema()
                if config['response_format'] == 'json_schema':
                    response_format = {'type': 'json_schema', 'json_schema': {
                        'name': 'Assessment', 'strict': True, 'schema': schema}}
                else:
                    response_format = {'type': 'json_object'}
                    messages[0]['content'] += '\nReturn only JSON matching this schema:\n' + json.dumps(schema)
                options = {'reasoning_effort': config['reasoning_effort']} if config['reasoning_effort'] else {}
                response = connection.chat.completions.create(
                    model=config['model'], messages=messages, response_format=response_format,
                    **{config['completion_token_parameter']: config['max_output_tokens']}, **options)
                if not response.choices or response.choices[0].finish_reason != 'stop':
                    raise ValueError('AI response was incomplete or refused')
                message = response.choices[0].message
                if message.refusal or not message.content:
                    raise ValueError('AI returned no assessment')
                assessment = Assessment.model_validate_json(message.content)
        assessment = validate_assessment(assessment, package, config,
                                         any(f['risk']['score'] is None for f in findings))
        result = {'available': True, 'cached': False, 'assessment': assessment.model_dump(),
                  'model': config['model'], 'prompt_name': task, 'prompt_version': prompt_version,
                  'timestamp': now(), 'evidence_supplied': package, 'cache_key': key,
                  'finding_ids': [f['id'] for f in findings], 'response_id': response.id,
                  'endpoint': config['base_url'], 'api': config['api'],
                  'usage': response.usage.model_dump() if response.usage else None,
                  'review_status': 'human_review_required',
                  'notice': 'Quotes and IDs are verified. AI interpretations require human review; citation validation cannot prove semantic correctness.'}
        return store.save_analysis(key, result)
    except (OpenAIError, ValidationError, ValueError) as error:
        LOGGER.warning(json.dumps({'event': 'ai_analysis_unavailable', 'error_type': type(error).__name__, 'cache_key': key}))
        return {'available': False, 'message': 'AI analysis unavailable. The detection result is unchanged.'}
