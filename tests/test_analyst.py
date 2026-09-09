import copy
import json

import httpx
import pytest
from openai import OpenAI

from backend.app.analyst import evidence_package, investigate
from backend.app.analyst_evaluation import evaluate
from backend.app.config import settings
from backend.app.detection import fuse
from backend.app.storage import Store


@pytest.fixture
def analyst(tmp_path, monkeypatch):
    monkeypatch.delenv('DATABASE_URL', raising=False)
    monkeypatch.setenv('OPENAI_API_KEY', 'must-not-leak-to-another-provider')
    configuration = settings()
    config = configuration['ai']['analyst']
    config.update(enabled=True, model='test-model', base_url='http://localhost:11434/v1', api_key_env=None)
    scores = {'ml': None, 'behaviour': None, 'context': None}
    risk = fuse(scores, configuration['risk'])
    finding = {'id': 'incomplete-engine', 'features': {}, 'risk': risk,
               'evidence': [{'id': 'engine-status', 'type': 'engine', 'data': {'scores': scores, 'risk': risk}}]}
    assessment = {
        'summary': [{'evidence_id': 'engine-status', 'quote': '"final_score": null',
                     'interpretation': 'No complete engine score is available.'}],
        'triage': 'needs_review', 'confidence': 0.0,
        'supporting_evidence': [], 'counter_evidence': [], 'risk': [],
        'recommended_actions': [], 'limitations': ['incomplete_engine', 'human_review_required'],
    }
    store = Store({'database_url': 'sqlite:///' + str(tmp_path / 'records.db')})
    return config, finding, assessment, store


@pytest.mark.parametrize('api,format_name', [
    ('chat_completions', 'json_schema'), ('chat_completions', 'json_object'), ('responses', 'json_schema'),
])
def test_provider_contracts_and_cache(analyst, monkeypatch, tmp_path, api, format_name):
    config, finding, assessment, store = analyst
    config.update(api=api, response_format=format_name, reasoning_effort='low')
    requests = []

    def respond(request):
        requests.append(request)
        body = json.loads(request.content)
        assert request.headers['authorization'] == 'Bearer local'
        assert body['model'] == config['model']
        if api == 'responses':
            assert request.url.path == '/v1/responses'
            assert body['store'] is False and body['reasoning'] == {'effort': 'low'}
            assert body['max_output_tokens'] == config['max_output_tokens']
            assert body['text']['format']['type'] == 'json_schema'
            result = {'id': 'response', 'object': 'response', 'created_at': 0, 'model': 'test-model',
                      'status': 'completed', 'output': [{'id': 'message', 'type': 'message', 'role': 'assistant',
                      'status': 'completed', 'content': [{'type': 'output_text', 'text': json.dumps(assessment),
                                                        'annotations': []}]}]}
        else:
            assert request.url.path == '/v1/chat/completions'
            assert body['response_format']['type'] == format_name
            assert body['max_tokens'] == config['max_output_tokens'] and body['reasoning_effort'] == 'low'
            if format_name == 'json_object':
                assert 'Return only JSON matching this schema' in body['messages'][0]['content']
            result = {'id': 'response', 'object': 'chat.completion', 'created': 0, 'model': 'test-model',
                      'choices': [{'index': 0, 'finish_reason': 'stop',
                                   'message': {'role': 'assistant', 'content': json.dumps(assessment)}}]}
        return httpx.Response(200, json=result)

    original = copy.deepcopy(finding)
    sdk = OpenAI

    def connect(**options):
        return sdk(**options, http_client=httpx.Client(transport=httpx.MockTransport(respond)))

    monkeypatch.setattr('backend.app.analyst.OpenAI', connect)
    result = investigate([finding], 'investigation', config, store)
    assert result['available'] and result['assessment'] == assessment
    assert finding == original
    assert investigate([finding], 'investigation', config, store)['cached']
    assert len(requests) == 1
    config['base_url'] = 'https://another-provider.example/v1'
    assert not investigate([finding], 'investigation', config, store)['cached']
    assert len(requests) == 2
    example_file = tmp_path / 'reviewed.jsonl'
    example_file.write_text(json.dumps({'task': 'investigation', 'reviewed_by': 'Contract test',
        'evidence': evidence_package([finding], config), 'assessment': assessment}))
    config['examples_file'] = str(example_file)
    with_examples = investigate([finding], 'investigation', config, store)
    assert with_examples['available'] and not with_examples['cached']
    assert with_examples['prompt_version'] != result['prompt_version']
    assert 'Reviewed examples' in requests[-1].content.decode()
    example_file.write_text(example_file.read_text().replace('No complete engine score is available.',
                                                           'The engine result is incomplete.'))
    revised = investigate([finding], 'investigation', config, store)
    assert revised['available'] and not revised['cached']
    assert revised['prompt_version'] != with_examples['prompt_version']


@pytest.mark.parametrize('failure', [
    'invalid_json', 'unknown_citation', 'unsupported_action', 'truncated', 'empty', 'incomplete_triage',
])
def test_bad_provider_output_never_changes_or_saves_assessment(analyst, failure):
    config, finding, assessment, store = analyst
    original = copy.deepcopy(finding)
    if failure == 'unknown_citation':
        assessment['summary'][0]['evidence_id'] = 'invented'
    if failure == 'unsupported_action':
        assessment['recommended_actions'] = ['Invented action']
    if failure == 'incomplete_triage':
        assessment['triage'] = 'high_priority'
    content = '{' if failure == 'invalid_json' else '' if failure == 'empty' else json.dumps(assessment)

    def respond(request):
        return httpx.Response(200, json={'id': 'bad-output', 'object': 'chat.completion', 'created': 0,
            'model': 'test-model', 'choices': [{'index': 0,
            'finish_reason': 'length' if failure == 'truncated' else 'stop',
            'message': {'role': 'assistant', 'content': content}}]})

    client = OpenAI(api_key='test', http_client=httpx.Client(transport=httpx.MockTransport(respond)))
    assert not investigate([finding], 'investigation', config, store, client=client)['available']
    assert store.latest_analysis(finding['id']) is None and finding == original


def test_reviewed_examples_and_held_out_evaluation(analyst, tmp_path):
    config, finding, assessment, store = analyst
    example = {'task': 'investigation', 'reviewed_by': 'Contract test',
               'evidence': evidence_package([finding], config), 'assessment': assessment}
    references, predictions, examples = [tmp_path / name for name in ('reference.jsonl', 'prediction.jsonl', 'examples.jsonl')]
    references.write_text(json.dumps({'case_id': 'a', **example}) + '\n' + json.dumps({'case_id': 'b', **example}))
    predictions.write_text(json.dumps({'case_id': 'a', 'assessment': assessment}))
    result = evaluate(references, predictions, config)
    assert result['cases'] == 2 and result['valid_assessments'] == 1
    assert result['triage_agreement'] == 0.5
    assert result['evidence_precision'] is None and result['evidence_recall'] is None
    examples.write_text(json.dumps(example))
    config['examples_file'] = str(examples)
    with pytest.raises(ValueError, match='held out'):
        evaluate(references, predictions, config)
    example['assessment']['summary'][0]['evidence_id'] = 'unreviewed-reference'
    examples.write_text(json.dumps(example))
    assert not investigate([finding], 'investigation', config, store)['available']
