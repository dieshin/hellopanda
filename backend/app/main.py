import hashlib
import json
import logging
from pathlib import Path
from uuid import uuid4

import httpx
from fastapi import BackgroundTasks, Depends, FastAPI, File, HTTPException, Query, Request, UploadFile
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .access import authorize
from .analyst import availability, investigate
from .config import ROOT, file_hash, fingerprint, project_path, settings
from .context import enrich, refresh_ranges
from .data.capture import EXTRACTION_VERSION, extract_flows
from .data.dataset_adapter import DatasetAdapter
from .data.schema_detector import confirm_schema, inspect_schema
from .detection import analyse
from .integrations import EndpointBatch, capture_network, correlate, export_event, send_siem
from .model import model_status, predict, train_model
from .storage import Store

LOGGER = logging.getLogger(__name__)
app = FastAPI(title='Hello Panda', version='0.1.0', docs_url=None, redoc_url=None)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings()['app']['app']['allowed_hosts'])


def resources():
    config = settings()
    return config, Store(config['app']['app'])


@app.middleware('http')
async def request_policy(request: Request, call_next):
    if request.url.path.startswith('/api/'):
        try:
            request.state.identity = authorize(request, settings()['integrations']['auth'])
        except HTTPException as error:
            return JSONResponse({'detail': error.detail}, status_code=error.status_code, headers=error.headers)
    if request.method not in ('GET', 'HEAD', 'OPTIONS'):
        origin = request.headers.get('origin')
        if origin and origin != str(request.base_url).rstrip('/'):
            return JSONResponse({'detail': 'Cross-origin writes are disabled.'}, status_code=403)
        if request.url.path in ('/api/datasets', '/api/endpoint-events'):
            length = request.headers.get('content-length')
            if length is None:
                return JSONResponse({'detail': 'An upload Content-Length is required.'}, status_code=411)
            try:
                size = int(length)
            except ValueError:
                return JSONResponse({'detail': 'Invalid upload length.'}, status_code=400)
            limit = settings()['app']['app']['max_upload_bytes']
            if size < 0 or size > limit:
                return JSONResponse({'detail': 'Upload exceeds the configured request size limit.'}, status_code=413)
    response = await call_next(request)
    if request.url.path.startswith('/api/') and request.method not in ('GET', 'HEAD', 'OPTIONS'):
        config, store = resources()
        store.save('access_audit', {'actor': request.state.identity['name'], 'role': request.state.identity['role'],
                                  'method': request.method, 'path': request.url.path, 'status': response.status_code})
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    response.headers['Cache-Control'] = 'no-store'
    return response


@app.exception_handler(ValueError)
async def invalid_request(request, error):
    return JSONResponse({'detail': str(error)}, status_code=422)


@app.exception_handler(KeyError)
async def missing_record(request, error):
    return JSONResponse({'detail': 'The requested record does not exist.'}, status_code=404)


@app.exception_handler(httpx.HTTPError)
async def unavailable_service(request, error):
    return JSONResponse({'detail': 'External service unavailable; existing evidence was preserved.'}, status_code=502)


@app.get('/api/status')
def status(state=Depends(resources)):
    config, store = state
    return {'app': config['app']['app']['name'], 'datasets': store.count('dataset'), 'findings': store.count('finding'),
            'ai': availability(config['ai']['analyst']), 'model': model_status(store),
            'configuration_version': fingerprint(config), 'risk_enabled': config['risk']['risk']['enabled'],
            'risk_levels': [level['name'] for level in config['risk']['risk']['levels']] + ['unavailable'],
            'formats': config['app']['app']['formats'], 'max_upload_bytes': config['app']['app']['max_upload_bytes'],
            'page_size': config['app']['app']['page_size'],
            'integrations': {'auth_enabled': config['integrations']['auth']['enabled'],
                'live_capture': config['integrations']['live_capture'],
                'siem_enabled': config['integrations']['siem']['enabled'],
                'hosting_enabled': config['providers']['hosting']['enabled'],
                'intel_enabled': config['providers']['threat_intelligence']['enabled'],
                'endpoint_events': store.count('endpoint')}}


@app.get('/api/session')
def session(request: Request):
    return request.state.identity


@app.post('/api/context/refresh')
def refresh_context(state=Depends(resources)):
    record = refresh_ranges(state[0]['providers']['hosting'], state[1])
    return {'id': record['id'], 'ranges': len(record['entries']), 'observed_at': record['observed_at']}


class CaptureRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    interface: str = Field(min_length=1, max_length=256)
    seconds: int = Field(ge=1)


@app.post('/api/capture', status_code=201)
def live_capture(payload: CaptureRequest, background_tasks: BackgroundTasks, state=Depends(resources)):
    config, store = state
    directory = project_path(config['app']['app']['upload_directory'])
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / (uuid4().hex + '.pcapng')
    try:
        capture_network(path, payload.interface, payload.seconds, config['integrations']['live_capture'])
        record = inspect_upload(path, f'capture-{payload.interface}.pcapng', file_hash(path), path.stat().st_size,
                                'capture', config, store)
    except Exception:
        path.unlink(missing_ok=True)
        path.with_suffix('.flows.csv').unlink(missing_ok=True)
        raise
    confirmation = store.confirmations(record['id'], 1)[0]
    result = analyse_dataset(confirmation['id'], background_tasks, state)
    return {'dataset': record, 'analysis': result}


@app.post('/api/endpoint-events', status_code=201)
def endpoint_events(payload: EndpointBatch, request: Request, state=Depends(resources)):
    config, store = state
    if len(payload.events) > config['integrations']['endpoint']['max_events']:
        raise ValueError('Endpoint batch exceeds the configured event limit')
    records = []
    for event in payload.events:
        data = {**event.model_dump(mode='json'), 'epoch': event.timestamp.timestamp(),
                'sensor_identity': request.state.identity['name']}
        identifier = fingerprint([data['sensor_identity'], event.source, event.host, event.event_id])
        records.append((identifier, data))
    return {'event_ids': store.save_batch('endpoint', records), 'message': 'Events saved; reanalyse a capture to correlate them.'}


class FindingSelection(BaseModel):
    model_config = ConfigDict(extra='forbid')
    finding_ids: list[str] = Field(min_length=1, max_length=100)


@app.post('/api/exports')
def export_findings(payload: FindingSelection, state=Depends(resources)):
    events = [export_event(state[1].get('finding', identifier)) for identifier in dict.fromkeys(payload.finding_ids)]
    return Response('\n'.join(json.dumps(event) for event in events) + '\n', media_type='application/x-ndjson',
                    headers={'Content-Disposition': 'attachment; filename="network-evidence.ndjson"'})


@app.post('/api/siem/send')
def forward_findings(payload: FindingSelection, state=Depends(resources)):
    config, store = state
    selected = [store.get('finding', identifier) for identifier in dict.fromkeys(payload.finding_ids)]
    result = send_siem(selected, config['integrations']['siem'])
    return store.save('delivery', {**result, 'finding_ids': [item['id'] for item in selected]})


@app.get('/api/config')
def configuration(state=Depends(resources)):
    return state[0]


@app.get('/api/datasets')
def datasets(offset: int = Query(0, ge=0), state=Depends(resources)):
    config, store = state
    return {'items': store.list('dataset', config['app']['app']['page_size'], offset), 'total': store.count('dataset')}


def inspect_upload(path, name, digest, size, format_name, config, store):
    extracted = None
    if format_name == 'capture':
        frame = extract_flows(path, config['model']['capture'])
        extracted = path.with_suffix('.flows.csv')
        frame.to_csv(extracted, index=False)
        inspection = inspect_schema(frame, config['app']['app'], config['dataset']['dataset'])
        status_name, message = 'ready', 'TCP/UDP streams and visible DNS/QUIC metadata extracted. ML applies only to eligible TCP streams.'
    else:
        try:
            adapter = DatasetAdapter(config['app']['app'], config['dataset']['dataset'])
            frame = adapter.read(path, format_name)
            inspection = inspect_schema(frame, config['app']['app'], config['dataset']['dataset'])
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ValueError('File must be valid UTF-8 in the selected format') from error
        status_name, message = 'needs_confirmation', 'Inspect fields and confirm the meaning of these records.'
    record = store.save('dataset', {'filename': name, 'path': str(path), 'sha256': digest, 'size_bytes': size,
                      'format': format_name, 'status': status_name, 'message': message, 'inspection': inspection,
                      'extracted_path': str(extracted) if extracted else None,
                      'extracted_sha256': file_hash(extracted) if extracted else None,
                      'feature_contract': EXTRACTION_VERSION if extracted else None,
                      'import_configuration': config['dataset']['dataset']})
    if extracted:
        mapping = Mapping(field_mapping={name: name for name in frame.columns}, flow_records_confirmed=True,
                          assumptions=[EXTRACTION_VERSION, 'First-observed direction; wire bytes include link headers and retransmissions.'])
        store.save('confirmation', {'dataset_id': record['id'], 'mapping': mapping.model_dump(),
                   **confirm_schema(frame, mapping.model_dump(), config['features']),
                   'configuration_version': fingerprint(config['features'])})
    return record


@app.post('/api/datasets', status_code=201)
async def upload(file: UploadFile = File(...), state=Depends(resources)):
    config, store = state
    app_config = config['app']['app']
    name = Path((file.filename or '').replace('\\', '/')).name
    extension = Path(name).suffix.lower()
    if extension not in app_config['formats']:
        raise HTTPException(415, 'Unsupported file extension; see the import format list.')
    directory = project_path(app_config['upload_directory'])
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / (uuid4().hex + extension)
    size, digest = 0, hashlib.sha256()
    try:
        with path.open('xb') as handle:
            while chunk := await file.read(app_config['upload_chunk_bytes']):
                size += len(chunk)
                if size > app_config['max_upload_bytes']:
                    raise HTTPException(413, 'File exceeds the configured upload limit.')
                digest.update(chunk)
                await run_in_threadpool(handle.write, chunk)
        if not size:
            raise ValueError('The supplied file is empty')
        return await run_in_threadpool(inspect_upload, path, name, digest.hexdigest(), size,
                                      app_config['formats'][extension], config, store)
    except Exception:
        path.unlink(missing_ok=True)
        path.with_suffix('.flows.csv').unlink(missing_ok=True)
        raise
    finally:
        await file.close()


@app.get('/api/datasets/{identifier}')
def dataset(identifier: str, state=Depends(resources)):
    return state[1].get('dataset', identifier)


@app.get('/api/datasets/{identifier}/confirmations')
def confirmations(identifier: str, state=Depends(resources)):
    config, store = state
    store.get('dataset', identifier)
    return store.confirmations(identifier, config['app']['app']['page_size'])


class Mapping(BaseModel):
    model_config = ConfigDict(extra='forbid')
    field_mapping: dict[str, str]
    label_column: str | None = None
    positive_labels: list[str] = Field(default_factory=list)
    negative_labels: list[str] = Field(default_factory=list)
    flow_records_confirmed: bool = False
    assumptions: list[str] = Field(default_factory=list)


def read_dataset(dataset, config):
    path = Path(dataset['path'])
    if not path.is_file():
        raise ValueError('Original dataset is missing; reimport the file')
    if file_hash(path) != dataset['sha256']:
        raise ValueError('Original file has changed; reimport it to preserve evidence provenance')
    adapter = DatasetAdapter(config['app']['app'], dataset['import_configuration'])
    if dataset['format'] == 'capture':
        extracted = Path(dataset['extracted_path'])
        if not extracted.is_file() or file_hash(extracted) != dataset['extracted_sha256']:
            raise ValueError('Extracted flow evidence changed; reimport the capture')
        return adapter, adapter.read(extracted, 'csv')
    return adapter, adapter.read(path, dataset['format'])


@app.post('/api/datasets/{identifier}/confirm', status_code=201)
def confirm(identifier: str, mapping: Mapping, state=Depends(resources)):
    config, store = state
    dataset = store.get('dataset', identifier)
    adapter, frame = read_dataset(dataset, config)
    adapter.map(frame, mapping.field_mapping)
    validation = confirm_schema(frame, mapping.model_dump(), config['features'])
    return store.save('confirmation', {'dataset_id': identifier, 'mapping': mapping.model_dump(), **validation,
                      'configuration_version': fingerprint(config['features'])})


def automatic_analysis(identifiers, config, store):
    policy = config['ai']['analyst']['automatic_analysis']
    if not policy['enabled'] or not availability(config['ai']['analyst'])['available']:
        return
    levels = [level['name'] for level in config['risk']['risk']['levels']]
    minimum = levels.index(policy['minimum_risk_level'])
    for identifier in identifiers:
        finding = store.get('finding', identifier)
        if finding['risk']['score'] is not None and levels.index(finding['risk']['level']) >= minimum:
            investigate(related_findings(finding, config, store), 'investigation', config['ai']['analyst'], store)


@app.post('/api/confirmations/{identifier}/analyse')
def analyse_dataset(identifier: str, background_tasks: BackgroundTasks, state=Depends(resources)):
    config, store = state
    confirmation = store.get('confirmation', identifier)
    mapping = confirmation['mapping']
    if not mapping['flow_records_confirmed']:
        raise ValueError('Confirm that rows represent extracted flows before behaviour analysis')
    dataset = store.get('dataset', confirmation['dataset_id'])
    adapter, raw = read_dataset(dataset, config)
    frame = adapter.map(raw, mapping['field_mapping'])

    def baseline_loader(confirmation_id):
        baseline_confirmation = store.get('confirmation', confirmation_id)
        baseline_mapping = baseline_confirmation['mapping']
        if not baseline_mapping['flow_records_confirmed'] or not baseline_mapping['label_column'] or not baseline_mapping['negative_labels']:
            raise ValueError('Baseline requires a confirmed flow dataset with explicit benign labels')
        source = store.get('dataset', baseline_confirmation['dataset_id'])
        baseline_adapter, baseline_raw = read_dataset(source, config)
        benign = baseline_raw[baseline_mapping['label_column']].astype(str).isin(baseline_mapping['negative_labels'])
        return baseline_adapter.map(baseline_raw.loc[benign], baseline_mapping['field_mapping'])

    model_record = model_status(store)
    predictions = predict(frame, model_record)
    contextual = enrich(frame, config['providers'], store)
    endpoint_context = correlate(frame, store, config['integrations']['endpoint'])
    run, reused = store.analysis_run(fingerprint([dataset['sha256'], confirmation, config, model_record.get('version'), contextual, endpoint_context]),
                                     analyse(frame, dataset, confirmation, config, baseline_loader, predictions, model_record, contextual, endpoint_context))
    identifiers = run['finding_ids']
    background_tasks.add_task(automatic_analysis, identifiers, config, store)
    return {'processed_records': len(frame), 'measured_findings': len(identifiers), 'unmeasured_records': len(frame) - len(identifiers),
            'ml_status': model_record['status'], 'ml_scored_records': len(predictions), 'reused': reused,
            'message': 'Evidence saved. ML scores are experimental; missing risk components remain unknown.'}


@app.get('/api/findings')
def findings(offset: int = Query(0, ge=0), source: str = '', destination: str = '', protocol: str = '',
             severity: str = '', state=Depends(resources)):
    config, store = state
    items, total = store.findings(config['app']['app']['page_size'], offset, source, destination, protocol, severity)
    return {'items': [{key: value for key, value in item.items() if key != 'configuration'} for item in items],
            'total': total}


@app.get('/api/findings/{identifier}')
def finding(identifier: str, state=Depends(resources)):
    return state[1].get('finding', identifier)


@app.post('/api/findings/{identifier}/investigate')
def investigate_finding(identifier: str, task: str = 'investigation', state=Depends(resources)):
    config, store = state
    finding = store.get('finding', identifier)
    return investigate(related_findings(finding, config, store), task, config['ai']['analyst'], store)


@app.get('/api/findings/{identifier}/analysis')
def saved_analysis(identifier: str, state=Depends(resources)):
    state[1].get('finding', identifier)
    return state[1].latest_analysis(identifier)


def related_findings(finding, config, store):
    maximum = config['ai']['analyst']['max_related_findings']
    group = set()
    for item in finding['evidence']:
        if item['type'] == 'behaviour' and item['data']['detector'] == 'periodicity':
            group.update(item['data']['measurements']['related_record_numbers'])
    related = store.related(finding['dataset_id'], sorted(group)[:maximum], maximum, finding['configuration_version'])
    return [finding] + [item for item in related if item['id'] != finding['id']][:max(0, maximum - 1)]


@app.post('/api/train')
def train(state=Depends(resources)):
    return train_model(*state)


app.mount('/', StaticFiles(directory=ROOT / 'frontend', html=True), name='dashboard')
