"""Rebuild source-attributed TCP labels. Run from any directory; no network or malware execution."""
import json
import re
import subprocess
import sys
from pathlib import Path

import pandas as pd

APP = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(APP))

from backend.app.config import file_hash, fingerprint  # noqa: E402
from backend.app.data.capture import CONTRACT, EXTRACTION_VERSION, extract_flows  # noqa: E402
from backend.app.model import feature_frame  # noqa: E402

WORKSPACE = APP.parents[1]
OUTPUT = WORKSPACE / 'datasets/training'
LIMITS = {'max_packets': 5000000, 'max_flows': 200000, 'timeout_seconds': 240}
CTU_FILTER = 'tcp && ip.addr in {147.32.84.165,147.32.84.170,147.32.84.134,147.32.84.164}'


def extract(path, display_filter=None):
    sha = file_hash(path)
    if display_filter:
        count = subprocess.check_output(['capinfos', '-c', '-T', '-r', str(path)], text=True, timeout=60)
        if int(count.rstrip().rsplit('\t', 1)[1]) > LIMITS['max_packets']:
            raise ValueError('Filtered capture exceeds packet limit; partial extraction would invalidate labels')
    version = subprocess.check_output(['tshark', '--version'], text=True).splitlines()[0]
    key = fingerprint([sha, CONTRACT, EXTRACTION_VERSION, version, display_filter, LIMITS])
    cache = OUTPUT / f'{key}.csv'
    metadata = cache.with_suffix('.json')
    if cache.is_file() and metadata.is_file() and json.loads(metadata.read_text())['sha256'] == file_hash(cache):
        frame = pd.read_csv(cache)
    else:
        frame = extract_flows(path, LIMITS, display_filter)
        frame.to_csv(cache, index=False)
        metadata.write_text(json.dumps({'sha256': file_hash(cache), 'source_sha256': sha,
                                       'extractor': version, 'contract': CONTRACT, 'filter': display_filter}, indent=2))
    frame['capture_sha256'] = sha
    frame['source_path'] = str(path.relative_to(WORKSPACE))
    frame['label'] = pd.NA
    frame['label_basis'] = 'unknown; no supported attribution'
    frame['group'] = path.stem
    frame['split'] = 'excluded'
    return frame


def label_ctu(frame, labels):
    labels = labels.loc[labels.Proto.eq('tcp')].copy()
    labels['epoch'] = pd.to_datetime(labels.StartTime).dt.tz_localize('Europe/Prague').astype('int64') / 1e9
    labels['Sport'] = pd.to_numeric(labels.Sport, errors='coerce')
    labels['Dport'] = pd.to_numeric(labels.Dport, errors='coerce')
    grouped = {key: rows for key, rows in labels.groupby(['SrcAddr', 'Sport', 'DstAddr', 'Dport'])}
    supported = set(feature_frame(frame).index)
    for index, flow in frame.iterrows():
        if index not in supported:
            continue
        candidates = grouped.get((flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port))
        if candidates is None:
            continue
        matches = candidates.loc[(candidates.epoch - flow.timestamp).abs().lt(.005)
                                 & (candidates.Dur - flow.duration).abs().lt(.02)]
        if len(matches) != 1:
            continue
        label = matches.iloc[0].Label
        if re.match(r'^flow=From-Botnet-V46-TCP-CC\d+-', label):
            target, split, group = 1, 'train', 'ctu5-training-hosts'
        elif label.startswith('flow=From-Normal-') and flow.src_ip in {'147.32.84.134', '147.32.84.170', '147.32.84.164'}:
            target = 0
            split = 'test' if flow.src_ip == '147.32.84.164' else 'train'
            group = 'ctu5-normal-host-164' if split == 'test' else 'ctu5-training-hosts'
        else:
            continue
        frame.loc[index, ['label', 'split', 'group', 'label_basis']] = [target, split, group,
            f'CTU detailed label row {int(matches.index[0]) + 2}: {label}; exact directed tuple; start <5ms and duration <20ms; Europe/Prague time']
    return frame


def http_streams(path, expression, keylog=None):
    command = ['tshark', '-n', '-r', str(path)]
    if keylog:
        command += ['-o', f'tls.keylog_file:{keylog}']
    command += ['-Y', expression, '-T', 'fields', '-e', 'tcp.stream']
    return {int(value) for value in subprocess.check_output(command, text=True, timeout=120).split()}


def prepare():
    OUTPUT.mkdir(parents=True, exist_ok=True)
    ctu = WORKSPACE / 'datasets/ctu13-scenario5'
    frames = [label_ctu(extract(ctu / 'capture20110815-2.truncated.pcap', CTU_FILTER),
                        pd.read_csv(ctu / 'capture20110815-2.binetflow'))]
    for entry in json.loads((WORKSPACE / 'datasets/sliver/manifest.json').read_text())['captures']:
        path = WORKSPACE / entry['path']
        if file_hash(path) != entry['sha256']:
            raise ValueError(f'Source hash changed: {path}')
        frame = extract(path)
        endpoint = entry['candidate_endpoint']
        matches = ((frame.dst_ip.eq(endpoint['ip']) & frame.dst_port.eq(endpoint['port']))
                   | (frame.src_ip.eq(endpoint['ip']) & frame.src_port.eq(endpoint['port'])))
        frame.loc[matches & frame.protocol.eq('tcp'), ['label', 'label_basis']] = [1, f"Publisher-attributed TCP endpoint {endpoint['ip']}:{endpoint['port']}; {entry['source_page']}"]
        frames.append(frame)
    for name, host, uri in [('acbackdoor', '193.29.15.147', '/'), ('backstage', 'www.wdsfw34erf93.com', '/index.php/api/fb')]:
        path = WORKSPACE / f'c2db/pcaps/{name}.pcap'
        keylog = path.with_suffix('.txt') if name == 'acbackdoor' else None
        streams = http_streams(path, f'http.request.method == "POST" && http.host == "{host}" && http.request.uri == "{uri}"', keylog)
        frame = extract(path)
        frame.loc[frame.protocol.eq('tcp') & frame.stream_id.astype(int).isin(streams), ['label', 'label_basis']] = [1,
            f'c2db/README.md {name}: matching POST host/path in TCP stream' + ('; supplied lab TLS keylog' if keylog else '')]
        frames.append(frame)
    for frame in frames[1:]:
        supported = frame.index.isin(feature_frame(frame).index)
        frame.loc[frame.label.notna() & supported, 'split'] = 'test'
    all_flows = pd.concat(frames, ignore_index=True)
    selected = all_flows.loc[all_flows.split.isin(['train', 'test'])].copy()
    selected['label'] = selected.label.astype(int)
    selected.to_csv(OUTPUT / 'labelled-flows.csv', index=False)
    all_flows.to_csv(OUTPUT / 'label-audit.csv', index=False)
    report = {'contract': CONTRACT, 'curator': 'Codex automated source-attribution review',
              'labelled_flows_sha256': file_hash(OUTPUT / 'labelled-flows.csv'),
              'sources': all_flows[['source_path', 'capture_sha256']].drop_duplicates().to_dict('records'),
              'label_sources': {str(path.relative_to(WORKSPACE)): file_hash(path) for path in [
                  ctu / 'capture20110815-2.binetflow', WORKSPACE / 'c2db/README.md',
                  WORKSPACE / 'c2db/pcaps/acbackdoor.txt', WORKSPACE / 'datasets/sliver/manifest.json']},
              'split_counts': selected.groupby(['group', 'split', 'label']).size().reset_index(name='count').to_dict('records'),
              'extracted_tcp_flows': len(all_flows), 'excluded_flows': int(all_flows.split.eq('excluded').sum()),
              'limitations': ['Background and non-C2 botnet flows are excluded, never labelled benign.',
                  'Only unique CTU tuple/start/duration matches are labelled; unmatched streams stay unknown.',
                  'CTU normal-host test is host-disjoint but shares the training capture.',
                  'All c2db and Sliver incidents are held out; their labels are source-attributed.',
                  'No threshold tuning on held-out captures. No pooled deployment accuracy claim.']}
    (OUTPUT / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    prepare()
