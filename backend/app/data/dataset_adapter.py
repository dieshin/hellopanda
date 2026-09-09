import csv
import json
import warnings

import pandas as pd


class DatasetAdapter:
    def __init__(self, app_config, dataset_config):
        self.app = app_config
        self.dataset = dataset_config

    def read(self, path, format_name):
        if format_name == 'capture':
            raise ValueError('Packet capture stored. Flow extraction requires inspection of your capture format; no flows were invented.')
        limit = self.app['max_rows'] + 1
        if format_name == 'jsonl':
            records = []
            with path.open(encoding='utf-8-sig') as handle:
                for line in handle:
                    if not line.strip():
                        continue
                    record = json.loads(line)
                    if not isinstance(record, dict) or any(isinstance(v, (dict, list)) for v in record.values()):
                        raise ValueError('Only flat JSON objects are supported; export structured flow metadata first')
                    records.append(record)
                    if len(records) >= limit:
                        break
            frame = pd.DataFrame(records)
        elif format_name in ('csv', 'tsv', 'zeek'):
            separator = ',' if format_name == 'csv' else '\t'
            header = None
            types = None
            if format_name == 'zeek':
                with path.open(encoding='utf-8-sig') as handle:
                    for line in handle:
                        if line.startswith('#separator '):
                            separator = bytes(line.split(' ', 1)[1].strip(), 'ascii').decode('unicode_escape')
                        elif line.startswith('#fields' + separator):
                            header = line.rstrip('\r\n').split(separator)[1:]
                        elif line.startswith('#types' + separator):
                            types = line.rstrip('\r\n').split(separator)[1:]
                        elif not line.startswith('#'):
                            break
                if not header or not types or len(header) != len(types):
                    raise ValueError('Zeek ASCII logs require valid #fields and #types headers; JSON logs should use .jsonl')
            else:
                with path.open(encoding='utf-8-sig', newline='') as handle:
                    header = next(csv.reader(handle, delimiter=separator), [])
            if not header or len(header) != len(set(header)) or any(not x.strip() for x in header):
                raise ValueError('Column names must be nonempty and unique')
            if len(header) > self.app['max_columns']:
                raise ValueError('Dataset exceeds configured column limit')
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter('error', pd.errors.ParserWarning)
                    frame = pd.read_csv(path, sep=separator, comment='#' if format_name == 'zeek' else None,
                                        names=header if format_name == 'zeek' else None, nrows=limit,
                                        dtype='string', keep_default_na=False, na_values=self.dataset['null_tokens'],
                                        encoding='utf-8-sig', index_col=False)
            except (pd.errors.ParserWarning, pd.errors.ParserError, pd.errors.EmptyDataError) as error:
                raise ValueError('The file has inconsistent tabular structure; check its delimiter, header, and record widths') from error
        else:
            raise ValueError('Unsupported adapter format')
        if frame.empty:
            raise ValueError('The supplied file contains no records')
        if len(frame) > self.app['max_rows'] or len(frame.columns) > self.app['max_columns']:
            raise ValueError('Dataset exceeds configured inspection limits; split the file or adjust config/app.yaml')
        return frame.replace(self.dataset['null_tokens'], pd.NA)

    def map(self, frame, mapping):
        if not mapping:
            raise ValueError('Confirm at least one field mapping before analysis')
        missing = set(mapping.values()) - set(frame.columns)
        if missing:
            raise ValueError(f'Mapped source columns are missing: {sorted(missing)}')
        if len(set(mapping.values())) != len(mapping):
            raise ValueError('Each source column may be mapped only once')
        if any(not key or not key.isidentifier() for key in mapping):
            raise ValueError('Canonical field names must be valid identifiers')
        return frame[list(mapping.values())].rename(columns={source: target for target, source in mapping.items()})
