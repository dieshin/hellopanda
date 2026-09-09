import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from .config import project_path


def now():
    return datetime.now(timezone.utc).isoformat()


class Store:
    def __init__(self, config):
        url = os.getenv('DATABASE_URL') or config['database_url']
        prefix = 'sqlite:///'
        if not url.startswith(prefix):
            raise ValueError('This local application currently supports sqlite:/// DATABASE_URL only')
        self.path = project_path(url[len(prefix):])
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as connection:
            connection.executescript('''
                CREATE TABLE IF NOT EXISTS records (
                    kind TEXT NOT NULL, id TEXT NOT NULL, created_at TEXT NOT NULL,
                    data TEXT NOT NULL, PRIMARY KEY(kind, id));
                CREATE INDEX IF NOT EXISTS record_time ON records(kind, created_at);
                CREATE INDEX IF NOT EXISTS endpoint_tuple_time ON records(
                    json_extract(data, '$.src_ip'), json_extract(data, '$.dst_ip'),
                    json_extract(data, '$.src_port'), json_extract(data, '$.dst_port'),
                    json_extract(data, '$.protocol'), json_extract(data, '$.epoch')) WHERE kind='endpoint';
                CREATE TABLE IF NOT EXISTS ai_analysis (
                    cache_key TEXT PRIMARY KEY, created_at TEXT NOT NULL, data TEXT NOT NULL);
            ''')

    @contextmanager
    def connect(self):
        connection = sqlite3.connect(self.path)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def save(self, kind, data, identifier=None):
        record = {**data, 'id': identifier or uuid4().hex, 'created_at': now()}
        with self.connect() as connection:
            connection.execute('INSERT INTO records VALUES (?, ?, ?, ?)',
                               (kind, record['id'], record['created_at'], json.dumps(record, allow_nan=False)))
        return record

    def get(self, kind, identifier):
        with self.connect() as connection:
            row = connection.execute('SELECT data FROM records WHERE kind=? AND id=?', (kind, identifier)).fetchone()
        if not row:
            raise KeyError('Record not found')
        return json.loads(row[0])

    def save_batch(self, kind, records):
        with self.connect() as connection:
            for identifier, data in records:
                existing = connection.execute('SELECT data FROM records WHERE kind=? AND id=?', (kind, identifier)).fetchone()
                if existing:
                    old = json.loads(existing[0])
                    if {key: value for key, value in old.items() if key not in ('id', 'created_at')} != data:
                        raise ValueError('An existing event ID has different data; send a new event ID for corrections')
                    continue
                record = {**data, 'id': identifier, 'created_at': now()}
                connection.execute('INSERT INTO records VALUES (?, ?, ?, ?)',
                                   (kind, identifier, record['created_at'], json.dumps(record, allow_nan=False)))
        return [identifier for identifier, _ in records]

    def list(self, kind, limit, offset=0):
        with self.connect() as connection:
            rows = connection.execute('SELECT data FROM records WHERE kind=? ORDER BY created_at DESC LIMIT ? OFFSET ?',
                                      (kind, limit, offset)).fetchall()
        return [json.loads(row[0]) for row in rows]

    def count(self, kind):
        with self.connect() as connection:
            return connection.execute('SELECT COUNT(*) FROM records WHERE kind=?', (kind,)).fetchone()[0]

    def findings(self, limit, offset, source='', destination='', protocol='', severity=''):
        where, parameters = ["kind='finding'"], []
        for field, value in [('features.src_ip', source), ('features.dst_ip', destination),
                             ('features.protocol', protocol), ('risk.level', severity)]:
            if value:
                where.append('json_extract(data, ?)=?')
                parameters.extend(['$.' + field, value])
        clause = ' AND '.join(where)
        with self.connect() as connection:
            total = connection.execute('SELECT COUNT(*) FROM records WHERE ' + clause, parameters).fetchone()[0]
            rows = connection.execute('SELECT data FROM records WHERE ' + clause +
                " ORDER BY json_extract(data, '$.risk.score') DESC, json_extract(data, '$.ml_score') DESC, created_at DESC LIMIT ? OFFSET ?",
                [*parameters, limit, offset]).fetchall()
        return [json.loads(row[0]) for row in rows], total

    def cached(self, key):
        with self.connect() as connection:
            row = connection.execute('SELECT data FROM ai_analysis WHERE cache_key=?', (key,)).fetchone()
        return json.loads(row[0]) if row else None

    def observation(self, key, max_age):
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=max_age)).isoformat()
        with self.connect() as connection:
            row = connection.execute("SELECT data FROM records WHERE kind='observation' AND json_extract(data, '$.cache_key')=? AND created_at>=? ORDER BY created_at DESC LIMIT 1", (key, cutoff)).fetchone()
        return json.loads(row[0]) if row else None

    def endpoint_matches(self, key, start, end, limit):
        with self.connect() as connection:
            rows = connection.execute("""SELECT data FROM records WHERE kind='endpoint'
                AND json_extract(data, '$.src_ip')=? AND json_extract(data, '$.dst_ip')=?
                AND json_extract(data, '$.src_port')=? AND json_extract(data, '$.dst_port')=?
                AND json_extract(data, '$.protocol')=? AND json_extract(data, '$.epoch') BETWEEN ? AND ?
                ORDER BY created_at DESC LIMIT ?""", [*key, start, end, limit]).fetchall()
        return [json.loads(row[0]) for row in rows]

    def confirmations(self, dataset_id, limit):
        with self.connect() as connection:
            rows = connection.execute("SELECT data FROM records WHERE kind='confirmation' AND json_extract(data, '$.dataset_id')=? ORDER BY created_at DESC LIMIT ?",
                                      (dataset_id, limit)).fetchall()
        return [json.loads(row[0]) for row in rows]

    def related(self, dataset_id, record_numbers, limit, configuration_version):
        if not record_numbers:
            return []
        placeholders = ','.join('?' for _ in record_numbers)
        with self.connect() as connection:
            rows = connection.execute(f"SELECT data FROM records WHERE kind='finding' AND json_extract(data, '$.dataset_id')=? AND json_extract(data, '$.configuration_version')=? AND json_extract(data, '$.raw_reference.record_number') IN ({placeholders}) ORDER BY created_at DESC LIMIT ?",
                                      (dataset_id, configuration_version, *record_numbers, limit)).fetchall()
        return [json.loads(row[0]) for row in rows]

    def analysis_run(self, key, records):
        with self.connect() as connection:
            connection.execute('BEGIN IMMEDIATE')
            existing = connection.execute("SELECT data FROM records WHERE kind='run' AND id=?", (key,)).fetchone()
            if existing:
                return json.loads(existing[0]), True
            identifiers = []
            for data in records:
                record = {**data, 'id': uuid4().hex, 'created_at': now()}
                connection.execute('INSERT INTO records VALUES (?, ?, ?, ?)',
                                   ('finding', record['id'], record['created_at'], json.dumps(record, allow_nan=False)))
                identifiers.append(record['id'])
            run = {'id': key, 'created_at': now(), 'finding_ids': identifiers}
            connection.execute('INSERT INTO records VALUES (?, ?, ?, ?)', ('run', key, run['created_at'], json.dumps(run)))
            return run, False

    def save_analysis(self, key, analysis):
        with self.connect() as connection:
            connection.execute('INSERT OR IGNORE INTO ai_analysis VALUES (?, ?, ?)', (key, now(), json.dumps(analysis)))
        return self.cached(key)

    def latest_analysis(self, finding_id):
        with self.connect() as connection:
            row = connection.execute("SELECT data FROM ai_analysis WHERE EXISTS (SELECT 1 FROM json_each(ai_analysis.data, '$.finding_ids') WHERE value=?) ORDER BY created_at DESC LIMIT 1",
                                     (finding_id,)).fetchone()
        return {**json.loads(row[0]), 'cached': True} if row else None
