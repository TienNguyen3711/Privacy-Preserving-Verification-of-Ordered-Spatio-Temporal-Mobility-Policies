"""Independent wallet head ledger (authenticated HTTP, SQLite CAS).

Deploy behind a trusted HTTPS terminator on a separately administered host.
The builtin server binds loopback only; raw HTTP is for local integration or
a TLS reverse proxy on that host. No reset/delete/re-register API exists.
The ledger and bearer token must NOT be copied/restored with client wallets.
"""
import argparse
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import sqlite3


def connect(path):
    # Never silently create a missing ledger after initialisation.
    con = sqlite3.connect(path.resolve().as_uri() + '?mode=rw', uri=True, timeout=15)
    con.execute('PRAGMA synchronous=FULL')
    return con


def head(value):
    if not isinstance(value, dict) or set(value) != {'wallet_id', 'revision', 'tip'}:
        raise ValueError('invalid head')
    for field in ('wallet_id', 'tip'):
        s = value[field]
        if not isinstance(s, str) or len(s) != 64 or any(c not in '0123456789abcdef' for c in s):
            raise ValueError('invalid digest')
    if type(value['revision']) is not int or not 0 <= value['revision'] < 2**63:
        raise ValueError('invalid revision')
    return value


def initialize(directory):
    directory.mkdir(mode=0o700)  # existing directory is an error, never reset
    db = directory/'ledger.sqlite'
    with sqlite3.connect(db) as con:
        con.execute('PRAGMA journal_mode=WAL')
        con.execute('PRAGMA synchronous=FULL')
        con.execute('CREATE TABLE heads(wallet_id TEXT PRIMARY KEY, revision INTEGER NOT NULL, tip TEXT NOT NULL)')
        con.execute('CREATE TABLE events(wallet_id TEXT, revision INTEGER, tip TEXT, PRIMARY KEY(wallet_id,revision))')
        con.execute('PRAGMA user_version=1')
    os.chmod(db, 0o600)
    for path in (directory, directory.parent):
        fd = os.open(path, os.O_RDONLY)
        try: os.fsync(fd)
        finally: os.close(fd)


def serve(directory, token_file, port):
    if token_file.stat().st_mode & 0o077:
        raise ValueError('bearer token file must be private (0600)')
    token = token_file.read_bytes()
    if len(token) != 32:
        raise ValueError('token file must contain 32 random bytes')
    auth = 'Bearer ' + token.hex()
    db = directory/'ledger.sqlite'
    with connect(db) as con:
        if con.execute('PRAGMA user_version').fetchone()[0] != 1:
            raise ValueError('unsupported ledger schema')

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass  # never log bearer credentials or wallet metadata by default

        def reply(self, code, body):
            data = json.dumps(body).encode()
            self.send_response(code)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def allowed(self):
            if not hmac.compare_digest(self.headers.get('Authorization', ''), auth):
                self.reply(401, {'error': 'unauthorized'})
                return False
            return True

        def do_GET(self):
            if not self.allowed(): return
            if not self.path.startswith('/head/'):
                self.reply(404, {'error': 'not found'}); return
            wallet_id = self.path[len('/head/'):]
            try:
                head(dict(wallet_id=wallet_id, revision=0, tip='0'*64))
                with connect(db) as con:
                    row = con.execute('SELECT revision,tip FROM heads WHERE wallet_id=?', (wallet_id,)).fetchone()
                self.reply(200 if row else 404, dict(wallet_id=wallet_id, revision=row[0], tip=row[1]) if row else {'error':'unregistered'})
            except (ValueError, sqlite3.Error):
                self.reply(400, {'error': 'invalid request or unavailable ledger'})

        def do_POST(self):
            if not self.allowed(): return
            try:
                length = int(self.headers.get('Content-Length', '-1'))
                if not 0 < length <= 4096: raise ValueError('invalid length')
                body = json.loads(self.rfile.read(length))
                if self.path == '/register':
                    new = head(body)
                    if new['revision'] != 0: raise ValueError('initial revision must be zero')
                    old = None
                elif self.path == '/advance':
                    old, new = head(body['old']), head(body['new'])
                    if new['wallet_id'] != old['wallet_id'] or new['revision'] != old['revision'] + 1:
                        raise ValueError('invalid transition')
                else:
                    self.reply(404, {'error':'not found'}); return
                with connect(db) as con:
                    con.execute('BEGIN IMMEDIATE')
                    current = con.execute('SELECT revision,tip FROM heads WHERE wallet_id=?', (new['wallet_id'],)).fetchone()
                    if old is None:
                        if current is not None:
                            self.reply(409, {'error':'wallet already enrolled'}); return
                        con.execute('INSERT INTO heads VALUES(?,?,?)', (new['wallet_id'], 0, new['tip']))
                    else:
                        if current == (new['revision'], new['tip']):
                            self.reply(200, new); return  # idempotent lost-response recovery
                        if current != (old['revision'], old['tip']):
                            self.reply(409, {'error':'stale wallet version'}); return
                        con.execute('UPDATE heads SET revision=?,tip=? WHERE wallet_id=?', (new['revision'], new['tip'], new['wallet_id']))
                    con.execute('INSERT INTO events VALUES(?,?,?)', (new['wallet_id'], new['revision'], new['tip']))
                    con.commit()  # durable commit BEFORE acknowledging
                self.reply(200, new)
            except (ValueError, KeyError, TypeError, sqlite3.Error):
                self.reply(400, {'error':'invalid request or unavailable ledger'})

    server = ThreadingHTTPServer(('127.0.0.1', port), Handler)
    print(json.dumps({'port': server.server_port}), flush=True)
    server.serve_forever()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state-dir', type=Path, required=True)
    parser.add_argument('--init', action='store_true')
    parser.add_argument('--token-file', type=Path)
    parser.add_argument('--port', type=int, default=8765)
    args = parser.parse_args()
    if args.init:
        initialize(args.state_dir)
    else:
        if not args.token_file: parser.error('--token-file is required to serve')
        serve(args.state_dir, args.token_file, args.port)


if __name__ == '__main__':
    main()
