"""Small localhost website backed by real ICMP checks."""
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import threading
import time
from urllib.parse import urlsplit

from main import check_targets, validate_inputs

WEB = Path(__file__).parent / 'web'


class Handler(BaseHTTPRequestHandler):
    def reply(self, status, body, content_type='application/json'):
        payload = json.dumps(body).encode() if content_type == 'application/json' else body
        self.send_response(status)
        self.send_header('Content-Type', content_type+'; charset=utf-8')
        self.send_header('Content-Length', str(len(payload)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header(
            'Content-Security-Policy',
            "default-src 'self'; style-src 'self'; script-src 'self'; "
            "img-src 'self' data:; frame-ancestors 'none'"
        )
        self.end_headers()
        try:
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        files = {'/': ('index.html', 'text/html'), '/style.css': ('style.css', 'text/css'),
                 '/app.js': ('app.js', 'application/javascript')}
        route = files.get(urlsplit(self.path).path)
        if route is None:
            self.reply(404, {'error': 'Page not found.'})
            return
        try:
            self.reply(200, (WEB/route[0]).read_bytes(), route[1])
        except OSError:
            self.reply(500, {'error': 'Website files are unavailable.'})

    def do_POST(self):
        if self.path != '/api/check':
            self.reply(404, {'error': 'Endpoint not found.'})
            return
        host = self.headers.get('Host', '')
        allowed = {f'127.0.0.1:{self.server.server_port}', f'localhost:{self.server.server_port}'}
        origin = self.headers.get('Origin')
        if host not in allowed or (origin is not None and origin != 'http://'+host):
            self.reply(403, {'error': 'Checks must come from this local website.'})
            return
        if self.headers.get_content_type() != 'application/json':
            self.reply(415, {'error': 'Send settings as JSON.'})
            return
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= 8192:
                raise ValueError('Invalid request size.')
            data = json.loads(self.rfile.read(length))
            if not isinstance(data, dict) or not isinstance(data.get('targets'), str):
                raise ValueError('Enter target IPv4 addresses as text.')
            count, ttl = data.get('count', 5), data.get('ttl', 64)
            if isinstance(count, bool) or not isinstance(count, (int, str)):
                raise ValueError('Packet count must be a whole number.')
            if isinstance(ttl, bool) or not isinstance(ttl, (int, str)):
                raise ValueError('TTL must be a whole number.')
            if isinstance(data.get('timeout'), bool):
                raise ValueError('Timeout must be a number.')
            targets, count, timeout = validate_inputs(data['targets'], count, data.get('timeout', 2))
            ttl = int(ttl)
            if count > 10 or timeout > 3 or len(targets) > 8:
                raise ValueError('Use up to 8 targets, 10 packets and 3 seconds timeout.')
            if not 1 <= ttl <= 255:
                raise ValueError('TTL must be between 1 and 255.')
        except (ValueError, TypeError, UnicodeDecodeError) as exc:
            self.reply(400, {'error': str(exc)})
            return
        if not self.server.scan_lock.acquire(blocking=False):
            self.reply(409, {'error': 'A check is already running. Wait for it to finish.'})
            return
        try:
            started = time.monotonic()
            results = check_targets(targets, count, timeout, ttl, self.server.stop_event)
            self.reply(200, {'targets': results, 'elapsed': time.monotonic()-started,
                             'checked_at': datetime.now().astimezone().isoformat(),
                             'settings': {'count': count, 'timeout': timeout, 'ttl': ttl}})
        except Exception:
            self.reply(500, {'error': 'The check could not complete. See the server terminal.'})
            raise
        finally:
            self.server.scan_lock.release()

    def log_message(self, message, *args):
        print(message % args, flush=True)


def make_server(port=8765):
    http = ThreadingHTTPServer(('127.0.0.1', port), Handler)
    http.daemon_threads = True
    http.scan_lock = threading.Lock()
    http.stop_event = threading.Event()
    return http


def serve():
    try:
        http = make_server()
    except OSError as exc:
        raise SystemExit(f'Cannot start the website: {exc}') from None
    print('ICMP Network Lab is ready: http://127.0.0.1:8765', flush=True)
    print('Open that address in your browser. Press Ctrl+C to stop.', flush=True)
    try:
        http.serve_forever()
    except KeyboardInterrupt:
        print('\nWebsite stopped.')
    finally:
        http.stop_event.set()
        http.server_close()


if __name__ == '__main__':
    serve()
