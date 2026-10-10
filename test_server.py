import json
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from unittest.mock import patch

import server


class WebsiteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.http = server.make_server(0)
        cls.origin = f'http://127.0.0.1:{cls.http.server_port}'
        cls.thread = threading.Thread(target=cls.http.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.http.shutdown()
        cls.http.server_close()
        cls.thread.join()

    def request(self, data, origin=None, content_type='application/json'):
        headers = {'Content-Type': content_type}
        if origin is not None:
            headers['Origin'] = origin
        req = Request(self.origin+'/api/check', data=json.dumps(data).encode(), headers=headers)
        try:
            with urlopen(req, timeout=3) as response:
                return response.status, json.load(response)
        except HTTPError as exc:
            with exc:
                return exc.code, json.load(exc)

    def test_page_and_assets(self):
        for path, kind in [('/', 'text/html'), ('/style.css', 'text/css'), ('/app.js', 'javascript')]:
            with urlopen(self.origin+path) as r:
                self.assertEqual(r.status, 200)
                self.assertIn(kind, r.headers['Content-Type'])

    def test_valid_request_uses_actual_engine(self):
        sample = [{'target': '127.0.0.1', 'status': 'REACHABLE', 'results': []}]
        with patch.object(server, 'check_targets', return_value=sample) as check:
            code, body = self.request({'targets': '127.0.0.1', 'count': 2, 'timeout': .5, 'ttl': 1}, self.origin)
        self.assertEqual(code, 200)
        self.assertEqual(body['targets'], sample)
        self.assertEqual(check.call_args.args[:4], (['127.0.0.1'], 2, .5, 1))

    def test_invalid_settings(self):
        for value in [{'targets': 'bad'}, {'targets': '0.0.0.0'},
                      {'targets': '127.0.0.1', 'ttl': 0}, {'targets': '127.0.0.1', 'count': 1.5},
                      {'targets': '127.0.0.1', 'ttl': True}, {'targets': ['127.0.0.1']}]:
            with self.subTest(value=value):
                self.assertEqual(self.request(value)[0], 400)

    def test_other_origins_and_content_types_rejected(self):
        data = {'targets': '127.0.0.1'}
        self.assertEqual(self.request(data, 'https://other.example')[0], 403)
        self.assertEqual(self.request(data, content_type='text/plain')[0], 415)

    def test_busy_service(self):
        self.http.scan_lock.acquire()
        try:
            self.assertEqual(self.request({'targets': '127.0.0.1'})[0], 409)
        finally:
            self.http.scan_lock.release()


if __name__ == '__main__':
    unittest.main()
