import importlib.util
import json
import threading
import unittest
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import Request, ProxyHandler, HTTPCookieProcessor, build_opener
from http.cookiejar import CookieJar
from wsgiref.simple_server import make_server, WSGIRequestHandler
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def load_portal():
    source = ROOT / 'app/score_portal.py'
    spec = importlib.util.spec_from_file_location('score_portal', source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PortalOverHTTPTests(unittest.TestCase):
    def test_full_idor_chain_over_a_real_http_server(self):
        module = load_portal()
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        flag = 'MeKoDataCTF{team03_c1a05e94}'
        app = module.create_app(Path(temp.name) / 'http.sqlite', 'team03_mekodatactf_2026_test1',
                                'sandbox-http', flag, student_id=20260301)

        class QuietHandler(WSGIRequestHandler):
            def log_message(self, *args):
                pass

        with make_server('127.0.0.1', 0, app, handler_class=QuietHandler) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base = f'http://127.0.0.1:{server.server_port}'
                client = build_opener(ProxyHandler({}), HTTPCookieProcessor(CookieJar()))
                # Step 1: point.js is served fresh and documents the API map.
                with client.open(base + '/static/point.js', timeout=5) as response:
                    script = response.read().decode('utf-8')
                self.assertIn('/api/scores/', script)
                self.assertIn('9000', script)
                self.assertNotIn(flag, script)
                # Step 2: log in, then read own profile and score list.
                login = Request(base + '/login', data=urlencode(
                    {'username': 'student', 'password': 'team03_mekodatactf_2026_test1'}).encode())
                with client.open(login, timeout=5) as response:
                    self.assertEqual(json.load(response)['user'], 'student')
                with client.open(base + '/api/scores', timeout=5) as response:
                    own = json.load(response)
                self.assertEqual([r['record_id'] for r in own], [1001, 1002, 1003])
                # Step 3 + 4: change the recordId (IDOR) to reach the hidden audit flag.
                with client.open(base + '/api/scores/9001', timeout=5) as response:
                    self.assertIn(flag, json.load(response)['remark'])
            finally:
                server.shutdown()
                thread.join(timeout=3)


class ProvisioningTests(unittest.TestCase):
    def test_port_80_portal_is_provisioned_on_each_team(self):
        playbook = (ROOT / 'provisioning/playbook.yml').read_text(encoding='utf-8')
        unit = (ROOT / 'provisioning/files/score-portal.service').read_text(encoding='utf-8')
        self.assertIn('hosts: teams', playbook)
        self.assertIn('score_portal.py', playbook)
        self.assertIn('point.js', playbook)
        self.assertIn("team_secrets[inventory_hostname].flag", playbook)
        self.assertIn("team_secrets[inventory_hostname].password", playbook)
        self.assertIn('--host 0.0.0.0 --port 80', unit)
        self.assertIn('AmbientCapabilities=CAP_NET_BIND_SERVICE', unit)
        # The team account works at the console and over password-only SSH.
        self.assertIn("name: '{{ inventory_hostname }}'", playbook)
        self.assertIn("team_secrets[inventory_hostname].console_password | password_hash('sha512')", playbook)
        self.assertIn('name: kali\n        password_lock: true', playbook)
        self.assertIn('groups: sudo', playbook)
        self.assertIn('DenyUsers kali meko*', playbook)
        self.assertIn('Match User {{ inventory_hostname }}', playbook)
        self.assertIn('PubkeyAuthentication no', playbook)
        self.assertIn('AuthenticationMethods password', playbook)
        self.assertIn("user_access_password: '{{ team_secrets[inventory_hostname].console_password }}'", playbook)
        self.assertIn('path: /home/user-access/.ssh/authorized_keys', playbook)
        self.assertNotIn('PubkeyAuthentication yes', playbook)
        # The obsolete central-server pieces must be gone.
        for gone in ['server-acl.nft', 'attacker-http', 'servicedesk.service', 'ip_forward']:
            self.assertNotIn(gone, playbook)
        self.assertFalse((ROOT / 'provisioning/files/server-acl.nft').exists())
        self.assertFalse((ROOT / 'app/attacker_http.py').exists())

    def test_checker_server_is_provisioned(self):
        playbook = (ROOT / 'provisioning/playbook.yml').read_text(encoding='utf-8')
        unit = (ROOT / 'provisioning/files/mekodata-checker.service').read_text(encoding='utf-8')
        self.assertIn('hosts: infra', playbook)
        self.assertIn('checker.py', playbook)
        self.assertIn('dict(flags=team_flags)', playbook)
        self.assertIn('checker.py --config', unit)
        # SSH is explicitly started so the console tunnel stays open.
        self.assertIn('name: ssh', playbook)
        self.assertIn('state: started', playbook)


class CheckerAppTests(unittest.TestCase):
    def load_checker(self):
        source = ROOT / 'app/checker.py'
        spec = importlib.util.spec_from_file_location('checker', source)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def call(self, app, query):
        env = {'PATH_INFO': '/validate', 'REQUEST_METHOD': 'GET', 'QUERY_STRING': query}
        result = {}
        body = b''.join(app(env, lambda status, headers: result.update(status=int(status.split()[0]))))
        return result['status'], json.loads(body)

    def test_validate_accepts_only_correct_flags(self):
        module = self.load_checker()
        app = module.create_app({'team01': 'MeKoDataCTF{team01_9f3a7c21}',
                                 'team02': 'MeKoDataCTF{team02_4d8e2b6f}'})
        status, ok = self.call(app, 'flag=MeKoDataCTF{team01_9f3a7c21}')
        self.assertEqual(status, 200)
        self.assertEqual((ok['valid'], ok['team']), (True, 'team01'))
        _, wrong_team = self.call(app, 'team=team02&flag=MeKoDataCTF{team01_9f3a7c21}')
        self.assertFalse(wrong_team['valid'])
        _, bad = self.call(app, 'flag=MeKoDataCTF{nope}')
        self.assertEqual((bad['valid'], bad['team']), (False, None))

    def test_health_lists_teams_and_empty_flags_rejected(self):
        module = self.load_checker()
        app = module.create_app({'team01': 'MeKoDataCTF{team01_9f3a7c21}'})
        env = {'PATH_INFO': '/health', 'REQUEST_METHOD': 'GET'}
        result = {}
        body = b''.join(app(env, lambda status, headers: result.update(status=int(status.split()[0]))))
        self.assertEqual(result['status'], 200)
        self.assertEqual(json.loads(body)['teams'], ['team01'])
        with self.assertRaises(ValueError):
            module.create_app({})


if __name__ == '__main__':
    unittest.main()
