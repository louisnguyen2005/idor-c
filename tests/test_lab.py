import importlib.util
import io
import json
import tempfile
import unittest
from unittest.mock import MagicMock, patch
from pathlib import Path
from urllib.parse import urlencode
import yaml

ROOT = Path(__file__).resolve().parents[1]

FLAG_A = 'MeKoDataCTF{team01_9f3a7c21}'


class PortalTests(unittest.TestCase):
    def setUp(self):
        source = ROOT / 'app/score_portal.py'
        self.assertTrue(source.exists(), 'Point-lookup portal implementation is required')
        spec = importlib.util.spec_from_file_location('score_portal', source)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.app = self.module.create_app(
            Path(self.temp.name) / 'a.sqlite', 'lab-password', 'sandbox-A', FLAG_A, student_id=20260101)

    def request(self, path, method='GET', data=None, cookie='', app=None):
        body = urlencode(data or {}).encode()
        env = {'PATH_INFO': path, 'REQUEST_METHOD': method, 'HTTP_COOKIE': cookie,
               'CONTENT_LENGTH': str(len(body)), 'wsgi.input': io.BytesIO(body)}
        result = {}
        def start(status, headers):
            result.update(status=int(status.split()[0]), headers=dict(headers))
        result['body'] = b''.join((app or self.app)(env, start))
        return result

    def login(self, app=None):
        result = self.request('/login', 'POST', {'username': 'student', 'password': 'lab-password'}, app=app)
        self.assertEqual(result['status'], 200)
        self.assertIn('HttpOnly', result['headers']['Set-Cookie'])
        return result['headers']['Set-Cookie'].split(';')[0]

    def test_portal_page_and_point_js_expose_the_api_map(self):
        page = self.request('/')
        self.assertEqual(page['status'], 200)
        self.assertIn(b'Tra c', page['body'])  # "Tra cuu diem" title (UTF-8)
        self.assertIn(b'/static/point.js', page['body'])
        script = self.request('/static/point.js')
        self.assertEqual(script['status'], 200)
        self.assertIn('javascript', script['headers']['Content-Type'])
        for clue in [b'/api/me', b'/api/scores', b'/api/scores/', b'9000']:
            self.assertIn(clue, script['body'])
        # The flag itself must NOT be sitting in the static JS -- it is reached via IDOR.
        self.assertNotIn(FLAG_A.encode(), script['body'])

    def test_me_and_own_scores_list(self):
        cookie = self.login()
        me = json.loads(self.request('/api/me', cookie=cookie)['body'])
        self.assertEqual(me['student_id'], 20260101)
        scores = json.loads(self.request('/api/scores', cookie=cookie)['body'])
        self.assertEqual([r['record_id'] for r in scores], [1001, 1002, 1003])
        self.assertTrue(all(r['student_id'] == 20260101 for r in scores))

    def test_idor_reads_peer_records_and_the_hidden_flag(self):
        cookie = self.login()
        peer = self.request('/api/scores/1004', cookie=cookie)
        self.assertEqual(peer['status'], 200)
        self.assertNotEqual(json.loads(peer['body'])['student_id'], 20260101)
        audit = self.request('/api/scores/9001', cookie=cookie)
        self.assertEqual(audit['status'], 200)
        self.assertIn(FLAG_A, json.loads(audit['body'])['remark'])

    def test_audit_flag_record_is_not_listed_for_the_student(self):
        cookie = self.login()
        scores = json.loads(self.request('/api/scores', cookie=cookie)['body'])
        self.assertNotIn(9001, [r['record_id'] for r in scores])

    def test_owner_check_protects_peer_and_audit_records(self):
        fixed = self.module.create_app(
            Path(self.temp.name) / 'fixed.sqlite', 'lab-password', 'fixed', FLAG_A,
            student_id=20260101, enforce_owner=True)
        cookie = self.login(fixed)
        self.assertEqual(self.request('/api/scores/1001', cookie=cookie, app=fixed)['status'], 200)
        self.assertEqual(self.request('/api/scores/1004', cookie=cookie, app=fixed)['status'], 403)
        self.assertEqual(self.request('/api/scores/9001', cookie=cookie, app=fixed)['status'], 403)

    def test_sessions_and_flags_are_separate_between_sandboxes(self):
        flag_b = 'MeKoDataCTF{team02_4d8e2b6f}'
        second = self.module.create_app(
            Path(self.temp.name) / 'b.sqlite', 'lab-password', 'sandbox-B', flag_b, student_id=20260201)
        cookie_a = self.login()
        self.assertEqual(self.request('/api/scores', cookie=cookie_a, app=second)['status'], 401)
        cookie_b = self.login(second)
        audit_b = json.loads(self.request('/api/scores/9001', cookie=cookie_b, app=second)['body'])
        self.assertIn(flag_b, audit_b['remark'])
        self.assertNotIn(FLAG_A, audit_b['remark'])

    def test_unauthenticated_wrong_login_and_logout(self):
        self.assertEqual(self.request('/api/scores/1001')['status'], 401)
        self.assertEqual(self.request('/api/me')['status'], 401)
        self.assertEqual(self.request('/login', 'POST', {'username': 'student', 'password': 'wrong'})['status'], 401)
        cookie = self.login()
        self.assertEqual(self.request('/logout', 'POST', cookie=cookie)['status'], 200)
        self.assertEqual(self.request('/api/scores', cookie=cookie)['status'], 401)

    def test_input_validation_and_missing_records(self):
        cookie = self.login()
        for path in ['/missing', '/api/scores/not-a-number', '/api/scores/999999']:
            self.assertEqual(self.request(path, cookie=cookie)['status'], 404)
        self.assertEqual(self.request('/api/scores/1001', 'DELETE', cookie=cookie)['status'], 405)

    def test_health_requires_password_sandbox_and_flag(self):
        self.assertEqual(json.loads(self.request('/health')['body'])['sandbox'], 'sandbox-A')
        with self.assertRaises(ValueError):
            self.module.create_app(Path(self.temp.name) / 'e1.sqlite', '', 'sandbox', FLAG_A)
        with self.assertRaises(ValueError):
            self.module.create_app(Path(self.temp.name) / 'e2.sqlite', 'pw', 'sandbox', '')

    def test_session_expiry_and_config_entrypoint(self):
        with patch.object(self.module.time, 'time', return_value=1000):
            cookie = self.login()
        with patch.object(self.module.time, 'time', return_value=3000):
            self.assertEqual(self.request('/api/scores', cookie=cookie)['status'], 401)
        for length, body, expected in [('bad', b'', 400), ('5000', b'', 413), ('1', b'\xff', 400)]:
            env = {'PATH_INFO': '/login', 'REQUEST_METHOD': 'POST', 'CONTENT_LENGTH': length, 'wsgi.input': io.BytesIO(body)}
            result = {}
            self.app(env, lambda status, headers: result.update(status=int(status.split()[0])))
            self.assertEqual(result['status'], expected)
        config = Path(self.temp.name) / 'config.json'
        config.write_text(json.dumps({
            'database': str(Path(self.temp.name) / 'cli.sqlite'),
            'password': 'lab-password', 'sandbox_id': 'cli', 'flag': FLAG_A}), encoding='utf-8')
        listener = MagicMock()
        with patch('sys.argv', ['score_portal.py', '--config', str(config), '--host', '0.0.0.0', '--port', '80']), \
                patch.object(self.module, 'make_server', return_value=listener) as make:
            self.module.main()
        self.assertEqual(make.call_args.args[:2], ('0.0.0.0', 80))
        listener.__enter__.return_value.serve_forever.assert_called_once()


class DefinitionTests(unittest.TestCase):
    def test_definition_describes_the_four_team_ctf(self):
        source = ROOT / 'training-definition.json'
        self.assertTrue(source.exists(), 'Training definition is required')
        definition = json.loads(source.read_text(encoding='utf-8'))
        self.assertFalse(definition['variant_sandboxes'])
        self.assertEqual(len(definition['levels']), 1)
        level = definition['levels'][0]
        self.assertEqual(level['level_type'], 'ACCESS_LEVEL')
        for address in ['10.80.0.11', '10.80.0.12', '10.80.0.13', '10.80.0.14']:
            self.assertIn('http://' + address + '/', level['cloud_content'])
        self.assertIn('MeKoDataCTF{', level['cloud_content'])
        self.assertIn('point.js', level['cloud_content'])
        self.assertTrue(level['local_content'].strip())
        for key in ['answer', 'answer_variable_name', 'questions', 'max_score', 'content']:
            self.assertNotIn(key, level)


class TopologyTests(unittest.TestCase):
    def test_sandbox_has_four_team_kali_hosts_and_a_checker(self):
        source = ROOT / 'topology.yml'
        self.assertTrue(source.exists(), 'Isolated lab topology is required')
        topology = yaml.safe_load(source.read_text(encoding='utf-8'))
        by_name = {h['name']: h for h in topology['hosts']}
        self.assertEqual(set(by_name), {'team01', 'team02', 'team03', 'team04', 'checker'})
        self.assertTrue(all(by_name[t]['base_box']['image'] == 'kali'
                            for t in ['team01', 'team02', 'team03', 'team04']))
        self.assertEqual(by_name['checker']['base_box']['image'], 'debian-12-x86_64')
        self.assertEqual(len(topology['networks']), 1)
        self.assertEqual(len(topology['routers']), 1)
        self.assertEqual(len(topology['net_mappings']), 5)
        self.assertIn({'name': 'teams', 'nodes': ['team01', 'team02', 'team03', 'team04']},
                      topology['groups'])
        self.assertIn({'name': 'infra', 'nodes': ['checker']}, topology['groups'])
        self.assertEqual({m['ip'] for m in topology['net_mappings']},
                         {'10.80.0.11', '10.80.0.12', '10.80.0.13', '10.80.0.14', '10.80.0.30'})
        self.assertEqual(topology['router_mappings'][0]['ip'], '10.80.0.1')

    def test_group_vars_define_per_team_password_and_flag(self):
        data = yaml.safe_load((ROOT / 'provisioning/group_vars/all.yml').read_text(encoding='utf-8'))
        self.assertEqual(set(data['team_secrets']), {'team01', 'team02', 'team03', 'team04'})
        for team, secret in data['team_secrets'].items():
            nn = team[len('team'):]  # '01'..'04'
            self.assertEqual(secret['password'], f'{team}_mekodatactf_2026_test1')  # web
            self.assertEqual(secret['console_password'], team)                       # team01
            self.assertEqual(secret['ssh_user'], f'meko{nn}')                         # meko01
            self.assertEqual(secret['ssh_password'], f'meko{nn}')                     # meko01
            self.assertTrue(secret['flag'].startswith('MeKoDataCTF{' + team + '_'))
            self.assertTrue(secret['flag'].endswith('}'))
        # team_flags (consumed by the checker) must match team_secrets.
        self.assertEqual(data['team_flags'],
                         {t: s['flag'] for t, s in data['team_secrets'].items()})


if __name__ == '__main__':
    unittest.main()
