import io
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from mailproject.storage import Storage
from mailproject.smtp_server import start_smtp
from mailproject.pop3_server import POP3Server
try:
    from mailproject.web import create_app
except ModuleNotFoundError as exc:
    if exc.name != 'flask':
        raise
    create_app = None
from test_integration import free_port


@unittest.skipIf(create_app is None, '安装 requirements-web.txt 后运行 Web 测试')
class WebTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        store = Storage(self.root / 'server')
        for user in ('alice', 'bob'):
            store.add_user(user + '@example.test', 'password')
        self.smtp_port = free_port()
        self.smtp = start_smtp(store, '127.0.0.1', self.smtp_port)
        self.pop = POP3Server(('127.0.0.1', 0), store)
        threading.Thread(target=self.pop.serve_forever, daemon=True).start()
        self.app = create_app(smtp_port=self.smtp_port, pop_port=self.pop.server_address[1],
                              output=self.root / 'web', tls=False)
        self.app.testing = True
        self.browser = self.app.test_client()

    def tearDown(self):
        self.pop.shutdown()
        self.pop.server_close()
        self.smtp.stop()
        self.temp.cleanup()

    def post(self, path, data=None):
        with self.browser.session_transaction() as s:
            token = s['csrf']
        return self.browser.post(path, data=dict(csrf=token, **(data or {})), follow_redirects=True)

    def login(self, user):
        self.browser.get('/login')
        return self.post('/login', dict(user=user + '@example.test', password='password'))

    def test_send_fetch_attachment_isolation_and_logout(self):
        self.assertEqual(self.browser.get('/').status_code, 302)
        self.login('alice')
        response = self.post('/compose', dict(to='bob@example.test', subject='<script>alert(1)</script>',
                             body='正文 <img src=x onerror=alert(1)>',
                             attachments=(io.BytesIO(b'attachment bytes'), '测试.txt')))
        self.assertIn('邮件已投递'.encode(), response.data)
        self.post('/logout')
        self.login('bob')
        self.assertIn('下载 1 封'.encode(), self.post('/fetch').data)
        self.assertIn('下载 0 封'.encode(), self.post('/fetch').data)
        path = next((self.root / 'web').rglob('*.eml'))
        detail = self.browser.get('/mail/' + path.stem)
        self.assertNotIn(b'<script>alert', detail.data)
        self.assertIn(b'&lt;img', detail.data)
        response = self.browser.get('/mail/' + path.stem + '/attachment/0')
        self.assertEqual(response.data, b'attachment bytes')
        self.assertIn('attachment;', response.headers['Content-Disposition'])
        self.assertEqual(self.browser.get('/mail/' + path.stem + '?folder=../').status_code, 404)
        self.post('/logout')
        self.assertEqual(self.browser.get('/mail/' + path.stem).status_code, 302)
        self.login('alice')
        self.assertEqual(self.browser.get('/mail/' + path.stem).status_code, 404)

    def test_csrf_and_invalid_login(self):
        self.browser.get('/login')
        self.assertEqual(self.browser.post('/login', data={'user': 'alice@example.test'}).status_code, 400)
        response = self.post('/login', dict(user='alice@example.test', password='wrong'))
        self.assertIn('登录失败'.encode(), response.data)
        self.assertEqual(self.browser.get('/compose').status_code, 302)
        self.login('alice')
        self.assertEqual(self.browser.post('/logout').status_code, 400)

    def test_filter_and_failure_fallback(self):
        class Filter:
            def classify(self, raw):
                return 'spam'
        with patch('mailproject.spam.SpamFilter.load', return_value=Filter()):
            self.app = create_app(smtp_port=self.smtp_port, pop_port=self.pop.server_address[1],
                                  output=self.root / 'filtered', tls=False, spam_model='test')
        self.browser = self.app.test_client()
        self.login('alice')
        self.post('/compose', dict(to='alice@example.test', subject='offer', body='test'))
        self.post('/fetch')
        self.assertIn(b'offer', self.browser.get('/?folder=spam').data)
        self.assertNotIn(b'offer', self.browser.get('/').data)
        broken = create_app(smtp_port=self.smtp_port, pop_port=self.pop.server_address[1],
                            output=self.root / 'fallback', tls=False, spam_model=str(self.root / 'missing'))
        self.browser = broken.test_client()
        self.assertIn('加载失败'.encode(), self.login('alice').data)
        self.assertIn('下载 1 封'.encode(), self.post('/fetch').data)
        self.assertIn(b'offer', self.browser.get('/').data)
