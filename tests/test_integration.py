import concurrent.futures
import hashlib
import os
import poplib
import smtplib
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from email import policy
from email.parser import BytesParser
from pathlib import Path

from mailproject.client import connect_pop, fetch_messages, list_messages, send
from mailproject.pop3_server import POP3Server
from mailproject.smtp_server import start_smtp
from mailproject.storage import Storage
from tools.mitm_demo import Handler as ProxyHandler


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


class Integration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.store = Storage(cls.root / 'server')
        cls.store.add_user('alice@example.test', 'alice-password')
        cls.store.add_user('bob@example.test', 'bob-password')
        cls.smtp_port, cls.pop_port = free_port(), free_port()
        cls.smtp = start_smtp(cls.store, '127.0.0.1', cls.smtp_port)
        cls.pop = POP3Server(('127.0.0.1', cls.pop_port), cls.store)
        cls.thread = threading.Thread(target=cls.pop.serve_forever, daemon=True); cls.thread.start()
        cls.cert, cls.key = cls.root / 'cert.pem', cls.root / 'key.pem'
        subprocess.run(['openssl', 'req', '-config', str(Path(__file__).with_name('openssl.cnf')), '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
                        '-keyout', str(cls.key), '-out', str(cls.cert), '-subj', '/CN=localhost',
                        '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1'], check=True, capture_output=True)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(cls.cert, cls.key)
        cls.secure_smtp_port, cls.secure_pop_port = free_port(), free_port()
        cls.secure_smtp = start_smtp(cls.store, '127.0.0.1', cls.secure_smtp_port, ctx)
        cls.secure_pop = POP3Server(('127.0.0.1', cls.secure_pop_port), cls.store, ctx)
        cls.secure_thread = threading.Thread(target=cls.secure_pop.serve_forever, daemon=True); cls.secure_thread.start()

    @classmethod
    def tearDownClass(cls):
        for server in (cls.pop, cls.secure_pop): server.shutdown(); server.server_close()
        cls.smtp.stop(); cls.secure_smtp.stop(); cls.temp.cleanup()

    def test_plain_mime_download_and_isolation(self):
        attach = self.root / '中文附件.bin'; original = b'\x00\xffhello\r\n' * 30; attach.write_bytes(original)
        send('127.0.0.1', self.smtp_port, 'alice@example.test', 'alice-password', ['bob@example.test'],
             '中文主题', '第一行\n.以点开头\n最后一行', '<b>中文 HTML</b>', [attach], tls=False)
        pop = connect_pop('127.0.0.1', self.pop_port, 'bob@example.test', 'bob-password', tls=False)
        paths = fetch_messages(pop, self.root / 'downloads', 'bob@example.test')
        self.assertTrue(paths)
        self.assertEqual(fetch_messages(pop, self.root / 'downloads', 'bob@example.test'), [])
        pop.quit()
        messages = [BytesParser(policy=policy.default).parsebytes(p.read_bytes()) for p in paths]
        msg = next(m for m in messages if m['Subject'] == '中文主题')
        self.assertIn('.以点开头', msg.get_body(preferencelist=('plain',)).get_content())
        self.assertIn('中文 HTML', msg.get_body(preferencelist=('html',)).get_content())
        item = list(msg.iter_attachments())[0]
        self.assertEqual(item.get_filename(), '中文附件.bin')
        self.assertEqual(hashlib.sha256(item.get_payload(decode=True)).digest(), hashlib.sha256(original).digest())
        alice = connect_pop('127.0.0.1', self.pop_port, 'alice@example.test', 'alice-password', tls=False)
        self.assertEqual(alice.stat()[0], 0); alice.quit()
        with self.assertRaises(poplib.error_proto):
            connect_pop('127.0.0.1', self.pop_port, 'bob@example.test', 'wrong', tls=False)
        with self.assertRaises(smtplib.SMTPAuthenticationError):
            send('127.0.0.1', self.smtp_port, 'alice@example.test', 'wrong', ['bob@example.test'], 'x', 'x', tls=False)

    def test_smtp_plain_and_login_auth(self):
        for method in ('PLAIN', 'LOGIN'):
            with smtplib.SMTP('127.0.0.1', self.smtp_port, timeout=10) as smtp:
                smtp.ehlo()
                smtp.user = 'alice@example.test'; smtp.password = 'alice-password'
                auth = smtp.auth_plain if method == 'PLAIN' else smtp.auth_login
                code, _ = smtp.auth(method, auth)
                self.assertEqual(code, 235)

    def test_windows_wildcard_bind(self):
        controller = start_smtp(self.store, '0.0.0.0', free_port())
        try:
            with smtplib.SMTP('127.0.0.1', controller.port, timeout=10) as smtp:
                self.assertEqual(smtp.noop()[0], 250)
        finally:
            controller.stop()

    def test_tls_and_reject_untrusted_or_wrong_hostname(self):
        send('127.0.0.1', self.secure_smtp_port, 'alice@example.test', 'alice-password', ['bob@example.test'],
             'TLS', 'encrypted', tls=True, cafile=self.cert)
        pop = connect_pop('127.0.0.1', self.secure_pop_port, 'bob@example.test', 'bob-password', tls=True, cafile=self.cert)
        self.assertGreater(pop.stat()[0], 0); pop.quit()
        with self.assertRaises(ssl.SSLCertVerificationError):
            connect_pop('127.0.0.1', self.secure_pop_port, 'bob@example.test', 'bob-password', tls=True)
        with self.assertRaises(ssl.SSLCertVerificationError):
            send('localhost', self.secure_smtp_port, 'alice@example.test', 'alice-password', ['bob@example.test'], 'x', 'x', tls=True)
        # Trusting the certificate does not make a mismatched hostname valid.
        wrong_ctx = ssl.create_default_context(cafile=str(self.cert))
        with socket.create_connection(('127.0.0.1', self.secure_pop_port)) as s:
            with self.assertRaises(ssl.SSLCertVerificationError):
                wrong_ctx.wrap_socket(s, server_hostname='wrong.example')

    def test_controlled_mitm_proxy_rejected(self):
        fake_cert, fake_key = self.root / 'fake-cert.pem', self.root / 'fake-key.pem'
        subprocess.run(['openssl', 'req', '-config', str(Path(__file__).with_name('openssl.cnf')), '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-keyout', str(fake_key), '-out', str(fake_cert), '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1'], check=True, capture_output=True)
        fake_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); fake_ctx.load_cert_chain(fake_cert, fake_key)
        class Proxy(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True
        proxy = Proxy(('127.0.0.1', 0), ProxyHandler)
        proxy.fake_context = fake_ctx
        proxy.upstream_context = ssl.create_default_context(cafile=str(self.cert))
        proxy.upstream_host, proxy.upstream_port = '127.0.0.1', self.secure_pop_port
        thread = threading.Thread(target=proxy.serve_forever, daemon=True); thread.start()
        try:
            with self.assertRaises(ssl.SSLCertVerificationError):
                connect_pop('127.0.0.1', proxy.server_address[1], 'bob@example.test', 'bob-password', tls=True, cafile=self.cert)
            p = connect_pop('127.0.0.1', self.secure_pop_port, 'bob@example.test', 'bob-password', tls=True, cafile=self.cert)
            p.quit()
        finally:
            proxy.shutdown(); proxy.server_close()

    def test_deletion_and_lock(self):
        send('127.0.0.1', self.smtp_port, 'alice@example.test', 'alice-password', ['bob@example.test'], 'delete', 'x', tls=False)
        p = connect_pop('127.0.0.1', self.pop_port, 'bob@example.test', 'bob-password', tls=False)
        before = p.stat()[0]
        with self.assertRaises(poplib.error_proto):
            connect_pop('127.0.0.1', self.pop_port, 'bob@example.test', 'bob-password', tls=False)
        p.dele(1); p.close()  # no QUIT: transaction must roll back
        for _ in range(50):
            try:
                p = connect_pop('127.0.0.1', self.pop_port, 'bob@example.test', 'bob-password', tls=False); break
            except poplib.error_proto: time.sleep(.05)
        self.assertEqual(p.stat()[0], before)
        p.dele(1); p.rset(); self.assertEqual(p.stat()[0], before)
        p.dele(1); p.quit()
        p = connect_pop('127.0.0.1', self.pop_port, 'bob@example.test', 'bob-password', tls=False)
        self.assertEqual(p.stat()[0], before - 1); p.quit()

    def test_ten_simultaneous_clients(self):
        n = 10
        for i in range(n): self.store.add_user(f'user{i}@example.test', 'test-password')
        barrier = threading.Barrier(n)
        def worker(i):
            user = f'user{i}@example.test'
            barrier.wait(timeout=20)
            send('127.0.0.1', self.smtp_port, user, 'test-password', [user], f'concurrent-{i}', f'body-{i}', tls=False)
            p = connect_pop('127.0.0.1', self.pop_port, user, 'test-password', tls=False)
            try:
                items = list_messages(p)
                _, lines, _ = p.retr(items[0][0])
                msg = BytesParser(policy=policy.default).parsebytes(b'\r\n'.join(lines)+b'\r\n')
                return p.stat()[0], str(msg['Subject'])
            finally: p.quit()
        started = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=n) as pool:
            results = list(pool.map(worker, range(n)))
        elapsed = time.perf_counter() - started
        self.assertEqual(results, [(1, f'concurrent-{i}') for i in range(n)])
        print(f'\n并发验证: {n}/{n} 客户端发送、接收成功，耗时 {elapsed:.2f} 秒')


if __name__ == '__main__': unittest.main(verbosity=2)
