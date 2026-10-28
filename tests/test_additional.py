"""Additional end-to-end cases against temporary local services."""
import concurrent.futures
import hashlib
import smtplib
import ssl
import sqlite3
import threading
import time
import unittest
import uuid
from email import policy
from email.parser import BytesParser
from pathlib import Path

from mailproject.client import connect_pop, fetch_messages, send
import test_integration


class AdditionalIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        test_integration.Integration.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        test_integration.Integration.tearDownClass.__func__(cls)

    def test_tls_multiple_recipients_and_attachments(self):
        recipients = ['multi1@example.test', 'multi2@example.test']
        for user in recipients:
            self.store.add_user(user, 'password')
        files = [self.root / '图像.bin', self.root / 'document.txt', self.root / 'large.bin']
        contents = [bytes(range(256)) * 5, '中文文件\n'.encode(), bytes(range(256)) * 4096]
        for file, data in zip(files, contents):
            file.write_bytes(data)
        send('127.0.0.1', self.secure_smtp_port, 'alice@example.test', 'alice-password', recipients,
             '加密多附件', '纯文本正文\n.首点', '<p>HTML 正文</p>', files, tls=True, cafile=self.cert)
        uids = []
        for user in recipients:
            p = connect_pop('127.0.0.1', self.secure_pop_port, user, 'password', tls=True, cafile=self.cert)
            try:
                self.assertEqual(p.stat()[0], 1)
                uids.append(p.uidl(1).split()[-1])
                paths = fetch_messages(p, self.root / 'multi-downloads', user)
                self.assertEqual(len(paths), 1)
                msg = BytesParser(policy=policy.default).parsebytes(paths[0].read_bytes())
                self.assertEqual(str(msg['Subject']), '加密多附件')
                self.assertIn('.首点', msg.get_body(preferencelist=('plain',)).get_content())
                self.assertIn('HTML 正文', msg.get_body(preferencelist=('html',)).get_content())
                attachments = list(msg.iter_attachments())
                self.assertEqual([x.get_filename() for x in attachments], [x.name for x in files])
                for part, original in zip(attachments, contents):
                    self.assertEqual(hashlib.sha256(part.get_payload(decode=True)).digest(), hashlib.sha256(original).digest())
            finally:
                p.quit()
        self.assertNotEqual(uids[0], uids[1])
        with sqlite3.connect(self.store.db) as c:
            rows = c.execute('SELECT m.sender, m.received_at, d.recipient FROM messages m JOIN deliveries d ON m.id=d.message_id WHERE d.recipient IN (?,?) ORDER BY d.recipient', recipients).fetchall()
        self.assertEqual([row[2] for row in rows], recipients)
        self.assertTrue(all(row[0] == 'alice@example.test' and row[1] for row in rows))
        print('\nTLS 多收件人和 3 附件：2/2 邮箱成功，1 MiB 附件哈希一致；SQLite 元数据匹配', flush=True)

    def test_tls_auth_rejections_and_sender_policy(self):
        with smtplib.SMTP('127.0.0.1', self.secure_smtp_port, timeout=10) as smtp:
            smtp.ehlo()
            self.assertNotEqual(smtp.mail('alice@example.test')[0], 250)
            smtp.starttls(context=ssl.create_default_context(cafile=str(self.cert)))
            smtp.ehlo()
            with self.assertRaises(smtplib.SMTPAuthenticationError):
                smtp.login('alice@example.test', 'incorrect')
        with smtplib.SMTP('127.0.0.1', self.secure_smtp_port, timeout=10) as smtp:
            smtp.starttls(context=ssl.create_default_context(cafile=str(self.cert)))
            smtp.login('alice@example.test', 'alice-password')
            self.assertEqual(smtp.mail('bob@example.test')[0], 550)
            self.assertEqual(smtp.mail('alice@example.test')[0], 250)
            self.assertEqual(smtp.rcpt('unknown@example.test')[0], 550)
        print('\nTLS 拒绝未加密发信、错误密码、冒用发件人及未知收件人', flush=True)

    def _concurrency(self, n, tls):
        tag = uuid.uuid4().hex[:8]
        for i in range(n): self.store.add_user(f'{tag}-{i}@example.test', 'password')
        barrier = threading.Barrier(n)
        def worker(i):
            user = f'{tag}-{i}@example.test'
            barrier.wait(timeout=30)
            send('127.0.0.1', self.secure_smtp_port if tls else self.smtp_port, user, 'password', [user], f'test-{i}', f'body-{i}', tls=tls, cafile=self.cert if tls else None)
            p = connect_pop('127.0.0.1', self.secure_pop_port if tls else self.pop_port, user, 'password', tls=tls, cafile=self.cert if tls else None)
            try:
                self.assertEqual(p.stat()[0], 1)
                msg = BytesParser(policy=policy.default).parsebytes(b'\r\n'.join(p.retr(1)[1]) + b'\r\n')
                self.assertEqual(str(msg['Subject']), f'test-{i}')
                self.assertEqual(msg.get_body().get_content().strip(), f'body-{i}')
                return True
            finally: p.quit()
        start = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=n) as pool:
            results = list(pool.map(worker, range(n)))
        elapsed = time.perf_counter() - start
        self.assertEqual(sum(results), n)
        print(f'\n{"TLS" if tls else "明文"}并发：{sum(results)}/{n} 收发成功；耗时 {elapsed:.2f} 秒', flush=True)

    def test_tls_ten_clients(self):
        self._concurrency(10, True)

    def test_plain_fifty_clients(self):
        self._concurrency(50, False)


if __name__ == '__main__':
    unittest.main(verbosity=2)
