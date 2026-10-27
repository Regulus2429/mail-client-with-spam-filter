import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


class CLISmokeTest(unittest.TestCase):
    def test_complete_command_line_workflow(self):
        env = dict(os.environ, PYTHONUTF8='1')
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); data = root / 'data'; output = root / 'out'
            def run(args, passwords=''):
                result = subprocess.run([sys.executable, '-m', 'mailproject', *args], input=passwords,
                                        text=True, encoding='utf-8', capture_output=True, env=env, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                return result.stdout
            for user in ('alice@example.test', 'bob@example.test'):
                run(['add-user', user, '--data', str(data)], 'password\npassword\n')
            smtp_port, pop_port = port(), port()
            server = subprocess.Popen([sys.executable, '-m', 'mailproject', 'server', '--plain', '--data', str(data), '--smtp-port', str(smtp_port), '--pop-port', str(pop_port)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
            try:
                for _ in range(100):
                    if server.poll() is not None: self.fail('server failed to start')
                    try:
                        with socket.create_connection(('127.0.0.1', smtp_port), timeout=.2): break
                    except OSError: time.sleep(.1)
                else: self.fail('server did not become ready')
                attachment = root / 'sample.txt'; attachment.write_text('attachment', encoding='utf-8')
                run(['send', '--plain', '--port', str(smtp_port), '--user', 'alice@example.test', '--to', 'bob@example.test', '--subject', 'CLI', '--text', 'hello', '--attach', str(attachment)], 'password\n')
                self.assertIn('字节', run(['list', '--plain', '--port', str(pop_port), '--user', 'bob@example.test'], 'password\n'))
                run(['fetch', '--plain', '--port', str(pop_port), '--user', 'bob@example.test', '--out', str(output)], 'password\n')
                paths = list(output.rglob('*.eml')); self.assertEqual(len(paths), 1)
                self.assertIn('CLI', run(['view', str(paths[0]), '--attachments-dir', str(root / 'attachments')]))
                self.assertEqual((root / 'attachments' / '1-sample.txt').read_text(), 'attachment')
            finally:
                server.terminate(); server.wait(timeout=10)


if __name__ == '__main__': unittest.main()
