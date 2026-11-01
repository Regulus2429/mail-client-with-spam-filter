import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from email.message import EmailMessage


class Usability(unittest.TestCase):
    def test_config_local_number_and_override(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            folder = root / 'out' / 'bob@example.test'.encode().hex()
            folder.mkdir(parents=True)
            message = EmailMessage()
            message['From'] = 'alice@example.test'
            message['Subject'] = 'Meeting'
            message.set_content('Agenda for Friday')
            (folder / 'abc.eml').write_bytes(message.as_bytes())
            config = root / 'client.json'
            config.write_text(json.dumps({name: {'user': 'bob@example.test', 'out': str(root / 'out')} for name in ('local-list', 'view')}))
            def run(*args):
                return subprocess.run([sys.executable, '-m', 'mailproject', '--config', str(config), *args], capture_output=True, text=True, encoding='utf-8', env=dict(os.environ, PYTHONUTF8='1'))
            listing = run('local-list')
            self.assertEqual(listing.returncode, 0, listing.stderr)
            self.assertIn('Meeting', listing.stdout)
            self.assertIn('alice@example.test', listing.stdout)
            viewed = run('view', '--number', '1')
            self.assertEqual(viewed.returncode, 0, viewed.stderr)
            self.assertIn('Agenda for Friday', viewed.stdout)
            self.assertNotEqual(run('view', '--number', '0').returncode, 0)
            self.assertNotIn('Meeting', run('local-list', '--user', 'other@example.test').stdout)
            self.assertNotIn('Meeting', run('local-list', '--folder', 'spam').stdout)
            config.write_text('{"view": {"password": "not-allowed"}}')
            self.assertNotEqual(run('view', '--number', '1').returncode, 0)
