import tempfile
import unittest
from email.message import EmailMessage
from email import policy
from pathlib import Path

from mailproject.client import fetch_messages
from mailproject.spam import SpamFilter, extract_text
from train_spam import load_dataset


class FakePOP:
    def __init__(self, raw):
        self.raw = raw
        self.downloads = 0

    def list(self):
        return b'+OK', [f'1 {len(self.raw)}'.encode()], 0

    def uidl(self):
        return b'+OK', [b'1 test-uid'], 0

    def retr(self, number):
        self.downloads += 1
        return b'+OK', self.raw[:-2].split(b'\r\n'), len(self.raw)


class FixedFilter:
    def __init__(self, label):
        self.label = label

    def classify(self, raw):
        if self.label == 'error':
            raise ValueError('prediction failed')
        return self.label


class SpamTests(unittest.TestCase):
    def message(self):
        msg = EmailMessage()
        msg['Subject'] = '中文 subject'
        msg.set_content('meeting tomorrow')
        msg.add_alternative('<b>alternative duplicate</b>', subtype='html')
        msg.add_attachment(b'attachment secret', maintype='application', subtype='octet-stream', filename='data.bin')
        return msg.as_bytes(policy=policy.SMTP)

    def test_mime_text_and_html(self):
        text = extract_text(self.message())
        self.assertIn('中文 subject', text)
        self.assertIn('meeting tomorrow', text)
        self.assertNotIn('duplicate', text)
        self.assertNotIn('secret', text)
        msg = EmailMessage()
        msg.set_content('<style>hidden</style><p>Hello &amp; bye</p><script>secret</script>', subtype='html')
        text = extract_text(msg.as_bytes())
        self.assertEqual(text, 'Hello & bye')

    def test_routing_deduplication_and_original_bytes(self):
        raw = self.message()
        for label in ('ham', 'spam', 'error', 'invalid'):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as folder:
                pop = FakePOP(raw)
                events = []
                paths = fetch_messages(pop, folder, 'a@test', FixedFilter(label), lambda *event: events.append(event))
                self.assertEqual(paths[0].read_bytes(), raw)
                self.assertEqual(paths[0].parent.name == 'spam', label == 'spam')
                self.assertEqual(events[0][1], label if label in ('ham', 'spam') else 'unclassified')
                self.assertEqual(fetch_messages(pop, folder, 'a@test'), [])
                self.assertEqual(pop.downloads, 1)
                self.assertEqual(len(fetch_messages(pop, folder, 'b@test')), 1)

    def test_move_failure_preserves_mail(self):
        raw = self.message()
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / 'a@test'.encode().hex()
            root.mkdir()
            (root / 'spam').write_text('blocked directory')
            events = []
            paths = fetch_messages(FakePOP(raw), folder, 'a@test', FixedFilter('spam'), lambda *x: events.append(x))
            self.assertEqual(paths[0].read_bytes(), raw)
            self.assertEqual(events[0][1], 'unclassified')

    def test_pipeline_receives_extracted_text(self):
        class Pipeline:
            def predict(self, texts):
                self.texts = texts
                return ['spam']
        pipeline = Pipeline()
        self.assertEqual(SpamFilter(pipeline).classify(self.message()), 'spam')
        self.assertEqual(pipeline.texts, [extract_text(self.message())])

    def test_conflicting_dataset_labels_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            for label in ('ham', 'spam'):
                directory = Path(folder) / label
                directory.mkdir()
                (directory / 'mail').write_bytes(self.message())
            with self.assertRaisesRegex(ValueError, '冲突标签'):
                load_dataset(folder)


if __name__ == '__main__':
    unittest.main()
