"""Optional spam inference. Importing this module needs only the standard library."""
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser


class _HTMLText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.hidden = 0

    def handle_starttag(self, tag, attrs):
        if tag in ('script', 'style'):
            self.hidden += 1

    def handle_endtag(self, tag):
        if tag in ('script', 'style'):
            self.hidden = max(0, self.hidden - 1)

    def handle_data(self, data):
        if not self.hidden:
            self.parts.append(data)


def extract_text(raw):
    """Use the subject and preferred MIME body, never attachment contents."""
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    body = msg.get_body(preferencelist=('plain', 'html'))
    content = ''
    if body is not None:
        content = body.get_content()
        if body.get_content_subtype() == 'html':
            parser = _HTMLText()
            parser.feed(content)
            content = ' '.join(parser.parts)
    return ' '.join((str(msg.get('Subject', '')) + '\n' + content).split())


class SpamFilter:
    def __init__(self, pipeline):
        self.pipeline = pipeline

    @classmethod
    def load(cls, path):
        # joblib/pickle can execute code: only load locally trained, trusted files.
        import joblib
        bundle = joblib.load(path)
        if not isinstance(bundle, dict) or bundle.get('format_version') != 1:
            raise ValueError('不支持的模型格式')
        pipeline = bundle['pipeline']
        if set(pipeline.classes_) != {'ham', 'spam'}:
            raise ValueError('模型必须包含 ham 和 spam 两个标签')
        return cls(pipeline)

    def classify(self, raw):
        text = extract_text(raw)
        if not text:
            raise ValueError('邮件没有可分类的文本')
        label = str(self.pipeline.predict([text])[0])
        if label not in ('ham', 'spam'):
            raise ValueError('模型返回未知标签')
        return label
