"""Standard-library SMTP/POP3 client and MIME handling."""
import mimetypes
import poplib
import smtplib
import ssl
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path
import re


def context(cafile):
    return ssl.create_default_context(cafile=str(cafile) if cafile else None)


def send(host, port, username, password, recipients, subject, body, html=None, attachments=(), tls=True, cafile=None):
    msg = EmailMessage()
    msg['From'] = username
    msg['To'] = ', '.join(recipients)
    msg['Subject'] = subject
    msg.set_content(body)
    if html is not None:
        msg.add_alternative(html, subtype='html')
    for item in attachments:
        path = Path(item)
        typ = mimetypes.guess_type(path.name)[0] or 'application/octet-stream'
        main, sub = typ.split('/', 1)
        msg.add_attachment(path.read_bytes(), maintype=main, subtype=sub, filename=path.name)
    with smtplib.SMTP(host, port, timeout=30) as smtp:
        smtp.ehlo()
        if tls:
            smtp.starttls(context=context(cafile))
            smtp.ehlo()
        smtp.login(username, password)
        refused = smtp.send_message(msg, from_addr=username, to_addrs=recipients)
        if refused:
            raise RuntimeError(f'部分收件人被拒绝: {refused}')
    return msg


def connect_pop(host, port, username, password, tls=True, cafile=None):
    client = (poplib.POP3_SSL(host, port, timeout=30, context=context(cafile)) if tls
              else poplib.POP3(host, port, timeout=30))
    try:
        client.user(username)
        client.pass_(password)
        return client
    except Exception:
        client.close()
        raise


def list_messages(client):
    sizes = {int(x.split()[0]): int(x.split()[1]) for x in client.list()[1]}
    return [(int(a), uid.decode('ascii'), sizes[int(a)]) for a, uid in (line.split() for line in client.uidl()[1])]


def fetch_messages(client, output, username):
    # Encode account as UTF-8 hex rather than trusting it as a filesystem path.
    target = Path(output) / username.lower().encode('utf-8').hex()
    target.mkdir(parents=True, exist_ok=True)
    result = []
    for number, uid, size in list_messages(client):
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,70}', uid):
            raise ValueError('POP3 UID contains unsafe characters')
        path = target / (uid + '.eml')
        if path.exists():
            continue
        _, lines, _ = client.retr(number)
        raw = b'\r\n'.join(lines) + b'\r\n'
        # Avoid silently keeping a truncated download.
        if len(raw) != size:
            raise ValueError(f'邮件 {uid} 长度与服务器报告不一致')
        path.write_bytes(raw)
        result.append(path)
    return result


def inspect_message(path, attachments_dir=None):
    msg = BytesParser(policy=policy.default).parsebytes(Path(path).read_bytes())
    body = msg.get_body(preferencelist=('plain', 'html'))
    print(f'发件人: {msg.get("From", "")}\n收件人: {msg.get("To", "")}\n主题: {msg.get("Subject", "")}')
    if body:
        print('\n正文:')
        print(body.get_content())
    parts = list(msg.iter_attachments())
    if not parts:
        return
    if attachments_dir:
        Path(attachments_dir).mkdir(parents=True, exist_ok=True)
    for index, part in enumerate(parts, 1):
        name = part.get_filename() or f'attachment-{index}'
        # Strip both Windows and POSIX paths and reserved filename characters.
        name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', name).strip(' .') or f'attachment-{index}'
        print(f'附件: {name}')
        if attachments_dir:
            out = Path(attachments_dir) / f'{index}-{name}'
            if out.exists():
                raise FileExistsError(f'附件已存在，避免覆盖: {out}')
            out.write_bytes(part.get_payload(decode=True))
            print(f'已保存: {out}')
