"""Optional loopback web client; mail transport remains SMTP/POP3."""
import argparse
import io
import re
import secrets
import tempfile
import threading
import time
from email import policy
from email.parser import BytesParser
from pathlib import Path

from flask import Flask, abort, flash, g, redirect, render_template, request, send_file, session, url_for
from .client import connect_pop, fetch_messages, send
from .usability import local_paths, summary


def create_app(host='127.0.0.1', smtp_port=1587, pop_port=1995,
               output='web-downloads', tls=True, cafile=None, spam_model=None):
    app = Flask(__name__)
    app.config.update(SECRET_KEY=secrets.token_hex(32), MAX_CONTENT_LENGTH=20 * 1024 * 1024,
                      SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Strict')
    accounts, locks = {}, {}
    guard = threading.Lock()
    classifier, filter_error = None, False
    if spam_model:
        try:
            from .spam import SpamFilter
            classifier = SpamFilter.load(spam_model)
        except Exception:
            filter_error = True

    def pop_for(user, password):
        return connect_pop(host, pop_port, user, password, tls, cafile)

    @app.before_request
    def authorize():
        # Reject cross-site form submission, including login/logout.
        session.setdefault('csrf', secrets.token_urlsafe(32))
        if request.method == 'POST' and not secrets.compare_digest(
                request.form.get('csrf', ''), session['csrf']):
            abort(400, '页面已过期，请刷新后重试。')
        now = time.monotonic()
        with guard:
            for token in list(accounts):
                if accounts[token]['expires'] <= now:
                    del accounts[token]
            g.account = accounts.get(session.get('token'))
        if request.endpoint not in ('login', 'static') and not g.account:
            return redirect(url_for('login'))

    @app.after_request
    def headers(response):
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'"
        return response

    @app.context_processor
    def context():
        return dict(account=g.get('account'), filter_status=(
            '过滤模型加载失败；新邮件将保留在收件箱。请检查模型路径并重启 Web 服务。' if filter_error else
            '已启用垃圾邮件过滤（只分类新下载的邮件）' if classifier else '未启用过滤；收件箱包含所有未分类邮件'))

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            user = request.form.get('user', '').strip().lower()
            password = request.form.get('password', '')
            try:
                p = pop_for(user, password)
                p.quit()
            except Exception:
                flash('登录失败：请核对账号密码、邮件服务、证书及端口；邮箱被占用时稍后再试。')
            else:
                with guard:
                    accounts.pop(session.get('token'), None)
                    token = secrets.token_urlsafe(32)
                    accounts[token] = dict(user=user, password=password, expires=time.monotonic() + 1800)
                    locks.setdefault(user, threading.Lock())
                session.clear()
                session.update(token=token, csrf=secrets.token_urlsafe(32))
                return redirect(url_for('inbox'))
        return render_template('login.html')

    @app.post('/logout')
    def logout():
        with guard:
            accounts.pop(session.get('token'), None)
        session.clear()
        return redirect(url_for('login'))

    def folder_arg():
        folder = request.args.get('folder', 'inbox')
        if folder not in ('inbox', 'spam'):
            abort(404)
        return folder

    @app.get('/')
    def inbox():
        folder = folder_arg()
        rows = []
        for path in local_paths(output, g.account['user'], folder):
            sender, subject = summary(path.read_bytes())
            rows.append(dict(uid=path.stem, sender=sender, subject=subject))
        return render_template('inbox.html', rows=rows, folder=folder)

    @app.post('/fetch')
    def fetch():
        user = g.account['user']
        with guard:
            lock = locks[user]
        if not lock.acquire(blocking=False):
            flash('此账号正在收信，请稍后刷新。')
            return redirect(url_for('inbox'))
        p = None
        try:
            p = pop_for(user, g.account['password'])
            failures = []
            paths = fetch_messages(p, output, user, classifier,
                                   lambda path, label, error: failures.append(path) if error else None)
            p.quit()
            p = None
            flash(f'收信完成，下载 {len(paths)} 封新邮件。')
            if failures:
                flash(f'{len(failures)} 封邮件分类失败，原文已保留在收件箱。')
        except Exception:
            flash('收信未完成，已下载邮件会保留。请检查邮件服务、证书及邮箱占用情况后重试。')
        finally:
            if p:
                p.close()
            lock.release()
        return redirect(url_for('inbox'))

    def message(uid):
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,70}', uid):
            abort(404)
        paths = local_paths(output, g.account['user'], folder_arg())
        path = next((p for p in paths if p.stem == uid), None)
        if path is None:
            abort(404)
        return BytesParser(policy=policy.default).parsebytes(path.read_bytes())

    @app.get('/mail/<uid>')
    def detail(uid):
        msg = message(uid)
        body = msg.get_body(preferencelist=('plain', 'html'))
        return render_template('detail.html', msg=msg, body=body.get_content() if body else '',
                               parts=list(msg.iter_attachments()), uid=uid, folder=folder_arg())

    @app.get('/mail/<uid>/attachment/<int:index>')
    def attachment(uid, index):
        parts = list(message(uid).iter_attachments())
        if not 0 <= index < len(parts):
            abort(404)
        part = parts[index]
        name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', part.get_filename() or 'attachment').strip(' .') or 'attachment'
        payload = part.get_payload(decode=True)
        if payload is None:
            payload = part.as_bytes()
        return send_file(io.BytesIO(payload), mimetype='application/octet-stream',
                         as_attachment=True, download_name=name)

    @app.route('/compose', methods=['GET', 'POST'])
    def compose():
        if request.method == 'POST':
            recipients = [x for x in re.split(r'[,;\s，；]+', request.form.get('to', '').strip()) if x]
            subject, body = request.form.get('subject', ''), request.form.get('body', '')
            if not recipients or not subject.strip() or not body.strip():
                flash('请填写收件人、主题和正文。')
            else:
                try:
                    with tempfile.TemporaryDirectory() as temp:
                        paths = []
                        for index, upload in enumerate(request.files.getlist('attachments')):
                            if not upload.filename:
                                continue
                            name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', upload.filename).strip(' .') or 'attachment'
                            directory = Path(temp) / str(index)
                            directory.mkdir()
                            path = directory / name
                            upload.save(path)
                            paths.append(path)
                        send(host, smtp_port, g.account['user'], g.account['password'], recipients,
                             subject, body, attachments=paths, tls=tls, cafile=cafile)
                except Exception:
                    flash('发送未确认成功：请检查收件人是否已注册、连接及附件。可能已有收件人收到邮件，重试前请核实；附件需要重新选择。')
                else:
                    flash('邮件已投递到服务器。收件人点击“收取邮件”后可查看。')
                    return redirect(url_for('inbox'))
        return render_template('compose.html')

    @app.errorhandler(413)
    def too_large(error):
        return render_template('error.html', text='提交内容超过 20 MiB，请减少附件大小后重新发送。'), 413

    return app


def main():
    parser = argparse.ArgumentParser(description='本机 Web 邮件客户端')
    parser.add_argument('--host', default='127.0.0.1', help='SMTP/POP3 服务器地址')
    parser.add_argument('--smtp-port', type=int, default=1587)
    parser.add_argument('--pop-port', type=int, default=1995)
    parser.add_argument('--port', type=int, default=8080, help='本机网页端口')
    parser.add_argument('--ca')
    parser.add_argument('--plain', action='store_true')
    parser.add_argument('--out', default='web-downloads')
    parser.add_argument('--spam-model')
    args = parser.parse_args()
    app = create_app(args.host, args.smtp_port, args.pop_port, args.out,
                     not args.plain, args.ca, args.spam_model)
    app.run(host='127.0.0.1', port=args.port, debug=False, use_reloader=False)


if __name__ == '__main__':
    main()
