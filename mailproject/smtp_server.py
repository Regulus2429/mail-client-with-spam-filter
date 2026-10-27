"""SMTP server based on aiosmtpd."""
import hmac
import socket
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import AuthResult


class SMTPHandler:
    def __init__(self, store):
        self.store = store

    async def handle_MAIL(self, server, session, envelope, address, mail_options):
        # Users may only send using their own envelope address.
        if not session.authenticated or not address.isascii() or not hmac.compare_digest(address.lower(), session.auth_data):
            return '550 Sender must match authenticated account'
        envelope.mail_from = address
        envelope.mail_options.extend(mail_options)
        return '250 OK'

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        if not self.store.has_user(address):
            return '550 No such local user'
        envelope.rcpt_tos.append(address)
        return '250 OK'

    async def handle_DATA(self, server, session, envelope):
        self.store.deliver(envelope.mail_from, envelope.rcpt_tos, envelope.original_content)
        return '250 Message accepted'


class MailController(Controller):
    def _trigger_server(self):
        # On Windows connecting to the wildcard bind address fails. Probe loopback instead.
        if self.hostname == '0.0.0.0':
            with socket.create_connection(('127.0.0.1', self.port), 1.0) as sock:
                sock.recv(1024)
        else:
            super()._trigger_server()


def start_smtp(store, host, port, tls_context=None):
    def auth(server, session, envelope, mechanism, data):
        try:
            name = data.login.decode('utf-8')
            password = data.password.decode('utf-8')
            if store.authenticate(name, password):
                return AuthResult(success=True, auth_data=store.normalize(name))
        except (UnicodeError, AttributeError):
            pass
        return AuthResult(success=False, handled=False)
    controller = MailController(SMTPHandler(store), hostname=host, port=port,
                            authenticator=auth, auth_required=True,
                            auth_require_tls=bool(tls_context), tls_context=tls_context,
                            require_starttls=bool(tls_context), decode_data=False)
    controller.start()
    return controller
