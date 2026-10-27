"""A small POP3 server with mailbox locking and transaction-state deletion."""
import socketserver


class POP3Handler(socketserver.StreamRequestHandler):
    def reply(self, text):
        self.wfile.write(text.encode('utf-8') + b'\r\n')

    def handle(self):
        self.connection.settimeout(60)
        self.reply('+OK Course POP3 server ready')
        user = None
        lock = None
        rows = None
        deleted = set()
        try:
            while True:
                line = self.rfile.readline(2049)
                if not line or len(line) > 2048 or not line.endswith(b'\r\n'):
                    break
                try:
                    text = line[:-2].decode('utf-8')
                    parts = text.split()
                except UnicodeDecodeError:
                    self.reply('-ERR Invalid command encoding'); continue
                if not parts:
                    self.reply('-ERR Empty command'); continue
                cmd, args = parts[0].upper(), parts[1:]
                if cmd == 'QUIT' and not args:
                    if rows is not None:
                        self.server.store.delete_mail(user, [rows[i][0] for i in deleted])
                    self.reply('+OK Goodbye'); break
                if rows is None:
                    if cmd == 'USER' and len(args) == 1:
                        user = self.server.store.normalize(args[0]); self.reply('+OK User accepted')
                    elif cmd == 'PASS' and ' ' in text and user:
                        password = text.partition(' ')[2]
                        if not self.server.store.authenticate(user, password):
                            user = None; self.reply('-ERR Authentication failed'); continue
                        lock = self.server.store.mailbox_lock(user)
                        if not lock.acquire(blocking=False):
                            lock = None; user = None; self.reply('-ERR Mailbox locked'); continue
                        rows = self.server.store.list_mail(user)
                        self.reply('+OK Mailbox ready')
                    else:
                        self.reply('-ERR Authenticate with USER and PASS')
                    continue
                active = [i for i in range(len(rows)) if i not in deleted]
                if cmd == 'STAT' and not args:
                    self.reply(f'+OK {len(active)} {sum(rows[i][2] for i in active)}')
                elif cmd in ('LIST', 'UIDL') and len(args) <= 1:
                    if args:
                        i = self.index(args[0], rows, deleted)
                        if i is None: self.reply('-ERR No such message'); continue
                        self.reply(f'+OK {i+1} {rows[i][2] if cmd == "LIST" else rows[i][0]}')
                    else:
                        self.reply('+OK Mailbox listing follows')
                        for i in active:
                            self.reply(f'{i+1} {rows[i][2] if cmd == "LIST" else rows[i][0]}')
                        self.reply('.')
                elif cmd == 'RETR' and len(args) == 1:
                    i = self.index(args[0], rows, deleted)
                    if i is None: self.reply('-ERR No such message'); continue
                    raw = self.server.store.read_mail(rows[i][1])
                    self.reply(f'+OK {len(raw)} octets')
                    for content in raw[:-2].split(b'\r\n'):
                        self.wfile.write((b'.' if content.startswith(b'.') else b'') + content + b'\r\n')
                    self.wfile.write(b'.\r\n')
                elif cmd == 'DELE' and len(args) == 1:
                    i = self.index(args[0], rows, deleted)
                    if i is None: self.reply('-ERR No such message'); continue
                    deleted.add(i); self.reply('+OK Marked for deletion')
                elif cmd == 'RSET' and not args:
                    deleted.clear(); self.reply('+OK Deletions reset')
                elif cmd == 'NOOP' and not args:
                    self.reply('+OK')
                else:
                    self.reply('-ERR Unknown command or invalid arguments')
        except (ConnectionError, OSError):
            pass
        finally:
            if lock is not None:
                lock.release()

    @staticmethod
    def index(value, rows, deleted):
        try: i = int(value) - 1
        except ValueError: return None
        return i if 0 <= i < len(rows) and i not in deleted else None


class POP3Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, store, tls_context=None):
        self.store = store
        self.tls_context = tls_context
        super().__init__(address, POP3Handler)

    def get_request(self):
        sock, addr = super().get_request()
        if self.tls_context:
            try:
                sock.settimeout(10)
                sock = self.tls_context.wrap_socket(sock, server_side=True)
            except Exception:
                sock.close()
                raise
        return sock, addr
