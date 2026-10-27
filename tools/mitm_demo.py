"""Controlled POP3 TLS impersonation proxy for certificate-verification demonstrations."""
import argparse
import select
import socket
import socketserver
import ssl


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            with self.server.fake_context.wrap_socket(self.request, server_side=True) as incoming:
                print('客户端接受了代理证书；连接真实服务器', flush=True)
                with socket.create_connection((self.server.upstream_host, self.server.upstream_port), timeout=10) as raw:
                    with self.server.upstream_context.wrap_socket(raw, server_hostname=self.server.upstream_host) as outgoing:
                        while True:
                            readable, _, _ = select.select([incoming, outgoing], [], [], 60)
                            if not readable: break
                            for source in readable:
                                data = source.recv(65536)
                                if not data: return
                                (outgoing if source is incoming else incoming).sendall(data)
        except (OSError, ssl.SSLError) as exc:
            print('连接结束或证书被拒绝:', exc, flush=True)


def main():
    p = argparse.ArgumentParser(description='在受控环境模拟冒充服务器的 POP3 TLS 代理')
    p.add_argument('--listen-host', default='127.0.0.1'); p.add_argument('--listen-port', type=int, default=1996)
    p.add_argument('--upstream-host', default='127.0.0.1'); p.add_argument('--upstream-port', type=int, default=1995)
    p.add_argument('--fake-cert', required=True); p.add_argument('--fake-key', required=True); p.add_argument('--upstream-ca', required=True)
    args = p.parse_args()
    fake = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); fake.load_cert_chain(args.fake_cert, args.fake_key)
    trusted = ssl.create_default_context(cafile=args.upstream_ca)
    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True
    with Server((args.listen_host, args.listen_port), Handler) as server:
        server.fake_context, server.upstream_context = fake, trusted
        server.upstream_host, server.upstream_port = args.upstream_host, args.upstream_port
        print(f'模拟代理监听 {args.listen_host}:{args.listen_port}', flush=True)
        try: server.serve_forever()
        except KeyboardInterrupt: pass


if __name__ == '__main__': main()
