import argparse
import getpass
import ssl
import sys
import threading
from pathlib import Path
from .storage import Storage
from .usability import configure, summary, local_paths, show_local
from .client import send, connect_pop, list_messages, fetch_messages, inspect_message


def read_password(prompt):
    if sys.stdin.isatty():
        return getpass.getpass(prompt)
    print(prompt, end='', file=sys.stderr, flush=True)
    value = sys.stdin.readline()
    if not value:
        raise EOFError('未收到密码')
    return value.rstrip('\r\n')


def main():
    parser = argparse.ArgumentParser(description='计算机网络课程邮件系统')
    parser.add_argument('--config', help='客户端 JSON 配置文件，放在子命令之前')
    sub = parser.add_subparsers(dest='command', required=True)
    add = sub.add_parser('add-user', help='创建服务端账号')
    add.add_argument('address'); add.add_argument('--data', default='data')
    server = sub.add_parser('server', help='运行 SMTP 和 POP3 服务')
    server.add_argument('--data', default='data'); server.add_argument('--host', default='127.0.0.1')
    server.add_argument('--smtp-port', type=int, default=1587); server.add_argument('--pop-port', type=int, default=1995)
    server.add_argument('--cert'); server.add_argument('--key'); server.add_argument('--plain', action='store_true', help='仅限受控实验网络；密码和邮件明文传输')
    sender = sub.add_parser('send', help='发送邮件')
    sender.add_argument('--host', default='127.0.0.1'); sender.add_argument('--port', type=int, default=1587)
    sender.add_argument('--user'); sender.add_argument('--to', nargs='+', required=True)
    sender.add_argument('--subject', required=True); sender.add_argument('--text', required=True)
    sender.add_argument('--html-file'); sender.add_argument('--attach', nargs='*', default=[])
    sender.add_argument('--plain', action='store_true'); sender.add_argument('--ca')
    for name in ('list', 'fetch'):
        p = sub.add_parser(name, help='列出邮件' if name == 'list' else '下载邮件')
        p.add_argument('--host', default='127.0.0.1'); p.add_argument('--port', type=int, default=1995)
        p.add_argument('--user'); p.add_argument('--plain', action='store_true'); p.add_argument('--ca')
        if name == 'fetch':
            p.add_argument('--out', default='downloads')
            p.add_argument('--spam-model', help='启用过滤，指定本地可信模型文件')
            p.add_argument('--color', choices=('auto', 'always', 'never'), default='auto')
    spam_list = sub.add_parser('spam-list', help='列出本地垃圾箱')
    spam_list.add_argument('--user')
    spam_list.add_argument('--out', default='downloads')
    view = sub.add_parser('view', help='查看本地邮件并可提取附件')
    view.add_argument('path', nargs='?'); view.add_argument('--attachments-dir')
    view.add_argument('--number', type=int, help='当前本地列表中的编号')
    view.add_argument('--user'); view.add_argument('--out', default='downloads')
    view.add_argument('--folder', choices=('inbox', 'spam'), default='inbox')
    local = sub.add_parser('local-list', help='列出已下载的本地邮件')
    local.add_argument('--user'); local.add_argument('--out', default='downloads')
    local.add_argument('--folder', choices=('inbox', 'spam'), default='inbox')
    configure(parser, sub.choices)
    args = parser.parse_args()
    if args.command in ('send', 'list', 'fetch', 'spam-list', 'local-list') and not args.user:
        parser.error('需要 --user 或配置文件中的 user')
    if args.command == 'add-user':
        pw = read_password('密码: ')
        if pw != read_password('再次输入密码: '): raise ValueError('两次密码不一致')
        Storage(args.data).add_user(args.address, pw)
        print('账号已创建:', args.address)
    elif args.command == 'server':
        if args.plain and (args.cert or args.key): parser.error('--plain 不应与证书同时使用')
        if not args.plain and not (args.cert and args.key): parser.error('TLS 模式必须提供 --cert 和 --key')
        tls = None
        if not args.plain:
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls.minimum_version = ssl.TLSVersion.TLSv1_2
            tls.load_cert_chain(args.cert, args.key)
        from .smtp_server import start_smtp
        from .pop3_server import POP3Server
        store = Storage(args.data)
        pop = POP3Server((args.host, args.pop_port), store, tls)
        try:
            smtp = start_smtp(store, args.host, args.smtp_port, tls)
        except BaseException:
            pop.server_close(); raise
        thread = threading.Thread(target=pop.serve_forever, daemon=True); thread.start()
        print(f'SMTP {args.host}:{args.smtp_port}; POP3 {args.host}:{args.pop_port}; 模式: {"明文" if args.plain else "TLS"}', flush=True)
        try:
            while thread.is_alive(): thread.join(1)
        except KeyboardInterrupt:
            print('\n正在停止服务')
        finally:
            pop.shutdown(); pop.server_close(); smtp.stop()
    elif args.command == 'send':
        html = Path(args.html_file).read_text(encoding='utf-8') if args.html_file else None
        send(args.host, args.port, args.user, read_password('密码: '), args.to, args.subject, args.text, html, args.attach, not args.plain, args.ca)
        print('邮件已投递到服务器')
    elif args.command in ('spam-list', 'local-list'):
        show_local(args.out, args.user, 'spam' if args.command == 'spam-list' else args.folder)
    elif args.command in ('list', 'fetch'):
        spam_filter = None
        if args.command == 'fetch' and args.spam_model:
            try:
                from .spam import SpamFilter
                spam_filter = SpamFilter.load(args.spam_model)
            except Exception as exc:
                print(f'警告：过滤不可用，本次新邮件不分类，仍保存原文：{exc}', file=sys.stderr)
        pop = connect_pop(args.host, args.port, args.user, read_password('密码: '), not args.plain, args.ca)
        try:
            if args.command == 'list':
                print('服务器编号\tUID\t大小\t发件人\t主题')
                rows = list_messages(pop)
                for number, uid, size in rows:
                    _, lines, _ = pop.retr(number)
                    sender, subject = summary(b'\r\n'.join(lines))
                    print(f'{number}\t{uid}\t{size} 字节\t{sender}\t{subject}')
                if not rows: print('服务器邮箱暂无邮件')
            else:
                def report(path, label, error):
                    text = f'[{label.upper()}] {path}'
                    if label == 'spam' and (args.color == 'always' or (args.color == 'auto' and sys.stdout.isatty())):
                        text = '\033[31m' + text + '\033[0m'
                    print(text)
                    if error: print(f'警告：邮件未分类：{error}', file=sys.stderr)
                paths = fetch_messages(pop, args.out, args.user, spam_filter, report)
                if spam_filter is None:
                    for path in paths:
                        print(('[UNCLASSIFIED] ' if args.spam_model else '') + str(path))
                print(f'下载 {len(paths)} 封新邮件')
            pop.quit()
        except BaseException:
            pop.close(); raise
    else:
        if (args.path is None) == (args.number is None):
            parser.error('请提供邮件路径或 --number，二者只能选一个')
        if args.number is not None:
            if not args.user: parser.error('按编号查看需要 --user 或配置中的 user')
            paths = local_paths(args.out, args.user, args.folder)
            if not 1 <= args.number <= len(paths): parser.error('编号不存在，请先运行 local-list 或 spam-list')
            args.path = paths[args.number - 1]
        inspect_message(args.path, args.attachments_dir)


if __name__ == '__main__':
    main()
