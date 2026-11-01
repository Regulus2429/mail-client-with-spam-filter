"""Client configuration and readable mailbox listings."""
import json
from pathlib import Path
from email import policy
from email.parser import BytesParser


def configure(parser, commands):
    probe, _ = parser.parse_known_args()
    if not probe.config:
        return
    try:
        data = json.loads(Path(probe.config).read_text(encoding='utf-8-sig'))
        if not isinstance(data, dict):
            raise ValueError('配置必须是 JSON 对象')
        allowed = {'host', 'user', 'ca', 'out', 'spam_model', 'port', 'color'}
        for name, values in data.items():
            if name not in ('send', 'list', 'fetch', 'local-list', 'spam-list', 'view') or not isinstance(values, dict):
                raise ValueError('配置只接受客户端命令及其参数对象')
            actions = {a.dest: a for a in commands[name]._actions}
            for key, value in values.items():
                if key not in allowed or key not in actions:
                    raise ValueError(f'{name} 不支持配置项 {key}')
                if key == 'port':
                    if type(value) is not int or not 1 <= value <= 65535:
                        raise ValueError('port 必须是 1–65535 的整数')
                elif not isinstance(value, str) or not value.strip():
                    raise ValueError(f'{key} 必须是非空字符串')
                if actions[key].choices and value not in actions[key].choices:
                    raise ValueError(f'{key} 的值无效')
            commands[name].set_defaults(**values)
    except (OSError, ValueError) as exc:
        parser.error(f'无法读取配置：{exc}')


def summary(raw):
    msg = BytesParser(policy=policy.default).parsebytes(raw, headersonly=True)
    def clean(value):
        return ''.join(c if c.isprintable() else ' ' for c in str(value))
    return clean(msg.get('From', '(无发件人)')), clean(msg.get('Subject', '(无主题)'))


def local_paths(output, user, folder):
    root = Path(output) / user.lower().encode('utf-8').hex()
    if folder == 'spam':
        root /= 'spam'
    return sorted(root.glob('*.eml'))


def show_local(output, user, folder):
    paths = local_paths(output, user, folder)
    print('编号\t位置\t发件人\t主题')
    for number, path in enumerate(paths, 1):
        sender, subject = summary(path.read_bytes())
        print(f'{number}\t[{"SPAM" if folder == "spam" else "INBOX"}]\t{sender}\t{subject}')
    if not paths:
        print('此本地邮箱暂无邮件')
