import argparse
import json


def main():
    parser = argparse.ArgumentParser(description='All Blue — local SDN firewall')
    parser.add_argument('--runtime', default='runtime')
    sub = parser.add_subparsers(dest='command', required=True)
    controller = sub.add_parser('controller')
    controller.add_argument('--policy', default='config/lab.json')
    controller.add_argument('--port', type=int, default=6653)
    controller.add_argument('--log-port', type=int, default=9020)
    controller.add_argument('--escalation', help='Local escalation configuration; omitted means disabled')
    controller.add_argument('--verbose', action='store_true', help='Bounded live enforcement and audit diagnostics')
    logger = sub.add_parser('logger')
    logger.add_argument('--port', type=int, default=9020)
    logger.add_argument('--verbose', action='store_true', help='Bounded live TCP and SQLite diagnostics')
    dashboard = sub.add_parser('dashboard')
    dashboard.add_argument('--port', type=int, default=8080)
    for action in ('block', 'release'):
        sub.add_parser(action).add_argument('host')
    sub.add_parser('mode').add_argument('mode', choices=('off', 'observe', 'enforce'))
    sub.add_parser('status')
    args = parser.parse_args()
    if args.command == 'controller':
        from .controller import run_controller
        run_controller(args.policy, args.runtime, args.port, args.log_port, args.escalation, args.verbose)
    elif args.command == 'logger':
        from .audit import run_logger
        run_logger(args.runtime, args.port, args.verbose)
    elif args.command == 'dashboard':
        from .dashboard import run_dashboard
        run_dashboard(args.runtime, args.port)
    elif args.command == 'status':
        from .dashboard import presentation
        print(json.dumps(presentation(args.runtime), indent=2))
    else:
        from .admin import request
        details = dict(mode=args.mode) if args.command == 'mode' else dict(host=args.host)
        print(json.dumps(request(args.runtime, args.command, **details), indent=2))


if __name__ == '__main__':
    main()
