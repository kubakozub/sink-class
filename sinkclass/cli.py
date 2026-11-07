"""Command line interface.

The exit code is the product. It lets this run as a gate in front of the work of
writing a report:

    0  something in scope was found (C or I), worth writing up
    1  everything found is out of scope (A or P), do not report it
    3  nothing conclusive (I? or no recognised sink), a human has to look
    2  usage or input error
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__, php
from .classify import (IN_SCOPE, MEANING, OUT_OF_SCOPE, classify,
                       classify_file)

EXIT_IN_SCOPE = 0
EXIT_OUT_OF_SCOPE = 1
EXIT_ERROR = 2
EXIT_UNDECIDED = 3

# Order worst first, so the thing worth reading is at the top of the output.
RANK = {'C': 0, 'I': 1, 'I?': 2, '-': 3, 'P': 4, 'A': 5}

COLOUR = {'C': '\033[1;31m', 'I': '\033[1;31m', 'I?': '\033[33m',
          '-': '\033[90m', 'P': '\033[36m', 'A': '\033[32m'}
RESET = '\033[0m'


def _paint(code: str, colour: bool) -> str:
    if not colour:
        return '%-3s' % code
    return COLOUR.get(code, '') + ('%-3s' % code) + RESET


def _decide(codes) -> int:
    codes = set(codes)
    if codes & IN_SCOPE:
        return EXIT_IN_SCOPE
    if codes & OUT_OF_SCOPE:
        return EXIT_OUT_OF_SCOPE
    return EXIT_UNDECIDED


def _emit(rows, args) -> int:
    """rows: [(where, name, Verdict), ...]"""
    only = set(args.only.split(',')) if args.only else None
    if only:
        rows = [r for r in rows if r[2].code in only]
    rows = sorted(rows, key=lambda r: (RANK.get(r[2].code, 9), r[0], r[1]))

    if args.json:
        print(json.dumps([{'where': w, 'function': n, 'verdict': v.code,
                           'meaning': MEANING[v.code], 'why': v.why}
                          for w, n, v in rows], indent=2))
    else:
        if not rows:
            print('no functions matched')
        for where, name, verdict in rows:
            head = '%s %s' % (_paint(verdict.code, args.colour), name or '(stdin)')
            if where:
                head += '  %s' % where
            print(head)
            print('      %s' % verdict.why)
        counts = {}
        for _, _, verdict in rows:
            counts[verdict.code] = counts.get(verdict.code, 0) + 1
        if counts:
            print('\n' + ', '.join('%s=%d' % (c, counts[c])
                                   for c in sorted(counts, key=lambda k: RANK.get(k, 9))))
    return _decide(v.code for _, _, v in rows)


def command_body(args) -> int:
    body = sys.stdin.read()
    if not body.strip():
        print('nothing on stdin', file=sys.stderr)
        return EXIT_ERROR
    verdict = classify(body, args.root, args.depth)
    return _emit([('', '', verdict)], args)


def command_file(args) -> int:
    if not os.path.isfile(args.path):
        print('not a file: %s' % args.path, file=sys.stderr)
        return EXIT_ERROR
    root = args.root or os.path.dirname(os.path.abspath(args.path))
    rows = [(args.path, name, verdict)
            for name, verdict in classify_file(args.path, root, args.depth)]
    return _emit(rows, args)


def command_scan(args) -> int:
    if not os.path.isdir(args.path):
        print('not a directory: %s' % args.path, file=sys.stderr)
        return EXIT_ERROR
    table = php.index(args.root or args.path)
    rows = []
    for dirpath, dirnames, filenames in os.walk(args.path):
        dirnames[:] = [d for d in dirnames if d not in php.SKIP_DIRS]
        for name in sorted(filenames):
            if not name.endswith('.php'):
                continue
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, args.path)
            for func, verdict in classify_file(path, table, args.depth):
                rows.append((rel, func, verdict))
    return _emit(rows, args)


def command_verdicts(args) -> int:
    width = max(len(c) for c in MEANING)
    for code in sorted(MEANING, key=lambda k: RANK.get(k, 9)):
        where = ('in scope' if code in IN_SCOPE else
                 'OUT OF SCOPE' if code in OUT_OF_SCOPE else 'undecided')
        print('%s  %-14s %s' % (('%-*s' % (width, code)), where, MEANING[code]))
    return EXIT_IN_SCOPE


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument('--root', help='plugin directory to resolve callees against '
                                      '(default: the directory of the input)')
    common.add_argument('--depth', type=int, default=1,
                        help='how many call levels to follow (default: 1)')
    common.add_argument('--json', action='store_true', help='machine readable output')
    common.add_argument('--only', help='show only these verdicts, e.g. --only C,I')
    common.add_argument('--no-colour', dest='colour', action='store_false',
                        default=True, help='plain output')

    parser = argparse.ArgumentParser(
        prog='sink-class',
        description='Classify what an unguarded entry point actually reaches.')
    parser.add_argument('--version', action='version', version=__version__)
    sub = parser.add_subparsers(dest='command', required=True)

    body = sub.add_parser('body', parents=[common],
                          help='classify a function body read from stdin')
    body.set_defaults(func=command_body)

    one = sub.add_parser('file', parents=[common],
                         help='classify every function in one PHP file')
    one.add_argument('path')
    one.set_defaults(func=command_file)

    tree = sub.add_parser('scan', parents=[common],
                          help='classify every function in a tree, worst first')
    tree.add_argument('path')
    tree.set_defaults(func=command_scan)

    codes = sub.add_parser('verdicts', parents=[common],
                           help='explain the verdict codes')
    codes.set_defaults(func=command_verdicts)

    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if not sys.stdout.isatty():
        args.colour = False
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130
    except OSError as error:
        print('read failed: %s' % error, file=sys.stderr)
        return EXIT_ERROR


if __name__ == '__main__':
    raise SystemExit(main())
