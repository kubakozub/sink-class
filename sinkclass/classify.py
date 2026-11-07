"""Decide what an entry point reaches, and whether that is worth reporting.

Order matters here more than any single pattern. SQL injection outranks
everything. A privileged write outranks the fact that an endpoint is supposed to
be public. A weak write next to a drain is the feature recording its own input,
not a finding. Each of those precedences was wrong once.
"""

from __future__ import annotations

import re
from typing import NamedTuple, Optional, Union

from . import php
from .sinks import (DRAIN, EXT_ALLOWLIST, OPTION_CRITICAL, OPTION_KEYED,
                    PUBLIC_BY_DESIGN, READ, REQ_INPUT, SQL_CALL, SQL_INTERP,
                    SQL_PREPARE, WRITE_KEYED, WRITE_STRONG, WRITE_WEAK)


class Verdict(NamedTuple):
    """Unpacks as (code, why), so `code, why = classify(body)` keeps working."""

    code: str
    why: str


#: What each code means, and what to do about it.
MEANING = {
    'C': 'reads data the caller should not see',
    'I': 'writes state the caller should not write',
    'I?': 'a write that may not cross a privilege boundary',
    'A': 'consumes a resource and nothing more',
    'P': 'public by design, the endpoint has to work unauthenticated',
    '-': 'no recognised sink',
}

IN_SCOPE = frozenset(('C', 'I'))
OUT_OF_SCOPE = frozenset(('A', 'P'))
UNDECIDED = frozenset(('I?', '-'))


def _hits(body: str, table: list) -> list:
    return [label for pattern, label in table if re.search(pattern, body, re.I)]


def _sqli(body: str) -> bool:
    """True when a wpdb call interpolates a variable and nothing prepares it."""
    for match in SQL_CALL.finditer(body):
        fragment = match.group(2)
        if SQL_INTERP.search(fragment) and not SQL_PREPARE.search(fragment):
            return True
    return False


def chain(body: str, root: Optional[Union[str, dict]] = None, depth: int = 1) -> str:
    """The body plus the bodies of what it calls, `depth` levels down.

    The sink is one hop below the handler often enough that classifying the
    handler alone produces "no recognised sink" on code that deletes files.
    """
    text = body
    if root is None or depth <= 0:
        return text
    table = php.index(root) if isinstance(root, str) else root
    for level in range(depth):
        added = []
        for name in php.callees(text):
            sub = table.get(name)
            if sub and len(sub) < php.MAX_BODY and sub not in text:
                added.append(sub)
        if not added:
            break
        text += '\n' + '\n'.join(added)
    return text


def classify(body: str, root: Optional[Union[str, dict]] = None,
             depth: int = 1) -> Verdict:
    """Classify one function body. `root` is a plugin directory or a prebuilt index."""
    text = chain(body, root, depth)

    reads = _hits(text, READ)
    strong = _hits(text, WRITE_STRONG)
    weak = _hits(text, WRITE_WEAK)
    drains = _hits(text, DRAIN)

    if WRITE_KEYED.search(text):
        strong.append('meta write with a request-controlled key, reaching wp_capabilities')
    if OPTION_KEYED.search(text):
        strong.append('option write with a request-controlled NAME, so any option is reachable')
    critical = OPTION_CRITICAL.search(text)
    if critical:
        strong.append('writes the security relevant option %s' % critical.group(3))
    tainted = bool(REQ_INPUT.search(text))

    if _sqli(text):
        return Verdict('C', 'SQL injection: a wpdb call interpolates a variable '
                            'and nothing prepares it')

    # An upload is either an arbitrary file write or a way to fill a disk, and
    # the extension allowlist is the only thing that decides which.
    if any('upload' in d for d in drains) or 'raw upload move' in strong:
        if not EXT_ALLOWLIST.search(text):
            return Verdict('I', 'upload with no extension allowlist anywhere in the '
                                'chain, so an arbitrary file write')
        strong = [w for w in strong if w != 'raw upload move']
        drains = [d for d in drains if 'upload' not in d]
        drains.append('upload behind an extension allowlist')

    # A privileged write wins even on an endpoint that is meant to be public,
    # which is why this test precedes PUBLIC_BY_DESIGN.
    if strong:
        return Verdict('I', 'writes privileged state: ' + ', '.join(sorted(set(strong))))

    public = PUBLIC_BY_DESIGN.search(text)
    if public:
        return Verdict('P', 'public by design: it calls %s(), core defends that path '
                            'itself, and being unauthenticated is the point of the '
                            'endpoint' % public.group(1))

    if weak and drains:
        return Verdict('A', 'resource consumption only: ' + ', '.join(sorted(set(drains)))
                       + ' (with a self scoped ' + weak[0] + '), OUT OF SCOPE')
    if weak:
        return Verdict('I?', 'unprivileged write, a human has to decide: '
                       + ', '.join(sorted(set(weak))))
    if reads:
        if tainted:
            return Verdict('C', 'reads data with a request-controlled scope: '
                           + ', '.join(sorted(set(reads))))
        return Verdict('C', 'reads data: ' + ', '.join(sorted(set(reads))))
    if drains:
        return Verdict('A', 'resource consumption only: '
                       + ', '.join(sorted(set(drains))) + ', OUT OF SCOPE')
    return Verdict('-', 'no recognised sink')


def classify_file(path: str, root: Optional[Union[str, dict]] = None,
                  depth: int = 1) -> list:
    """Classify every function in one PHP file. Returns [(name, Verdict), ...]."""
    with open(path, encoding='utf-8', errors='replace') as handle:
        text = handle.read()
    table = php.index(root) if isinstance(root, str) else root
    return [(name, classify(body, table, depth))
            for name, body in sorted(php.bodies(text).items())]
