"""Just enough PHP reading to find a function body and the names it calls.

This is not a parser and does not try to be. It needs two things: the text
between a function's braces, and the set of names that text calls, so a sink one
hop down is still visible.
"""

from __future__ import annotations

import os
import re

# Follow plain calls AND method calls. A real allowlist once lived behind
# `Reviews::is_valid_file_type(...)`, and a lookbehind that excluded `::` and
# `->` made the classifier blind to it, so it called a gated upload an arbitrary
# file write. The guard, or in this case the mitigation, is in the callee more
# often than not.
CALL = re.compile(r'(?:(?<![\w:>$])|::|->)\s*([a-zA-Z_]\w{3,})\s*\(')

# Language and output plumbing. Following these wastes the depth budget and adds
# noise to every chain.
SKIP_CALLS = frozenset((
    'array', 'count', 'isset', 'empty', 'esc_html', 'esc_attr', 'esc_url',
    'sprintf', 'printf', 'implode', 'explode', 'sanitize_text_field',
    'sanitize_key', 'absint', 'intval', 'strval', 'json_encode', 'json_decode',
    'wp_json_encode', 'apply_filters', 'do_action', '__', '_e', 'is_array',
    'is_string', 'in_array', 'str_replace', 'preg_match', 'preg_replace',
    'trim', 'wp_send_json_success', 'wp_send_json_error', 'wp_send_json',
    'defined', 'function_exists', 'class_exists', 'method_exists', 'sizeof',
    'strlen', 'substr', 'strpos', 'date', 'time',
))

SKIP_DIRS = ('node_modules', 'vendor', 'tests', '.git', 'languages')

FUNCTION = re.compile(r'function\s+([a-zA-Z_]\w*)\s*\([^)]*\)[^{;]*\{')

# A body longer than this is almost always a whole file that failed to close, and
# appending it to a chain buries the real sink in noise.
MAX_BODY = 20000


def bodies(text: str) -> dict:
    """Map function name to body text, by brace matching. Tolerates closures."""
    out: dict = {}
    for match in FUNCTION.finditer(text):
        name, start, depth = match.group(1), match.end() - 1, 0
        for pos in range(start, min(len(text), start + 200000)):
            char = text[pos]
            if char == '{':
                depth += 1
            elif char == '}':
                depth -= 1
                if depth == 0:
                    out.setdefault(name, text[start + 1:pos])
                    break
    return out


def index(root: str, cap: int = 1200) -> dict:
    """Map name to body across a whole tree, so a callee in another file resolves.

    `cap` bounds the number of PHP files read. A plugin with more files than that
    is indexed partially rather than slowly, which is the right trade for a tool
    meant to run while someone is reading code.
    """
    found: dict = {}
    seen = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in sorted(filenames):
            if not name.endswith('.php'):
                continue
            seen += 1
            if seen > cap:
                return found
            try:
                with open(os.path.join(dirpath, name), encoding='utf-8',
                          errors='replace') as handle:
                    found.update(bodies(handle.read()))
            except OSError:
                pass
    return found


def callees(body: str) -> set:
    """Names called by this body, minus the plumbing."""
    return set(CALL.findall(body)) - SKIP_CALLS
