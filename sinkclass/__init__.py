"""sink-class: classify what an unguarded entry point actually reaches.

Every missing-authorization detector answers "is a guard missing?". None answers
"missing guard in front of WHAT?". A gap whose only consequence is resource
consumption is worth nothing to a coordinator, however good the proof is.

    from sinkclass import classify
    code, why = classify(body, root='/path/to/plugin')
"""

from __future__ import annotations

__version__ = '1.0.0'

from .classify import (IN_SCOPE, MEANING, OUT_OF_SCOPE, UNDECIDED, Verdict,
                       classify, classify_file)

__all__ = ['classify', 'classify_file', 'Verdict', 'MEANING', 'IN_SCOPE',
           'OUT_OF_SCOPE', 'UNDECIDED', '__version__']
