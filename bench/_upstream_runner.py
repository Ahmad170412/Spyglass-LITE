"""Run upstream Spyglass in a child process and print one JSON document.

``spyglass.username`` prints a rich console report while it works, so the
benchmark marks the JSON payload and reads only what follows the marker.
"""

from __future__ import annotations

import json
import sys


def main() -> int:
    handle = sys.argv[1]
    from spyglass.username import username

    result = username(handle)
    print("---SGJSON---")
    print(json.dumps(result, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
