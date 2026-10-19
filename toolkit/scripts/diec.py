#!/opt/re/venv/bin/python
"""Detect It Easy command line on top of die-python (the pip package ships no CLI).

Usage: diec [-j] FILE...   (-j prints the engine's JSON; default prints one line per detection)
"""
import json
import sys

import die


def scan(path: str, as_json: bool) -> str:
    flags = die.ScanFlags.RESULT_AS_JSON | die.ScanFlags.DEEP_SCAN
    raw = die.scan_file(path, flags, str(die.database_path))
    if as_json:
        return raw
    lines = [f"{path}:"]
    for detect in json.loads(raw).get("detects", []):
        lines.append(f"  {detect.get('filetype', '?')}")
        lines.extend(f"    {value.get('string', '')}" for value in detect.get("values", []))
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__.strip())
        return 0
    if argv[0] == "--version":
        print(f"diec (die-python, DIE engine {die.die_version})")
        return 0
    as_json = argv[0] == "-j"
    paths = argv[1:] if as_json else argv
    for path in paths:
        print(scan(path, as_json))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
