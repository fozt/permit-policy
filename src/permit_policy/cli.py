"""Command-line interface for offline permit policy checks."""

import argparse
import json
import sys
from pathlib import Path
from typing import Never

from permit_policy.core import check_permit
from permit_policy.validation import InputError, parse_uint256

MAX_INPUT_BYTES = 1024 * 1024


def _integer_time(value: str) -> int:
    if not value.isascii() or not value.isdecimal():
        raise argparse.ArgumentTypeError("Use a non-negative integer Unix timestamp.")
    try:
        return parse_uint256(value, "Evaluation time")
    except InputError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise InputError("JSON contains duplicate keys. Remove the duplicates.")
        result[key] = value
    return result


def _reject_non_integer(value: str) -> Never:
    raise InputError("JSON numbers must be integers. Use decimal or 0x strings for uint256 values.")


def _read_json(path: str, *, label: str, allow_stdin: bool = False) -> object:
    if path == "-" and not allow_stdin:
        raise InputError("Policy must be a separate JSON file. Set --policy to its path.")
    try:
        if path == "-":
            raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        else:
            with Path(path).open("rb") as stream:
                raw = stream.read(MAX_INPUT_BYTES + 1)
    except OSError:
        raise InputError(f"Could not read {label}. Check the path and permissions.") from None
    if len(raw) > MAX_INPUT_BYTES:
        raise InputError(f"The {label} exceeds 1 MiB. Use a smaller JSON document.")
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_non_integer,
            parse_float=_reject_non_integer,
        )
    except (UnicodeError, ValueError, RecursionError):
        raise InputError(
            f"The {label} is invalid JSON. Use UTF-8 JSON with unique keys and integers."
        ) from None


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="permit-policy",
        description="Compare an ERC-2612 signing request with a trusted policy, offline.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check", help="Check a permit against a policy.")
    check.add_argument(
        "--request", required=True, metavar="REQUEST.json", help="Request file, or - for stdin."
    )
    check.add_argument(
        "--policy", required=True, metavar="POLICY.json", help="Separate trusted policy file."
    )
    check.add_argument(
        "--at-time",
        required=True,
        type=_integer_time,
        metavar="TIMESTAMP",
        help="Evaluation time in Unix seconds.",
    )
    check.add_argument(
        "--format", choices=("json",), default="json", help="Output format (default: json)."
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        request = _read_json(args.request, label="request", allow_stdin=True)
        policy = _read_json(args.policy, label="policy")
        report = check_permit(request, policy, at_time=args.at_time)
    except InputError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except RecursionError:
        print(
            "Error: JSON is too deeply nested. Use a flat ERC-2612 request and policy.",
            file=sys.stderr,
        )
        return 2
    output = json.dumps(report, indent=2, ensure_ascii=True)
    try:
        print(output)
    except OSError:
        print("Error: Could not write the report. Check the output destination.", file=sys.stderr)
        return 2
    return 0 if report["decision"] == "allow" else 1
