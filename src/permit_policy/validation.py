"""Strict validation shared by the policy checker and CLI."""

import re

UINT256_MAX = 2**256 - 1
_DECIMAL = re.compile(r"[0-9]{1,78}\Z")
_HEX = re.compile(r"0x[0-9a-fA-F]{1,64}\Z")


class InputError(ValueError):
    """The request or policy cannot be evaluated."""


def parse_uint256(value: object, field: str) -> int:
    if isinstance(value, bool):
        raise InputError(f"{field} must be a uint256 integer.")
    if isinstance(value, int):
        result = value
    elif isinstance(value, str) and _DECIMAL.fullmatch(value):
        result = int(value)
    elif isinstance(value, str) and _HEX.fullmatch(value):
        result = int(value, 16)
    else:
        raise InputError(f"{field} must be a uint256 integer.")
    if not 0 <= result <= UINT256_MAX:
        raise InputError(f"{field} must be between 0 and 2**256 - 1.")
    return result
