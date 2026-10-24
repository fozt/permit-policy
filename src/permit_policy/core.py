"""Compare supported ERC-2612 requests with a separately trusted policy."""

import re
from dataclasses import dataclass
from typing import cast

from permit_policy.validation import InputError, normalize_address, parse_uint256

_PERMIT_FIELDS = [
    {"name": "owner", "type": "address"},
    {"name": "spender", "type": "address"},
    {"name": "value", "type": "uint256"},
    {"name": "nonce", "type": "uint256"},
    {"name": "deadline", "type": "uint256"},
]
_DOMAIN_TYPES = {
    "name": "string",
    "version": "string",
    "chainId": "uint256",
    "verifyingContract": "address",
    "salt": "bytes32",
}
_POLICY_REQUIRED = {
    "chain_id",
    "token",
    "owner",
    "spender",
    "max_value",
    "expected_nonce",
    "max_ttl_seconds",
}
_POLICY_OPTIONAL = {"domain_name", "domain_version"}
_BYTES32 = re.compile(r"0x[0-9a-fA-F]{64}\Z")
_ZERO_ADDRESS = "0x" + "0" * 40


@dataclass(frozen=True)
class _Policy:
    chain_id: int
    token: str
    owner: str
    spender: str
    max_value: int
    expected_nonce: int
    max_ttl_seconds: int
    domain_name: str | None
    domain_version: str | None


@dataclass(frozen=True)
class _Permit:
    chain_id: int
    token: str
    owner: str
    spender: str
    value: int
    nonce: int
    deadline: int
    domain_name: str | None
    domain_version: str | None

    def as_report(self) -> dict[str, str]:
        return {
            "chain_id": str(self.chain_id),
            "token": self.token,
            "owner": self.owner,
            "spender": self.spender,
            "value": str(self.value),
            "nonce": str(self.nonce),
            "deadline": str(self.deadline),
        }


def _object(value: object, field: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise InputError(f"{field} must be a JSON object with named fields.")
    return cast(dict[str, object], value)


def _keys(
    value: dict[str, object], field: str, required: set[str], optional: set[str] | None = None
) -> None:
    allowed = required | (optional or set())
    if not required <= value.keys() or not value.keys() <= allowed:
        raise InputError(f"{field} has missing or unsupported fields.")


def _optional_string(value: dict[str, object], key: str, field: str) -> str | None:
    if key not in value:
        return None
    result = value[key]
    if not isinstance(result, str):
        raise InputError(f"{field}.{key} must be a string.")
    return result


def _owner(value: object, field: str) -> str:
    result = normalize_address(value, field)
    if result == _ZERO_ADDRESS:
        raise InputError(f"{field} must not be the zero address.")
    return result


def _parse_policy(value: object) -> _Policy:
    policy = _object(value, "policy")
    _keys(policy, "policy", _POLICY_REQUIRED, _POLICY_OPTIONAL)
    return _Policy(
        chain_id=parse_uint256(policy["chain_id"], "policy.chain_id"),
        token=normalize_address(policy["token"], "policy.token"),
        owner=_owner(policy["owner"], "policy.owner"),
        spender=normalize_address(policy["spender"], "policy.spender"),
        max_value=parse_uint256(policy["max_value"], "policy.max_value"),
        expected_nonce=parse_uint256(policy["expected_nonce"], "policy.expected_nonce"),
        max_ttl_seconds=parse_uint256(policy["max_ttl_seconds"], "policy.max_ttl_seconds"),
        domain_name=_optional_string(policy, "domain_name", "policy"),
        domain_version=_optional_string(policy, "domain_version", "policy"),
    )


def _parse_permit(value: object) -> _Permit:
    request = _object(value, "request")
    _keys(request, "request", {"types", "primaryType", "domain", "message"})
    if request["primaryType"] != "Permit":
        raise InputError("Only the standard ERC-2612 Permit type is supported.")
    types = _object(request["types"], "types")
    _keys(types, "types", {"EIP712Domain", "Permit"})
    if types["Permit"] != _PERMIT_FIELDS:
        raise InputError("Use the exact ERC-2612 Permit fields and field order.")

    domain = _object(request["domain"], "domain")
    _keys(domain, "domain", {"chainId", "verifyingContract"}, set(_DOMAIN_TYPES))
    expected_domain = [
        {"name": name, "type": field_type}
        for name, field_type in _DOMAIN_TYPES.items()
        if name in domain
    ]
    if types["EIP712Domain"] != expected_domain:
        raise InputError("Domain fields and types must match in standard EIP-712 order.")
    domain_name = _optional_string(domain, "name", "domain")
    domain_version = _optional_string(domain, "version", "domain")
    if "salt" in domain and (
        not isinstance(domain["salt"], str) or not _BYTES32.fullmatch(domain["salt"])
    ):
        raise InputError("domain.salt must be a 32-byte 0x value.")

    message = _object(request["message"], "message")
    _keys(message, "message", {field["name"] for field in _PERMIT_FIELDS})
    return _Permit(
        chain_id=parse_uint256(domain["chainId"], "domain.chainId"),
        token=normalize_address(domain["verifyingContract"], "domain.verifyingContract"),
        owner=_owner(message["owner"], "message.owner"),
        spender=normalize_address(message["spender"], "message.spender"),
        value=parse_uint256(message["value"], "message.value"),
        nonce=parse_uint256(message["nonce"], "message.nonce"),
        deadline=parse_uint256(message["deadline"], "message.deadline"),
        domain_name=domain_name,
        domain_version=domain_version,
    )


def check_permit(typed_data: object, policy: object, *, at_time: int) -> dict[str, object]:
    """Report policy mismatches without authenticating a signature or chain state."""
    if isinstance(at_time, bool) or not isinstance(at_time, int):
        raise InputError("at_time must be an integer Unix timestamp.")
    parse_uint256(at_time, "at_time")
    expected = _parse_policy(policy)
    permit = _parse_permit(typed_data)
    findings: list[dict[str, object]] = []

    def add(code: str, field: str, message: str, actual: object, expected: object) -> None:
        findings.append(
            {
                "code": code,
                "field": field,
                "message": message,
                "actual": actual,
                "expected": expected,
            }
        )

    for code, field, message, actual, wanted in (
        (
            "chain_mismatch",
            "domain.chainId",
            "Chain does not match the policy.",
            str(permit.chain_id),
            str(expected.chain_id),
        ),
        (
            "token_mismatch",
            "domain.verifyingContract",
            "Token does not match the policy.",
            permit.token,
            expected.token,
        ),
        (
            "owner_mismatch",
            "message.owner",
            "Owner does not match the policy.",
            permit.owner,
            expected.owner,
        ),
        (
            "spender_mismatch",
            "message.spender",
            "Spender does not match the policy.",
            permit.spender,
            expected.spender,
        ),
    ):
        if actual != wanted:
            add(code, field, message, actual, wanted)
    return {
        "decision": "reject" if findings else "allow",
        "findings": findings,
        "permit": permit.as_report(),
    }
