from copy import deepcopy
from typing import Any, cast

import pytest

from permit_policy.core import check_permit
from permit_policy.validation import UINT256_MAX, InputError

JsonObject = dict[str, Any]
NOW = 1_800_000_000
TOKEN = "0x" + "11" * 20
OWNER = "0x" + "ab" * 20
SPENDER = "0x" + "cd" * 20
OTHER = "0x" + "99" * 20


@pytest.fixture
def request_data() -> JsonObject:
    return {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "Permit": [
                {"name": "owner", "type": "address"},
                {"name": "spender", "type": "address"},
                {"name": "value", "type": "uint256"},
                {"name": "nonce", "type": "uint256"},
                {"name": "deadline", "type": "uint256"},
            ],
        },
        "primaryType": "Permit",
        "domain": {
            "name": "Synthetic Token",
            "version": "1",
            "chainId": 1,
            "verifyingContract": TOKEN,
        },
        "message": {
            "owner": OWNER,
            "spender": SPENDER,
            "value": "1000",
            "nonce": "7",
            "deadline": NOW + 60,
        },
    }


@pytest.fixture
def policy() -> JsonObject:
    return {
        "chain_id": 1,
        "token": TOKEN,
        "owner": OWNER,
        "spender": SPENDER,
        "max_value": 1000,
        "expected_nonce": 7,
        "max_ttl_seconds": 60,
    }


def findings(report: dict[str, object]) -> list[JsonObject]:
    return cast(list[JsonObject], report["findings"])


def test_matches_policy_without_mutating_inputs(
    request_data: JsonObject, policy: JsonObject
) -> None:
    original_request, original_policy = deepcopy(request_data), deepcopy(policy)
    report = check_permit(request_data, policy, at_time=NOW)
    assert report == {
        "decision": "allow",
        "findings": [],
        "permit": {
            "chain_id": "1",
            "token": TOKEN,
            "owner": OWNER,
            "spender": SPENDER,
            "value": "1000",
            "nonce": "7",
            "deadline": str(NOW + 60),
        },
    }
    assert request_data == original_request
    assert policy == original_policy


@pytest.mark.parametrize(
    ("section", "field", "value", "code"),
    [
        ("domain", "chainId", 2, "chain_mismatch"),
        ("domain", "verifyingContract", OTHER, "token_mismatch"),
        ("message", "owner", OTHER, "owner_mismatch"),
        ("message", "spender", OTHER, "spender_mismatch"),
        ("message", "nonce", 8, "nonce_mismatch"),
        ("message", "value", 1001, "value_exceeds_limit"),
        ("message", "deadline", NOW - 1, "permit_expired"),
        ("message", "deadline", NOW + 61, "ttl_exceeds_limit"),
    ],
)
def test_rejects_each_policy_mismatch(
    request_data: JsonObject,
    policy: JsonObject,
    section: str,
    field: str,
    value: object,
    code: str,
) -> None:
    request_data[section][field] = value
    report = check_permit(request_data, policy, at_time=NOW)
    assert report["decision"] == "reject"
    assert [finding["code"] for finding in findings(report)] == [code]


@pytest.mark.parametrize("deadline", [NOW, NOW + 60])
def test_deadline_and_ttl_inclusive_boundaries(
    request_data: JsonObject, policy: JsonObject, deadline: int
) -> None:
    request_data["message"]["deadline"] = deadline
    assert check_permit(request_data, policy, at_time=NOW)["decision"] == "allow"


def test_zero_ttl_accepts_only_current_deadline(
    request_data: JsonObject, policy: JsonObject
) -> None:
    policy["max_ttl_seconds"] = 0
    request_data["message"]["deadline"] = NOW
    assert check_permit(request_data, policy, at_time=NOW)["decision"] == "allow"
    request_data["message"]["deadline"] = NOW + 1
    assert (
        findings(check_permit(request_data, policy, at_time=NOW))[0]["code"] == "ttl_exceeds_limit"
    )


@pytest.mark.parametrize("amount", [0, 1000, UINT256_MAX])
def test_amount_and_revocation_boundaries(
    request_data: JsonObject, policy: JsonObject, amount: int
) -> None:
    request_data["message"]["value"] = hex(amount)
    policy["max_value"] = str(amount)
    report = check_permit(request_data, policy, at_time=NOW)
    assert report["decision"] == "allow"
    assert cast(JsonObject, report["permit"])["value"] == str(amount)


def test_large_numbers_remain_exact(request_data: JsonObject, policy: JsonObject) -> None:
    request_data["domain"]["chainId"] = hex(UINT256_MAX)
    policy["chain_id"] = str(UINT256_MAX)
    request_data["message"].update(value=UINT256_MAX, nonce=UINT256_MAX, deadline=UINT256_MAX)
    policy.update(
        max_value=UINT256_MAX - 1, expected_nonce=UINT256_MAX, max_ttl_seconds=UINT256_MAX
    )
    report = check_permit(request_data, policy, at_time=UINT256_MAX)
    assert len(findings(report)) == 1
    finding = findings(report)[0]
    assert finding["code"] == "value_exceeds_limit"
    assert finding["field"] == "message.value"
    assert finding["actual"] == str(UINT256_MAX)
    assert finding["expected"] == str(UINT256_MAX - 1)
    normalized = cast(JsonObject, report["permit"])
    assert normalized["chain_id"] == str(UINT256_MAX)
    assert normalized["nonce"] == str(UINT256_MAX)
    assert normalized["deadline"] == str(UINT256_MAX)


def test_addresses_are_compared_by_value(request_data: JsonObject, policy: JsonObject) -> None:
    request_data["message"].update(owner="0x" + "AB" * 20, spender="0x" + "CD" * 20)
    report = check_permit(request_data, policy, at_time=NOW)
    assert report["decision"] == "allow"
    normalized = cast(JsonObject, report["permit"])
    assert normalized["owner"] == OWNER
    assert normalized["spender"] == SPENDER


@pytest.mark.parametrize("field", ["owner", "spender", "value", "nonce", "deadline"])
@pytest.mark.parametrize("invalid", [None, True, 1.5, -1, UINT256_MAX + 1, "-1"])
def test_rejects_malformed_message_fields(
    request_data: JsonObject, policy: JsonObject, field: str, invalid: object
) -> None:
    request_data["message"][field] = invalid
    with pytest.raises(InputError):
        check_permit(request_data, policy, at_time=NOW)


@pytest.mark.parametrize("field", ["chain_id", "max_value", "expected_nonce", "max_ttl_seconds"])
@pytest.mark.parametrize("invalid", [None, True, 1.5, -1, UINT256_MAX + 1, "1_000"])
def test_rejects_invalid_policy_numbers(
    request_data: JsonObject, policy: JsonObject, field: str, invalid: object
) -> None:
    policy[field] = invalid
    with pytest.raises(InputError):
        check_permit(request_data, policy, at_time=NOW)


@pytest.mark.parametrize("field", ["token", "owner", "spender"])
def test_rejects_invalid_policy_addresses(
    request_data: JsonObject, policy: JsonObject, field: str
) -> None:
    policy[field] = "0x123"
    with pytest.raises(InputError):
        check_permit(request_data, policy, at_time=NOW)


@pytest.mark.parametrize("invalid", [True, 1.0, "1800000000", -1, UINT256_MAX + 1, None])
def test_evaluation_time_is_an_explicit_uint256_integer(
    request_data: JsonObject, policy: JsonObject, invalid: Any
) -> None:
    with pytest.raises(InputError):
        check_permit(request_data, policy, at_time=invalid)


@pytest.mark.parametrize("zero_in_policy", [False, True])
def test_rejects_zero_owner(
    request_data: JsonObject, policy: JsonObject, zero_in_policy: bool
) -> None:
    if zero_in_policy:
        policy["owner"] = "0x" + "0" * 40
    else:
        request_data["message"]["owner"] = "0x" + "0" * 40
    with pytest.raises(InputError):
        check_permit(request_data, policy, at_time=NOW)


def test_zero_token_or_spender_requires_exact_policy_binding(
    request_data: JsonObject, policy: JsonObject
) -> None:
    zero = "0x" + "0" * 40
    request_data["domain"]["verifyingContract"] = zero
    request_data["message"]["spender"] = zero
    assert check_permit(request_data, policy, at_time=NOW)["decision"] == "reject"
    policy.update(token=zero, spender=zero)
    assert check_permit(request_data, policy, at_time=NOW)["decision"] == "allow"


@pytest.mark.parametrize("key", ["chainId", "verifyingContract"])
def test_rejects_missing_domain_binding(
    request_data: JsonObject, policy: JsonObject, key: str
) -> None:
    del request_data["domain"][key]
    request_data["types"]["EIP712Domain"] = [
        field for field in request_data["types"]["EIP712Domain"] if field["name"] != key
    ]
    with pytest.raises(InputError):
        check_permit(request_data, policy, at_time=NOW)


@pytest.mark.parametrize("invalid", [True, 1.0, -1, UINT256_MAX + 1, "1e9"])
def test_rejects_invalid_chain_id(
    request_data: JsonObject, policy: JsonObject, invalid: object
) -> None:
    request_data["domain"]["chainId"] = invalid
    with pytest.raises(InputError):
        check_permit(request_data, policy, at_time=NOW)


def test_rejects_invalid_domain_contract(request_data: JsonObject, policy: JsonObject) -> None:
    request_data["domain"]["verifyingContract"] = "0x123"
    with pytest.raises(InputError):
        check_permit(request_data, policy, at_time=NOW)


@pytest.mark.parametrize("kind", ["DAI", "Permit2", "custom", "reordered", "missing", "extra"])
def test_rejects_unsupported_permit_schemas(
    request_data: JsonObject, policy: JsonObject, kind: str
) -> None:
    if kind == "DAI":
        request_data["types"]["Permit"] = [
            {"name": "holder", "type": "address"},
            {"name": "spender", "type": "address"},
            {"name": "nonce", "type": "uint256"},
            {"name": "expiry", "type": "uint256"},
            {"name": "allowed", "type": "bool"},
        ]
    elif kind == "Permit2":
        request_data["primaryType"] = "PermitSingle"
    elif kind == "custom":
        request_data["types"]["Permit"][2]["type"] = "uint"
    elif kind == "reordered":
        request_data["types"]["Permit"].reverse()
    elif kind == "missing":
        request_data["types"]["Permit"].pop()
    else:
        request_data["types"]["Permit"][0]["description"] = "not a type field"
    with pytest.raises(InputError):
        check_permit(request_data, policy, at_time=NOW)


@pytest.mark.parametrize("kind", ["reordered", "wrong_type", "missing_value", "extra_value"])
def test_rejects_domain_schema_disagreement(
    request_data: JsonObject, policy: JsonObject, kind: str
) -> None:
    if kind == "reordered":
        request_data["types"]["EIP712Domain"].reverse()
    elif kind == "wrong_type":
        request_data["types"]["EIP712Domain"][2]["type"] = "string"
    elif kind == "missing_value":
        del request_data["domain"]["name"]
    else:
        request_data["domain"]["salt"] = "0x" + "12" * 32
    with pytest.raises(InputError):
        check_permit(request_data, policy, at_time=NOW)


@pytest.mark.parametrize("field", ["name", "version"])
@pytest.mark.parametrize("invalid", [None, 1, True, {}, []])
def test_rejects_nonstring_domain_metadata(
    request_data: JsonObject, policy: JsonObject, field: str, invalid: object
) -> None:
    request_data["domain"][field] = invalid
    with pytest.raises(InputError):
        check_permit(request_data, policy, at_time=NOW)


@pytest.mark.parametrize("field", ["domain_name", "domain_version"])
def test_rejects_nonstring_policy_domain_binding(
    request_data: JsonObject, policy: JsonObject, field: str
) -> None:
    policy[field] = None
    with pytest.raises(InputError):
        check_permit(request_data, policy, at_time=NOW)


@pytest.mark.parametrize("salt", ["0x" + "12" * 32, "0x" + "aB" * 32])
def test_supports_declared_domain_salt(
    request_data: JsonObject, policy: JsonObject, salt: str
) -> None:
    request_data["domain"]["salt"] = salt
    request_data["types"]["EIP712Domain"].append({"name": "salt", "type": "bytes32"})
    assert check_permit(request_data, policy, at_time=NOW)["decision"] == "allow"


@pytest.mark.parametrize("salt", [None, True, "0x12", "0x" + "gg" * 32, "12" * 32])
def test_rejects_malformed_domain_salt(
    request_data: JsonObject, policy: JsonObject, salt: object
) -> None:
    request_data["domain"]["salt"] = salt
    request_data["types"]["EIP712Domain"].append({"name": "salt", "type": "bytes32"})
    with pytest.raises(InputError):
        check_permit(request_data, policy, at_time=NOW)


@pytest.mark.parametrize("section", [None, "types", "domain", "message"])
def test_rejects_unknown_request_fields(
    request_data: JsonObject, policy: JsonObject, section: str | None
) -> None:
    target = request_data if section is None else request_data[section]
    target["ignored"] = "untrusted value"
    with pytest.raises(InputError):
        check_permit(request_data, policy, at_time=NOW)


@pytest.mark.parametrize(
    "key", ["chain_id", "token", "owner", "spender", "max_value", "expected_nonce"]
)
def test_rejects_incomplete_policy(request_data: JsonObject, policy: JsonObject, key: str) -> None:
    del policy[key]
    with pytest.raises(InputError):
        check_permit(request_data, policy, at_time=NOW)


def test_rejects_policy_typo(request_data: JsonObject, policy: JsonObject) -> None:
    policy["max_ttl_second"] = policy["max_ttl_seconds"]
    with pytest.raises(InputError):
        check_permit(request_data, policy, at_time=NOW)


@pytest.mark.parametrize("value", [None, [], "Permit", 1, {1: "secret"}])
def test_invalid_objects_raise_input_error_without_echoing_data(value: object) -> None:
    with pytest.raises(InputError) as error:
        check_permit(value, value, at_time=NOW)
    assert "secret" not in str(error.value)
