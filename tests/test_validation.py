import pytest

from permit_policy.validation import UINT256_MAX, InputError, normalize_address, parse_uint256


@pytest.mark.parametrize("value", [0, "0", "0x0", UINT256_MAX, str(UINT256_MAX), hex(UINT256_MAX)])
def test_uint256_preserves_full_precision(value: object) -> None:
    expected = 0 if value in (0, "0", "0x0") else UINT256_MAX
    assert parse_uint256(value, "value") == expected


@pytest.mark.parametrize(
    "value",
    [
        True,
        False,
        1.0,
        -1,
        UINT256_MAX + 1,
        str(UINT256_MAX + 1),
        "1_000",
        "+1",
        " 1",
        "١",
        "0x",
        "0x" + "f" * 65,
        None,
    ],
)
def test_uint256_rejects_ambiguous_or_out_of_range_values(value: object) -> None:
    with pytest.raises(InputError):
        parse_uint256(value, "value")


def test_address_normalization_preserves_identity() -> None:
    assert normalize_address("0x" + "aB" * 20, "owner") == "0x" + "ab" * 20


@pytest.mark.parametrize("value", ["0x123", "ab" * 20, "0x" + "gg" * 20, True, None])
def test_address_rejects_malformed_identity(value: object) -> None:
    with pytest.raises(InputError):
        normalize_address(value, "owner")
