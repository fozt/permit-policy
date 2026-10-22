# Implementation contract

## Purpose

Before a wallet or agent signs an ERC-2612 permit, compare its typed data with a separately trusted policy. The initial version supports only the exact standard Permit schema; DAI-style permits and Permit2 are unsupported.

## Inputs

- EIP-712 typed-data JSON with `types`, `primaryType`, `domain`, and `message`.
- Policy JSON with exactly these required fields: `chain_id`, `token`, `owner`, `spender`, `max_value`, `expected_nonce`, `max_ttl_seconds`. Numeric values are uint256 integers or decimal / 0x strings; booleans are rejected. Addresses are 20-byte 0x strings, compared case-insensitively.
- An explicit integer evaluation time, `at_time`, in Unix seconds. `deadline == at_time` remains valid. `max_ttl_seconds` limits how far in the future a signature may expire.

`primaryType` must be `Permit`, with fields in order: owner/address, spender/address, value/uint256, nonce/uint256, deadline/uint256. Domain must bind `chainId` and `verifyingContract`; declared domain fields must agree exactly with actual domain values, using canonical EIP-712 field order and correct field types. Permit fields and actual message keys must agree exactly. Reject ambiguous, unsupported, or malformed inputs. Domain may include name/string, version/string, and salt/bytes32, but cannot omit chainId or verifyingContract. Optional policy `domain_name` and `domain_version`, when present, bind those fields too. These checks do not authenticate the domain or contract. Reject unknown policy keys to catch typos.

## Shared API

`permit_policy.core.check_permit(typed_data: object, policy: object, *, at_time: int) -> dict[str, object]`

Malformed or unsupported input raises `permit_policy.validation.InputError` (a ValueError). Valid, supported requests return a report, even if rejected by policy. Report keys:

- `decision`: `allow` or `reject`.
- `findings`: list of dictionaries with `code`, `field`, `message`, `actual`, `expected`.
- `permit`: dictionary with normalized `chain_id`, `token`, `owner`, `spender`, `value`, `nonce`, `deadline`. Addresses lowercase; numeric values decimal strings (including chain_id) to preserve full uint256 precision in JSON consumers.

Mismatch finding codes: `chain_mismatch`, `token_mismatch`, `owner_mismatch`, `spender_mismatch`, `value_exceeds_limit`, `nonce_mismatch`, `permit_expired`, `ttl_exceeds_limit`, `domain_name_mismatch`, `domain_version_mismatch`. Zero-value revocations are accepted if all other checks pass. Every mismatch is reported in deterministic order. `allow` means matching the policy only.

## CLI

`permit-policy check --request REQUEST.json --policy POLICY.json --at-time TIMESTAMP [--format json|text]`

Request may be read from stdin with `--request -`; policy must be a separate file. Default output is JSON. Exit 0 for matching policy; 1 for policy rejection; 2 for invalid input or IO failure. Errors go to stderr without traceback or raw request disclosure. Reject duplicate JSON keys, NaN/Infinity, and oversized input (1 MiB per file). No network access. Preserve arbitrary-precision integers through parsing and output.

## Acceptance checks

- Happy path, each policy boundary, exact deadline and maximum value boundary, zero-value revocation, case-insensitive addresses.
- Wrong chain/token/spender/owner/nonce, expired or overlong permit, and multiple simultaneous mismatches.
- Reject bool/float/negative/oversized uint256 values, malformed addresses, different Permit schemas, DAI/Permit2, missing domain binding, type/value disagreement, unknown fields, duplicate JSON keys, and malformed files.
- Deterministic report, CLI exit codes/stdin/text output, no tracebacks for invalid input, no network or key material required.
- `task check` passes. README documents exact commands, data formats, trust boundary, supported/unsupported cases, and primary specifications. Examples are synthetic. A short threat model describes what the checker can and cannot establish.

