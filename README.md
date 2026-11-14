# permit-policy

Compare an ERC-2612 EIP-712 signing request with a separately trusted policy before a wallet or agent signs it. The checker runs offline and uses only Python's standard library at runtime.

An `allow` result means that the request matches the supplied policy. It does not establish that the token, spender, signature, or transaction is safe. See the [threat model](docs/threat-model.md) for the integration boundary.

## Run a check

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```sh
uv sync
uv run permit-policy check --request examples/request.json --policy examples/policy.json --at-time 1800000000
```

The examples use synthetic addresses and a fixed evaluation time. The first command returns `decision: "allow"` and exits with status 0. To see a rejected spender:

```sh
uv run permit-policy check --request examples/rejected-spender.json --policy examples/policy.json --at-time 1800000000 --format text
```

This command exits with status 1. Read a request from stdin with `--request -`; the policy must remain a separate file:

```sh
cat examples/request.json | uv run python -m permit_policy check --request - --policy examples/policy.json --at-time 1800000000
```

Use an independently supplied current Unix timestamp in an actual signing integration. The examples' timestamp is only a reproducible test value.

| Exit status | Meaning |
|---|---|
| 0 | Request matches the policy |
| 1 | Supported request rejected by policy |
| 2 | Invalid or unsupported input, usage error, or I/O failure |

JSON is the default output. Reports contain `decision`, `findings`, and normalized `permit` fields. Addresses are lowercase, and all normalized numeric values are decimal strings to preserve uint256 precision. Every policy mismatch is reported in a deterministic order. Errors go to stderr without echoing the request.

## Policy

See [examples/policy.json](examples/policy.json) for a complete policy:

| Field | Check |
|---|---|
| `chain_id` | Expected domain chain ID |
| `token` | Expected domain verifying contract |
| `owner` | Expected token owner |
| `spender` | Expected allowance recipient |
| `max_value` | Inclusive maximum allowance, in raw token units |
| `expected_nonce` | Exact expected owner nonce |
| `max_ttl_seconds` | Inclusive maximum of `deadline - at_time` |
| `domain_name` | Optional exact match for the domain name |
| `domain_version` | Optional exact match for the domain version |

The first seven fields are required. Unknown keys are rejected. Numeric values must be uint256 integers or ASCII decimal / `0x` strings; booleans, floats, negatives, and values above `2**256 - 1` are rejected. Addresses must be 20-byte `0x` strings and are compared without regard to letter case. The owner cannot be the zero address.

`deadline == at_time` is valid. A value of zero is accepted when the remaining policy checks pass, but it changes an allowance only after a valid permit is signed and executed. A permit deadline limits submission time; it does not make an installed allowance expire. These semantics follow [ERC-2612](https://eips.ethereum.org/EIPS/eip-2612).

## Supported request format

[examples/request.json](examples/request.json) shows the complete wire format. Only these top-level keys are accepted: `types`, `primaryType`, `domain`, and `message`. `types` must contain exactly `EIP712Domain` and `Permit`, and `primaryType` must be `Permit`.

`Permit` must declare exactly these fields in this order:

```text
owner/address, spender/address, value/uint256, nonce/uint256, deadline/uint256
```

The message must contain exactly those five keys. The domain must include `chainId/uint256` and `verifyingContract/address`. Optional fields are `name/string`, `version/string`, and `salt/bytes32`. Domain declarations must match the supplied values and use this canonical order, skipping omitted fields:

```text
name, version, chainId, verifyingContract, salt
```

This deliberately narrow parser uses the domain fields defined in [EIP-712](https://eips.ethereum.org/EIPS/eip-712). Name and version are policy-bound only when their policy fields are supplied. Salt is schema-validated but is not bound by the policy.

DAI-style permits, Permit2, other typed messages, alternate schemas, extra fields, and noncanonical declaration order are unsupported. JSON documents are limited to 1 MiB of raw UTF-8 bytes each, including stdin. Duplicate keys at any depth, non-integer JSON numbers, NaN/Infinity, and invalid JSON are rejected.

## Python API

```python
import json
from pathlib import Path

from permit_policy.core import check_permit
from permit_policy.validation import InputError

request = json.loads(Path("examples/request.json").read_text())
policy = json.loads(Path("examples/policy.json").read_text())

try:
    report = check_permit(request, policy, at_time=1_800_000_000)
except InputError:
    raise SystemExit("The request or policy is invalid.")

print(report["decision"])
```

`check_permit(typed_data, policy, *, at_time)` receives already parsed objects. Use a strict, size-limited decoder at your own JSON boundary; the API cannot detect duplicate keys discarded by an earlier decoder. Evaluation time must be a non-boolean uint256 integer. The API raises `InputError` for malformed or unsupported inputs and returns a report for supported requests, including policy rejections.

## Integration and development

Keep the policy and evaluation time outside the requesting agent's control. A trusted signer must enforce the result and sign exactly the checked data. Obtain `expected_nonce` from an independent trusted source immediately before use; this checker has no RPC access, nonce reservation, replay protection, or signing capability.

Development checks also require [Task](https://taskfile.dev/). Install project dependencies with `uv sync`, then run:

```sh
task check
```

The task runs Ruff, type checking, and behavior tests. CI runs the same checks on Python 3.11 and 3.13. Security reports are covered by [SECURITY.md](SECURITY.md).
