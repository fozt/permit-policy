# Threat model

## Asset and intended decision

The asset is the token owner's authority to grant an allowance. Before a signature is produced, this checker compares one supported ERC-2612 request with a separately trusted policy. Its output is a policy decision, not authorization to move funds and not a claim about deployed contracts.

The attacker may control the requesting website, an agent's retrieved content, or the typed-data request passed through a tool. They may substitute a chain, token, owner, spender, amount, nonce, deadline, or signing-domain description. They may also provide malformed JSON, misleading declarations, duplicate fields, very large numbers, or excessive input to confuse the integration.

## Trust boundary

The policy, evaluation time, checker installation, and final signer must be trusted independently of the requesting agent. An integration must deny signing after either a policy rejection or an input error. It must pass the exact checked data to the signer and prevent changes between checking and signing.

A separate policy filename is an interface rule, not an operating-system access boundary. If the agent can edit that file, choose the evaluation time, replace the checker, forge its report, or call the signer directly, this tool does not prevent malicious signing. An independent integration must enforce that boundary; v0.1 does not provide wallet integration, sandboxing, or process isolation.

A trusted policy can still be wrong. In particular, allowing an attacker-controlled spender or an excessive amount merely causes the checker to allow that choice consistently. Policies should use raw token units from a trusted source; the checker does not fetch token decimals or infer a human-readable amount.

## Checks provided

For the exact supported schema, the checker compares chain ID, verifying contract, owner, spender, maximum value, expected nonce, expiry, and maximum remaining lifetime. Name and version are checked only when explicitly included in the policy. Address comparison ignores letter case; numeric comparisons retain full uint256 precision.

The parser requires an exact Permit declaration, matching domain declarations and values, and domain binding to both chain ID and verifying contract. Salt, if present, must be bytes32 but has no policy binding. These checks constrain the submitted fields; a name, version, or address in a request does not authenticate a real service or contract.

At the CLI boundary, each UTF-8 JSON document is limited to 1 MiB. Duplicate keys, unsupported numeric values, invalid encodings, invalid JSON, and excessive nesting are handled as input errors. Errors and text findings do not print attacker-controlled request contents. JSON reports intentionally contain normalized permit fields and the actual/expected values of findings, so callers should treat saved reports as request data.

## Remaining risks

**On-chain state and replay.** The checker never calls RPC. The caller supplies `expected_nonce` from a trusted independent source; it can become stale before execution. An allowed report does not reserve a nonce, verify current allowance or balances, stop replay, or guarantee execution. EIP-712 itself does not provide replay protection. ERC-2612 defines a per-owner nonce enforced by a conforming contract, which this tool does not inspect. See [EIP-712](https://eips.ethereum.org/EIPS/eip-712) and [ERC-2612](https://eips.ethereum.org/EIPS/eip-2612).

**Time.** The supplied evaluation time can be stale or wrong. The checker does not read a trusted clock or a block timestamp. A deadline is an inclusive limit for permit submission, not the expiry of the resulting allowance; token spending may remain possible afterward. An untrusted clock can therefore undermine the intended lifetime limit. [ERC-2612](https://eips.ethereum.org/EIPS/eip-2612).

**Signatures and contract behavior.** The checker does not hash typed data, recover a signer, validate a signature, inspect bytecode, verify a domain separator, simulate a transaction, or establish ERC-2612 compliance. A proxy upgrade or nonstandard token may change the meaning of an otherwise matching request. It does not establish the safety of a spender, relayer, token contract, or browser session.

**Unsupported requests.** DAI-style permits, Permit2, alternative EIP-712 declarations, and other signing methods are rejected. A rejection is not a fallback request to another signing method. Extending support requires a separate schema and policy design rather than weakening the existing checks.

## Evaluation

Behavior tests cover matching requests, policy boundaries, multiple mismatches, malformed schemas, strict JSON handling, large integers, CLI exit codes, and request-data disclosure in errors and text output. Examples use synthetic fixed addresses and timestamps. These tests assess the local checker; they do not validate a wallet integration or live token contract.
