# permit-policy

Offline policy checks for ERC-2612 EIP-712 signing requests, intended for wallet and agent-tool integrations.

The checker compares a signing request with a separately trusted policy. It does not verify signatures, deployed contract behavior, or current on-chain state.
