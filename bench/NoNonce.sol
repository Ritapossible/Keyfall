// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {PQCAuth} from "./PQCAuth.sol";

/// BENCHMARK (vulnerable): withdrawals need a real ML-DSA-87 signature, but the signed digest has
/// no nonce and no deadline. Anyone who has seen one valid withdrawal can submit it again.
/// Expected Keyfall result: Critical (replay of a past PQC authorization drains the vault).
contract NoNonce is PQCAuth {
    event Withdrawn(address indexed to, uint256 amount);

    constructor(bytes32 keyHash_) {
        keyHash = keyHash_;
    }

    receive() external payable {}

    function digest(address to, uint256 amount) public view returns (bytes32) {
        // BUG: no nonce, no deadline.
        return keccak256(abi.encode("NoNonce", block.chainid, address(this), to, amount));
    }

    function withdraw(address payable to, uint256 amount, bytes calldata pubkey, bytes calldata sig) external {
        _checkKey(pubkey);
        if (!_pqcValid(pubkey, sig, digest(to, amount))) revert InvalidPQCSignature();
        (bool ok,) = to.call{value: amount}("");
        require(ok, "transfer failed");
        emit Withdrawn(to, amount);
    }
}
