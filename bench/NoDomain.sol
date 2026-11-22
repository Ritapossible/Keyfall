// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {PQCAuth} from "./PQCAuth.sol";

/// BENCHMARK (vulnerable, cross-contract): the signed digest has a nonce and a deadline but does not
/// name the contract or the chain. Two vaults controlled by the same ML-DSA-87 key accept each
/// other's signatures.
/// Expected Keyfall result: Critical (a withdrawal signed for vault A drains vault B),
/// found with `--harvest-from <vault A>`.
contract NoDomain is PQCAuth {
    uint256 public nonce;

    event Withdrawn(address indexed to, uint256 amount, uint256 nonce);

    constructor(bytes32 keyHash_) {
        keyHash = keyHash_;
    }

    receive() external payable {}

    function digest(address to, uint256 amount, uint256 deadline) public view returns (bytes32) {
        // BUG: no address(this), no block.chainid.
        return keccak256(abi.encode("WITHDRAW", to, amount, nonce, deadline));
    }

    function withdraw(address payable to, uint256 amount, uint256 deadline, bytes calldata pubkey, bytes calldata sig)
        external
    {
        if (block.timestamp > deadline) revert Expired();
        _checkKey(pubkey);
        if (!_pqcValid(pubkey, sig, digest(to, amount, deadline))) revert InvalidPQCSignature();
        uint256 n = nonce++;
        (bool ok,) = to.call{value: amount}("");
        require(ok, "transfer failed");
        emit Withdrawn(to, amount, n);
    }
}
