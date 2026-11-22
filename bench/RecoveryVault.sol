// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {PQCAuth} from "./PQCAuth.sol";

/// BENCHMARK (vulnerable, two steps): withdrawals are PQC-gated, but there is a "recovery agent"
/// that can sweep the vault, and the owner appoints it with a classical `msg.sender` check.
/// No agent is set at deployment, so no single call drains the vault.
/// Expected Keyfall result: High (owner's leaked key appoints an agent) escalating to
/// Critical as a sequence (appoint the attacker, then sweep).
contract RecoveryVault is PQCAuth {
    address public owner;
    address public recoveryAgent;
    uint256 public nonce;

    event Withdrawn(address indexed to, uint256 amount, uint256 nonce);
    event Recovered(address indexed to, uint256 amount);

    constructor(bytes32 keyHash_) {
        keyHash = keyHash_;
        owner = msg.sender;
    }

    receive() external payable {}

    /// BUG: a classical key appoints an account that can move funds.
    function setRecoveryAgent(address agent) external {
        require(msg.sender == owner, "not owner");
        recoveryAgent = agent;
    }

    function recover(address payable to) external {
        require(recoveryAgent != address(0) && msg.sender == recoveryAgent, "not agent");
        uint256 amount = address(this).balance;
        (bool ok,) = to.call{value: amount}("");
        require(ok, "transfer failed");
        emit Recovered(to, amount);
    }

    function digest(bytes32 action, bytes memory payload, uint256 deadline) public view returns (bytes32) {
        return keccak256(abi.encode("RecoveryVault", block.chainid, address(this), action, nonce, deadline, keccak256(payload)));
    }

    function withdraw(address payable to, uint256 amount, uint256 deadline, bytes calldata pubkey, bytes calldata sig)
        external
    {
        if (block.timestamp > deadline) revert Expired();
        _checkKey(pubkey);
        if (!_pqcValid(pubkey, sig, digest(keccak256("WITHDRAW"), abi.encode(to, amount), deadline))) revert InvalidPQCSignature();
        uint256 n = nonce++;
        (bool ok,) = to.call{value: amount}("");
        require(ok, "transfer failed");
        emit Withdrawn(to, amount, n);
    }
}
