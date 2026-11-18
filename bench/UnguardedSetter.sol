// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {PQCAuth} from "./PQCAuth.sol";

/// BENCHMARK (vulnerable): withdrawals are PQC-gated correctly, but the guardian is managed with a
/// classical `msg.sender == owner` check, and the guardian can freeze withdrawals.
/// Expected Keyfall result: High (owner's leaked key replaces the guardian) and
/// Medium (guardian's leaked key freezes the vault).
contract UnguardedSetter is PQCAuth {
    address public owner;
    address public guardian;
    bool public frozen;
    uint256 public nonce;

    event Withdrawn(address indexed to, uint256 amount, uint256 nonce);

    constructor(bytes32 keyHash_, address guardian_) {
        keyHash = keyHash_;
        owner = msg.sender;
        guardian = guardian_;
    }

    receive() external payable {}

    /// BUG: classical authorization of a control change.
    function setGuardian(address g) external {
        require(msg.sender == owner, "not owner");
        guardian = g;
    }

    /// BUG: a classical key can halt the vault.
    function freeze() external {
        require(msg.sender == guardian, "not guardian");
        frozen = true;
    }

    function digest(bytes32 action, bytes memory payload, uint256 deadline) public view returns (bytes32) {
        return keccak256(abi.encode("UnguardedSetter", block.chainid, address(this), action, nonce, deadline, keccak256(payload)));
    }

    function withdraw(address payable to, uint256 amount, uint256 deadline, bytes calldata pubkey, bytes calldata sig)
        external
    {
        require(!frozen, "frozen");
        if (block.timestamp > deadline) revert Expired();
        _checkKey(pubkey);
        if (!_pqcValid(pubkey, sig, digest(keccak256("WITHDRAW"), abi.encode(to, amount), deadline))) revert InvalidPQCSignature();
        uint256 n = nonce++;
        (bool ok,) = to.call{value: amount}("");
        require(ok, "transfer failed");
        emit Withdrawn(to, amount, n);
    }
}
