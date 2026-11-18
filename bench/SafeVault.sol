// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {PQCAuth} from "./PQCAuth.sol";

/// BENCHMARK (correct): every sensitive action needs an ML-DSA-87 signature over a digest bound to
/// chain id, contract, action, nonce and deadline. msg.sender is never trusted.
/// Expected Keyfall result: empty leak surface.
contract SafeVault is PQCAuth {
    address public guardian;
    uint256 public nonce;

    event Withdrawn(address indexed to, uint256 amount, uint256 nonce);
    event GuardianSet(address guardian);

    constructor(bytes32 keyHash_, address guardian_) {
        keyHash = keyHash_;
        guardian = guardian_;
    }

    receive() external payable {}

    function digest(bytes32 action, bytes memory payload, uint256 deadline) public view returns (bytes32) {
        return keccak256(abi.encode("SafeVault", block.chainid, address(this), action, nonce, deadline, keccak256(payload)));
    }

    function withdraw(address payable to, uint256 amount, uint256 deadline, bytes calldata pubkey, bytes calldata sig)
        external
    {
        uint256 n = nonce;
        _auth(keccak256("WITHDRAW"), abi.encode(to, amount), deadline, pubkey, sig);
        (bool ok,) = to.call{value: amount}("");
        require(ok, "transfer failed");
        emit Withdrawn(to, amount, n);
    }

    function setGuardian(address g, uint256 deadline, bytes calldata pubkey, bytes calldata sig) external {
        _auth(keccak256("SET_GUARDIAN"), abi.encode(g), deadline, pubkey, sig);
        guardian = g;
        emit GuardianSet(g);
    }

    function _auth(bytes32 action, bytes memory payload, uint256 deadline, bytes calldata pubkey, bytes calldata sig)
        internal
    {
        if (block.timestamp > deadline) revert Expired();
        _checkKey(pubkey);
        if (!_pqcValid(pubkey, sig, digest(action, payload, deadline))) revert InvalidPQCSignature();
        nonce += 1;
    }
}
