// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// Shared ML-DSA-87 helpers for the Keyfall benchmark vaults.
abstract contract PQCAuth {
    address internal constant PQC_VERIFY = 0x0000000000000000000000000000000000000a01;
    bytes32 public keyHash;

    error BadPubkey();
    error InvalidPQCSignature();
    error Expired();

    function _checkKey(bytes calldata pubkey) internal view {
        if (pubkey.length != 2592 || keccak256(pubkey) != keyHash) revert BadPubkey();
    }

    function _pqcValid(bytes calldata pubkey, bytes calldata sig, bytes32 d) internal view returns (bool) {
        (bool ok, bytes memory ret) = PQC_VERIFY.staticcall(
            abi.encodeWithSignature("pqcVerify(bytes,bytes,bytes)", pubkey, sig, abi.encodePacked(d))
        );
        return ok && ret.length == 32 && abi.decode(ret, (uint256)) == 1;
    }
}
