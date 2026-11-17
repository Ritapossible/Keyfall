// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title KeyfallRegistry
/// @notice Stores hashes of signed Keyfall scan reports and holds a small treasury.
///         Every state-changing call is authorized by an ML-DSA-87 signature checked
///         through QoreChain's PQC Verify precompile. `msg.sender` is never trusted, so
///         a leaked classical (ECDSA) key grants no privilege here: anyone may relay a
///         call, and only a valid post-quantum signature makes it succeed.
/// @dev    Threat model: the attacker holds the classical key of every account that
///         ever touched this contract, and can see every past calldata (including past
///         PQC signatures). Defences: no msg.sender checks, a strictly increasing nonce,
///         a deadline, and a digest bound to chain id + this contract + action.
contract KeyfallRegistry {
    /// QoreChain PQC Verify precompile: pqcVerify(bytes pubkey, bytes sig, bytes msg) -> bool.
    /// Where inactive it returns empty data; we treat anything but a 32-byte `true` as invalid.
    address public constant PQC_VERIFY = 0x0000000000000000000000000000000000000a01;

    uint256 public constant ML_DSA_87_PUBKEY_LEN = 2592;
    uint256 public constant ML_DSA_87_SIG_LEN = 4627;

    bytes32 public constant DOMAIN_TAG = keccak256("Keyfall.KeyfallRegistry.v1");
    bytes32 public constant ACTION_ANCHOR = keccak256("ANCHOR_REPORT");
    bytes32 public constant ACTION_WITHDRAW = keccak256("WITHDRAW");
    bytes32 public constant ACTION_ROTATE = keccak256("ROTATE_KEY");
    bytes32 public constant ACTION_CANCEL = keccak256("CANCEL");

    /// keccak256 of the controlling ML-DSA-87 public key. The key itself is passed in
    /// calldata (2592 bytes) to avoid storing ~81 slots.
    bytes32 public keyHash;
    uint256 public nonce;

    struct Report {
        address target; // contract that was scanned
        bytes32 targetCodeHash; // extcodehash of the target at scan time
        uint64 blockNumber; // fork block the scan ran against
        uint64 anchoredAt; // timestamp of anchoring
        uint32 findings; // number of findings (0 = empty leak surface found)
    }

    /// reportHash => Report
    mapping(bytes32 => Report) public reports;

    event ReportAnchored(
        bytes32 indexed reportHash, address indexed target, bytes32 targetCodeHash, uint64 blockNumber, uint32 findings
    );
    event Withdrawn(address indexed to, uint256 amount, uint256 nonce);
    event KeyRotated(bytes32 indexed oldKeyHash, bytes32 indexed newKeyHash, uint256 nonce);
    event Deposited(address indexed from, uint256 amount);
    event Cancelled(uint256 nonce);

    error BadPubkey();
    error BadSignatureLength();
    error InvalidPQCSignature();
    error Expired();
    error AlreadyAnchored();
    error TransferFailed();
    error ZeroValue();
    error NotCurrentNonce();

    constructor(bytes32 initialKeyHash) {
        if (initialKeyHash == bytes32(0)) revert BadPubkey();
        keyHash = initialKeyHash;
    }

    receive() external payable {
        emit Deposited(msg.sender, msg.value);
    }

    // ---------------------------------------------------------------- actions

    function anchorReport(
        bytes32 reportHash,
        Report calldata r,
        uint256 deadline,
        bytes calldata pubkey,
        bytes calldata signature
    ) external {
        if (reportHash == bytes32(0)) revert ZeroValue();
        if (reports[reportHash].anchoredAt != 0) revert AlreadyAnchored();
        bytes memory payload = abi.encode(reportHash, r.target, r.targetCodeHash, r.blockNumber, r.findings);
        _authorize(ACTION_ANCHOR, payload, deadline, pubkey, signature);

        reports[reportHash] = Report({
            target: r.target,
            targetCodeHash: r.targetCodeHash,
            blockNumber: r.blockNumber,
            anchoredAt: uint64(block.timestamp),
            findings: r.findings
        });
        emit ReportAnchored(reportHash, r.target, r.targetCodeHash, r.blockNumber, r.findings);
    }

    function withdraw(address payable to, uint256 amount, uint256 deadline, bytes calldata pubkey, bytes calldata signature)
        external
    {
        if (to == address(0) || amount == 0) revert ZeroValue();
        uint256 n = nonce;
        _authorize(ACTION_WITHDRAW, abi.encode(to, amount), deadline, pubkey, signature);
        (bool ok,) = to.call{value: amount}("");
        if (!ok) revert TransferFailed();
        emit Withdrawn(to, amount, n);
    }

    /// @notice Rotate the controlling key. Both the current key and the NEW key must sign the
    ///         same rotation digest (proof of possession), so a typo or an unusable key can
    ///         never brick the registry.
    function rotateKey(
        bytes calldata newPubkey,
        bytes calldata newKeySignature,
        uint256 deadline,
        bytes calldata pubkey,
        bytes calldata signature
    ) external {
        if (newPubkey.length != ML_DSA_87_PUBKEY_LEN) revert BadPubkey();
        if (newKeySignature.length != ML_DSA_87_SIG_LEN) revert BadSignatureLength();
        bytes32 newKeyHash = keccak256(newPubkey);
        if (newKeyHash == keyHash) revert BadPubkey();
        uint256 n = nonce;
        bytes memory payload = abi.encode(newKeyHash);
        // Proof of possession: computed before _authorize bumps the nonce.
        bytes32 d = digest(ACTION_ROTATE, payload, deadline);
        if (!_pqcValid(newPubkey, newKeySignature, d)) revert InvalidPQCSignature();
        _authorize(ACTION_ROTATE, payload, deadline, pubkey, signature);
        bytes32 old = keyHash;
        keyHash = newKeyHash;
        emit KeyRotated(old, newKeyHash, n);
    }

    /// @notice Burn the current nonce, invalidating any signed-but-unsubmitted authorization.
    function cancel(uint256 expectedNonce, uint256 deadline, bytes calldata pubkey, bytes calldata signature) external {
        if (expectedNonce != nonce) revert NotCurrentNonce();
        _authorize(ACTION_CANCEL, abi.encode(expectedNonce), deadline, pubkey, signature);
        emit Cancelled(expectedNonce);
    }

    // ---------------------------------------------------------------- views

    /// @notice The exact 32 bytes the ML-DSA-87 key must sign for the *next* call.
    function digest(bytes32 action, bytes memory payload, uint256 deadline) public view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TAG, block.chainid, address(this), action, nonce, deadline, keccak256(payload)));
    }

    // ---------------------------------------------------------------- internal

    function _authorize(bytes32 action, bytes memory payload, uint256 deadline, bytes calldata pubkey, bytes calldata sig)
        internal
    {
        if (block.timestamp > deadline) revert Expired();
        if (pubkey.length != ML_DSA_87_PUBKEY_LEN || keccak256(pubkey) != keyHash) revert BadPubkey();
        if (sig.length != ML_DSA_87_SIG_LEN) revert BadSignatureLength();

        if (!_pqcValid(pubkey, sig, digest(action, payload, deadline))) revert InvalidPQCSignature();

        // Effects after the check, before any external call in the caller.
        unchecked {
            nonce += 1;
        }
    }

    /// @dev The signed message is the raw 32-byte digest (ML-DSA-87, empty context).
    ///      Fail closed: an inactive precompile returns empty data, and anything but an
    ///      ABI-encoded `true` is rejected.
    function _pqcValid(bytes calldata pubkey, bytes calldata sig, bytes32 d) internal view returns (bool) {
        (bool ok, bytes memory ret) = PQC_VERIFY.staticcall(
            abi.encodeWithSignature("pqcVerify(bytes,bytes,bytes)", pubkey, sig, abi.encodePacked(d))
        );
        return ok && ret.length == 32 && abi.decode(ret, (uint256)) == 1;
    }
}
