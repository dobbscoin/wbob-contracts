// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "./WBob.sol";

/**
 * @title BridgeControllerV2
 * @notice Replacement controller for the existing wBOB token (the token is NOT
 *         redeployed; the Safe moves BRIDGE_EXECUTOR_ROLE from V1 to this).
 *
 * Changes from V1 (2026-11 review):
 *   - Replay protection on the SOURCE OUTPOINT (chainId, txHash, vout), not only
 *     on the opaque depositId: one Dobbscoin output can never mint twice, even if
 *     a DB writer pairs it with a new recipient and a freshly computed depositId.
 *     V1's minted outpoints are imported, then sealed; minting is disabled until
 *     the seal. Marking an outpoint can only BLOCK a mint, so the admin may keep
 *     importing after the seal: a gap found later is never permanent.
 *   - Malformed / non-signer signatures are skipped (ECDSA.tryRecover), never revert.
 *   - Rolling mint cap over 25 hourly buckets: NO 24-hour window can exceed it
 *     (V1/WBob use a fixed UTC day, which allows 2x the cap across midnight).
 *     Capacity returns 24-25 h after a mint. The token's own cap still applies.
 *   - Deployed PAUSED: nothing mints or burns until the Safe unpauses it as the
 *     last cutover step (after V1 is paused/revoked, V1's outpoints imported and
 *     sealed, and the backend + watchers point at V2).
 *   - Withdrawals: on-chain minimum and a basic Dobbscoin P2PKH address check
 *     (starts with '1', 26-35 base58 chars), so obviously unpayable burns revert
 *     instead of burning the user's wBOB.
 *   - withdrawalId includes address(this): V1 ids were keccak(sender, nonce) with
 *     per-user nonces from 0, so a fresh controller would otherwise re-issue ids
 *     the backend has already recorded (and would skip as duplicates).
 *   - unpause requires DEFAULT_ADMIN_ROLE (the Safe); PAUSER_ROLE can only pause.
 *   - Refund accounting ON-CHAIN (2026-11 review round 3): watchers sign the
 *     deposit output's full value (sourceValue, read from their own node), and
 *     the backend records every refund here (REFUND_MARKER_ROLE) BEFORE sending
 *     it. Per output: minted + refunded <= value. A DB writer can no longer mint
 *     against a refunded deposit, or mint more than the part not refunded.
 *     Recording a refund can only BLOCK mints, so the marker key is low-risk.
 *   - The Dobbscoin chain id is pinned (SOURCE_CHAIN_ID): outpoint uniqueness
 *     no longer rests on every watcher's DOBBSCOIN_NETWORK setting.
 *
 * Unchanged on purpose: the MintExecuted and WithdrawalRequested event
 * signatures (the backend keeps its parsers), and THRESHOLD = 3. The
 * MintAuthorization struct gains sourceValue (so its typehash differs from V1).
 *
 * Roles: DEFAULT_ADMIN_ROLE → Safe. PAUSER_ROLE → Safe (an emergency module
 * pauses through the Safe).
 */
contract BridgeControllerV2 is EIP712, AccessControl, Pausable {
    // ─── Constants ───────────────────────────────────────────────────────────

    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    /// @notice May only RECORD refunds (which can only block mints). Granted to the backend relayer.
    bytes32 public constant REFUND_MARKER_ROLE = keccak256("REFUND_MARKER_ROLE");

    uint8 public constant MAX_SIGNERS = 7;
    uint8 public constant THRESHOLD = 3;

    /// @dev 25, not 24: a real 24 h interval touches at most 25 hourly buckets, so
    ///      checking 25 bounds EVERY 24 h window by the limit.
    uint256 public constant WINDOW_BUCKETS = 25;
    uint256 public constant BUCKET_SECONDS = 1 hours;

    bytes32 public constant MINT_AUTHORIZATION_TYPEHASH = keccak256(
        "MintAuthorization(bytes32 depositId,address recipient,uint256 amount,"
        "uint256 sourceChainId,bytes32 sourceTxHash,uint32 sourceVout,"
        "uint256 sourceValue,uint256 deadline,uint256 nonce)"
    );

    // ─── State ───────────────────────────────────────────────────────────────

    WBob public immutable wBOB;

    /// @notice The only Dobbscoin chain id this controller mints for.
    uint256 public immutable SOURCE_CHAIN_ID;

    mapping(address => bool) public isSigner;
    uint8 public signerCount;

    /// @notice Admin increments to invalidate all outstanding authorizations.
    uint256 public mintNonce;

    /// @notice depositId → minted (kept for parity with V1 tooling).
    mapping(bytes32 => bool) public processedDeposits;

    /// @notice keccak256(abi.encode(sourceChainId, sourceTxHash, sourceVout)) → minted.
    mapping(bytes32 => bool) public processedOutpoints;

    /// @notice Per output: full value (set by the first mint or refund record), minted, refunded.
    mapping(bytes32 => uint256) public outpointValue;
    mapping(bytes32 => uint256) public mintedAmount;
    mapping(bytes32 => uint256) public refundedAmount;

    /// @notice True once V1's minted outpoints are imported. No mint before the seal.
    bool public importSealed;

    /// @notice Per-user withdrawal nonce.
    mapping(address => uint256) public withdrawalNonces;

    /// @notice Max wBOB (8 decimals) mintable through this controller in any 24 hours.
    uint256 public mintLimitPerWindow;
    uint256[25] private _bucketAmount;
    uint256[25] private _bucketHour;

    /// @notice Withdrawals must be strictly greater than this (8 decimals).
    uint256 public minWithdrawal;

    // ─── Events ──────────────────────────────────────────────────────────────

    event MintExecuted(
        bytes32 indexed depositId,
        address indexed recipient,
        uint256 amount,
        uint256 sourceChainId,
        bytes32 sourceTxHash,
        uint32 sourceVout
    );

    event WithdrawalRequested(
        uint256 indexed withdrawalId,
        address indexed sender,
        uint256 amount,
        string dobbscoinAddress,
        uint256 nonce
    );

    event SignerAdded(address indexed signer);
    event SignerRemoved(address indexed signer);
    event MintNonceIncremented(uint256 newNonce);
    event OutpointsImported(uint256 count, uint256 newlyMarked);
    event ImportSealed();
    event MintLimitPerWindowUpdated(uint256 oldLimit, uint256 newLimit);
    event MinWithdrawalUpdated(uint256 oldMin, uint256 newMin);
    event RefundRecorded(bytes32 indexed outpointKey, uint256 value, uint256 refundedTotal);
    event OutpointValueSet(bytes32 indexed outpointKey, uint256 value);
    event OutpointRecordReset(bytes32 indexed outpointKey, uint256 oldValue, uint256 oldRefunded, uint256 newValue, uint256 newRefunded);

    // ─── Errors ──────────────────────────────────────────────────────────────

    error AlreadyProcessed(bytes32 depositId);
    error OutpointAlreadyMinted(bytes32 outpointKey);
    error DeadlineExpired(uint256 deadline, uint256 blockTimestamp);
    error WrongMintNonce(uint256 provided, uint256 expected);
    error InsufficientValidSignatures(uint256 valid, uint8 threshold);
    error ExceedsWindowLimit(uint256 requested, uint256 remaining);
    error ImportNotSealed();
    error ImportAlreadySealed();
    error SignerAlreadyExists(address signer);
    error SignerDoesNotExist(address signer);
    error SignerSetFull();
    error BelowThreshold();
    error ZeroAddress();
    error ZeroAmount();
    error WithdrawalTooSmall(uint256 amount, uint256 minimum);
    error InvalidDobbscoinAddress();
    error WrongSourceChain(uint256 provided, uint256 expected);
    error SourceValueMismatch(bytes32 outpointKey, uint256 provided, uint256 recorded);
    error ExceedsSourceValue(bytes32 outpointKey, uint256 minted, uint256 refunded, uint256 value);
    error OutpointAlreadyProcessed(bytes32 outpointKey);

    // ─── MintAuthorization (identical to V1) ─────────────────────────────────

    struct MintAuthorization {
        bytes32 depositId;
        address recipient;
        uint256 amount;
        uint256 sourceChainId;
        bytes32 sourceTxHash;
        uint32 sourceVout;
        uint256 sourceValue;   // full value of the deposit output (8 decimals), per the signers' nodes
        uint256 deadline;
        uint256 nonce;
    }

    // ─── Constructor ─────────────────────────────────────────────────────────

    constructor(
        address wBOB_,
        address admin_,
        address[] memory signers_,
        uint256 mintLimitPerWindow_,
        uint256 minWithdrawal_,
        uint256 sourceChainId_
    ) EIP712("BridgeController", "2") {
        if (wBOB_ == address(0) || admin_ == address(0)) revert ZeroAddress();
        if (sourceChainId_ == 0) revert WrongSourceChain(0, 1);
        SOURCE_CHAIN_ID = sourceChainId_;
        if (signers_.length > MAX_SIGNERS) revert SignerSetFull();
        if (signers_.length < THRESHOLD) revert BelowThreshold();

        wBOB = WBob(wBOB_);
        _grantRole(DEFAULT_ADMIN_ROLE, admin_);
        _grantRole(PAUSER_ROLE, admin_);

        for (uint256 i = 0; i < signers_.length; i++) _addSigner(signers_[i]);

        mintLimitPerWindow = mintLimitPerWindow_;
        minWithdrawal = minWithdrawal_;
        emit MintLimitPerWindowUpdated(0, mintLimitPerWindow_);
        emit MinWithdrawalUpdated(0, minWithdrawal_);

        // Born paused: withdrawals would otherwise burn as soon as the Safe grants
        // BRIDGE_EXECUTOR_ROLE, possibly before the backend watches this address.
        _pause();
    }

    // ─── Inbound ─────────────────────────────────────────────────────────────

    /**
     * @notice Mint once THRESHOLD distinct registered signers signed `auth`.
     *         Signatures that are malformed, non-65-byte, from non-signers or
     *         duplicates are skipped. Permissionless relay.
     */
    function executeMint(MintAuthorization calldata auth, bytes[] calldata signatures)
        external
        whenNotPaused
    {
        if (!importSealed) revert ImportNotSealed();
        if (auth.amount == 0) revert ZeroAmount();
        if (auth.recipient == address(0)) revert ZeroAddress();
        if (auth.sourceChainId != SOURCE_CHAIN_ID) revert WrongSourceChain(auth.sourceChainId, SOURCE_CHAIN_ID);
        if (processedDeposits[auth.depositId]) revert AlreadyProcessed(auth.depositId);
        bytes32 opKey = outpointKey(auth.sourceChainId, auth.sourceTxHash, auth.sourceVout);
        if (processedOutpoints[opKey]) revert OutpointAlreadyMinted(opKey);
        _checkAndSetValue(opKey, auth.sourceValue);
        uint256 refunded = refundedAmount[opKey];
        if (auth.amount + refunded > auth.sourceValue) {
            revert ExceedsSourceValue(opKey, auth.amount, refunded, auth.sourceValue);
        }
        if (block.timestamp > auth.deadline) revert DeadlineExpired(auth.deadline, block.timestamp);
        if (auth.nonce != mintNonce) revert WrongMintNonce(auth.nonce, mintNonce);

        uint256 valid = _countValidSignatures(_digest(auth), signatures);
        if (valid < THRESHOLD) revert InsufficientValidSignatures(valid, THRESHOLD);

        _consumeWindow(auth.amount);
        processedDeposits[auth.depositId] = true;
        processedOutpoints[opKey] = true;
        mintedAmount[opKey] = auth.amount;

        wBOB.mint(auth.recipient, auth.amount);

        emit MintExecuted(
            auth.depositId, auth.recipient, auth.amount,
            auth.sourceChainId, auth.sourceTxHash, auth.sourceVout
        );
    }

    // ─── Outbound ────────────────────────────────────────────────────────────

    /**
     * @notice Burn the caller's wBOB and emit WithdrawalRequested for the backend.
     *         Reverts (nothing burned) on an amount at/under the minimum or an
     *         address that cannot be a Dobbscoin P2PKH address.
     */
    function requestWithdrawal(uint256 amount, string calldata dobbscoinAddress)
        external
        whenNotPaused
    {
        if (amount <= minWithdrawal) revert WithdrawalTooSmall(amount, minWithdrawal);
        if (!isPlausibleDobbscoinAddress(dobbscoinAddress)) revert InvalidDobbscoinAddress();

        uint256 nonce = withdrawalNonces[msg.sender]++;
        wBOB.burn(msg.sender, amount);

        uint256 withdrawalId = uint256(keccak256(abi.encodePacked(address(this), msg.sender, nonce)));
        emit WithdrawalRequested(withdrawalId, msg.sender, amount, dobbscoinAddress, nonce);
    }

    // ─── Refund accounting ───────────────────────────────────────────────────

    /**
     * @notice Record that `refundedTotal` of output (txHash, vout), worth `value`,
     *         is refunded on Dobbscoin. The backend calls this BEFORE broadcasting
     *         a refund. Monotonic and idempotent: sets the total, never lowers it.
     *         Can only BLOCK mints: minted + refunded <= value always holds.
     */
    function recordRefund(bytes32 sourceTxHash, uint32 sourceVout, uint256 value, uint256 refundedTotal)
        external
        onlyRole(REFUND_MARKER_ROLE)
    {
        if (refundedTotal == 0) revert ZeroAmount();
        bytes32 opKey = outpointKey(SOURCE_CHAIN_ID, sourceTxHash, sourceVout);
        // Imported from V1 (processed, but nothing minted HERE): V2 knows neither
        // its value nor what V1 minted, so no refund can be accounted against it.
        if (processedOutpoints[opKey] && mintedAmount[opKey] == 0) revert OutpointAlreadyProcessed(opKey);
        _checkAndSetValue(opKey, value);
        if (refundedTotal <= refundedAmount[opKey]) return;     // already recorded (retry)
        uint256 minted = mintedAmount[opKey];
        if (minted + refundedTotal > value) revert ExceedsSourceValue(opKey, minted, refundedTotal, value);
        refundedAmount[opKey] = refundedTotal;
        emit RefundRecorded(opKey, value, refundedTotal);
    }

    /**
     * @notice Admin escape hatch for a wrongly recorded output that never minted
     *         (e.g. a stolen REFUND_MARKER key poisoned it): sets its record to the
     *         TRUE value and the refund REALLY paid from it (0, 0 clears it).
     *         Setting the true refund matters: zeroing a refund that was paid
     *         would let the same coins be minted. Refuses for anything processed
     *         (minted here or imported).
     */
    function resetOutpointRecord(bytes32 opKey, uint256 trueValue, uint256 trueRefunded)
        external onlyRole(DEFAULT_ADMIN_ROLE)
    {
        if (processedOutpoints[opKey]) revert OutpointAlreadyProcessed(opKey);
        if (trueRefunded > trueValue) revert ExceedsSourceValue(opKey, 0, trueRefunded, trueValue);
        emit OutpointRecordReset(opKey, outpointValue[opKey], refundedAmount[opKey], trueValue, trueRefunded);
        outpointValue[opKey] = trueValue;
        refundedAmount[opKey] = trueRefunded;
    }

    // ─── One-time migration import ───────────────────────────────────────────

    /**
     * @notice Mark outpoints V1 already minted, so they can never mint here.
     *         In batches; idempotent per key. Also allowed after sealImport():
     *         marking can only block a mint, never enable one.
     */
    function importProcessedOutpoints(bytes32[] calldata keys) external onlyRole(DEFAULT_ADMIN_ROLE) {
        uint256 marked;
        for (uint256 i = 0; i < keys.length; i++) {
            if (!processedOutpoints[keys[i]]) {
                processedOutpoints[keys[i]] = true;
                marked++;
            }
        }
        emit OutpointsImported(keys.length, marked);
    }

    /// @notice Enable minting (irreversible). Run the read-back check first.
    function sealImport() external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (importSealed) revert ImportAlreadySealed();
        importSealed = true;
        emit ImportSealed();
    }

    // ─── Admin ───────────────────────────────────────────────────────────────

    function addSigner(address signer) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _addSigner(signer);
    }

    function removeSigner(address signer) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (!isSigner[signer]) revert SignerDoesNotExist(signer);
        if (signerCount - 1 < THRESHOLD) revert BelowThreshold();
        isSigner[signer] = false;
        signerCount--;
        emit SignerRemoved(signer);
    }

    function incrementMintNonce() external onlyRole(DEFAULT_ADMIN_ROLE) {
        mintNonce++;
        emit MintNonceIncremented(mintNonce);
    }

    function setMintLimitPerWindow(uint256 newLimit) external onlyRole(DEFAULT_ADMIN_ROLE) {
        emit MintLimitPerWindowUpdated(mintLimitPerWindow, newLimit);
        mintLimitPerWindow = newLimit;
    }

    function setMinWithdrawal(uint256 newMin) external onlyRole(DEFAULT_ADMIN_ROLE) {
        emit MinWithdrawalUpdated(minWithdrawal, newMin);
        minWithdrawal = newMin;
    }

    /// @notice Anyone holding PAUSER_ROLE (Safe, or the emergency module via the Safe) can pause.
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /// @notice Only the Safe itself (DEFAULT_ADMIN_ROLE) can unpause.
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    // ─── Views ───────────────────────────────────────────────────────────────

    function outpointKey(uint256 sourceChainId, bytes32 sourceTxHash, uint32 sourceVout)
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(sourceChainId, sourceTxHash, sourceVout));
    }

    /// @notice Minted in the current hour plus the previous 24 (bounds every 24 h window).
    function mintedInWindow() public view returns (uint256 total) {
        uint256 nowHour = block.timestamp / BUCKET_SECONDS;
        for (uint256 i = 0; i < WINDOW_BUCKETS; i++) {
            uint256 h = _bucketHour[i];
            if (h + WINDOW_BUCKETS > nowHour && _bucketAmount[i] > 0) total += _bucketAmount[i];
        }
    }

    /// @notice What the next mint may use right now (0 if the limit was lowered below usage).
    function remainingMintCapacity() public view returns (uint256) {
        uint256 used = mintedInWindow();
        return used >= mintLimitPerWindow ? 0 : mintLimitPerWindow - used;
    }

    function getMintAuthorizationDigest(MintAuthorization calldata auth) external view returns (bytes32) {
        return _digest(auth);
    }

    /// @notice Mainnet P2PKH shape: '1' then 25-34 base58 chars (26-35 total). Not a checksum check.
    function isPlausibleDobbscoinAddress(string calldata a) public pure returns (bool) {
        bytes calldata b = bytes(a);
        if (b.length < 26 || b.length > 35 || b[0] != "1") return false;
        for (uint256 i = 1; i < b.length; i++) {
            bytes1 c = b[i];
            bool ok = (c >= "1" && c <= "9")
                || (c >= "A" && c <= "Z" && c != "I" && c != "O")
                || (c >= "a" && c <= "z" && c != "l");
            if (!ok) return false;
        }
        return true;
    }

    // ─── Internal ────────────────────────────────────────────────────────────

    function _digest(MintAuthorization calldata auth) internal view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(
            MINT_AUTHORIZATION_TYPEHASH,
            auth.depositId, auth.recipient, auth.amount,
            auth.sourceChainId, auth.sourceTxHash, auth.sourceVout,
            auth.sourceValue, auth.deadline, auth.nonce
        )));
    }

    /// @dev First record of an output fixes its value; every later mint/refund must agree.
    function _checkAndSetValue(bytes32 opKey, uint256 value) internal {
        if (value == 0) revert ZeroAmount();
        uint256 recorded = outpointValue[opKey];
        if (recorded == 0) {
            outpointValue[opKey] = value;
            emit OutpointValueSet(opKey, value);
        } else if (recorded != value) {
            revert SourceValueMismatch(opKey, value, recorded);
        }
    }

    function _consumeWindow(uint256 amount) internal {
        uint256 remaining = remainingMintCapacity();
        if (amount > remaining) revert ExceedsWindowLimit(amount, remaining);
        uint256 nowHour = block.timestamp / BUCKET_SECONDS;
        uint256 idx = nowHour % WINDOW_BUCKETS;
        if (_bucketHour[idx] != nowHour) {
            _bucketHour[idx] = nowHour;
            _bucketAmount[idx] = 0;
        }
        _bucketAmount[idx] += amount;
    }

    function _addSigner(address signer) internal {
        if (signer == address(0)) revert ZeroAddress();
        if (isSigner[signer]) revert SignerAlreadyExists(signer);
        if (signerCount >= MAX_SIGNERS) revert SignerSetFull();
        isSigner[signer] = true;
        signerCount++;
        emit SignerAdded(signer);
    }

    function _countValidSignatures(bytes32 digest, bytes[] calldata signatures)
        internal
        view
        returns (uint256 validCount)
    {
        address[MAX_SIGNERS] memory seen;
        for (uint256 i = 0; i < signatures.length; i++) {
            if (signatures[i].length != 65) continue;
            (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(digest, signatures[i]);
            if (err != ECDSA.RecoverError.NoError || !isSigner[recovered]) continue;
            bool dup;
            for (uint256 j = 0; j < validCount; j++) {
                if (seen[j] == recovered) { dup = true; break; }
            }
            if (dup) continue;
            seen[validCount] = recovered;
            validCount++;
            if (validCount == THRESHOLD) break;
        }
    }
}
