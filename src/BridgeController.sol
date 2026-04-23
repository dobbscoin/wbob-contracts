// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "./WBob.sol";

/**
 * @title BridgeController
 * @notice Orchestrates the Dobbscoin ↔ Gnosis wBOB bridge. Two flows:
 *
 *   Inbound  (Dobbscoin → Gnosis):
 *     3-of-5 independent watcher EOAs each observe Dobbscoin for confirmed
 *     deposits and submit an off-chain EIP-712 MintAuthorization signature.
 *     Once THRESHOLD valid unique signer signatures are collected, any
 *     account may call executeMint() to deliver wBOB to the recipient.
 *
 *   Outbound (Gnosis → Dobbscoin):
 *     Users call requestWithdrawal(). The contract burns their wBOB immediately
 *     and emits WithdrawalRequested. The backend observes this event, constructs
 *     and broadcasts the Dobbscoin payout transaction, and reconciles the order.
 *
 * Security properties:
 *   - processedDeposits mapping prevents depositId replay
 *   - Per-user withdrawalNonces prevent withdrawal replay
 *   - mintNonce (admin-incrementable) invalidates all outstanding mint authorizations
 *   - EIP-712 typed signatures bind all relevant parameters
 *   - Signer deduplication in executeMint prevents a single key counting multiple times
 *   - Daily mint limit enforced by WBob; additional per-controller tracking possible
 *   - Pause stops both inbound and outbound
 *
 * Role layout:
 *   DEFAULT_ADMIN_ROLE  → Gnosis Safe (signer add/remove, mintNonce increment, limits)
 *   PAUSER_ROLE         → Gnosis Safe
 */
contract BridgeController is EIP712, AccessControl, Pausable {
    using ECDSA for bytes32;

    // ─── Constants ───────────────────────────────────────────────────────────

    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    uint8 public constant MAX_SIGNERS = 5;
    uint8 public constant THRESHOLD = 3;

    bytes32 public constant MINT_AUTHORIZATION_TYPEHASH = keccak256(
        "MintAuthorization(bytes32 depositId,address recipient,uint256 amount,"
        "uint256 sourceChainId,bytes32 sourceTxHash,uint32 sourceVout,"
        "uint256 deadline,uint256 nonce)"
    );

    // ─── State ───────────────────────────────────────────────────────────────

    WBob public immutable wBOB;

    /// @notice Authorized watcher EOAs. Max MAX_SIGNERS entries.
    mapping(address => bool) public isSigner;
    uint8 public signerCount;

    /// @notice Monotonic counter. Admin increments to invalidate all outstanding authorizations.
    uint256 public mintNonce;

    /// @notice Replay protection: depositId → already processed.
    mapping(bytes32 => bool) public processedDeposits;

    /// @notice Per-user nonce for withdrawal replay protection.
    mapping(address => uint256) public withdrawalNonces;

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

    // ─── Errors ──────────────────────────────────────────────────────────────

    error AlreadyProcessed(bytes32 depositId);
    error DeadlineExpired(uint256 deadline, uint256 blockTimestamp);
    error WrongMintNonce(uint256 provided, uint256 expected);
    error InsufficientValidSignatures(uint256 valid, uint8 threshold);
    error SignerAlreadyExists(address signer);
    error SignerDoesNotExist(address signer);
    error SignerSetFull();
    error ZeroAddress();
    error EmptyDobbscoinAddress();
    error ZeroAmount();

    // ─── MintAuthorization struct ─────────────────────────────────────────────

    struct MintAuthorization {
        bytes32 depositId;     // keccak256(chain, txid, vout, depositAddr, amount, recipient)
        address recipient;     // Gnosis address to receive wBOB
        uint256 amount;        // wBOB amount in satoshi units (8 decimals)
        uint256 sourceChainId; // Dobbscoin chain identifier (numeric)
        bytes32 sourceTxHash;  // Dobbscoin txid (bytes32, zero-padded if shorter)
        uint32 sourceVout;     // Output index on the Dobbscoin transaction
        uint256 deadline;      // Authorization expiry (unix timestamp)
        uint256 nonce;         // Must equal current mintNonce
    }

    // ─── Constructor ─────────────────────────────────────────────────────────

    /**
     * @param wBOB_       Address of the deployed WBob contract.
     * @param admin_      DEFAULT_ADMIN_ROLE holder (Gnosis Safe).
     * @param pauser_     PAUSER_ROLE holder (Gnosis Safe).
     * @param signers_    Initial set of watcher EOAs (length must be <= MAX_SIGNERS).
     */
    constructor(
        address wBOB_,
        address admin_,
        address pauser_,
        address[] memory signers_
    ) EIP712("BridgeController", "1") {
        require(wBOB_ != address(0), "BC: zero wBOB");
        require(admin_ != address(0), "BC: zero admin");
        require(pauser_ != address(0), "BC: zero pauser");
        require(signers_.length <= MAX_SIGNERS, "BC: too many signers");
        require(signers_.length >= THRESHOLD, "BC: below threshold");

        wBOB = WBob(wBOB_);

        _grantRole(DEFAULT_ADMIN_ROLE, admin_);
        _grantRole(PAUSER_ROLE, pauser_);

        for (uint256 i = 0; i < signers_.length; i++) {
            _addSigner(signers_[i]);
        }
    }

    // ─── Inbound: executeMint ─────────────────────────────────────────────────

    /**
     * @notice Execute a mint once THRESHOLD independent watcher signatures are provided.
     *
     * @param auth       The MintAuthorization struct (all fields must match what signers signed).
     * @param signatures Array of raw ECDSA signatures. At least THRESHOLD must be from distinct
     *                   registered signers. Extra or invalid sigs are silently ignored.
     *
     * Callability: permissionless once threshold is met (any EOA can relay).
     */
    function executeMint(
        MintAuthorization calldata auth,
        bytes[] calldata signatures
    ) external whenNotPaused {
        // ── Validity checks ──────────────────────────────────────────────────
        if (processedDeposits[auth.depositId]) revert AlreadyProcessed(auth.depositId);
        if (block.timestamp > auth.deadline) revert DeadlineExpired(auth.deadline, block.timestamp);
        if (auth.nonce != mintNonce) revert WrongMintNonce(auth.nonce, mintNonce);

        // ── Signature verification ────────────────────────────────────────────
        bytes32 digest = _hashTypedDataV4(
            keccak256(abi.encode(
                MINT_AUTHORIZATION_TYPEHASH,
                auth.depositId,
                auth.recipient,
                auth.amount,
                auth.sourceChainId,
                auth.sourceTxHash,
                auth.sourceVout,
                auth.deadline,
                auth.nonce
            ))
        );

        uint256 validCount = _countValidSignatures(digest, signatures);
        if (validCount < THRESHOLD) revert InsufficientValidSignatures(validCount, THRESHOLD);

        // ── State changes (CEI order) ─────────────────────────────────────────
        processedDeposits[auth.depositId] = true;

        wBOB.mint(auth.recipient, auth.amount);

        emit MintExecuted(
            auth.depositId,
            auth.recipient,
            auth.amount,
            auth.sourceChainId,
            auth.sourceTxHash,
            auth.sourceVout
        );
    }

    // ─── Outbound: requestWithdrawal ──────────────────────────────────────────

    /**
     * @notice Burn caller's wBOB and emit a WithdrawalRequested event for the backend
     *         to process the Dobbscoin payout.
     *
     * @param amount           wBOB amount to withdraw (satoshi units, 8 decimals).
     * @param dobbscoinAddress Destination Dobbscoin address (validated off-chain by backend).
     */
    function requestWithdrawal(
        uint256 amount,
        string calldata dobbscoinAddress
    ) external whenNotPaused {
        if (amount == 0) revert ZeroAmount();
        if (bytes(dobbscoinAddress).length == 0) revert EmptyDobbscoinAddress();

        uint256 nonce = withdrawalNonces[msg.sender]++;

        // Burn first (revert here if insufficient balance/allowance).
        wBOB.burn(msg.sender, amount);

        // Unique withdrawal ID: hash of sender + nonce, truncated to uint256 for indexing.
        uint256 withdrawalId = uint256(keccak256(abi.encodePacked(msg.sender, nonce)));

        emit WithdrawalRequested(withdrawalId, msg.sender, amount, dobbscoinAddress, nonce);
    }

    // ─── Signer management (DEFAULT_ADMIN_ROLE) ───────────────────────────────

    function addSigner(address signer) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _addSigner(signer);
    }

    function removeSigner(address signer) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (!isSigner[signer]) revert SignerDoesNotExist(signer);
        // After removal the remaining count must still be >= THRESHOLD to keep the bridge
        // operational. Enforce this invariant here.
        require(signerCount - 1 >= THRESHOLD, "BC: would drop below threshold");
        isSigner[signer] = false;
        signerCount--;
        emit SignerRemoved(signer);
    }

    /**
     * @notice Invalidate all outstanding MintAuthorizations by bumping mintNonce.
     *         Use in emergencies (e.g., suspected signer key compromise).
     */
    function incrementMintNonce() external onlyRole(DEFAULT_ADMIN_ROLE) {
        mintNonce++;
        emit MintNonceIncremented(mintNonce);
    }

    // ─── Pause (PAUSER_ROLE) ─────────────────────────────────────────────────

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    // ─── Internal helpers ─────────────────────────────────────────────────────

    function _addSigner(address signer) internal {
        if (signer == address(0)) revert ZeroAddress();
        if (isSigner[signer]) revert SignerAlreadyExists(signer);
        if (signerCount >= MAX_SIGNERS) revert SignerSetFull();
        isSigner[signer] = true;
        signerCount++;
        emit SignerAdded(signer);
    }

    /**
     * @dev Count distinct valid signatures from registered signers.
     *      Deduplication: a signer whose address appears in multiple signatures is
     *      counted only once. Uses a small array (bounded by MAX_SIGNERS) for dedup.
     */
    function _countValidSignatures(bytes32 digest, bytes[] calldata signatures)
        internal
        view
        returns (uint256 validCount)
    {
        address[MAX_SIGNERS] memory seen;

        for (uint256 i = 0; i < signatures.length; i++) {
            if (signatures[i].length != 65) continue;

            address recovered = digest.recover(signatures[i]);
            if (!isSigner[recovered]) continue;

            // Dedup check
            bool duplicate = false;
            for (uint256 j = 0; j < validCount; j++) {
                if (seen[j] == recovered) {
                    duplicate = true;
                    break;
                }
            }
            if (duplicate) continue;

            seen[validCount] = recovered;
            validCount++;

            // Early exit once threshold reached (saves gas on common path).
            if (validCount == THRESHOLD) break;
        }
    }

    // ─── View helpers ─────────────────────────────────────────────────────────

    /**
     * @notice Returns the EIP-712 digest for a MintAuthorization. Useful for
     *         off-chain signers and test helpers.
     */
    function getMintAuthorizationDigest(MintAuthorization calldata auth)
        external
        view
        returns (bytes32)
    {
        return _hashTypedDataV4(
            keccak256(abi.encode(
                MINT_AUTHORIZATION_TYPEHASH,
                auth.depositId,
                auth.recipient,
                auth.amount,
                auth.sourceChainId,
                auth.sourceTxHash,
                auth.sourceVout,
                auth.deadline,
                auth.nonce
            ))
        );
    }
}
