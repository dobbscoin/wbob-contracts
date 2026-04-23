// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

/**
 * @title BridgeExecutorModule
 * @notice Gnosis Safe module that permits an off-chain operator (the backend executor
 *         hot wallet) to call pause() and unpause() on BridgeController without
 *         requiring a full Safe multisig approval.
 *
 * Background:
 *   - BridgeController.pause/unpause require PAUSER_ROLE, which is held by the Safe.
 *   - In normal operation the Safe needs ≥ N-of-M owner signatures to execute any tx.
 *   - This module, once enabled on the Safe, lets a single trusted operator key
 *     trigger pause/unpause quickly — important for emergency response.
 *   - Admin operations (signer add/remove, mintNonce increment, role changes) still
 *     require full Safe multisig and are NOT reachable through this module.
 *
 * Security invariants:
 *   - Only `operator` can call pause() / unpause().
 *   - Only the Safe itself can rotate the operator key (setOperator).
 *   - No DELEGATECALL path — all calls use Operation.Call.
 *   - The operator has NO direct admin capability on BridgeController or WBob.
 *
 * Deployment flow:
 *   1. Deploy this contract (constructor sets safe, bridgeController, operator).
 *   2. Safe owners execute enableModule(address(this)) via multisig.
 *   3. Backend is configured with the module address and operator private key.
 *
 * Key rotation:
 *   The Safe can call setOperator() via a regular multisig tx at any time.
 */

/// @dev Minimal Gnosis Safe interface — only the method this module needs.
interface ISafe {
    /// @dev Executes a transaction from this Safe as if initiated by the Safe itself.
    ///      Reverts if the module is not enabled on the Safe.
    function execTransactionFromModule(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation     // 0 = Call, 1 = DelegateCall
    ) external returns (bool success);
}

contract BridgeExecutorModule {
    // ─── Immutables ───────────────────────────────────────────────────────────

    /// @notice The Gnosis Safe this module is attached to.
    ISafe public immutable safe;

    /// @notice The BridgeController whose pause/unpause are exposed.
    address public immutable bridgeController;

    // ─── State ───────────────────────────────────────────────────────────────

    /// @notice The backend hot wallet authorized to trigger pause/unpause.
    address public operator;

    // ─── Events ──────────────────────────────────────────────────────────────

    event OperatorChanged(address indexed oldOperator, address indexed newOperator);
    event EmergencyPaused(address indexed triggeredBy);
    event EmergencyUnpaused(address indexed triggeredBy);

    // ─── Errors ──────────────────────────────────────────────────────────────

    error OnlyOperator();
    error OnlySafe();
    error ZeroAddress();
    error ModuleCallFailed();

    // ─── Modifiers ───────────────────────────────────────────────────────────

    modifier onlyOperator() {
        if (msg.sender != operator) revert OnlyOperator();
        _;
    }

    modifier onlySafe() {
        if (msg.sender != address(safe)) revert OnlySafe();
        _;
    }

    // ─── Constructor ─────────────────────────────────────────────────────────

    /**
     * @param safe_             Gnosis Safe that will enable this module.
     * @param bridgeController_ BridgeController to pause/unpause.
     * @param operator_         Initial backend operator address.
     */
    constructor(ISafe safe_, address bridgeController_, address operator_) {
        if (address(safe_) == address(0)) revert ZeroAddress();
        if (bridgeController_ == address(0))  revert ZeroAddress();
        if (operator_ == address(0))          revert ZeroAddress();

        safe             = safe_;
        bridgeController = bridgeController_;
        operator         = operator_;
    }

    // ─── Operator actions ─────────────────────────────────────────────────────

    /**
     * @notice Pause BridgeController via the Safe.
     *         Callable only by the operator. Executes BridgeController.pause()
     *         with the Safe as msg.sender (which holds PAUSER_ROLE).
     */
    function pause() external onlyOperator {
        bool ok = safe.execTransactionFromModule(
            bridgeController,
            0,
            abi.encodeWithSignature("pause()"),
            0  // Operation.Call
        );
        if (!ok) revert ModuleCallFailed();
        emit EmergencyPaused(msg.sender);
    }

    /**
     * @notice Unpause BridgeController via the Safe.
     *         Callable only by the operator. Use with care — ensure the
     *         emergency condition is resolved before unpausing.
     */
    function unpause() external onlyOperator {
        bool ok = safe.execTransactionFromModule(
            bridgeController,
            0,
            abi.encodeWithSignature("unpause()"),
            0  // Operation.Call
        );
        if (!ok) revert ModuleCallFailed();
        emit EmergencyUnpaused(msg.sender);
    }

    // ─── Safe-only administration ─────────────────────────────────────────────

    /**
     * @notice Rotate the operator key. Only callable by the Safe via multisig.
     *         Used for key rotation or when the operator wallet is compromised.
     * @param newOperator New backend operator address.
     */
    function setOperator(address newOperator) external onlySafe {
        if (newOperator == address(0)) revert ZeroAddress();
        emit OperatorChanged(operator, newOperator);
        operator = newOperator;
    }
}
