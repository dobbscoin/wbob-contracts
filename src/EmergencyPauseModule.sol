// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

/**
 * @title EmergencyPauseModule
 * @notice Safe module that lets one operator key PAUSE the bridge controller and
 *         the wBOB token, through the Safe (which holds PAUSER_ROLE on both).
 *
 * Replaces V1's BridgeExecutorModule, which could also UNPAUSE (so the hot key
 * could undo an emergency pause the Safe owners imposed) and paused only the
 * controller (minted wBOB stayed transferable, so it could be dumped into the
 * pools while the owners gathered signatures).
 *
 *   - pauseAll(): operator only. Pauses each target that is not already paused,
 *     INDEPENDENTLY: if one target can't be paused (role lost, Safe guard), the
 *     other still is. Reverts only if neither ends up paused.
 *   - There is NO unpause path here. Unpausing is a normal Safe transaction.
 *   - setOperator(): Safe only.
 *   - Only Operation.Call; targets are immutable.
 */
interface ISafe {
    function execTransactionFromModule(address to, uint256 value, bytes calldata data, uint8 operation)
        external
        returns (bool success);
}

interface IPausableTarget {
    function paused() external view returns (bool);
}

contract EmergencyPauseModule {
    ISafe public immutable safe;
    address public immutable controller;
    address public immutable token;

    address public operator;

    event OperatorChanged(address indexed oldOperator, address indexed newOperator);
    event EmergencyPaused(address indexed triggeredBy, bool controllerPaused, bool tokenPaused);
    event PauseFailed(address indexed target);

    error OnlyOperator();
    error OnlySafe();
    error ZeroAddress();
    error NothingPaused();
    error NotEnoughGas(uint256 left, uint256 needed);

    /// @dev Checked before EACH target. Without it, an eth_estimateGas'd tx can land
    ///      in a band where the controller pause succeeds and the token's inner call
    ///      runs out of gas (the Safe returns false, we catch it), so the tx succeeds
    ///      with the token still live. 63/64 of this is ample for a pause() call.
    uint256 public constant MIN_GAS_PER_TARGET = 150_000;

    constructor(ISafe safe_, address controller_, address token_, address operator_) {
        if (address(safe_) == address(0) || controller_ == address(0) || token_ == address(0) || operator_ == address(0)) {
            revert ZeroAddress();
        }
        safe = safe_;
        controller = controller_;
        token = token_;
        operator = operator_;
    }

    /// @notice Pause the controller and the token. Safe to call when either is already paused.
    function pauseAll() external {
        if (msg.sender != operator) revert OnlyOperator();
        bool c = _pauseIfNeeded(controller);
        bool t = _pauseIfNeeded(token);
        if (!c && !t) revert NothingPaused();
        emit EmergencyPaused(msg.sender, c, t);
    }

    function setOperator(address newOperator) external {
        if (msg.sender != address(safe)) revert OnlySafe();
        if (newOperator == address(0)) revert ZeroAddress();
        emit OperatorChanged(operator, newOperator);
        operator = newOperator;
    }

    /// @return isPaused whether the target is paused after this call
    function _pauseIfNeeded(address target) internal returns (bool isPaused) {
        if (IPausableTarget(target).paused()) return true;
        if (gasleft() < MIN_GAS_PER_TARGET) revert NotEnoughGas(gasleft(), MIN_GAS_PER_TARGET);
        bool ok;
        try safe.execTransactionFromModule(target, 0, abi.encodeWithSignature("pause()"), 0) returns (bool r) {
            ok = r;
        } catch {
            ok = false;
        }
        if (!ok) emit PauseFailed(target);
        return ok;
    }
}
