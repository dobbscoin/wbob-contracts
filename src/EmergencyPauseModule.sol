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
 *   - pauseAll(): operator only. Pauses each target that is not already paused.
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

    error OnlyOperator();
    error OnlySafe();
    error ZeroAddress();
    error ModuleCallFailed(address target);

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
        emit EmergencyPaused(msg.sender, c, t);
    }

    function setOperator(address newOperator) external {
        if (msg.sender != address(safe)) revert OnlySafe();
        if (newOperator == address(0)) revert ZeroAddress();
        emit OperatorChanged(operator, newOperator);
        operator = newOperator;
    }

    function _pauseIfNeeded(address target) internal returns (bool pausedNow) {
        if (IPausableTarget(target).paused()) return false;
        bool ok = safe.execTransactionFromModule(target, 0, abi.encodeWithSignature("pause()"), 0);
        if (!ok) revert ModuleCallFailed(target);
        return true;
    }
}
