// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Pausable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title WBob
 * @notice Wrapped BOB (wBOB) — ERC-20 representation of Dobbscoin on Gnosis chain.
 *
 * Role layout (all assigned at deploy time, hot wallet never holds any role):
 *   DEFAULT_ADMIN_ROLE  → Gnosis Safe (governance: role changes, limit updates)
 *   BRIDGE_EXECUTOR_ROLE → BridgeController only (mint + burn)
 *   PAUSER_ROLE         → Gnosis Safe (emergency halt)
 *
 * Decimal precision: 8 (matches Dobbscoin satoshi unit).
 * Supply controls: hard cap (immutable) + rolling 24-hour mint limit (admin-adjustable).
 */
contract WBob is ERC20, ERC20Pausable, AccessControl {
    // ─── Roles ───────────────────────────────────────────────────────────────

    bytes32 public constant BRIDGE_EXECUTOR_ROLE = keccak256("BRIDGE_EXECUTOR_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    // ─── Supply controls ─────────────────────────────────────────────────────

    /// @notice Absolute maximum supply in satoshi units (0 = no cap).
    uint256 public immutable MAX_SUPPLY;

    /// @notice Maximum wBOB that may be minted within any rolling 24-hour window.
    uint256 public dailyMintLimit;

    // Rolling-window state (resets when block.timestamp crosses currentDayStart + 1 days)
    uint256 public currentDayMinted;
    uint256 public currentDayStart;

    // ─── Events ──────────────────────────────────────────────────────────────

    event DailyMintLimitUpdated(uint256 oldLimit, uint256 newLimit);

    // ─── Errors ──────────────────────────────────────────────────────────────

    error ExceedsMaxSupply(uint256 requested, uint256 available);
    error ExceedsDailyMintLimit(uint256 requested, uint256 remaining);

    // ─── Constructor ─────────────────────────────────────────────────────────

    /**
     * @param admin_          Address granted DEFAULT_ADMIN_ROLE (should be Gnosis Safe).
     * @param pauser_         Address granted PAUSER_ROLE (should be Gnosis Safe).
     * @param maxSupply_      Hard cap in satoshi units (8 decimals). 0 = uncapped.
     * @param dailyMintLimit_ Rolling 24-hour mint ceiling in satoshi units.
     */
    constructor(
        address admin_,
        address pauser_,
        uint256 maxSupply_,
        uint256 dailyMintLimit_
    ) ERC20("Wrapped BOB", "wBOB") {
        require(admin_ != address(0), "WBob: zero admin");
        require(pauser_ != address(0), "WBob: zero pauser");

        _grantRole(DEFAULT_ADMIN_ROLE, admin_);
        _grantRole(PAUSER_ROLE, pauser_);

        MAX_SUPPLY = maxSupply_;
        dailyMintLimit = dailyMintLimit_;
        currentDayStart = block.timestamp;
    }

    // ─── ERC-20 overrides ────────────────────────────────────────────────────

    function decimals() public pure override returns (uint8) {
        return 8;
    }

    // ─── Bridge operations (BRIDGE_EXECUTOR_ROLE only) ───────────────────────

    /**
     * @notice Mint wBOB to `to`. Called exclusively by BridgeController after
     *         3-of-5 watcher threshold is met and EIP-712 authorization verified.
     */
    function mint(address to, uint256 amount) external onlyRole(BRIDGE_EXECUTOR_ROLE) whenNotPaused {
        _checkAndUpdateDailyLimit(amount);

        if (MAX_SUPPLY > 0) {
            uint256 available = MAX_SUPPLY - totalSupply();
            if (amount > available) revert ExceedsMaxSupply(amount, available);
        }

        _mint(to, amount);
    }

    /**
     * @notice Burn wBOB from `from`. Called by BridgeController when processing
     *         a withdrawal request (user has already approved or called requestWithdrawal).
     */
    function burn(address from, uint256 amount) external onlyRole(BRIDGE_EXECUTOR_ROLE) whenNotPaused {
        _burn(from, amount);
    }

    // ─── Admin operations ────────────────────────────────────────────────────

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    /**
     * @notice Update the rolling 24-hour mint limit. Only callable by DEFAULT_ADMIN_ROLE (Safe).
     */
    function setDailyMintLimit(uint256 newLimit) external onlyRole(DEFAULT_ADMIN_ROLE) {
        emit DailyMintLimitUpdated(dailyMintLimit, newLimit);
        dailyMintLimit = newLimit;
    }

    // ─── Internal ────────────────────────────────────────────────────────────

    /**
     * @dev Resets the daily window if 24 hours have elapsed, then checks and records usage.
     */
    function _checkAndUpdateDailyLimit(uint256 amount) internal {
        if (block.timestamp >= currentDayStart + 1 days) {
            currentDayMinted = 0;
            // Align to day boundary so window doesn't creep across multiple days.
            currentDayStart = block.timestamp - (block.timestamp % 1 days);
        }

        uint256 remaining = dailyMintLimit - currentDayMinted;
        if (amount > remaining) revert ExceedsDailyMintLimit(amount, remaining);

        currentDayMinted += amount;
    }

    /**
     * @dev Required by Solidity for ERC20 + ERC20Pausable diamond inheritance.
     */
    function _update(address from, address to, uint256 value)
        internal
        override(ERC20, ERC20Pausable)
    {
        super._update(from, to, value);
    }
}
