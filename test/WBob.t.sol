// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import "forge-std/Test.sol";
import "../src/WBob.sol";

contract WBobTest is Test {
    WBob internal wBOB;

    address internal admin = makeAddr("admin");
    address internal pauser = makeAddr("pauser");
    address internal executor = makeAddr("executor");
    address internal user = makeAddr("user");
    address internal nobody = makeAddr("nobody");

    uint256 internal constant MAX_SUPPLY = 21_000_000 * 1e8; // 21M BOB in satoshis
    uint256 internal constant DAILY_LIMIT = 1_000_000 * 1e8; // 1M BOB/day

    function setUp() public {
        wBOB = new WBob(admin, pauser, MAX_SUPPLY, DAILY_LIMIT);

        // Cache constant before prank — prank is consumed by any external call
        // including the STATICCALL to .BRIDGE_EXECUTOR_ROLE().
        bytes32 executorRole = wBOB.BRIDGE_EXECUTOR_ROLE();
        vm.prank(admin);
        wBOB.grantRole(executorRole, executor);
    }

    // ─── Deployment ──────────────────────────────────────────────────────────

    function test_Decimals() public view {
        assertEq(wBOB.decimals(), 8);
    }

    function test_Name() public view {
        assertEq(wBOB.name(), "Wrapped BOB");
    }

    function test_Symbol() public view {
        assertEq(wBOB.symbol(), "wBOB");
    }

    function test_MaxSupply() public view {
        assertEq(wBOB.MAX_SUPPLY(), MAX_SUPPLY);
    }

    function test_InitialSupply() public view {
        assertEq(wBOB.totalSupply(), 0);
    }

    function test_AdminRole() public view {
        assertTrue(wBOB.hasRole(wBOB.DEFAULT_ADMIN_ROLE(), admin));
    }

    function test_PauserRole() public view {
        assertTrue(wBOB.hasRole(wBOB.PAUSER_ROLE(), pauser));
    }

    // ─── Mint ────────────────────────────────────────────────────────────────

    function test_Mint_ByExecutor() public {
        uint256 amount = 100 * 1e8;
        vm.prank(executor);
        wBOB.mint(user, amount);
        assertEq(wBOB.balanceOf(user), amount);
        assertEq(wBOB.totalSupply(), amount);
    }

    function test_Mint_UpdatesDailyMinted() public {
        uint256 amount = 500 * 1e8;
        vm.prank(executor);
        wBOB.mint(user, amount);
        assertEq(wBOB.currentDayMinted(), amount);
    }

    function test_Mint_UnauthorizedReverts() public {
        vm.prank(nobody);
        vm.expectRevert();
        wBOB.mint(user, 1e8);
    }

    function test_Mint_ExceedsCapReverts() public {
        // First fill up to MAX_SUPPLY across multiple days
        uint256 chunk = DAILY_LIMIT;
        uint256 totalMinted = 0;

        vm.startPrank(executor);
        while (totalMinted + chunk <= MAX_SUPPLY) {
            // Advance time by 1 day to reset daily limit
            vm.warp(block.timestamp + 1 days);
            wBOB.mint(user, chunk);
            totalMinted += chunk;
        }
        vm.stopPrank();

        // Now minting 1 more satoshi should revert (cap exceeded)
        vm.warp(block.timestamp + 1 days);
        vm.prank(executor);
        vm.expectRevert();
        wBOB.mint(user, 1);
    }

    function test_Mint_ExceedsDailyLimitReverts() public {
        vm.prank(executor);
        wBOB.mint(user, DAILY_LIMIT);

        // Same day: 1 more satoshi should revert
        vm.prank(executor);
        vm.expectRevert(
            abi.encodeWithSelector(WBob.ExceedsDailyMintLimit.selector, 1, 0)
        );
        wBOB.mint(user, 1);
    }

    function test_Mint_DailyLimitResetsAfter24h() public {
        vm.prank(executor);
        wBOB.mint(user, DAILY_LIMIT);

        vm.warp(block.timestamp + 1 days);

        // Should succeed on next day
        vm.prank(executor);
        wBOB.mint(user, DAILY_LIMIT);

        assertEq(wBOB.totalSupply(), DAILY_LIMIT * 2);
    }

    function test_Mint_PausedReverts() public {
        vm.prank(pauser);
        wBOB.pause();

        vm.prank(executor);
        vm.expectRevert();
        wBOB.mint(user, 1e8);
    }

    function testFuzz_Mint_ValidAmounts(uint256 amount) public {
        // Bound within single-day cap and max supply
        amount = bound(amount, 1, DAILY_LIMIT);
        vm.prank(executor);
        wBOB.mint(user, amount);
        assertEq(wBOB.balanceOf(user), amount);
    }

    // ─── Burn ────────────────────────────────────────────────────────────────

    function test_Burn_ByExecutor() public {
        uint256 amount = 100 * 1e8;
        vm.prank(executor);
        wBOB.mint(user, amount);

        vm.prank(executor);
        wBOB.burn(user, amount);

        assertEq(wBOB.balanceOf(user), 0);
        assertEq(wBOB.totalSupply(), 0);
    }

    function test_Burn_PartialAmount() public {
        uint256 mintAmt = 100 * 1e8;
        uint256 burnAmt = 40 * 1e8;

        vm.prank(executor);
        wBOB.mint(user, mintAmt);

        vm.prank(executor);
        wBOB.burn(user, burnAmt);

        assertEq(wBOB.balanceOf(user), mintAmt - burnAmt);
    }

    function test_Burn_UnauthorizedReverts() public {
        vm.prank(executor);
        wBOB.mint(user, 100 * 1e8);

        vm.prank(nobody);
        vm.expectRevert();
        wBOB.burn(user, 100 * 1e8);
    }

    function test_Burn_PausedReverts() public {
        vm.prank(executor);
        wBOB.mint(user, 100 * 1e8);

        vm.prank(pauser);
        wBOB.pause();

        vm.prank(executor);
        vm.expectRevert();
        wBOB.burn(user, 100 * 1e8);
    }

    function test_Burn_InsufficientBalanceReverts() public {
        vm.prank(executor);
        wBOB.mint(user, 50 * 1e8);

        vm.prank(executor);
        vm.expectRevert();
        wBOB.burn(user, 100 * 1e8);
    }

    // ─── Pause / Unpause ─────────────────────────────────────────────────────

    function test_Pause_ByPauser() public {
        vm.prank(pauser);
        wBOB.pause();
        assertTrue(wBOB.paused());
    }

    function test_Unpause_ByPauser() public {
        vm.prank(pauser);
        wBOB.pause();

        vm.prank(pauser);
        wBOB.unpause();

        assertFalse(wBOB.paused());
    }

    function test_Pause_ByUnauthorizedReverts() public {
        vm.prank(nobody);
        vm.expectRevert();
        wBOB.pause();
    }

    function test_Unpause_ByUnauthorizedReverts() public {
        vm.prank(pauser);
        wBOB.pause();

        vm.prank(nobody);
        vm.expectRevert();
        wBOB.unpause();
    }

    // ─── Transfers blocked while paused ──────────────────────────────────────

    function test_Transfer_PausedReverts() public {
        vm.prank(executor);
        wBOB.mint(user, 100 * 1e8);

        vm.prank(pauser);
        wBOB.pause();

        vm.prank(user);
        vm.expectRevert();
        wBOB.transfer(nobody, 50 * 1e8);
    }

    // ─── Admin: setDailyMintLimit ─────────────────────────────────────────────

    function test_SetDailyMintLimit_ByAdmin() public {
        uint256 newLimit = 500_000 * 1e8;
        vm.prank(admin);
        wBOB.setDailyMintLimit(newLimit);
        assertEq(wBOB.dailyMintLimit(), newLimit);
    }

    function test_SetDailyMintLimit_EmitsEvent() public {
        uint256 newLimit = 500_000 * 1e8;
        vm.expectEmit(false, false, false, true, address(wBOB));
        emit WBob.DailyMintLimitUpdated(DAILY_LIMIT, newLimit);
        vm.prank(admin);
        wBOB.setDailyMintLimit(newLimit);
    }

    function test_SetDailyMintLimit_ByUnauthorizedReverts() public {
        vm.prank(nobody);
        vm.expectRevert();
        wBOB.setDailyMintLimit(999);
    }

    // ─── Zero-address constructor guards ─────────────────────────────────────

    function test_Constructor_ZeroAdminReverts() public {
        vm.expectRevert("WBob: zero admin");
        new WBob(address(0), pauser, MAX_SUPPLY, DAILY_LIMIT);
    }

    function test_Constructor_ZeroPauserReverts() public {
        vm.expectRevert("WBob: zero pauser");
        new WBob(admin, address(0), MAX_SUPPLY, DAILY_LIMIT);
    }

    // ─── ERC-20 standard behaviour (sanity) ──────────────────────────────────

    function test_Transfer_Works() public {
        vm.prank(executor);
        wBOB.mint(user, 100 * 1e8);

        vm.prank(user);
        wBOB.transfer(nobody, 30 * 1e8);

        assertEq(wBOB.balanceOf(user), 70 * 1e8);
        assertEq(wBOB.balanceOf(nobody), 30 * 1e8);
    }
}
