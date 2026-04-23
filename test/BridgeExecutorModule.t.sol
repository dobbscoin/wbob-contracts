// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

import "forge-std/Test.sol";
import "../src/WBob.sol";
import "../src/BridgeController.sol";
import "../src/BridgeExecutorModule.sol";

// ─── MockSafe ─────────────────────────────────────────────────────────────────

/**
 * @notice Minimal Gnosis Safe stand-in.
 *
 * Implements `execTransactionFromModule` by actually forwarding the call with
 * the MockSafe as msg.sender. In tests, MockSafe holds PAUSER_ROLE on
 * BridgeController, so pause/unpause succeed when routed through it.
 *
 * Also exposes `execTransactionFromModuleReturnBool` to test failure paths.
 */
contract MockSafe {
    bool public shouldFail;

    function setShouldFail(bool _fail) external { shouldFail = _fail; }

    function execTransactionFromModule(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 /* operation */
    ) external returns (bool success) {
        if (shouldFail) return false;
        (success, ) = to.call{ value: value }(data);
    }
}

// ─── BridgeExecutorModuleTest ─────────────────────────────────────────────────

contract BridgeExecutorModuleTest is Test {
    WBob               internal wBOB;
    BridgeController   internal bridge;
    MockSafe           internal safe;
    BridgeExecutorModule internal module;

    address internal admin    = makeAddr("admin");
    address internal operator = makeAddr("operator");
    address internal nobody   = makeAddr("nobody");

    uint256 internal constant MAX_SUPPLY  = 21_000_000 * 1e8;
    uint256 internal constant DAILY_LIMIT = 1_000_000 * 1e8;

    // ── Setup ─────────────────────────────────────────────────────────────────

    function setUp() public {
        // Deploy WBob
        wBOB = new WBob(admin, admin, MAX_SUPPLY, DAILY_LIMIT);

        // Deploy BridgeController (5 dummy signers required)
        address[] memory signers = new address[](5);
        for (uint256 i = 0; i < 5; i++) {
            signers[i] = vm.addr(uint256(keccak256(abi.encodePacked("watcher", i))));
        }
        bridge = new BridgeController(address(wBOB), admin, admin, signers);

        // Grant BRIDGE_EXECUTOR_ROLE to BridgeController on WBob
        bytes32 execRole = wBOB.BRIDGE_EXECUTOR_ROLE();
        vm.prank(admin);
        wBOB.grantRole(execRole, address(bridge));

        // Deploy MockSafe
        safe = new MockSafe();

        // Grant PAUSER_ROLE on BridgeController and WBob to the MockSafe.
        // The module routes calls through the safe, so safe needs the role.
        bytes32 pauserRole = bridge.PAUSER_ROLE();
        vm.startPrank(admin);
        bridge.grantRole(pauserRole, address(safe));
        wBOB.grantRole(wBOB.PAUSER_ROLE(), address(safe));
        vm.stopPrank();

        // Deploy module
        module = new BridgeExecutorModule(ISafe(address(safe)), address(bridge), operator);
    }

    // ─── Constructor ──────────────────────────────────────────────────────────

    function test_constructor_setsImmutables() public view {
        assertEq(address(module.safe()),             address(safe));
        assertEq(module.bridgeController(),          address(bridge));
        assertEq(module.operator(),                  operator);
    }

    function test_constructor_zeroSafe_reverts() public {
        vm.expectRevert(BridgeExecutorModule.ZeroAddress.selector);
        new BridgeExecutorModule(ISafe(address(0)), address(bridge), operator);
    }

    function test_constructor_zeroBridge_reverts() public {
        vm.expectRevert(BridgeExecutorModule.ZeroAddress.selector);
        new BridgeExecutorModule(ISafe(address(safe)), address(0), operator);
    }

    function test_constructor_zeroOperator_reverts() public {
        vm.expectRevert(BridgeExecutorModule.ZeroAddress.selector);
        new BridgeExecutorModule(ISafe(address(safe)), address(bridge), address(0));
    }

    // ─── pause() ─────────────────────────────────────────────────────────────

    function test_pause_operatorCanPause() public {
        assertFalse(bridge.paused(), "should start unpaused");
        vm.prank(operator);
        module.pause();
        assertTrue(bridge.paused(), "should be paused after module.pause()");
    }

    function test_pause_emitsEvent() public {
        vm.expectEmit(true, false, false, false);
        emit BridgeExecutorModule.EmergencyPaused(operator);
        vm.prank(operator);
        module.pause();
    }

    function test_pause_nonOperator_reverts() public {
        vm.prank(nobody);
        vm.expectRevert(BridgeExecutorModule.OnlyOperator.selector);
        module.pause();
    }

    function test_pause_safeCallFailure_reverts() public {
        safe.setShouldFail(true);
        vm.prank(operator);
        vm.expectRevert(BridgeExecutorModule.ModuleCallFailed.selector);
        module.pause();
    }

    function test_pause_alreadyPaused_reverts() public {
        // Pause directly via admin first
        bytes32 pauserRole = bridge.PAUSER_ROLE();
        vm.prank(admin);
        bridge.grantRole(pauserRole, admin);
        vm.prank(admin);
        bridge.pause();
        assertTrue(bridge.paused());

        // Trying to pause again through the module should cause the Safe call to fail
        // because BridgeController.pause() reverts when already paused.
        // MockSafe returns false when the inner call fails, so we get ModuleCallFailed.
        vm.prank(operator);
        vm.expectRevert(BridgeExecutorModule.ModuleCallFailed.selector);
        module.pause();
    }

    // ─── unpause() ───────────────────────────────────────────────────────────

    function test_unpause_operatorCanUnpause() public {
        // First pause via the admin path
        bytes32 pauserRole = bridge.PAUSER_ROLE();
        vm.prank(admin);
        bridge.grantRole(pauserRole, admin);
        vm.prank(admin);
        bridge.pause();
        assertTrue(bridge.paused());

        // Now unpause via the module
        vm.prank(operator);
        module.unpause();
        assertFalse(bridge.paused(), "should be unpaused after module.unpause()");
    }

    function test_unpause_emitsEvent() public {
        // Pause first so unpause has something to do
        bytes32 pauserRole = bridge.PAUSER_ROLE();
        vm.prank(admin);
        bridge.grantRole(pauserRole, admin);
        vm.prank(admin);
        bridge.pause();

        vm.expectEmit(true, false, false, false);
        emit BridgeExecutorModule.EmergencyUnpaused(operator);
        vm.prank(operator);
        module.unpause();
    }

    function test_unpause_nonOperator_reverts() public {
        vm.prank(nobody);
        vm.expectRevert(BridgeExecutorModule.OnlyOperator.selector);
        module.unpause();
    }

    function test_unpause_safeCallFailure_reverts() public {
        safe.setShouldFail(true);
        vm.prank(operator);
        vm.expectRevert(BridgeExecutorModule.ModuleCallFailed.selector);
        module.unpause();
    }

    // ─── pause → unpause round-trip ───────────────────────────────────────────

    function test_pauseUnpause_roundTrip() public {
        assertFalse(bridge.paused());

        vm.prank(operator);
        module.pause();
        assertTrue(bridge.paused());

        vm.prank(operator);
        module.unpause();
        assertFalse(bridge.paused());
    }

    function test_pauseUnpause_stopsAndResumesWithdrawals() public {
        // Give user some wBOB
        bytes32 execRole = wBOB.BRIDGE_EXECUTOR_ROLE();
        vm.prank(admin);
        wBOB.grantRole(execRole, admin);
        vm.prank(admin);
        wBOB.mint(makeAddr("user"), 1_000 * 1e8);

        // Pause via module
        vm.prank(operator);
        module.pause();

        // Withdrawal should revert
        address user = makeAddr("user");
        vm.prank(user);
        vm.expectRevert();
        bridge.requestWithdrawal(100 * 1e8, "1DobbsAddr");

        // Unpause via module
        vm.prank(operator);
        module.unpause();

        // Withdrawal should succeed now
        vm.prank(user);
        bridge.requestWithdrawal(100 * 1e8, "1DobbsAddr");
    }

    // ─── setOperator() ───────────────────────────────────────────────────────

    function test_setOperator_safeCanRotate() public {
        address newOperator = makeAddr("newOperator");

        vm.prank(address(safe));
        module.setOperator(newOperator);

        assertEq(module.operator(), newOperator);
    }

    function test_setOperator_emitsEvent() public {
        address newOperator = makeAddr("newOperator");

        vm.expectEmit(true, true, false, false);
        emit BridgeExecutorModule.OperatorChanged(operator, newOperator);

        vm.prank(address(safe));
        module.setOperator(newOperator);
    }

    function test_setOperator_nonSafe_reverts() public {
        vm.prank(operator);
        vm.expectRevert(BridgeExecutorModule.OnlySafe.selector);
        module.setOperator(makeAddr("newOperator"));
    }

    function test_setOperator_admin_reverts() public {
        vm.prank(admin);
        vm.expectRevert(BridgeExecutorModule.OnlySafe.selector);
        module.setOperator(makeAddr("newOperator"));
    }

    function test_setOperator_zero_reverts() public {
        vm.prank(address(safe));
        vm.expectRevert(BridgeExecutorModule.ZeroAddress.selector);
        module.setOperator(address(0));
    }

    function test_setOperator_newKeyCanPause() public {
        address newOperator = makeAddr("newOperator");
        vm.prank(address(safe));
        module.setOperator(newOperator);

        // Old operator cannot pause
        vm.prank(operator);
        vm.expectRevert(BridgeExecutorModule.OnlyOperator.selector);
        module.pause();

        // New operator can pause
        vm.prank(newOperator);
        module.pause();
        assertTrue(bridge.paused());
    }

    // ─── Fuzz ────────────────────────────────────────────────────────────────

    function testFuzz_onlyOperatorCanPause(address caller) public {
        vm.assume(caller != operator);
        vm.prank(caller);
        vm.expectRevert(BridgeExecutorModule.OnlyOperator.selector);
        module.pause();
    }

    function testFuzz_onlySafeCanSetOperator(address caller) public {
        vm.assume(caller != address(safe));
        vm.prank(caller);
        vm.expectRevert(BridgeExecutorModule.OnlySafe.selector);
        module.setOperator(makeAddr("x"));
    }
}
