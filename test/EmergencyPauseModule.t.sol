// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import "forge-std/Test.sol";
import "../src/WBob.sol";
import "../src/BridgeControllerV2.sol";
import "../src/EmergencyPauseModule.sol";

/// Minimal Safe stand-in: holds roles, forwards module calls as itself (Operation.Call only).
contract MockSafe {
    mapping(address => bool) public moduleEnabled;
    function enableModule(address m) external { moduleEnabled[m] = true; }
    function execTransactionFromModule(address to, uint256 value, bytes calldata data, uint8 operation)
        external returns (bool ok)
    {
        require(moduleEnabled[msg.sender], "GS104");
        require(operation == 0, "no delegatecall");
        (ok, ) = to.call{value: value}(data);
    }
    function exec(address to, bytes calldata data) external returns (bool ok, bytes memory ret) {
        (ok, ret) = to.call(data);
    }
}

contract EmergencyPauseModuleTest is Test {
    MockSafe safe;
    WBob token;
    BridgeControllerV2 bc;
    EmergencyPauseModule mod;
    address operator = makeAddr("operator");

    function setUp() public {
        safe = new MockSafe();
        token = new WBob(address(safe), address(safe), 0, type(uint128).max);
        address[] memory s = new address[](3);
        s[0] = makeAddr("a"); s[1] = makeAddr("b"); s[2] = makeAddr("c");
        bc = new BridgeControllerV2(address(token), address(safe), s, 250_000e8, 100_000);
        mod = new EmergencyPauseModule(ISafe(address(safe)), address(bc), address(token), operator);
        safe.enableModule(address(mod));
    }

    function test_operatorPausesControllerAndToken() public {
        safe.exec(address(bc), abi.encodeWithSignature("unpause()"));    // live controller (born paused)
        vm.prank(operator);
        mod.pauseAll();
        assertTrue(bc.paused());
        assertTrue(token.paused());
    }

    function test_pauseAllIsIdempotent() public {
        safe.exec(address(bc), abi.encodeWithSignature("unpause()"));    // live controller
        safe.exec(address(token), abi.encodeWithSignature("pause()"));   // token already paused by the Safe
        vm.prank(operator);
        mod.pauseAll();
        assertTrue(bc.paused());
        assertTrue(token.paused());
        vm.prank(operator);
        mod.pauseAll();                                                    // both paused: no revert
    }

    function test_nonOperatorCannotPause() public {
        vm.expectRevert(EmergencyPauseModule.OnlyOperator.selector);
        mod.pauseAll();
    }

    function test_moduleHasNoUnpausePath() public {
        vm.prank(operator);
        mod.pauseAll();
        vm.prank(operator);
        (bool ok, ) = address(mod).call(abi.encodeWithSignature("unpause()"));
        assertFalse(ok);
        assertTrue(bc.paused());
        assertTrue(token.paused());
        // Only the Safe (admin) unpauses.
        (bool okC, ) = safe.exec(address(bc), abi.encodeWithSignature("unpause()"));
        (bool okT, ) = safe.exec(address(token), abi.encodeWithSignature("unpause()"));
        assertTrue(okC && okT);
        assertFalse(bc.paused());
        assertFalse(token.paused());
    }

    function test_pausesControllerEvenIfTokenPauseFails() public {
        // Safe lost PAUSER on the token: the controller must still get paused.
        safe.exec(address(token), abi.encodeWithSignature("revokeRole(bytes32,address)", token.PAUSER_ROLE(), address(safe)));
        safe.exec(address(bc), abi.encodeWithSignature("unpause()"));
        vm.expectEmit(true, false, false, false);
        emit EmergencyPauseModule.PauseFailed(address(token));
        vm.prank(operator);
        mod.pauseAll();
        assertTrue(bc.paused());
        assertFalse(token.paused());
    }

    function test_onlySafeRotatesOperator() public {
        vm.expectRevert(EmergencyPauseModule.OnlySafe.selector);
        mod.setOperator(makeAddr("x"));
        vm.prank(address(safe));
        mod.setOperator(makeAddr("x"));
        assertEq(mod.operator(), makeAddr("x"));
    }

    function test_disabledModuleCannotPause() public {
        safe.exec(address(bc), abi.encodeWithSignature("unpause()"));    // live controller (born paused)
        EmergencyPauseModule rogue = new EmergencyPauseModule(ISafe(address(safe)), address(bc), address(token), operator);
        vm.prank(operator);
        vm.expectRevert(EmergencyPauseModule.NothingPaused.selector);
        rogue.pauseAll();
        assertFalse(bc.paused());
        assertFalse(token.paused());
    }
}
