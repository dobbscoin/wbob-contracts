// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import "forge-std/Test.sol";
import "../src/WBob.sol";
import "../src/BridgeControllerV2.sol";
import "../src/EmergencyPauseModule.sol";

interface ISafeFull {
    function enableModule(address module) external;
    function disableModule(address prevModule, address module) external;
    function getModulesPaginated(address start, uint256 pageSize) external view returns (address[] memory, address);
    function getThreshold() external view returns (uint256);
}

interface IBridgeV1 {
    function requestWithdrawal(uint256 amount, string calldata dobbscoinAddress) external;
}

/**
 * Rehearses the V1 → V2 cutover against REAL Gnosis state (a local fork; nothing
 * is sent anywhere). Skipped unless FORK_RPC is set:
 *
 *   FORK_RPC=http://100.87.114.52:8545 forge test --match-contract ForkCutover -vv
 *
 * Acts as the real admin Safe via vm.prank (the fork lets us impersonate it).
 */
contract ForkCutoverTest is Test {
    WBob constant WBOB = WBob(0x13550ae65f22A36f60A50d625B70b58666488263);
    address constant V1 = 0x20a9A6D5FB3615a79603a6Ed74A3d26FB11aB872;
    address constant SAFE = 0x09BD8F882f02c4A5F1FE9894f9Ad714Ec371e8f4;
    address constant OLD_MODULE = 0xd5ebf9EC7971B18A6b1e7f05Ee0BF96BE72e3410;
    address constant SENTINEL = address(0x1);

    // A real V1 MintExecuted (Gnosis block 48,995,233).
    uint256 constant CHAIN = 1000001;
    bytes32 constant REAL_TXH = 0x00ba16cf912b00c6e863d3304f31ee6bc1c2643f60be65d6c6613ae136b33132;
    uint32 constant REAL_VOUT = 1;

    string constant ADDR = "1L9YGqctBWaCmn7y8d8CBkTXzXXZ4EAECN";

    BridgeControllerV2 bc;
    EmergencyPauseModule mod;
    uint256[3] keys;
    address operator = makeAddr("operator");
    address recipient = makeAddr("recipient");
    bool forked;

    function setUp() public {
        string memory rpc = vm.envOr("FORK_RPC", string(""));
        if (bytes(rpc).length == 0) return;
        vm.createSelectFork(rpc);
        forked = true;

        address[] memory signers = new address[](3);
        for (uint256 i = 0; i < 3; i++) {
            keys[i] = uint256(keccak256(abi.encode("fork-signer", i)));
            signers[i] = vm.addr(keys[i]);
        }
        bc = new BridgeControllerV2(address(WBOB), SAFE, signers, 250_000e8, 100_000);
        mod = new EmergencyPauseModule(ISafe(SAFE), address(bc), address(WBOB), operator);

        // ── The cutover, as the Safe would run it ──
        vm.startPrank(SAFE);
        WBOB.grantRole(WBOB.BRIDGE_EXECUTOR_ROLE(), address(bc));
        WBOB.revokeRole(WBOB.BRIDGE_EXECUTOR_ROLE(), V1);
        bytes32[] memory k = new bytes32[](1);
        k[0] = bc.outpointKey(CHAIN, REAL_TXH, REAL_VOUT);
        bc.importProcessedOutpoints(k);
        bc.sealImport();
        ISafeFull(SAFE).enableModule(address(mod));
        // New module is at the head of the list, so the old one's predecessor is it.
        ISafeFull(SAFE).disableModule(address(mod), OLD_MODULE);
        vm.stopPrank();
    }

    modifier onlyFork() {
        if (!forked) { vm.skip(true); }
        _;
    }

    function _auth(bytes32 depositId, uint256 amount, bytes32 txh, uint32 vout)
        internal view returns (BridgeControllerV2.MintAuthorization memory a)
    {
        a = BridgeControllerV2.MintAuthorization(depositId, recipient, amount, CHAIN, txh, vout, block.timestamp + 1 hours, 0);
    }

    function _sigs(BridgeControllerV2.MintAuthorization memory a) internal view returns (bytes[] memory s) {
        s = new bytes[](3);
        bytes32 d = bc.getMintAuthorizationDigest(a);
        for (uint256 i = 0; i < 3; i++) {
            (uint8 v, bytes32 r, bytes32 ss) = vm.sign(keys[i], d);
            s[i] = abi.encodePacked(r, ss, v);
        }
    }

    function test_fork_rolesMoved_andOldModuleGone() public onlyFork {
        assertTrue(WBOB.hasRole(WBOB.BRIDGE_EXECUTOR_ROLE(), address(bc)));
        assertFalse(WBOB.hasRole(WBOB.BRIDGE_EXECUTOR_ROLE(), V1));
        (address[] memory mods,) = ISafeFull(SAFE).getModulesPaginated(SENTINEL, 10);
        assertEq(mods.length, 1);
        assertEq(mods[0], address(mod));
    }

    function test_fork_v2MintsRealWbob() public onlyFork {
        uint256 supply = WBOB.totalSupply();
        BridgeControllerV2.MintAuthorization memory a = _auth("fork-d1", 1e8, keccak256("fresh-tx"), 0);
        bc.executeMint(a, _sigs(a));
        assertEq(WBOB.balanceOf(recipient), 1e8);
        assertEq(WBOB.totalSupply(), supply + 1e8);
    }

    function test_fork_realV1OutpointCannotMintAgain() public onlyFork {
        BridgeControllerV2.MintAuthorization memory a = _auth("forged-id", 1e8, REAL_TXH, REAL_VOUT);
        bytes[] memory s = _sigs(a);
        vm.expectRevert(abi.encodeWithSelector(
            BridgeControllerV2.OutpointAlreadyMinted.selector, bc.outpointKey(CHAIN, REAL_TXH, REAL_VOUT)));
        bc.executeMint(a, s);
    }

    function test_fork_v1WithdrawalNowReverts_noBurn() public onlyFork {
        deal(address(WBOB), recipient, 5e8, true);
        vm.prank(recipient);
        vm.expectRevert();                              // V1 lost BRIDGE_EXECUTOR_ROLE: its burn reverts
        IBridgeV1(V1).requestWithdrawal(1e8, ADDR);
        assertEq(WBOB.balanceOf(recipient), 5e8);
    }

    function test_fork_v2WithdrawalBurnsRealWbob() public onlyFork {
        deal(address(WBOB), recipient, 5e8, true);
        uint256 supply = WBOB.totalSupply();
        vm.prank(recipient);
        bc.requestWithdrawal(2e8, ADDR);
        assertEq(WBOB.balanceOf(recipient), 3e8);
        assertEq(WBOB.totalSupply(), supply - 2e8);
    }

    function test_fork_emergencyPauseFreezesTokenToo_onlySafeUnpauses() public onlyFork {
        deal(address(WBOB), recipient, 5e8, true);
        vm.prank(operator);
        mod.pauseAll();
        assertTrue(bc.paused());
        assertTrue(WBOB.paused());
        vm.prank(recipient);
        vm.expectRevert();
        WBOB.transfer(makeAddr("dex"), 1e8);            // minted wBOB can't be dumped while paused
        vm.startPrank(SAFE);
        bc.unpause();
        WBOB.unpause();
        vm.stopPrank();
        vm.prank(recipient);
        WBOB.transfer(makeAddr("dex"), 1e8);
    }

    function test_fork_tokenDailyCapStillApplies() public onlyFork {
        // The token's own (fixed-day) cap sits on top of V2's rolling cap.
        uint256 tokenLimit = WBOB.dailyMintLimit();
        assertGt(tokenLimit, 0);
        bc.remainingMintCapacity();
    }
}
