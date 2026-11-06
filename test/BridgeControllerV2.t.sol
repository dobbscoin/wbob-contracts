// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import "forge-std/Test.sol";
import "../src/WBob.sol";
import "../src/BridgeControllerV2.sol";

contract BridgeControllerV2Test is Test {
    WBob token;
    BridgeControllerV2 bc;

    address admin = address(this);
    address pauserOnly = makeAddr("pauserOnly");
    address recipient = makeAddr("recipient");
    address user = makeAddr("user");

    uint256[5] keys;
    address[] signers;

    uint256 constant LIMIT = 250_000e8;
    uint256 constant MIN_W = 100_000;
    uint256 constant CHAIN = 0x444f4242; // any constant
    string constant ADDR = "1L9YGqctBWaCmn7y8d8CBkTXzXXZ4EAECN";

    function setUp() public {
        vm.warp(1_800_000_000);
        token = new WBob(admin, admin, 0, type(uint128).max); // no max supply, token cap out of the way
        for (uint256 i = 0; i < 5; i++) {
            keys[i] = uint256(keccak256(abi.encode("signer", i)));
            signers.push(vm.addr(keys[i]));
        }
        bc = new BridgeControllerV2(address(token), admin, signers, LIMIT, MIN_W, CHAIN);
        token.grantRole(token.BRIDGE_EXECUTOR_ROLE(), address(bc));
        bc.grantRole(bc.PAUSER_ROLE(), pauserOnly);
        bc.unpause();                                 // the Safe's LAST cutover step
    }

    function test_bornPaused() public {
        BridgeControllerV2 fresh = new BridgeControllerV2(address(token), admin, signers, LIMIT, MIN_W, CHAIN);
        assertTrue(fresh.paused());
    }

    // ─── helpers ─────────────────────────────────────────────────────────────

    function _auth(bytes32 depositId, address to, uint256 amount, bytes32 txh, uint32 vout)
        internal view returns (BridgeControllerV2.MintAuthorization memory a)
    {
        a = _authV(depositId, to, amount, txh, vout, amount);   // whole output minted
    }

    function _authV(bytes32 depositId, address to, uint256 amount, bytes32 txh, uint32 vout, uint256 value)
        internal view returns (BridgeControllerV2.MintAuthorization memory a)
    {
        a = BridgeControllerV2.MintAuthorization({
            depositId: depositId, recipient: to, amount: amount, sourceChainId: CHAIN,
            sourceTxHash: txh, sourceVout: vout, sourceValue: value,
            deadline: block.timestamp + 1 hours, nonce: bc.mintNonce()
        });
    }

    function _sig(BridgeControllerV2.MintAuthorization memory a, uint256 k) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(k, bc.getMintAuthorizationDigest(a));
        return abi.encodePacked(r, s, v);
    }

    function _sigs(BridgeControllerV2.MintAuthorization memory a) internal view returns (bytes[] memory s) {
        s = new bytes[](3);
        for (uint256 i = 0; i < 3; i++) s[i] = _sig(a, keys[i]);
    }

    function _seal() internal { bc.sealImport(); }

    function _mint(bytes32 depositId, uint256 amount, bytes32 txh, uint32 vout) internal {
        BridgeControllerV2.MintAuthorization memory a = _auth(depositId, recipient, amount, txh, vout);
        bc.executeMint(a, _sigs(a));
    }

    // ─── import / seal ───────────────────────────────────────────────────────

    function test_noMintBeforeImportSealed() public {
        BridgeControllerV2.MintAuthorization memory a = _auth("d1", recipient, 1e8, "tx1", 0);
        bytes[] memory s = _sigs(a);
        vm.expectRevert(BridgeControllerV2.ImportNotSealed.selector);
        bc.executeMint(a, s);
    }

    function test_importedOutpointCannotMint() public {
        bytes32[] memory k = new bytes32[](1);
        k[0] = bc.outpointKey(CHAIN, "v1tx", 1);
        bc.importProcessedOutpoints(k);
        _seal();
        BridgeControllerV2.MintAuthorization memory a = _auth("fresh-deposit-id", recipient, 1e8, "v1tx", 1);
        bytes[] memory s = _sigs(a);
        vm.expectRevert(abi.encodeWithSelector(BridgeControllerV2.OutpointAlreadyMinted.selector, k[0]));
        bc.executeMint(a, s);
    }

    function test_importStillAllowedAfterSeal_blocksOnly_andSealOnce() public {
        _seal();
        bytes32[] memory k = new bytes32[](1);
        k[0] = bc.outpointKey(CHAIN, "late-found-v1tx", 0);
        bc.importProcessedOutpoints(k);                // a gap found after the seal can still be closed
        BridgeControllerV2.MintAuthorization memory a = _auth("x", recipient, 1e8, "late-found-v1tx", 0);
        bytes[] memory s = _sigs(a);
        vm.expectRevert(abi.encodeWithSelector(BridgeControllerV2.OutpointAlreadyMinted.selector, k[0]));
        bc.executeMint(a, s);
        vm.expectRevert(BridgeControllerV2.ImportAlreadySealed.selector);
        bc.sealImport();
    }

    function test_importAndSealAdminOnly() public {
        bytes32[] memory k = new bytes32[](0);
        vm.prank(user);
        vm.expectRevert();
        bc.importProcessedOutpoints(k);
        vm.prank(user);
        vm.expectRevert();
        bc.sealImport();
    }

    // ─── mint ────────────────────────────────────────────────────────────────

    function test_happyMint() public {
        _seal();
        _mint("d1", 5e8, "tx1", 0);
        assertEq(token.balanceOf(recipient), 5e8);
        assertTrue(bc.processedOutpoints(bc.outpointKey(CHAIN, "tx1", 0)));
        assertTrue(bc.processedDeposits("d1"));
    }

    function test_sameOutpointNewDepositIdAndRecipient_reverts() public {
        _seal();
        _mint("d1", 5e8, "tx1", 0);
        BridgeControllerV2.MintAuthorization memory a = _auth("d1-forged", user, 5e8, "tx1", 0);
        bytes[] memory s = _sigs(a);
        vm.expectRevert(abi.encodeWithSelector(BridgeControllerV2.OutpointAlreadyMinted.selector, bc.outpointKey(CHAIN, "tx1", 0)));
        bc.executeMint(a, s);
    }

    function test_sameTxOtherVoutMints() public {
        _seal();
        _mint("d1", 5e8, "tx1", 0);
        _mint("d2", 5e8, "tx1", 1);
        assertEq(token.balanceOf(recipient), 10e8);
    }

    function test_malformedSignaturesAreSkipped() public {
        _seal();
        BridgeControllerV2.MintAuthorization memory a = _auth("d1", recipient, 1e8, "tx1", 0);
        bytes memory good0 = _sig(a, keys[0]);
        (bytes32 r, bytes32 s) = (bytes32(0), bytes32(0));
        assembly { r := mload(add(good0, 0x20)) s := mload(add(good0, 0x40)) }
        uint256 n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        bytes memory highS = abi.encodePacked(r, bytes32(n - uint256(s)), uint8(good0[64]) == 27 ? uint8(28) : uint8(27));
        bytes[] memory sigs = new bytes[](6);
        sigs[0] = highS;                                   // malleated: tryRecover → error, skipped
        sigs[1] = abi.encodePacked(bytes32(0), bytes32(0), uint8(27)); // invalid
        sigs[2] = hex"deadbeef";                           // wrong length
        sigs[3] = good0;
        sigs[4] = _sig(a, keys[1]);
        sigs[5] = _sig(a, keys[2]);
        bc.executeMint(a, sigs);
        assertEq(token.balanceOf(recipient), 1e8);
    }

    function test_duplicateSignerCountsOnce() public {
        _seal();
        BridgeControllerV2.MintAuthorization memory a = _auth("d1", recipient, 1e8, "tx1", 0);
        bytes[] memory sigs = new bytes[](3);
        sigs[0] = _sig(a, keys[0]); sigs[1] = _sig(a, keys[0]); sigs[2] = _sig(a, keys[1]);
        vm.expectRevert(abi.encodeWithSelector(BridgeControllerV2.InsufficientValidSignatures.selector, 2, 3));
        bc.executeMint(a, sigs);
    }

    function test_nonSignerIgnored() public {
        _seal();
        BridgeControllerV2.MintAuthorization memory a = _auth("d1", recipient, 1e8, "tx1", 0);
        bytes[] memory sigs = new bytes[](3);
        sigs[0] = _sig(a, keys[0]); sigs[1] = _sig(a, keys[1]); sigs[2] = _sig(a, 0xBAD);
        vm.expectRevert(abi.encodeWithSelector(BridgeControllerV2.InsufficientValidSignatures.selector, 2, 3));
        bc.executeMint(a, sigs);
    }

    function test_deadlineAndNonce() public {
        _seal();
        BridgeControllerV2.MintAuthorization memory a = _auth("d1", recipient, 1e8, "tx1", 0);
        bytes[] memory s = _sigs(a);
        vm.warp(a.deadline + 1);
        vm.expectRevert(abi.encodeWithSelector(BridgeControllerV2.DeadlineExpired.selector, a.deadline, block.timestamp));
        bc.executeMint(a, s);

        a = _auth("d2", recipient, 1e8, "tx2", 0);
        s = _sigs(a);
        bc.incrementMintNonce();
        vm.expectRevert(abi.encodeWithSelector(BridgeControllerV2.WrongMintNonce.selector, 0, 1));
        bc.executeMint(a, s);
    }

    function test_digestMatchesManualEip712_version2() public view {
        BridgeControllerV2.MintAuthorization memory a = _auth("d1", recipient, 1e8, "tx1", 0);
        bytes32 domain = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("BridgeController"), keccak256("2"), block.chainid, address(bc)));
        bytes32 structHash = keccak256(abi.encode(bc.MINT_AUTHORIZATION_TYPEHASH(),
            a.depositId, a.recipient, a.amount, a.sourceChainId, a.sourceTxHash, a.sourceVout, a.sourceValue, a.deadline, a.nonce));
        assertEq(bc.getMintAuthorizationDigest(a), keccak256(abi.encodePacked("\x19\x01", domain, structHash)));
    }

    // ─── rolling window ──────────────────────────────────────────────────────

    function test_noDoubleCapAcrossMidnight() public {
        _seal();
        uint256 midnight = (block.timestamp / 1 days + 1) * 1 days;
        vm.warp(midnight - 10);
        _mint("d1", LIMIT, "tx1", 0);
        vm.warp(midnight + 5);                       // new UTC day: V1/WBob would allow LIMIT again
        BridgeControllerV2.MintAuthorization memory a = _auth("d2", recipient, 1, "tx2", 0);
        bytes[] memory s = _sigs(a);
        vm.expectRevert(abi.encodeWithSelector(BridgeControllerV2.ExceedsWindowLimit.selector, 1, 0));
        bc.executeMint(a, s);
    }

    function test_capacityReturnsAfter24to25Hours() public {
        _seal();
        _mint("d1", LIMIT, "tx1", 0);
        vm.warp(block.timestamp + 24 hours);
        assertEq(bc.remainingMintCapacity(), 0);      // still inside the 25-bucket window
        vm.warp(block.timestamp + 1 hours);
        assertEq(bc.remainingMintCapacity(), LIMIT);
        _mint("d2", LIMIT, "tx2", 0);
    }

    /// Reviewer's worst case for 24 buckets: L at hh:59:59, L again 23h0m1s later.
    function test_noDoubleCapWithinAny24Hours() public {
        _seal();
        uint256 hourEnd = (block.timestamp / 1 hours + 1) * 1 hours;
        vm.warp(hourEnd - 1);
        _mint("d1", LIMIT, "tx1", 0);
        vm.warp(hourEnd - 1 + 23 hours + 1);
        BridgeControllerV2.MintAuthorization memory a = _auth("d2", recipient, 1, "tx2", 0);
        bytes[] memory s = _sigs(a);
        vm.expectRevert(abi.encodeWithSelector(BridgeControllerV2.ExceedsWindowLimit.selector, 1, 0));
        bc.executeMint(a, s);
        vm.warp(hourEnd - 1 + 24 hours + 1);           // a full 24 h later: allowed again
        assertEq(bc.remainingMintCapacity(), LIMIT);
    }

    function test_partialWindowAcrossHours() public {
        _seal();
        _mint("d1", 100_000e8, "tx1", 0);
        vm.warp(block.timestamp + 5 hours);
        _mint("d2", 150_000e8, "tx2", 0);
        assertEq(bc.remainingMintCapacity(), 0);
        vm.warp(block.timestamp + 20 hours);         // first bucket (25 h old) drops out
        assertEq(bc.remainingMintCapacity(), 100_000e8);
    }

    function test_loweringLimitBelowUsageDoesNotUnderflow() public {
        _seal();
        _mint("d1", 200_000e8, "tx1", 0);
        bc.setMintLimitPerWindow(100_000e8);
        assertEq(bc.remainingMintCapacity(), 0);
        BridgeControllerV2.MintAuthorization memory a = _auth("d2", recipient, 1, "tx2", 0);
        bytes[] memory s = _sigs(a);
        vm.expectRevert(abi.encodeWithSelector(BridgeControllerV2.ExceedsWindowLimit.selector, 1, 0));
        bc.executeMint(a, s);
    }

    // ─── withdrawals ─────────────────────────────────────────────────────────

    function _fundUser(uint256 amount) internal {
        _seal();
        BridgeControllerV2.MintAuthorization memory a = _auth("fund", user, amount, "fundtx", 0);
        bc.executeMint(a, _sigs(a));
    }

    function test_withdrawHappy_idIncludesController() public {
        _fundUser(10e8);
        uint256 expectedId = uint256(keccak256(abi.encodePacked(address(bc), user, uint256(0))));
        uint256 v1StyleId = uint256(keccak256(abi.encodePacked(user, uint256(0))));
        assertTrue(expectedId != v1StyleId);
        vm.expectEmit(true, true, false, true);
        emit BridgeControllerV2.WithdrawalRequested(expectedId, user, 2e8, ADDR, 0);
        vm.prank(user);
        bc.requestWithdrawal(2e8, ADDR);
        assertEq(token.balanceOf(user), 8e8);
    }

    function test_withdrawAtOrUnderMinimumReverts_nothingBurned() public {
        _fundUser(10e8);
        vm.startPrank(user);
        vm.expectRevert(abi.encodeWithSelector(BridgeControllerV2.WithdrawalTooSmall.selector, MIN_W, MIN_W));
        bc.requestWithdrawal(MIN_W, ADDR);
        vm.expectRevert(abi.encodeWithSelector(BridgeControllerV2.WithdrawalTooSmall.selector, 1, MIN_W));
        bc.requestWithdrawal(1, ADDR);
        bc.requestWithdrawal(MIN_W + 1, ADDR);
        vm.stopPrank();
        assertEq(token.balanceOf(user), 10e8 - (MIN_W + 1));
    }

    function test_withdrawBadAddressesRevert() public {
        _fundUser(10e8);
        string[8] memory bad = [
            "",
            "\x00",
            "0x1111111111111111111111111111111111111111",
            "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",          // P2SH: not payable by the bridge
            "1L9YGqctBWaCmn7y8d8CBkTXzXXZ4EAEC\x00",
            "1L9YGqctBWaCmn7y8d8CBkTXzXXZ4EAEO0",           // O and 0 are not base58
            "1short",
            "1L9YGqctBWaCmn7y8d8CBkTXzXXZ4EAECNxxxxxx"      // too long
        ];
        vm.startPrank(user);
        for (uint256 i = 0; i < bad.length; i++) {
            vm.expectRevert(BridgeControllerV2.InvalidDobbscoinAddress.selector);
            bc.requestWithdrawal(1e8, bad[i]);
        }
        vm.stopPrank();
        assertEq(token.balanceOf(user), 10e8);
    }

    // ─── pause / roles / signers ─────────────────────────────────────────────

    function test_pauserCanPauseButNotUnpause() public {
        vm.prank(pauserOnly);
        bc.pause();
        assertTrue(bc.paused());
        vm.prank(pauserOnly);
        vm.expectRevert();
        bc.unpause();
        bc.unpause();                                 // admin (Safe) can
        assertFalse(bc.paused());
    }

    function test_pausedBlocksMintAndWithdraw() public {
        _fundUser(10e8);
        bc.pause();
        BridgeControllerV2.MintAuthorization memory a = _auth("d9", recipient, 1e8, "tx9", 0);
        bytes[] memory s = _sigs(a);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        bc.executeMint(a, s);
        vm.prank(user);
        vm.expectRevert(Pausable.EnforcedPause.selector);
        bc.requestWithdrawal(1e8, ADDR);
    }

    function test_removeDownToThresholdThenBlocked() public {
        bc.removeSigner(signers[0]);
        bc.removeSigner(signers[1]);
        vm.expectRevert(BridgeControllerV2.BelowThreshold.selector);
        bc.removeSigner(signers[2]);
    }

    function test_maxSevenSigners() public {
        bc.addSigner(makeAddr("s6"));
        bc.addSigner(makeAddr("s7"));
        vm.expectRevert(BridgeControllerV2.SignerSetFull.selector);
        bc.addSigner(makeAddr("s8"));
    }

    // ─── Refund accounting (review round 3) ──────────────────────────────────

    address marker = makeAddr("marker");

    function _grantMarker() internal { bc.grantRole(bc.REFUND_MARKER_ROLE(), marker); }

    function _mintV(bytes32 depositId, uint256 amount, bytes32 txh, uint32 vout, uint256 value) internal {
        BridgeControllerV2.MintAuthorization memory a = _authV(depositId, recipient, amount, txh, vout, value);
        bc.executeMint(a, _sigs(a));
    }

    function test_fullyRefundedOutputCanNeverMint() public {
        _seal(); _grantMarker();
        vm.prank(marker);
        bc.recordRefund("rtx", 0, 5e8, 5e8);                 // whole deposit refunded
        // A DB writer forges a mint for it: watchers would sign (output is real), the contract refuses.
        BridgeControllerV2.MintAuthorization memory a = _authV("forged", user, 1, "rtx", 0, 5e8);
        bytes[] memory s = _sigs(a);
        vm.expectRevert(abi.encodeWithSelector(BridgeControllerV2.ExceedsSourceValue.selector,
            bc.outpointKey(CHAIN, "rtx", 0), 1, 5e8, 5e8));
        bc.executeMint(a, s);
    }

    function test_splitDeposit_mintCappedAtValueMinusRefund() public {
        _seal(); _grantMarker();
        vm.prank(marker);
        bc.recordRefund("stx", 0, 10e8, 4e8);                // 4 of 10 refunded over the cap
        BridgeControllerV2.MintAuthorization memory a = _authV("inflated", recipient, 10e8, "stx", 0, 10e8);
        bytes[] memory s = _sigs(a);
        vm.expectRevert(abi.encodeWithSelector(BridgeControllerV2.ExceedsSourceValue.selector,
            bc.outpointKey(CHAIN, "stx", 0), 10e8, 4e8, 10e8));
        bc.executeMint(a, s);                                // DB raised the mint to the full deposit
        _mintV("honest", 6e8, "stx", 0, 10e8);               // the honest split mints
        assertEq(token.balanceOf(recipient), 6e8);
    }

    function test_refundAfterMintCannotExceedRemainder() public {
        _seal(); _grantMarker();
        _mintV("m", 6e8, "ptx", 0, 10e8);
        bytes32 k = bc.outpointKey(CHAIN, "ptx", 0);         // computed BEFORE the prank (an external call consumes it)
        vm.prank(marker);
        vm.expectRevert(abi.encodeWithSelector(BridgeControllerV2.ExceedsSourceValue.selector, k, 6e8, 5e8, 10e8));
        bc.recordRefund("ptx", 0, 10e8, 5e8);
        vm.prank(marker);
        bc.recordRefund("ptx", 0, 10e8, 4e8);
        assertEq(bc.refundedAmount(bc.outpointKey(CHAIN, "ptx", 0)), 4e8);
    }

    function test_recordRefundIsIdempotentAndMonotonic() public {
        _grantMarker();
        vm.startPrank(marker);
        bc.recordRefund("itx", 0, 10e8, 4e8);
        bc.recordRefund("itx", 0, 10e8, 4e8);                // retry: no-op
        bc.recordRefund("itx", 0, 10e8, 2e8);                // lower: ignored, never decreases
        vm.stopPrank();
        assertEq(bc.refundedAmount(bc.outpointKey(CHAIN, "itx", 0)), 4e8);
    }

    function test_onlyMarkerRecordsRefunds() public {
        vm.prank(user);
        vm.expectRevert();
        bc.recordRefund("x", 0, 1e8, 1e8);
    }

    function test_valueMismatchBlocks() public {
        _seal(); _grantMarker();
        vm.prank(marker);
        bc.recordRefund("vtx", 0, 10e8, 1e8);
        BridgeControllerV2.MintAuthorization memory a = _authV("v", recipient, 1e8, "vtx", 0, 99e8);
        bytes[] memory s = _sigs(a);
        vm.expectRevert(abi.encodeWithSelector(BridgeControllerV2.SourceValueMismatch.selector,
            bc.outpointKey(CHAIN, "vtx", 0), 99e8, 10e8));
        bc.executeMint(a, s);
    }

    function test_wrongSourceChainRejected() public {
        _seal();
        BridgeControllerV2.MintAuthorization memory a = _auth("c", recipient, 1e8, "ctx", 0);
        a.sourceChainId = CHAIN + 1;
        bytes[] memory s = _sigs(a);
        vm.expectRevert(abi.encodeWithSelector(BridgeControllerV2.WrongSourceChain.selector, CHAIN + 1, CHAIN));
        bc.executeMint(a, s);
    }

    function test_amountAboveSignedValueRejected() public {
        _seal();
        BridgeControllerV2.MintAuthorization memory a = _authV("over", recipient, 2e8, "otx", 0, 1e8);
        bytes[] memory s = _sigs(a);
        vm.expectRevert(abi.encodeWithSelector(BridgeControllerV2.ExceedsSourceValue.selector,
            bc.outpointKey(CHAIN, "otx", 0), 2e8, 0, 1e8));
        bc.executeMint(a, s);
    }

    // ─── Review round 4 ──────────────────────────────────────────────────────

    function test_importedV1OutpointCannotBeRefunded() public {
        _grantMarker();
        bytes32[] memory k = new bytes32[](1);
        k[0] = bc.outpointKey(CHAIN, "v1minted", 0);
        bc.importProcessedOutpoints(k);
        vm.prank(marker);
        vm.expectRevert(abi.encodeWithSelector(BridgeControllerV2.OutpointAlreadyProcessed.selector, k[0]));
        bc.recordRefund("v1minted", 0, 5e8, 5e8);
    }

    function test_zeroRefundRejected() public {
        _grantMarker();
        vm.prank(marker);
        vm.expectRevert(BridgeControllerV2.ZeroAmount.selector);
        bc.recordRefund("z", 0, 5e8, 0);
    }

    function test_adminCanResetAPoisonedRecord_notAMintedOne() public {
        _seal(); _grantMarker();
        vm.prank(marker);
        bc.recordRefund("poison", 0, 1, 1);                   // stolen marker: wrong value + full refund
        bytes32 k = bc.outpointKey(CHAIN, "poison", 0);
        bc.resetOutpointRecord(k, 0, 0);                      // Safe clears it
        assertEq(bc.outpointValue(k), 0);
        assertEq(bc.refundedAmount(k), 0);
        _mintV("honest", 5e8, "poison", 0, 5e8);              // the real deposit can mint again
        vm.expectRevert(abi.encodeWithSelector(BridgeControllerV2.OutpointAlreadyProcessed.selector, k));
        bc.resetOutpointRecord(k, 0, 0);                      // never for a minted output
        bytes32 other = bc.outpointKey(CHAIN, "other", 0);    // before the prank (external call consumes it)
        vm.prank(user);
        vm.expectRevert();
        bc.resetOutpointRecord(other, 0, 0);                  // admin only
    }

    function test_valueSetIsLogged() public {
        _grantMarker();
        vm.expectEmit(true, false, false, true);
        emit BridgeControllerV2.OutpointValueSet(bc.outpointKey(CHAIN, "ev", 0), 7e8);
        vm.prank(marker);
        bc.recordRefund("ev", 0, 7e8, 1e8);
    }

    // ─── Review round 5 ──────────────────────────────────────────────────────

    function test_resetKeepsARealRefund_soItCanNeverBeMinted() public {
        _seal(); _grantMarker();
        vm.prank(marker);
        bc.recordRefund("half", 0, 1, 1);                     // poisoned: wrong value 1
        bytes32 k = bc.outpointKey(CHAIN, "half", 0);
        bc.resetOutpointRecord(k, 10e8, 4e8);                 // truth: 10 BOB output, 4 BOB really refunded
        assertEq(bc.outpointValue(k), 10e8);
        assertEq(bc.refundedAmount(k), 4e8);
        BridgeControllerV2.MintAuthorization memory a = _authV("over", recipient, 7e8, "half", 0, 10e8);
        bytes[] memory sg = _sigs(a);
        vm.expectRevert(abi.encodeWithSelector(BridgeControllerV2.ExceedsSourceValue.selector, k, 7e8, 4e8, 10e8));
        bc.executeMint(a, sg);                                // 7 + 4 > 10
        _mintV("honest", 6e8, "half", 0, 10e8);               // 6 + 4 = 10: ok
    }

    function test_resetRejectsRefundOverValue() public {
        bytes32 k = bc.outpointKey(CHAIN, "x", 0);
        vm.expectRevert(abi.encodeWithSelector(BridgeControllerV2.ExceedsSourceValue.selector, k, 0, 2e8, 1e8));
        bc.resetOutpointRecord(k, 1e8, 2e8);
    }
}
