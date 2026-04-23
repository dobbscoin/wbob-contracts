// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import "forge-std/Test.sol";
import "../src/WBob.sol";
import "../src/BridgeController.sol";

contract BridgeControllerTest is Test {
    WBob internal wBOB;
    BridgeController internal bridge;

    // ── Accounts ─────────────────────────────────────────────────────────────
    address internal admin = makeAddr("admin");
    address internal pauser = makeAddr("pauser");

    // 5 watcher EOAs (we store their private keys for signing)
    uint256[5] internal watcherKeys;
    address[5] internal watchers;

    address internal user = makeAddr("user");
    address internal nobody = makeAddr("nobody");

    // ── Constants ─────────────────────────────────────────────────────────────
    uint256 internal constant MAX_SUPPLY = 21_000_000 * 1e8;
    uint256 internal constant DAILY_LIMIT = 1_000_000 * 1e8;
    uint256 internal constant AMOUNT = 100 * 1e8;
    uint256 internal constant SOURCE_CHAIN_ID = 1_000_001; // placeholder Dobbscoin chain ID

    // ── Setup ─────────────────────────────────────────────────────────────────

    function setUp() public {
        // Derive 5 watcher keys
        for (uint256 i = 0; i < 5; i++) {
            watcherKeys[i] = uint256(keccak256(abi.encodePacked("watcher", i)));
            watchers[i] = vm.addr(watcherKeys[i]);
        }

        // Deploy WBob
        wBOB = new WBob(admin, pauser, MAX_SUPPLY, DAILY_LIMIT);

        // Build initial signer list
        address[] memory signers = new address[](5);
        for (uint256 i = 0; i < 5; i++) signers[i] = watchers[i];

        // Deploy BridgeController
        bridge = new BridgeController(
            address(wBOB),
            admin,
            pauser,
            signers
        );

        // Grant BRIDGE_EXECUTOR_ROLE to BridgeController on WBob.
        // Cache constant before prank — prank is consumed by any external call.
        bytes32 executorRole = wBOB.BRIDGE_EXECUTOR_ROLE();
        vm.prank(admin);
        wBOB.grantRole(executorRole, address(bridge));
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

    /// @dev Grants BRIDGE_EXECUTOR_ROLE to `to` from admin.
    ///      Caches the role constant before pranking to avoid prank being consumed
    ///      by the STATICCALL argument evaluation of .BRIDGE_EXECUTOR_ROLE().
    function _grantExecutorRole(address to) internal {
        bytes32 role = wBOB.BRIDGE_EXECUTOR_ROLE();
        vm.prank(admin);
        wBOB.grantRole(role, to);
    }

    function _makeAuth(
        bytes32 depositId,
        address recipient,
        uint256 amount,
        uint256 deadline
    ) internal view returns (BridgeController.MintAuthorization memory) {
        return BridgeController.MintAuthorization({
            depositId: depositId,
            recipient: recipient,
            amount: amount,
            sourceChainId: SOURCE_CHAIN_ID,
            sourceTxHash: keccak256("sometxid"),
            sourceVout: 0,
            deadline: deadline,
            nonce: bridge.mintNonce()
        });
    }

    function _signAuth(BridgeController.MintAuthorization memory auth, uint256 privateKey)
        internal
        view
        returns (bytes memory)
    {
        bytes32 digest = bridge.getMintAuthorizationDigest(auth);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    /**
     * @dev Build signatures from signerIndices (0-based index into watcherKeys array).
     */
    function _buildSigs(
        BridgeController.MintAuthorization memory auth,
        uint256[] memory signerIndices
    ) internal view returns (bytes[] memory sigs) {
        sigs = new bytes[](signerIndices.length);
        for (uint256 i = 0; i < signerIndices.length; i++) {
            sigs[i] = _signAuth(auth, watcherKeys[signerIndices[i]]);
        }
    }

    // ─── Deployment / initial state ───────────────────────────────────────────

    function test_InitialSignerCount() public view {
        assertEq(bridge.signerCount(), 5);
    }

    function test_AllWatchersAreSigned() public view {
        for (uint256 i = 0; i < 5; i++) {
            assertTrue(bridge.isSigner(watchers[i]));
        }
    }

    function test_MintNonceStartsAtZero() public view {
        assertEq(bridge.mintNonce(), 0);
    }

    function test_Threshold() public view {
        assertEq(bridge.THRESHOLD(), 3);
    }

    // ─── executeMint: success cases ───────────────────────────────────────────

    function test_ExecuteMint_ThreeSigs_Succeeds() public {
        BridgeController.MintAuthorization memory auth =
            _makeAuth(keccak256("deposit1"), user, AMOUNT, block.timestamp + 1 hours);

        uint256[] memory indices = new uint256[](3);
        indices[0] = 0; indices[1] = 1; indices[2] = 2;
        bytes[] memory sigs = _buildSigs(auth, indices);

        bridge.executeMint(auth, sigs);

        assertEq(wBOB.balanceOf(user), AMOUNT);
    }

    function test_ExecuteMint_FiveSigs_Succeeds() public {
        BridgeController.MintAuthorization memory auth =
            _makeAuth(keccak256("deposit2"), user, AMOUNT, block.timestamp + 1 hours);

        uint256[] memory indices = new uint256[](5);
        for (uint256 i = 0; i < 5; i++) indices[i] = i;
        bytes[] memory sigs = _buildSigs(auth, indices);

        bridge.executeMint(auth, sigs);

        assertEq(wBOB.balanceOf(user), AMOUNT);
    }

    function test_ExecuteMint_MarksDepositProcessed() public {
        bytes32 depositId = keccak256("deposit3");
        BridgeController.MintAuthorization memory auth =
            _makeAuth(depositId, user, AMOUNT, block.timestamp + 1 hours);

        uint256[] memory indices = new uint256[](3);
        indices[0] = 0; indices[1] = 1; indices[2] = 2;

        bridge.executeMint(auth, _buildSigs(auth, indices));

        assertTrue(bridge.processedDeposits(depositId));
    }

    function test_ExecuteMint_EmitsEvent() public {
        bytes32 depositId = keccak256("deposit_event");
        BridgeController.MintAuthorization memory auth =
            _makeAuth(depositId, user, AMOUNT, block.timestamp + 1 hours);

        uint256[] memory indices = new uint256[](3);
        indices[0] = 0; indices[1] = 1; indices[2] = 2;

        vm.expectEmit(true, true, false, true, address(bridge));
        emit BridgeController.MintExecuted(
            depositId, user, AMOUNT, SOURCE_CHAIN_ID, auth.sourceTxHash, 0
        );
        bridge.executeMint(auth, _buildSigs(auth, indices));
    }

    // ─── executeMint: replay protection ──────────────────────────────────────

    function test_ExecuteMint_ReplayReverts() public {
        bytes32 depositId = keccak256("deposit_replay");
        BridgeController.MintAuthorization memory auth =
            _makeAuth(depositId, user, AMOUNT, block.timestamp + 2 hours);

        uint256[] memory indices = new uint256[](3);
        indices[0] = 0; indices[1] = 1; indices[2] = 2;
        bytes[] memory sigs = _buildSigs(auth, indices);

        bridge.executeMint(auth, sigs);

        vm.expectRevert(abi.encodeWithSelector(BridgeController.AlreadyProcessed.selector, depositId));
        bridge.executeMint(auth, sigs);
    }

    // ─── executeMint: deadline ────────────────────────────────────────────────

    function test_ExecuteMint_ExpiredDeadlineReverts() public {
        BridgeController.MintAuthorization memory auth =
            _makeAuth(keccak256("deposit_expired"), user, AMOUNT, block.timestamp - 1);

        uint256[] memory indices = new uint256[](3);
        indices[0] = 0; indices[1] = 1; indices[2] = 2;
        // Build sigs before expectRevert — _buildSigs makes an external view call that
        // would otherwise consume the vm.expectRevert in this Foundry nightly build.
        bytes[] memory sigs = _buildSigs(auth, indices);

        vm.expectRevert(
            abi.encodeWithSelector(
                BridgeController.DeadlineExpired.selector,
                auth.deadline,
                block.timestamp
            )
        );
        bridge.executeMint(auth, sigs);
    }

    // ─── executeMint: nonce mismatch ──────────────────────────────────────────

    function test_ExecuteMint_WrongNonceReverts() public {
        BridgeController.MintAuthorization memory auth = BridgeController.MintAuthorization({
            depositId: keccak256("deposit_nonce"),
            recipient: user,
            amount: AMOUNT,
            sourceChainId: SOURCE_CHAIN_ID,
            sourceTxHash: keccak256("txid"),
            sourceVout: 0,
            deadline: block.timestamp + 1 hours,
            nonce: 999 // wrong
        });

        uint256[] memory indices = new uint256[](3);
        indices[0] = 0; indices[1] = 1; indices[2] = 2;
        bytes[] memory sigs = _buildSigs(auth, indices);

        vm.expectRevert(
            abi.encodeWithSelector(BridgeController.WrongMintNonce.selector, 999, 0)
        );
        bridge.executeMint(auth, sigs);
    }

    // ─── executeMint: insufficient valid signatures ───────────────────────────

    function test_ExecuteMint_TwoSigsReverts() public {
        BridgeController.MintAuthorization memory auth =
            _makeAuth(keccak256("deposit_2sig"), user, AMOUNT, block.timestamp + 1 hours);

        uint256[] memory indices = new uint256[](2);
        indices[0] = 0; indices[1] = 1;
        bytes[] memory sigs = _buildSigs(auth, indices);

        vm.expectRevert(
            abi.encodeWithSelector(
                BridgeController.InsufficientValidSignatures.selector, 2, 3
            )
        );
        bridge.executeMint(auth, sigs);
    }

    function test_ExecuteMint_ZeroSigsReverts() public {
        BridgeController.MintAuthorization memory auth =
            _makeAuth(keccak256("deposit_0sig"), user, AMOUNT, block.timestamp + 1 hours);

        bytes[] memory sigs = new bytes[](0);

        vm.expectRevert(
            abi.encodeWithSelector(
                BridgeController.InsufficientValidSignatures.selector, 0, 3
            )
        );
        bridge.executeMint(auth, sigs);
    }

    function test_ExecuteMint_UnknownSignerNotCounted() public {
        BridgeController.MintAuthorization memory auth =
            _makeAuth(keccak256("deposit_unknown"), user, AMOUNT, block.timestamp + 1 hours);

        // 2 valid watchers + 1 random non-signer
        uint256 unknownKey = uint256(keccak256("unknown"));
        bytes[] memory sigs = new bytes[](3);
        sigs[0] = _signAuth(auth, watcherKeys[0]);
        sigs[1] = _signAuth(auth, watcherKeys[1]);
        sigs[2] = _signAuth(auth, unknownKey);

        vm.expectRevert(
            abi.encodeWithSelector(
                BridgeController.InsufficientValidSignatures.selector, 2, 3
            )
        );
        bridge.executeMint(auth, sigs);
    }

    // ─── executeMint: duplicate signature deduplication ──────────────────────

    function test_ExecuteMint_DuplicateSigNotDoubleCounted() public {
        BridgeController.MintAuthorization memory auth =
            _makeAuth(keccak256("deposit_dup"), user, AMOUNT, block.timestamp + 1 hours);

        // Same watcher signs 3 times — should only count as 1
        bytes[] memory sigs = new bytes[](3);
        sigs[0] = _signAuth(auth, watcherKeys[0]);
        sigs[1] = _signAuth(auth, watcherKeys[0]);
        sigs[2] = _signAuth(auth, watcherKeys[0]);

        vm.expectRevert(
            abi.encodeWithSelector(
                BridgeController.InsufficientValidSignatures.selector, 1, 3
            )
        );
        bridge.executeMint(auth, sigs);
    }

    // ─── executeMint: paused ─────────────────────────────────────────────────

    function test_ExecuteMint_PausedReverts() public {
        vm.prank(pauser);
        bridge.pause();

        BridgeController.MintAuthorization memory auth =
            _makeAuth(keccak256("deposit_paused"), user, AMOUNT, block.timestamp + 1 hours);

        uint256[] memory indices = new uint256[](3);
        indices[0] = 0; indices[1] = 1; indices[2] = 2;
        bytes[] memory sigs = _buildSigs(auth, indices);

        vm.expectRevert();
        bridge.executeMint(auth, sigs);
    }

    // ─── requestWithdrawal ────────────────────────────────────────────────────

    function test_RequestWithdrawal_BurnsTokens() public {
        // Give user some wBOB first
        _grantExecutorRole(address(this));
        wBOB.mint(user, AMOUNT);

        uint256 supplyBefore = wBOB.totalSupply();

        vm.prank(user);
        bridge.requestWithdrawal(AMOUNT, "Bob1DobbsXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");

        assertEq(wBOB.balanceOf(user), 0);
        assertEq(wBOB.totalSupply(), supplyBefore - AMOUNT);
    }

    function test_RequestWithdrawal_IncrementsNonce() public {
        _grantExecutorRole(address(this));
        wBOB.mint(user, AMOUNT * 3);

        assertEq(bridge.withdrawalNonces(user), 0);

        vm.prank(user);
        bridge.requestWithdrawal(AMOUNT, "Bob1DobbsXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");

        assertEq(bridge.withdrawalNonces(user), 1);

        vm.prank(user);
        bridge.requestWithdrawal(AMOUNT, "Bob1DobbsXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");

        assertEq(bridge.withdrawalNonces(user), 2);
    }

    function test_RequestWithdrawal_EmitsEvent() public {
        _grantExecutorRole(address(this));
        wBOB.mint(user, AMOUNT);

        // We can't predict withdrawalId exactly, so just check event fires.
        vm.recordLogs();
        vm.prank(user);
        bridge.requestWithdrawal(AMOUNT, "Bob1DobbsXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool found = false;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].emitter == address(bridge)) {
                found = true;
                break;
            }
        }
        assertTrue(found, "WithdrawalRequested event not emitted");
    }

    function test_RequestWithdrawal_ZeroAmountReverts() public {
        vm.prank(user);
        vm.expectRevert(BridgeController.ZeroAmount.selector);
        bridge.requestWithdrawal(0, "Bob1DobbsXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
    }

    function test_RequestWithdrawal_EmptyAddressReverts() public {
        vm.prank(user);
        vm.expectRevert(BridgeController.EmptyDobbscoinAddress.selector);
        bridge.requestWithdrawal(AMOUNT, "");
    }

    function test_RequestWithdrawal_InsufficientBalanceReverts() public {
        // user has no wBOB
        vm.prank(user);
        vm.expectRevert();
        bridge.requestWithdrawal(AMOUNT, "Bob1DobbsXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
    }

    function test_RequestWithdrawal_PausedReverts() public {
        vm.prank(pauser);
        bridge.pause();

        vm.prank(user);
        vm.expectRevert();
        bridge.requestWithdrawal(AMOUNT, "Bob1DobbsXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
    }

    // ─── Signer management ────────────────────────────────────────────────────

    function test_AddSigner_ByAdmin() public {
        address newSigner = makeAddr("newSigner");
        // Remove one first to make room (currently at MAX_SIGNERS=5)
        vm.startPrank(admin);
        bridge.removeSigner(watchers[4]);
        bridge.addSigner(newSigner);
        vm.stopPrank();

        assertTrue(bridge.isSigner(newSigner));
        assertEq(bridge.signerCount(), 5);
    }

    function test_AddSigner_ByUnauthorizedReverts() public {
        vm.prank(nobody);
        vm.expectRevert();
        bridge.addSigner(makeAddr("x"));
    }

    function test_AddSigner_DuplicateReverts() public {
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(BridgeController.SignerAlreadyExists.selector, watchers[0])
        );
        bridge.addSigner(watchers[0]);
    }

    function test_AddSigner_FullSetReverts() public {
        // Already at MAX_SIGNERS=5; adding more should revert
        vm.prank(admin);
        vm.expectRevert(BridgeController.SignerSetFull.selector);
        bridge.addSigner(makeAddr("extra"));
    }

    function test_RemoveSigner_ByAdmin() public {
        vm.prank(admin);
        bridge.removeSigner(watchers[4]);

        assertFalse(bridge.isSigner(watchers[4]));
        assertEq(bridge.signerCount(), 4);
    }

    function test_RemoveSigner_DropsBelowThresholdReverts() public {
        // Remove signers until 3 remain, then the next remove should fail
        vm.startPrank(admin);
        bridge.removeSigner(watchers[4]);
        bridge.removeSigner(watchers[3]);
        // Now signerCount == 3 == THRESHOLD; removing one more would break liveness
        vm.expectRevert("BC: would drop below threshold");
        bridge.removeSigner(watchers[2]);
        vm.stopPrank();
    }

    function test_RemoveSigner_NonexistentReverts() public {
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(BridgeController.SignerDoesNotExist.selector, nobody)
        );
        bridge.removeSigner(nobody);
    }

    // ─── mintNonce ────────────────────────────────────────────────────────────

    function test_IncrementMintNonce_ByAdmin() public {
        vm.prank(admin);
        bridge.incrementMintNonce();
        assertEq(bridge.mintNonce(), 1);
    }

    function test_IncrementMintNonce_InvalidatesOldSigs() public {
        // Build auth for old nonce=0
        BridgeController.MintAuthorization memory auth =
            _makeAuth(keccak256("deposit_nonce_inv"), user, AMOUNT, block.timestamp + 1 hours);

        uint256[] memory indices = new uint256[](3);
        indices[0] = 0; indices[1] = 1; indices[2] = 2;
        bytes[] memory sigs = _buildSigs(auth, indices);

        // Increment nonce — old sigs now have wrong nonce
        vm.prank(admin);
        bridge.incrementMintNonce();

        vm.expectRevert(
            abi.encodeWithSelector(BridgeController.WrongMintNonce.selector, 0, 1)
        );
        bridge.executeMint(auth, sigs);
    }

    function test_IncrementMintNonce_ByUnauthorizedReverts() public {
        vm.prank(nobody);
        vm.expectRevert();
        bridge.incrementMintNonce();
    }

    // ─── Constructor guards ────────────────────────────────────────────────────

    function test_Constructor_TooFewSignersReverts() public {
        address[] memory signers = new address[](2); // below THRESHOLD=3
        signers[0] = watchers[0];
        signers[1] = watchers[1];

        vm.expectRevert("BC: below threshold");
        new BridgeController(address(wBOB), admin, pauser, signers);
    }

    function test_Constructor_TooManySignersReverts() public {
        address[] memory signers = new address[](6);
        for (uint256 i = 0; i < 6; i++) signers[i] = makeAddr(string(abi.encode(i)));

        vm.expectRevert("BC: too many signers");
        new BridgeController(address(wBOB), admin, pauser, signers);
    }

    // ─── Fuzz tests ───────────────────────────────────────────────────────────

    function testFuzz_ExecuteMint_ValidAmount(uint256 amount) public {
        amount = bound(amount, 1, DAILY_LIMIT);

        BridgeController.MintAuthorization memory auth = BridgeController.MintAuthorization({
            depositId: keccak256(abi.encode(amount, "fuzz")),
            recipient: user,
            amount: amount,
            sourceChainId: SOURCE_CHAIN_ID,
            sourceTxHash: keccak256("fuzz"),
            sourceVout: 0,
            deadline: block.timestamp + 1 hours,
            nonce: 0
        });

        uint256[] memory indices = new uint256[](3);
        indices[0] = 0; indices[1] = 1; indices[2] = 2;

        bridge.executeMint(auth, _buildSigs(auth, indices));

        assertEq(wBOB.balanceOf(user), amount);
    }

    function testFuzz_WithdrawalNonces_Monotonic(uint8 rounds) public {
        rounds = uint8(bound(rounds, 1, 10));

        // Fund user
        _grantExecutorRole(address(this));
        wBOB.mint(user, uint256(rounds) * AMOUNT);

        for (uint256 i = 0; i < rounds; i++) {
            assertEq(bridge.withdrawalNonces(user), i);
            vm.prank(user);
            bridge.requestWithdrawal(AMOUNT, "Bob1DobbsXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
        }

        assertEq(bridge.withdrawalNonces(user), rounds);
    }
}
