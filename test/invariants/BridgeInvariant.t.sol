// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import "forge-std/Test.sol";
import "../../src/WBob.sol";
import "../../src/BridgeController.sol";

/**
 * @title BridgeInvariant
 * @notice Foundry invariant tests. The fuzzer calls the handler contract's
 *         functions in arbitrary sequences and then checks the invariants.
 *
 * Invariants:
 *   1. totalSupply never exceeds MAX_SUPPLY
 *   2. A depositId that has been processed is never un-processed
 *   3. withdrawalNonces for any account only ever increase
 *   4. signerCount always satisfies THRESHOLD <= signerCount <= MAX_SIGNERS
 *   5. currentDayMinted <= dailyMintLimit (within a single day window)
 */
contract BridgeInvariantHandler is Test {
    WBob public wBOB;
    BridgeController public bridge;

    address internal admin;
    address internal pauser;
    uint256[5] internal watcherKeys;
    address[5] internal watchers;

    // Track processed depositIds so we can verify they stay processed
    bytes32[] public processedDepositIds;

    // Track user nonces for monotonicity check
    address[] public knownUsers;
    mapping(address => uint256) public lastKnownNonce;

    uint256 private depositCounter;

    constructor() {
        admin = makeAddr("inv_admin");
        pauser = makeAddr("inv_pauser");

        for (uint256 i = 0; i < 5; i++) {
            watcherKeys[i] = uint256(keccak256(abi.encodePacked("inv_watcher", i)));
            watchers[i] = vm.addr(watcherKeys[i]);
        }

        wBOB = new WBob(admin, pauser, 21_000_000 * 1e8, 1_000_000 * 1e8);

        address[] memory signers = new address[](5);
        for (uint256 i = 0; i < 5; i++) signers[i] = watchers[i];

        bridge = new BridgeController(address(wBOB), admin, pauser, signers);

        bytes32 executorRole = wBOB.BRIDGE_EXECUTOR_ROLE();
        vm.prank(admin);
        wBOB.grantRole(executorRole, address(bridge));
    }

    // ── Handlers the fuzzer can call ─────────────────────────────────────────

    function executeMint(address recipient, uint256 amount) public {
        amount = bound(amount, 1, 100_000 * 1e8);
        recipient = recipient == address(0) ? address(0xBEEF) : recipient;

        uint256 dailyRemaining = wBOB.dailyMintLimit() - wBOB.currentDayMinted();
        if (amount > dailyRemaining) {
            vm.warp(block.timestamp + 1 days);
        }

        bytes32 depositId = keccak256(abi.encodePacked("inv_deposit", depositCounter++));

        BridgeController.MintAuthorization memory auth = BridgeController.MintAuthorization({
            depositId: depositId,
            recipient: recipient,
            amount: amount,
            sourceChainId: 1_000_001,
            sourceTxHash: keccak256(abi.encodePacked(depositId)),
            sourceVout: 0,
            deadline: block.timestamp + 1 hours,
            nonce: bridge.mintNonce()
        });

        bytes32 digest = bridge.getMintAuthorizationDigest(auth);
        bytes[] memory sigs = new bytes[](3);
        for (uint256 i = 0; i < 3; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(watcherKeys[i], digest);
            sigs[i] = abi.encodePacked(r, s, v);
        }

        try bridge.executeMint(auth, sigs) {
            processedDepositIds.push(depositId);
        } catch {}
    }

    function requestWithdrawal(address user, uint256 amount) public {
        amount = bound(amount, 1, 100_000 * 1e8);
        user = user == address(0) ? address(0xBEEF) : user;

        if (wBOB.balanceOf(user) < amount) {
            // Fund the user via direct mint bypassing bridge (handler has executor role? No.)
            // We skip if insufficient balance.
            return;
        }

        uint256 nonceBefore = bridge.withdrawalNonces(user);

        if (!_isKnownUser(user)) {
            knownUsers.push(user);
            lastKnownNonce[user] = nonceBefore;
        }

        vm.prank(user);
        try bridge.requestWithdrawal(amount, "Bob1Dobbs") {
            lastKnownNonce[user] = bridge.withdrawalNonces(user);
        } catch {}
    }

    // ── View helpers ─────────────────────────────────────────────────────────

    function processedDepositIdsLength() external view returns (uint256) {
        return processedDepositIds.length;
    }

    function knownUsersLength() external view returns (uint256) {
        return knownUsers.length;
    }

    function _isKnownUser(address user) internal view returns (bool) {
        for (uint256 i = 0; i < knownUsers.length; i++) {
            if (knownUsers[i] == user) return true;
        }
        return false;
    }
}

contract BridgeInvariantTest is Test {
    BridgeInvariantHandler internal handler;

    function setUp() public {
        handler = new BridgeInvariantHandler();

        // Target only the handler — not the contracts themselves
        targetContract(address(handler));
    }

    // ── Invariant 1: totalSupply <= MAX_SUPPLY ────────────────────────────────

    function invariant_SupplyNeverExceedsCap() public view {
        WBob wBOB = handler.wBOB();
        assertLe(wBOB.totalSupply(), wBOB.MAX_SUPPLY());
    }

    // ── Invariant 2: processed depositIds stay processed ─────────────────────

    function invariant_ProcessedDepositIdsStayProcessed() public view {
        BridgeController bridge = handler.bridge();
        uint256 len = handler.processedDepositIdsLength();
        for (uint256 i = 0; i < len; i++) {
            assertTrue(bridge.processedDeposits(handler.processedDepositIds(i)));
        }
    }

    // ── Invariant 3: withdrawalNonces only increase ───────────────────────────

    function invariant_WithdrawalNoncesMonotonic() public view {
        BridgeController bridge = handler.bridge();
        uint256 len = handler.knownUsersLength();
        for (uint256 i = 0; i < len; i++) {
            address user = handler.knownUsers(i);
            assertGe(bridge.withdrawalNonces(user), handler.lastKnownNonce(user));
        }
    }

    // ── Invariant 4: signerCount in [THRESHOLD, MAX_SIGNERS] ─────────────────

    function invariant_SignerCountInBounds() public view {
        BridgeController bridge = handler.bridge();
        assertGe(bridge.signerCount(), bridge.THRESHOLD());
        assertLe(bridge.signerCount(), bridge.MAX_SIGNERS());
    }

    // ── Invariant 5: currentDayMinted <= dailyMintLimit ───────────────────────

    function invariant_DailyMintedWithinLimit() public view {
        WBob wBOB = handler.wBOB();
        assertLe(wBOB.currentDayMinted(), wBOB.dailyMintLimit());
    }
}
