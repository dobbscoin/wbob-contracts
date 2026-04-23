// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import "forge-std/Script.sol";
import "../src/WBob.sol";
import "../src/BridgeController.sol";
import "../src/BridgeExecutorModule.sol";

/**
 * @title Deploy
 * @notice Deploys WBob + BridgeController, wires roles, and transfers admin to Safe.
 *
 * Required env vars:
 *   DEPLOYER_PRIVATE_KEY   — EOA that pays gas (will NOT retain any role after deploy)
 *   SAFE_ADDRESS           — Gnosis Safe address (receives DEFAULT_ADMIN_ROLE + PAUSER_ROLE)
 *   EXECUTOR_ADDRESS       — Backend hot wallet address (BridgeExecutorModule operator)
 *   WATCHER_1..5           — Five watcher EOA addresses
 *   MAX_SUPPLY_BOB         — Max supply in whole BOB (e.g., "21000000"). 0 = uncapped.
 *   DAILY_LIMIT_BOB        — Daily mint ceiling in whole BOB (e.g., "1000000")
 *
 * Usage (dry-run):
 *   forge script script/Deploy.s.sol --rpc-url $RPC_URL --sig "run()" -vvvv
 *
 * Usage (broadcast to Gnosis mainnet):
 *   forge script script/Deploy.s.sol \
 *     --rpc-url $RPC_URL \
 *     --private-key $DEPLOYER_PRIVATE_KEY \
 *     --broadcast \
 *     --verify \
 *     --chain-id 100
 */
contract Deploy is Script {
    function run() external {
        // ── Load env ──────────────────────────────────────────────────────────
        address safe = vm.envAddress("SAFE_ADDRESS");
        require(safe != address(0), "Deploy: SAFE_ADDRESS not set");

        address executorOperator = vm.envAddress("EXECUTOR_ADDRESS");
        require(executorOperator != address(0), "Deploy: EXECUTOR_ADDRESS not set");

        address[5] memory watchers = [
            vm.envAddress("WATCHER_1"),
            vm.envAddress("WATCHER_2"),
            vm.envAddress("WATCHER_3"),
            vm.envAddress("WATCHER_4"),
            vm.envAddress("WATCHER_5")
        ];

        uint256 maxSupplyBOB = vm.envUint("MAX_SUPPLY_BOB");
        uint256 dailyLimitBOB = vm.envUint("DAILY_LIMIT_BOB");

        // Convert whole BOB → satoshi units (8 decimals)
        uint256 maxSupply = maxSupplyBOB * 1e8;
        uint256 dailyLimit = dailyLimitBOB * 1e8;

        address deployer = vm.addr(vm.envUint("DEPLOYER_PRIVATE_KEY"));

        console.log("=== wBOB Bridge Deployment ===");
        console.log("Deployer        :", deployer);
        console.log("Safe            :", safe);
        console.log("Executor operator:", executorOperator);
        console.log("Chain ID        :", block.chainid);
        console.log("Max supply (sats) :", maxSupply);
        console.log("Daily limit (sats):", dailyLimit);

        // ── Deploy ────────────────────────────────────────────────────────────
        vm.startBroadcast(vm.envUint("DEPLOYER_PRIVATE_KEY"));

        // 1. Deploy WBob — deployer holds admin/pauser temporarily
        WBob wBOB = new WBob(deployer, deployer, maxSupply, dailyLimit);
        console.log("WBob deployed         :", address(wBOB));

        // 2. Build signer array
        address[] memory signers = new address[](5);
        for (uint256 i = 0; i < 5; i++) {
            signers[i] = watchers[i];
        }

        // 3. Deploy BridgeController — deployer holds admin/pauser temporarily
        BridgeController bridge = new BridgeController(
            address(wBOB),
            deployer,  // admin (will be transferred to Safe below)
            deployer,  // pauser (will be transferred to Safe below)
            signers
        );
        console.log("BridgeController deployed:", address(bridge));

        // 4. Grant BRIDGE_EXECUTOR_ROLE to BridgeController on WBob
        wBOB.grantRole(wBOB.BRIDGE_EXECUTOR_ROLE(), address(bridge));
        console.log("BRIDGE_EXECUTOR_ROLE granted to BridgeController");

        // 5. Grant PAUSER_ROLE + DEFAULT_ADMIN_ROLE on WBob to Safe
        wBOB.grantRole(wBOB.PAUSER_ROLE(), safe);
        wBOB.grantRole(wBOB.DEFAULT_ADMIN_ROLE(), safe);
        console.log("WBob admin/pauser roles granted to Safe");

        // 6. Grant PAUSER_ROLE + DEFAULT_ADMIN_ROLE on BridgeController to Safe
        bridge.grantRole(bridge.PAUSER_ROLE(), safe);
        bridge.grantRole(bridge.DEFAULT_ADMIN_ROLE(), safe);
        console.log("BridgeController admin/pauser roles granted to Safe");

        // 7. Deploy BridgeExecutorModule — allows the backend hot wallet to
        //    trigger pause/unpause via the Safe without a full multisig round-trip.
        BridgeExecutorModule execModule = new BridgeExecutorModule(
            ISafe(safe),
            address(bridge),
            executorOperator
        );
        console.log("BridgeExecutorModule deployed:", address(execModule));

        // 8. Revoke deployer's admin roles on both contracts
        wBOB.revokeRole(wBOB.PAUSER_ROLE(), deployer);
        wBOB.revokeRole(wBOB.DEFAULT_ADMIN_ROLE(), deployer);
        bridge.revokeRole(bridge.PAUSER_ROLE(), deployer);
        bridge.revokeRole(bridge.DEFAULT_ADMIN_ROLE(), deployer);
        console.log("Deployer roles revoked - Safe is now sole admin");

        vm.stopBroadcast();

        // ── Summary ───────────────────────────────────────────────────────────
        console.log("");
        console.log("=== Deployment Complete ===");
        console.log("WBob                :", address(wBOB));
        console.log("BridgeController    :", address(bridge));
        console.log("BridgeExecutorModule:", address(execModule));
        console.log("Admin (Safe)        :", safe);
        console.log("Executor operator   :", executorOperator);
        console.log("Watchers:");
        for (uint256 i = 0; i < 5; i++) {
            console.log("  [%d] %s", i, watchers[i]);
        }
        console.log("");
        console.log("Next steps:");
        console.log("  1. Verify contracts on Gnosisscan");
        console.log("  2. Confirm Safe holds DEFAULT_ADMIN_ROLE + PAUSER_ROLE on both contracts");
        console.log("  3. Confirm no deployer role remaining");
        console.log("  4. Safe owners: execute enableModule(BridgeExecutorModule) via multisig");
        console.log("  5. Start watcher and backend services");
        console.log("  6. Set BRIDGE_EXECUTOR_MODULE_ADDRESS in backend .env");
    }
}
