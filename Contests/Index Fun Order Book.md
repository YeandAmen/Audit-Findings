## Medium-1: Emergency Resolver Cannot Resolve Past Epochs, Leading to Permanent Fund Lock if Oracle Fails

Summary:
The emergency resolution flow in the Index Fun Order Book contest can only resolve the currently active epoch. If the primary oracle becomes unavailable while past epochs remain unresolved, users with collateral locked in those past epochs are permanently stuck until the oracle (or an admin able to swap it) returns, causing indefinite capital lock.

Vulnerability Details:
In `MarketController::emergencyResolveMarket` the contract always calls `marketResolver.resolveMarketEpoch` with `market.getCurrentEpoch(questionId)`. Unlike the oracle, which can specify any epoch directly on `marketResolver`, the emergency pathway lacks an epoch parameter. As a result, even though the system supports multi-epoch markets, the emergency resolver cannot resolve historical epochs.

Affected Code:
MarketController.sol#L745
```solidity
function emergencyResolveMarket(bytes32 questionId, uint256 numberOfOutcomes, bytes32 merkleRoot)
    external
    onlyAuthorizedMatcher
{
    require(market.isMarketReadyForResolution(questionId), "Market not ready for resolution");

    uint256 currentEpoch = market.getCurrentEpoch(questionId);
    marketResolver.resolveMarketEpoch(questionId, currentEpoch, numberOfOutcomes, merkleRoot);
    //                           ^^^^^^^^^^^^ always resolves current epoch only

    emit EmergencyResolution(questionId, currentEpoch, merkleRoot);
}
```

Root Cause:
The emergency resolver route hardcodes `currentEpoch` instead of accepting an epoch argument, preventing it from targeting any unresolved historical epoch.

Attack Path:
1. Users participate across epochs 1, 2, and 3, locking collateral each round.
2. Market progresses to epoch 4 (time-based or manual rollover), but epochs 1–3 stay unresolved.
3. Oracle infrastructure fails (extended outage, key loss, etc.).
4. Admin invokes `emergencyResolveMarket` hoping to unblock funds.
5. Function resolves only epoch 4 because it always uses `currentEpoch`.
6. Admin is unavailable to swap the oracle contract (multi-sig delay, vacation, compromised keys).
7. Epochs 1–3 never resolve, so collateral in `totalLockedPerCondition[conditionId_epoch_X]` remains locked indefinitely.

Impact:
- Permanent Fund Lock: Winners from earlier epochs cannot claim or withdraw collateral, effectively losing 100% of locked funds until the oracle/admin recovers.
- Protocol Reputation Damage: Multi-epoch markets (daily/weekly) can accumulate unresolved capital quickly, degrading trust in emergency tooling.
- Worst-Case Capital at Risk: With 100 users locking 1,000 USDC over three unresolved epochs, 300,000 USDC stays frozen indefinitely.

Pre-conditions:
- **Internal:** Market advanced through ≥2 epochs, previous epochs unresolved, emergency resolver set via `setEmergencyResolver`.
- **External:** Oracle offline/malfunctioning, protocol admin unavailable to call `updateOracle`, users’ collateral still locked.

Tools Used:
- Manual review
- Foundry (for PoC)

Proof of Concept:
```solidity
function test_CannotResolvePastEpochs() public {
    assertEq(market.getCurrentEpoch(questionId), 1, "Initial epoch");

    uint256 epochStart = market.getEpochStartTime(questionId, 1);
    vm.warp(epochStart + (2 * 86400) + 1); // advance to epoch 3

    assertEq(market.getCurrentEpoch(questionId), 3, "Now in epoch 3");

    vm.prank(matcher);
    controller.emergencyResolveMarket(questionId, 2, bytes32(uint256(1)));

    bytes32 conditionEpoch1 = market.getConditionId(oracle, questionId, 2, 1);
    bytes32 conditionEpoch3 = market.getConditionId(oracle, questionId, 2, 3);

    assertFalse(resolver.getResolutionStatus(conditionEpoch1), "Epoch 1 remains unresolved");
    assertTrue(resolver.getResolutionStatus(conditionEpoch3), "Only current epoch resolved");
}
```

Recommendations:
- Extend `emergencyResolveMarket` to accept an explicit epoch parameter (validated to be ≤ current epoch and unresolved) so emergency operators can resolve historical epochs when the oracle is unavailable.
- Alternatively, loop through unresolved epochs or allow the emergency resolver to invoke the lower-level resolver function directly.

Links to affected code:
https://github.com/sherlock-audit/2025-10-index-fun-order-book-contest/blob/main/orderbook-solidity/src/Market/MarketController.sol#L745
