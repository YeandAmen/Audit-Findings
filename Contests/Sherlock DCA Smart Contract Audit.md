## High-4: Bucket Rewards Will Be Wiped by Stake/Unstake Before AccrueRewards, lastRewardIndex Resets Without Settling Rewards, accrueRewards Delta Becomes 0

Summary:
The contract resets a token bucket's lastRewardIndex in stake / unstake without first settling pending rewards, this will cause a complete loss of accrued rewards for stakers as any user can call stake/unstake right before accrueReward and this will zero the bucket's delta.

Vulnerability Details:
Inside SuperDCAStaking::accrueReward we subtract the info.lastRewardIndex from rewardIndex, however inside stake/unstake we set lastRewardIndex == rewardIndex. If stake/unstake were to be called just before accrueRewards the system "forgets" about past rewards and can make the accrueRewards return zero leading to 100% lost rewards for users.

Affected Code:
SuperDCAStaking.sol
```solidity
function unstake(address token, uint256 amount) external override {
    // Validate amount is non-zero and available
    if (amount == 0) revert SuperDCAStaking__ZeroAmount();

    // Check both token bucket and user balances are sufficient
    TokenRewardInfo storage info = tokenRewardInfoOf[token];
    if (info.stakedAmount < amount) revert SuperDCAStaking__InsufficientBalance();
    if (userStakes[msg.sender][token] < amount) revert SuperDCAStaking__InsufficientBalance();

    // Update global reward index to current time
    _updateRewardIndex();

    // Update token bucket accounting and user stakes
    info.stakedAmount -= amount;
    info.lastRewardIndex = rewardIndex; // ❌ Resets without settling pending rewards

    totalStakedAmount -= amount;
    userStakes[msg.sender][token] -= amount;

    // Remove token from user's set if balance reaches zero
    if (userStakes[msg.sender][token] == 0) {
        userTokenSet[msg.sender].remove(token);
    }

    // Transfer SuperDCA tokens back to user
    IERC20(DCA_TOKEN).transfer(msg.sender, amount);
    emit Unstaked(token, msg.sender, amount);
}
```

Root Cause: Inside SuperDCAStaking::accrueReward we subtract the info.lastRewardIndex from rewardIndex to calculate the delta (pending rewards). However, inside stake/unstake we set lastRewardIndex == rewardIndex without first settling the pending rewards. This causes the delta calculation in accrueReward to become zero (rewardIndex - info.lastRewardIndex = rewardIndex - rewardIndex = 0), effectively wiping all accrued rewards for that token bucket.

Attack Path:
1. Stakers have accrued rewards over time, with lastRewardIndex = 50 and current rewardIndex = 100.
2. The delta (pending rewards) should be 100 - 50 = 50.
3. A user or attacker calls stake/unstake just before _beforeAddLiquidity is triggered (which calls accrueReward).
4. During stake/unstake, lastRewardIndex is set to the current rewardIndex (100), resetting the bucket's reward tracking.
5. _beforeAddLiquidity calls into accrueReward, which calculates delta = rewardIndex - info.lastRewardIndex = 100 - 100 = 0.
6. No rewards are distributed, and all accrued rewards are lost.

Impact:
Complete Reward Loss: Users will lose up to 100% of their accrued rewards if stake/unstake is called before accrueRewards, as the delta becomes zero.
Systemic Vulnerability: Any user can trigger this vulnerability by calling stake/unstake at the right time, making it easily exploitable.
Protocol Trust Erosion: Users who have staked tokens expecting rewards will receive nothing, severely damaging protocol reputation and user trust.
Economic Impact: Significant financial loss for stakers who have accrued rewards over time, potentially leading to protocol insolvency if rewards are substantial.

Tools Used:
Manual review
Foundry (for POC testing)

```solidity
Proof of Concept: The following Foundry test demonstrates the vulnerability:
function test_PoC_UnstakeBeforeAccrue_WipesBucketDelta() public {
    // Set up a single bucket stake
    vm.prank(user);
    staking.stake(tokenA, 100e18);

    // Let rewards accrue
    uint256 start = staking.lastMinted();
    uint256 secs = 100;
    vm.warp(start + secs);

    //what should be paid 
    uint256 expectedMint = secs * rate;
    assertGt(expectedMint, 0, "sanity");

    // Unstake before accrue resets bucket lastRewardIndex and wipes  delta
    vm.prank(user);
    staking.unstake(tokenA, 1);

    // Accrue now => pays 0 due to wiped delta
    vm.prank(gauge);
    uint256 paid = staking.accrueReward(tokenA);
    assertEq(paid, 0, "pending bucket rewards wiped by unstake reset");
}
```

Test Results:
The test confirms the vulnerability: When unstake is called before accrueReward, the lastRewardIndex is reset to the current rewardIndex, causing the delta calculation to return zero. The accrueReward function then pays 0 rewards, confirming that all pending bucket rewards have been wiped by the unstake reset.

Recommendations:
Make the contract remember the passed rewards even after stake/unstake has been called. Settle pending rewards before resetting lastRewardIndex:
```solidity
function unstake(address token, uint256 amount) external override {
    if (amount == 0) revert SuperDCAStaking__ZeroAmount();

    TokenRewardInfo storage info = tokenRewardInfoOf[token];
    if (info.stakedAmount < amount) revert SuperDCAStaking__InsufficientBalance();
    if (userStakes[msg.sender][token] < amount) revert SuperDCAStaking__InsufficientBalance();

    // Update global reward index to current time
    _updateRewardIndex();

    // ✅ Settle pending rewards BEFORE resetting lastRewardIndex
    if (info.lastRewardIndex < rewardIndex) {
        uint256 delta = rewardIndex - info.lastRewardIndex;
        // Distribute pending rewards or store them appropriately
        _settleBucketRewards(token, delta);
    }

    // Update token bucket accounting and user stakes
    info.stakedAmount -= amount;
    info.lastRewardIndex = rewardIndex; // Now safe to reset

    totalStakedAmount -= amount;
    userStakes[msg.sender][token] -= amount;

    if (userStakes[msg.sender][token] == 0) {
        userTokenSet[msg.sender].remove(token);
    }

    IERC20(DCA_TOKEN).transfer(msg.sender, amount);
    emit Unstaked(token, msg.sender, amount);
}
```

Alternative: Track accrued rewards separately from lastRewardIndex to prevent loss when stake/unstake is called.

Links to affected code:
https://github.com/sherlock-audit/2025-01-super-dca-gauge

---

## Medium-3: Manager Can Retroactively Apply New Rate to Past Time, Misallocating Emissions - Invariant Broken

Summary:
The staking system is supposed to guarantee that on any call that triggers _updateRewardIndex() with elapsed = block.timestamp - lastMinted and totalStakedAmount > 0, rewardIndex increases by Math.mulDiv(elapsed * mintRate, 1e18, totalStakedAmount) exactly. But in SuperDCAStaking.sol, setMintRate() overwrites mintRate immediately without first applying rewards for the elapsed time. This breaks the invariant: the next reward update uses the new rate for the past interval, instead of the old rate. A manager (or attacker with control) can backdate a rate change and distort emissions.

Vulnerability Details:
In setMintRate(), the mintRate is overwritten immediately without first calling _updateRewardIndex() to apply rewards for the elapsed time using the old rate. Since _updateRewardIndex() isn't called first, the entire elapsed = now - lastMinted window gets charged at the new rate instead of the old rate, breaking the intended invariant that past time should be priced at the old rate.

Affected Code:
SuperDCAStaking.sol
```solidity
function setMintRate(uint256 newMintRate) external onlyManager {
    // ❌ Overwrites rate before old rewards are applied
    mintRate = newMintRate;
    emit MintRateUpdated(newMintRate);
}
```

```solidity
function _updateRewardIndex() internal {
    if (totalStakedAmount == 0) {
        lastMinted = block.timestamp;
        return;
    }
    
    uint256 elapsed = block.timestamp - lastMinted;
    if (elapsed == 0) return;
    
    // Uses current mintRate, which may have been changed retroactively
    rewardIndex += Math.mulDiv(elapsed * mintRate, 1e18, totalStakedAmount);
    lastMinted = block.timestamp;
}
```

Root Cause: The setMintRate() function overwrites mintRate immediately without first calling _updateRewardIndex() to apply rewards for the elapsed time period using the old rate. When _updateRewardIndex() is called next, it uses the new rate for the entire elapsed period (block.timestamp - lastMinted), effectively backdating the rate change and breaking the invariant that past time should be priced at the old rate.

Attack Path:
1. Stakers are earning at rate 10 tokens/sec.
2. 1000 seconds pass since lastMinted, but no update occurs (no stake/unstake/accrueReward calls).
3. Manager calls setMintRate(1000) to change rate to 1000 tokens/sec.
4. mintRate is immediately overwritten to 1000 without applying the old rate (10/sec) to the elapsed 1000 seconds.
5. On next accrual, _updateRewardIndex() is called, which calculates: elapsed = 1000 seconds, uses current mintRate = 1000.
6. The system applies the whole 1000 seconds at 1000/sec, not 10/sec.
7. Should have minted: 1000 * 10 = 10,000 tokens, but actually mints: 1000 * 1000 = 1,000,000 tokens (100x overpayment).

Impact:
Invariant Broken: The intended invariant ("past time is priced at the old rate") is broken, causing incorrect reward calculations.
Reward Misallocation: Rewards are overpaid or underpaid depending on whether the rate is increased or decreased, distorting the emission schedule.
Manager Abuse: A malicious manager (or attacker with control) can retroactively apply rate changes to past periods, manipulating emissions for their benefit.
Protocol Economics Distortion: Incorrect reward distribution can lead to protocol insolvency if rates are increased, or unfair distribution if rates are decreased retroactively.

Tools Used:
Manual review

Proof of Concept:
In the example scenario:
- Initial rate: 10 tokens/sec
- Time elapsed: 1000 seconds
- New rate set: 1000 tokens/sec
- Should mint: 1000 * 10 = 10,000 tokens (using old rate for past period)
- Actually mints: 1000 * 1000 = 1,000,000 tokens (using new rate for past period)
- Overpayment: 100x the intended amount

This demonstrates that the rate change is being applied retroactively to the past time period, breaking the invariant and causing massive overpayment.

Recommendations:
Apply old rewards first, then update the rate:
```solidity
function setMintRate(uint256 newMintRate) external onlyManager {
    // ✅ Apply old rate to past interval first
    _updateRewardIndex();
    
    // Now safe to update the rate for future periods
    mintRate = newMintRate;
    emit MintRateUpdated(newMintRate);
}
```

This ensures that:
1. All elapsed time up to the rate change is priced at the old rate.
2. Future time periods will use the new rate.
3. The invariant is maintained: past time is always priced at the rate that was active during that period.

Additional Safeguards:
- Add validation to prevent rate changes that are too extreme (e.g., max 2x increase/decrease per change).
- Emit events with both old and new rates for transparency.
- Consider time-locking rate changes to allow stakers to react.

Links to affected code:
https://github.com/sherlock-audit/2025-01-super-dca-gauge

