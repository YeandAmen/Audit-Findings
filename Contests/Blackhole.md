## Low-1: Race Condition in BlackClaims Allows Season Extension After Reward Revocation
Summary:
The BlackClaims contract contains a race condition vulnerability that allows the admin to extend the claim period of a season after revoking unclaimed rewards. This creates a misleading state where the season appears active, but user attempts to claim rewards fail due to an arithmetic underflow, resulting in wasted gas and degraded user experience.

Vulnerability Details:
The extendClaimDuration function allows the admin to extend claim_end_time without checking if remaining_reward_amount is non-zero. After revokeUnclaimedReward sets remaining_reward_amount to 0, extending the claim period causes isSeasonClaimingActive to return true, misleading users into attempting claims via claimAndStakeReward, which reverts due to an underflow.

Affected Code:
BlackClaims.sol#L141
BlackClaims.sol#L107
```solidity 
function extendClaimDuration(uint256 claim_duration_) external onlyOwner {
    Season storage _season = season;
    require(_season.start_time > 0, "SEASON NOT FOUND");
    require(isSeasonFinalized(), "SEASON_NOT_FINALIZED");
    require(_season.reward_amount > 0, "NO REWARD AMOUNT");
    _season.claim_end_time = season.claim_end_time + claim_duration;
}
```

```solidity
function claimAndStakeReward(uint128 lock_duration) external {
    Season storage _season = season;
    uint256 _amount = season_rewards[msg.sender];
    require(_amount > 0, "MUST HAVE A NON ZERO REWARD");
    require(isSeasonClaimingActive(), "CLAIMING NOT ACTIVE");
    season_rewards[msg.sender] -= uint128(_amount);
    _season.remaining_reward_amount -= uint128(_amount); // Underflow when remaining_reward_amount = 0
    bool transfer_success = token.transfer(address(votingEscrow), _amount);
    require(transfer_success, "FAILED TRANSFER");
    votingEscrow.create_lock_for(msg.sender, amount, lock_duration);
}
```
Root Cause: The extendClaimDuration function lacks a check to ensure remaining_reward_amount > 0, allowing the season to be extended after rewards are revoked, creating a trap for users.

Attack Path:
Admin initializes a season with rewards and finalizes it with a claim_end_time.
After claim_end_time, admin calls revokeUnclaimedReward, setting remaining_reward_amount to 0 and transferring funds to the treasury.
Admin calls extendClaimDuration, extending claim_end_time, making isSeasonClaimingActive return true.
Users attempt to claim via claimAndStakeReward, which reverts due to an underflow when subtracting _amount from remaining_reward_amount (0).

Impact:
Gas Loss: Users waste gas on failed claimAndStakeReward transactions due to the underflow revert (panic code 0x11).
User Confusion and Trust Erosion: The active season state misleads users (via front-end or direct interaction) into believing claims are possible, eroding trust.
Potential Malicious Exploitation: A malicious admin could extend the claim period post-revocation to induce failed transactions, potentially benefiting from gas fees via MEV or misrepresenting protocol functionality.
Operational Disruption: Legitimate users cannot claim rewards, undermining the contract’s core reward distribution and staking functionality.

Tools Used:
Manual review



Hardhat (for POC testing)
```solidity
Proof of Concept: The following Hardhat test demonstrates the vulnerability:
const { expect } = require("chai");
const { ethers } = require("hardhat");
const helpers = require("@nomicfoundation/hardhat-network-helpers");

describe("BlackClaims Race Conditions", function () {
    let blackClaims, token, votingEscrow, votingBalanceLogic, owner, user, treasury;

    beforeEach(async function () {
        [owner, user, treasury] = await ethers.getSigners();
        const TestERC20 = await ethers.getContractFactory("TestERC20");
        token = await TestERC20.deploy("Test Token", "TEST");
        await token.deployed();
        const VotingBalanceLogic = await ethers.getContractFactory("VotingBalanceLogic");
        votingBalanceLogic = await VotingBalanceLogic.deploy();
        await votingBalanceLogic.deployed();
        const VotingEscrowFactory = await ethers.getContractFactory("VotingEscrow", {
            libraries: { VotingBalanceLogic: votingBalanceLogic.address },
        });
        votingEscrow = await VotingEscrowFactory.deploy(token.address, owner.address, owner.address);
        await votingEscrow.deployed();
        await token.mint(owner.address, ethers.utils.parseEther("1000"));
        await token.approve(votingEscrow.address, ethers.utils.parseEther("1000"));
        const BlackClaims = await ethers.getContractFactory("BlackClaims");
        blackClaims = await BlackClaims.deploy(treasury.address, votingEscrow.address);
        await blackClaims.deployed();
        const currentTime = await helpers.time.latest();
        await blackClaims.connect(owner).startSeason(currentTime);
        await token.mint(treasury.address, ethers.utils.parseEther("1000"));
        await token.connect(treasury).approve(blackClaims.address, ethers.utils.parseEther("1000"));
        await blackClaims.connect(owner).reportRewards([user.address], [ethers.utils.parseEther("100")]);
        await blackClaims.connect(owner).finalize(7 * 24 * 3600);
    });

    it("Should demonstrate critical race condition vulnerability", async function () {
        await helpers.time.increase(7 * 24 * 3600 + 3600);
        const seasonBefore = await blackClaims.season();
        expect(seasonBefore.remaining_reward_amount).to.be.gt(0);
        await blackClaims.connect(owner).revokeUnclaimedReward();
        await blackClaims.connect(owner).extendClaimDuration(7 * 24 * 3600);
        const seasonAfter = await blackClaims.season();
        expect(await blackClaims.isSeasonClaimingActive()).to.be.true;
        expect(seasonAfter.remaining_reward_amount).to.equal(0);
        await expect(blackClaims.connect(user).claimAndStakeReward(100)).to.be.reverted;
    });
});
```

Test Results:
The test confirms the vulnerability: revokeUnclaimedReward and extendClaimDuration execute successfully, setting remaining_reward_amount to 0 and extending claim_end_time. claimAndStakeReward reverts due to an underflow, wasting gas.
A second test (failing as expected) shows that extendClaimDuration does not revert post-revocation, confirming the missing check.

Recommendations:
Prevent Extension of Revoked Seasons: Add a check in extendClaimDuration to ensure remaining_reward_amount > 0:
```solidity
function extendClaimDuration(uint256 claim_duration_) external onlyOwner {
    Season storage _season = season;
    require(_season.start_time > 0, "SEASON NOT FOUND");
    require(isSeasonFinalized(), "SEASON_NOT_FINALIZED");
    require(_season.reward_amount > 0, "NO REWARD AMOUNT");
+   require(_season.remaining_reward_amount > 0, "CANNOT_EXTEND_REVOKED_SEASON");
    _season.claim_end_time = season.claim_end_time + claim_duration;
}
```


Enhance claimAndStakeReward Safety: Add a check to prevent underflows, even if the race condition occurs:
```solidity
function claimAndStakeReward(uint128 lock_duration) external {
    Season storage _season = season;
    uint256 _amount = season_rewards[msg.sender];
    require(_amount > 0, "MUST HAVE A NON ZERO REWARD");
    require(isSeasonClaimingActive(), "CLAIMING NOT ACTIVE");
+   require(_season.remaining_reward_amount >= _amount, "INSUFFICIENT_REMAINING_REWARDS");
    season_rewards[msg.sender] -= uint128(_amount);
    _season.remaining_reward_amount -= uint128(_amount);
    bool transfer_success = token.transfer(address(votingEscrow), _amount);
    require(transfer_success, "FAILED TRANSFER");
    votingEscrow.create_lock_for(msg.sender, _amount, lock_duration);
}
```

Links to affected code:
https://github.com/code-423n4/2025-05-blackhole/blob/92fff849d3b266e609e6d63478c4164d9f608e91/contracts/BlackClaims.sol#L141
https://github.com/code-423n4/2025-05-blackhole/blob/92fff849d3b266e609e6d63478c4164d9f608e91/contracts/BlackClaims.sol#L107
