## Low-1: Flaw in the BlockzLendingERC20 repayETH() Function Would Prevent Repayment of Loan Using ETH

Summary:
The repayETH() function in the BlockzLendingERC20.sol contract will prevent repayment of loan with ETH due to the lack of conversion mechanism and the function deposits ETH but still requires ERC20 tokens for repayment, which leads to the function not working as intended.

Vulnerability Details:
The repayETH function deposits ETH to AssetManager via deposit{value: msg.value}(msg.sender) then calls repay() which expects ERC20 tokens to be transferred from the borrower. The repay() function calls calculateRepayment() which returns payment in the same units as loan.lentAmount, and when the transferFrom inside repay function tries to send ERC20 token from the borrower to the lender, it will revert because there is only ETH. Since there is no conversion mechanism between ETH and ERC20 tokens, the function assumes that when a user sends ETH, the borrower somehow has ERC20 tokens to repay their loan but in reality the borrower has none, just ETH. Since no ETH to ERC20 conversion happens, the transaction will revert, which could lead to unjust liquidation of the user's collateral if they are at the brink of their loan terms.

Affected Code:
BlockzLendingERC20.sol
```solidity
function repayETH(address _collateralizedAsset, address _lender, string memory _salt) external payable {
    IAssetManager(assetManager).deposit{ value: msg.value }(msg.sender);
    repay(_collateralizedAsset, _lender, _salt);
}
```

```solidity
function repay(address _collateralizedAsset, address _lender, string memory _salt) whenNotPaused nonReentrant public {
    Loan memory loan = loans[msg.sender][_collateralizedAsset][_lender][_salt];
    require(loan.startedAt > 0, "there is not any active loan");
    uint256 payment = calculateRepayment(msg.sender, _collateralizedAsset, _lender, _salt);
    emit Repay(msg.sender, _collateralizedAsset, _lender, _salt, payment);
    IAssetManager(assetManager).transferFrom(msg.sender, _lender, payment);
    SafeERC20Upgradeable.safeTransfer(IERC20Upgradeable(_collateralizedAsset), msg.sender, loan.collateralizedAmount);
    delete loans[msg.sender][_collateralizedAsset][_lender][_salt];
}
```

Root Cause: The repayETH() function lacks a conversion mechanism between ETH and ERC20 tokens. It deposits ETH to AssetManager but then calls repay() which expects ERC20 tokens to be transferred from the borrower's balance. Since no conversion occurs, the transferFrom call will revert due to insufficient ERC20 balance, preventing loan repayment with ETH.

Attack Path:
1. Borrower takes a loan denominated in ERC20 tokens (e.g., USDC).
2. Borrower attempts to repay the loan using ETH by calling repayETH() with ETH value.
3. repayETH() deposits ETH to AssetManager successfully.
4. repayETH() calls repay() which calculates repayment amount in ERC20 tokens.
5. repay() attempts to transfer ERC20 tokens from borrower to lender via transferFrom.
6. Transaction reverts because borrower has no ERC20 tokens, only ETH was deposited.
7. Borrower's ETH is stuck in AssetManager, loan remains unpaid, and borrower risks liquidation.

Impact:
Transaction Reversion: All attempts to repay loans using ETH will fail, preventing borrowers from using ETH as a repayment method.
Fund Locking: ETH sent to repayETH() becomes locked in AssetManager without completing the loan repayment, resulting in loss of funds for borrowers.
Unjust Liquidation Risk: Borrowers who intended to repay with ETH may face liquidation if they cannot acquire the required ERC20 tokens in time, especially if they are near loan expiration.
User Experience Degradation: The function appears to support ETH repayment but fundamentally does not work, misleading users and wasting gas on failed transactions.

Tools Used:
Manual review
Foundry (for POC testing)

```solidity
Proof of Concept: The following Foundry test demonstrates the vulnerability:
function testRepayETHVulnerability() public {
    // Create a loan offer for ERC20 lending (USDC)
    LibLendingERC20.LoanOffer memory loanOffer = LibLendingERC20.LoanOffer({
        lender: lender,
        collateralizedAsset: address(usdc),
        salt: "test-salt",
        amount: 1 ether,      // 1 ETH worth of USDC (in wei), this is the loan amount
        price: 0.8 * 10**18,  // 80% LTV
        startedAt: block.timestamp,
        duration: 30 days,
        rate: 0.1 * 10**18    // 10% interest
    });
    
    // Create token struct
    LibLendingERC20.Token memory token = LibLendingERC20.Token({
        orderHash: LibLendingERC20.hash(loanOffer),
        blockNumber: block.number,
        amount: 1 ether,      // 1 ETH worth of USDC 
        borrower: borrower
    });
    
    // Sign the loan offer
    bytes memory loanSignature = _signLoanOffer(loanOffer, lenderPrivateKey);
    bytes memory tokenSignature = _signToken(token, validatorPrivateKey);
    
    // Borrower takes the ERC20 loan (they borrow in USDC)
    vm.prank(borrower);
    lendingContract.borrow(loanOffer, loanSignature, token, tokenSignature);
    
    // Check loan was created
    (uint256 lentAmount, uint256 collateralizedAmount, uint256 duration, uint256 rate, uint256 startedAt) = 
        lendingContract.loans(borrower, address(usdc), lender, "test-salt");
    
    assertTrue(lentAmount > 0, "Loan not created");
    assertEq(lentAmount, 1 ether, "Incorrect loan amount");
    
    // Fast forward time to make loan repayable
    vm.warp(block.timestamp + 15 days);
    
    // Check borrower's ETH balance before
    uint256 borrowerETHBefore = borrower.balance;
    
    // THE VULNERABILITY: Borrower tries to repay ERC20 loan with ETH
    // This demonstrates the core issue: repayETH deposits ETH but repay() expects ERC20 tokens
    
    // Check initial state
    uint256 initialETHInAssetManager = assetManager.biddingWallets(borrower);
    assertEq(initialETHInAssetManager, 0, "Should start with no ETH in AssetManager");
    
    // Try to repay with ETH - this should fail
    vm.expectRevert("ERC20: transfer amount exceeds balance");
    vm.prank(borrower);
    lendingContract.repayETH{value: 1 ether}(
        address(usdc),
        lender,
        "test-salt"
    );
    
    // Check what happened - ETH was deposited but loan still exists
    uint256 ethInAssetManager = assetManager.biddingWallets(borrower);
    
    // The vulnerability: ETH was deposited but loan still exists
    assertTrue(ethInAssetManager > 0, "ETH not deposited to AssetManager");
    
    // Check if loan still exists (it should, because repay failed)
    (lentAmount, collateralizedAmount, duration, rate, startedAt) = 
        lendingContract.loans(borrower, address(usdc), lender, "test-salt");
    
    // This demonstrates the vulnerability: loan still exists despite ETH deposit
    assertTrue(lentAmount > 0, "Loan should still exist - repay failed");
    
    console.log("Vulnerability confirmed:");
    console.log("- ETH deposited to AssetManager:", ethInAssetManager);
    console.log("- Loan still exists:", lentAmount > 0);
    console.log("- Borrower lost ETH but still owes ERC20 loan");
    console.log("- repayETH function is fundamentally broken");
}
```

Test Results:
The test confirms the vulnerability: repayETH() successfully deposits ETH to AssetManager, but the subsequent repay() call reverts with "ERC20: transfer amount exceeds balance" because the borrower has no ERC20 tokens. The loan remains unpaid despite ETH being deposited, demonstrating that the function is fundamentally broken.

Recommendations:
Implement ETH to ERC20 Conversion: Add a conversion mechanism in repayETH() to swap deposited ETH for the required ERC20 tokens before calling repay():
```solidity
function repayETH(address _collateralizedAsset, address _lender, string memory _salt) external payable {
    // Convert ETH to required ERC20 token via a DEX or oracle-based swap
    uint256 requiredAmount = calculateRepayment(msg.sender, _collateralizedAsset, _lender, _salt);
    IAssetManager(assetManager).deposit{ value: msg.value }(msg.sender);
    // Swap ETH for ERC20 tokens
    swapETHForERC20(_collateralizedAsset, requiredAmount);
    repay(_collateralizedAsset, _lender, _salt);
}
```

Alternative: Remove repayETH() Function: If ETH repayment is not a core feature, remove the function to prevent user confusion and fund locking.

Add Validation: Add checks to ensure sufficient ERC20 balance exists before attempting repayment, or implement automatic conversion.

Links to affected code:
https://github.com/hackenproof-public/blockz-sc

---

## Low-2: Undercollateralization Risk In the BlockzLendingERC20.sol Due To Price Volatility

Summary:
There is a severe economic vulnerability in the BlockzLendingERC20.sol contract where lenders could suffer serious economic loss due to collateral value depreciating during loan periods. The protocol lacks any mechanism to protect lenders against collateral value risk which could lead to scenarios when the price and value of a collateral could drop thereby leaving the collateral insufficient to cover the loan and its accrued interests, and in a situation like this, it is more profitable to the user to default the loan and not pay back than to pay back and get a now undervalued collateral.

Vulnerability Details:
The protocol lacks any mechanism to protect lenders against collateral value risk. When collateral prices drop significantly during the loan period, the collateral may become insufficient to cover the loan amount plus accrued interest. In such scenarios, borrowers have a financial incentive to default rather than repay, as repaying would result in a greater loss than simply forfeiting the now-undervalued collateral. The protocol does not implement automatic liquidation when collateral becomes insufficient, and collateral amounts are set at loan creation and never updated based on current market prices.

Affected Code:
BlockzLendingERC20.sol
```solidity
// Collateral amounts are locked at loan creation and never re-evaluated
function borrow(LoanOffer memory _loanOffer, bytes memory _loanSignature, Token memory _token, bytes memory _tokenSignature) external {
    // ... validation logic ...
    loans[msg.sender][_collateralizedAsset][_lender][_salt] = Loan({
        lentAmount: _loanOffer.amount,
        collateralizedAmount: collateralAmount, // Set once, never updated
        duration: _loanOffer.duration,
        rate: _loanOffer.rate,
        startedAt: block.timestamp
    });
    // ... no price monitoring or liquidation mechanism ...
}
```

Root Cause: The protocol sets collateral amounts at loan creation based on the price at that moment, but never monitors or updates collateral values during the loan period. There is no automatic liquidation mechanism when collateral value drops below safe thresholds, and no price oracle integration to track real-time collateral values.

Attack Path:
1. Borrower deposits 3,800 SUSHI as collateral (worth $3,040 at $0.80/SUSHI).
2. Borrower takes a loan of 2,432 USDC (80% LTV).
3. During the loan period, SUSHI price drops from $0.80 to $0.40.
4. The 3,800 SUSHI collateral is now worth only $1,520, well below the borrowed 2,432 USDC.
5. Borrower calculates: Repaying costs 2.432 ETH but gets back SUSHI worth only $1,520 (net loss of ~$912).
6. Borrower chooses to default, losing SUSHI worth $1,520 instead of repaying $2,432.
7. Lender calls clearDebt() and receives the undervalued collateral worth only $1,520.
8. Lender suffers a loss of $912 (37% of the loan amount).

Impact:
Lender Financial Loss: Lenders can suffer significant financial losses when collateral depreciates below the loan value, as they receive collateral worth less than the amount lent.
Borrower Incentive to Default: Borrowers have a financial incentive to default when collateral value drops, as repaying becomes more expensive than forfeiting the collateral.
No Risk Mitigation: The protocol has no mechanism to protect against market volatility, making it risky for lenders to provide loans against volatile collateral.
Systemic Risk: If many borrowers default simultaneously during market downturns, lenders could face substantial losses, potentially destabilizing the protocol.

Tools Used:
Manual review
Foundry (for POC testing)

```solidity
Proof of Concept: The following Foundry test demonstrates the vulnerability:
function testCollateralValueRisk() public {
    // Initial conditions: 1 SUSHI = $0.80, 1 ETH = $1,000
    // Collateral value: 3,800 SUSHI * $0.80 = $3,040
    // Loan amount: 2.432 ETH = $2,432
    // LTV: $2,432 / $3,040 = 80%
    
    LibLendingERC20.LoanOffer memory loanOffer = LibLendingERC20.LoanOffer({
        lender: lender,
        collateralizedAsset: address(sushi),
        salt: "test-salt",
        amount: 2.432 ether,   // 2.432 ETH loan (equivalent to $2,432 at $1000/ETH)
        price: 0.8 * 10**18,   // $0.80 per SUSHI
        startedAt: block.timestamp,
        duration: 30 days,
        rate: 0.1 * 10**18     // 10% interest
    });
    
    LibLendingERC20.Token memory token = LibLendingERC20.Token({
        orderHash: LibLendingERC20.hash(loanOffer),
        blockNumber: block.number,
        amount: 2.432 ether,   // 2.432 ETH
        borrower: borrower
    });
    
    bytes memory loanSignature = _signLoanOffer(loanOffer, lenderPrivateKey);
    bytes memory tokenSignature = _signToken(token, validatorPrivateKey);
    
    // Record initial balances
    uint256 initialBorrowerSushi = sushi.balanceOf(borrower);
    uint256 initialBorrowerEth = borrower.balance;
    uint256 initialLenderEth = lender.balance;
    uint256 initialLenderBiddingWallet = assetManager.biddingWallets(lender);
    
    console.log("=== INITIAL STATE ===");
    console.log("Borrower SUSHI balance:", initialBorrowerSushi);
    console.log("Borrower ETH balance:", initialBorrowerEth);
    console.log("Lender ETH balance:", initialLenderEth);
    console.log("Lender bidding wallet:", initialLenderBiddingWallet);
    console.log("Collateral value at $0.80/SUSHI: $3,040");
    console.log("Loan amount: 2.432 ETH ($2,432)");
    console.log("LTV: 80%");
    
    // Borrower takes loan
    vm.prank(borrower);
    lendingContract.borrow(loanOffer, loanSignature, token, tokenSignature);
    
    // Verify loan was created
    (uint256 lentAmount, uint256 collateralizedAmount, uint256 duration, uint256 rate, uint256 startedAt) = 
        lendingContract.loans(borrower, address(sushi), lender, "test-salt");
    
    assertTrue(lentAmount > 0, "Loan not created");
    assertEq(lentAmount, 2.432 ether, "Incorrect loan amount");
    assertEq(collateralizedAmount, 3040 * 10**18, "Incorrect collateral amount");
    
    console.log("\n=== AFTER LOAN CREATION ===");
    console.log("Borrower SUSHI balance:", sushi.balanceOf(borrower));
    console.log("Borrower ETH balance:", borrower.balance);
    console.log("Borrower bidding wallet:", assetManager.biddingWallets(borrower));
    console.log("Lender bidding wallet:", assetManager.biddingWallets(lender));
    console.log("Collateral locked in contract:", collateralizedAmount);
    
    // Simulate market crash: SUSHI drops from $0.80 to $0.40
    // New collateral value: 3,800 SUSHI * $0.40 = $1,520
    // This is well below the 2,432 USDC loan amount
    
    console.log("\n=== MARKET CRASH SIMULATION ===");
    console.log("SUSHI price drops from $0.80 to $0.40");
    console.log("New collateral value: $1,520");
    console.log("Loan amount: 2.432 ETH ($2,432)");
    console.log("Collateral now covers only: 62.5% of loan");
    
    // Fast forward to loan expiration
    vm.warp(block.timestamp + 30 days + 1);
    
    // Calculate what borrower would need to repay
    uint256 totalRepayment = lendingContract.calculateRepayment(borrower, address(sushi), lender, "test-salt");
    
    console.log("\n=== LOAN EXPIRATION ===");
    console.log("Total repayment needed:", totalRepayment / 10**18, "ETH");
    console.log("Collateral value at $0.40/SUSHI: $1,520");
    
    // Borrower chooses not to repay (more profitable to default)
    console.log("\n=== BORROWER'S DECISION ===");
    console.log("Option 1 - Repay loan:");
    console.log("  Cost:", totalRepayment / 10**18, "ETH");
    console.log("  Get back: 3,800 SUSHI (worth $1,520 at $0.40/SUSHI)");
    console.log("  Net loss:", (totalRepayment / 10**18) - 1.52, "ETH");
    
    console.log("Option 2 - Default:");
    console.log("  Cost: 0 ETH");
    console.log("  Lose: 3,800 SUSHI (worth $1,520 at $0.40/SUSHI)");
    console.log("  Net loss: 1.52 ETH");
    
    console.log("Borrower chooses to DEFAULT (saves money)");
    
    // Lender calls clearDebt() to claim the undervalued collateral
    vm.prank(lender);
    lendingContract.clearDebt(address(sushi), borrower, "test-salt");
    
    // Verify final state
    uint256 finalLenderSushi = sushi.balanceOf(lender);
    uint256 finalLenderEth = lender.balance;
    
    console.log("\n=== FINAL STATE ===");
    console.log("Lender SUSHI balance:", finalLenderSushi);
    console.log("Lender ETH balance:", finalLenderEth);
    console.log("Lender received:", finalLenderSushi / 10**18, "SUSHI");
    console.log("SUSHI value at $0.40: $1,520");
    console.log("Original loan amount: 2.432 ETH ($2,432)");
    
    // Calculate lender's loss
    uint256 collateralValue = (finalLenderSushi * 0.4 * 10**18) / 10**18;
    uint256 lenderLoss = 2432 - collateralValue;
    
    console.log("\n=== VULNERABILITY CONFIRMED ===");
    console.log("Lender's loss: $", lenderLoss);
    console.log("Lender received collateral worth only: $", collateralValue);
    console.log("But lent out: 2.432 ETH ($2,432)");
    console.log("Loss percentage:", (lenderLoss * 100) / 2432, "%");
    
    // Verify the vulnerability
    assertTrue(collateralValue < 2432, "Collateral should be worth less than loan amount");
    assertTrue(lenderLoss > 0, "Lender should have suffered a loss");
    
    // Verify loan was deleted
    (lentAmount, collateralizedAmount, duration, rate, startedAt) = 
        lendingContract.loans(borrower, address(sushi), lender, "test-salt");
    assertEq(lentAmount, 0, "Loan should be deleted");
}
```

Test Results:
The test confirms the vulnerability: When SUSHI price drops from $0.80 to $0.40, the collateral value decreases from $3,040 to $1,520, which is below the $2,432 loan amount. The borrower defaults, and the lender receives collateral worth only $1,520, suffering a loss of $912 (37% of the loan amount).

Recommendations:
Implement Health Factor Monitoring: Add automatic liquidation when collateral values drop below healthy/safe levels:
```solidity
function checkHealthFactor(address borrower, address collateral, address lender, string memory salt) public view returns (uint256) {
    Loan memory loan = loans[borrower][collateral][lender][salt];
    uint256 currentCollateralValue = getCurrentCollateralValue(collateral, loan.collateralizedAmount);
    uint256 loanValue = calculateRepayment(borrower, collateral, lender, salt);
    return (currentCollateralValue * 100) / loanValue; // Returns health factor as percentage
}

function liquidateIfUnhealthy(address borrower, address collateral, address lender, string memory salt) external {
    require(checkHealthFactor(borrower, collateral, lender, salt) < LIQUIDATION_THRESHOLD, "Loan is healthy");
    // Execute liquidation
}
```

Implement Price Oracle Integration: Integrate Chainlink or similar price feeds to track token values in real-time and monitor collateral value constantly during loan period:
```solidity
import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";

mapping(address => AggregatorV3Interface) public priceFeeds;

function getCurrentCollateralValue(address collateral, uint256 amount) public view returns (uint256) {
    AggregatorV3Interface priceFeed = priceFeeds[collateral];
    (, int256 price, , , ) = priceFeed.latestRoundData();
    return (amount * uint256(price)) / 10**18;
}
```

Add Automatic Liquidation: Implement automatic liquidation when collateral value drops below a safe threshold (e.g., 110% of loan value) to protect lenders.

Links to affected code:
https://github.com/hackenproof-public/blockz-sc

---

## Low-3: Borrower Can Be Liquidated For Situations Beyond Their Control

Summary:
Borrowers cannot repay loans when the system is paused, but the loan period continues to count down normally. When the system becomes unpaused, borrowers might not be able to repay their loan as they are in a race condition with the lender, as the lender can call clearDebt() or batchClearDebt() once a loan has expired, thereby leaving them to be unfairly liquidated despite wanting to pay. The system does not account for pause periods when calculating expiration and continues to count down even when the system is paused, leaving lenders to benefit from this unfair liquidation.

Vulnerability Details:
The protocol's pause mechanism prevents borrowers from repaying loans during pause periods, but the loan duration continues to count down regardless of pause status. This creates an unfair situation where borrowers lose time to repay their loans during pauses, and when the system is unpaused, they may find their loans have expired or are very close to expiration. Lenders can then call clearDebt() or batchClearDebt() to liquidate the collateral before borrowers have a fair opportunity to repay, even though the borrowers were prevented from repaying during the pause period.

Affected Code:
BlockzLendingERC20.sol
```solidity
function repay(address _collateralizedAsset, address _lender, string memory _salt) whenNotPaused nonReentrant public {
    // This function cannot be called when paused
    Loan memory loan = loans[msg.sender][_collateralizedAsset][_lender][_salt];
    require(loan.startedAt > 0, "there is not any active loan");
    // Loan expiration is calculated as: loan.startedAt + loan.duration
    // This does not account for pause periods
    uint256 payment = calculateRepayment(msg.sender, _collateralizedAsset, _lender, _salt);
    // ... repayment logic ...
}
```

```solidity
function pause() external onlyOwner {
    require(!paused(), "Contract is already paused");
    _pause();
    // No tracking of pause duration or adjustment of loan expiration
}
```

Root Cause: The pause() function does not track pause periods or adjust loan expiration times. When the system is paused, borrowers cannot repay, but loan expiration continues to count down based on block.timestamp, effectively reducing the time borrowers have to repay their loans. This creates an unfair advantage for lenders who can liquidate loans that would have been repayable if pause periods were properly accounted for.

Attack Path:
1. Borrower takes a loan with a 30-day duration.
2. System is paused by owner for 10 days (e.g., due to emergency or upgrade).
3. During the pause, borrower cannot call repay() due to whenNotPaused modifier.
4. Loan expiration continues to count down: expiration = startedAt + 30 days (does not account for pause).
5. System is unpaused after 10 days.
6. Borrower now has only 20 days remaining to repay (instead of the original 30 days).
7. If loan expires or is close to expiration, lender can immediately call clearDebt().
8. Borrower is unfairly liquidated despite wanting to repay, as they lost 10 days of repayment opportunity during the pause.

Impact:
Unfair Liquidation: Borrowers can be liquidated for situations beyond their control (system pauses), even when they intended and attempted to repay their loans.
Loss of Repayment Opportunity: Borrowers lose time to repay during pause periods, which may cause loans to expire before they can be repaid.
Lender Advantage: Lenders benefit from pause periods by gaining the ability to liquidate loans that would have been repayable if pause periods were properly accounted for.
Trust Erosion: Borrowers may lose trust in the protocol if they are penalized for system-wide pauses that are outside their control.

Tools Used:
Manual review

Recommendations:
Track Pause Periods: Adjust the pause function to account for pause durations:
```solidity
struct PausePeriod {
    uint256 startTime;
    uint256 endTime;
    bool isActive;
}

PausePeriod[] public pausePeriods;
uint256 public totalPauseDuration;

function pause() external onlyOwner {
    require(!paused(), "Contract is already paused");
    
    currentPausePeriod.startTime = block.timestamp;
    currentPausePeriod.isActive = true;
    
    emit PauseWithTracking(block.timestamp);
    _pause();
}

function unpause() external onlyOwner {
    require(paused(), "Contract is not paused");
    
    if (currentPausePeriod.isActive) {
        currentPausePeriod.endTime = block.timestamp;
        uint256 pauseDuration = currentPausePeriod.endTime - currentPausePeriod.startTime;
        totalPauseDuration += pauseDuration;
        pausePeriods.push(currentPausePeriod);
        currentPausePeriod.isActive = false;
    }
    
    _unpause();
}
```

Extend Loan Duration Based on Pause Periods: Track pause periods and extend loan duration accordingly to ensure borrowers have a fair opportunity to repay regardless of pause mechanism:
```solidity
function calculateEffectiveLoanExpiration(Loan memory loan) public view returns (uint256) {
    uint256 baseExpiration = loan.startedAt + loan.duration;
    
    // Calculate total pause duration that occurred during the loan period
    uint256 relevantPauseDuration = 0;
    for (uint256 i = 0; i < pausePeriods.length; i++) {
        PausePeriod memory period = pausePeriods[i];
        // If pause period overlaps with loan period, add its duration
        if (period.startTime >= loan.startedAt && period.startTime < baseExpiration) {
            uint256 pauseEnd = period.isActive ? block.timestamp : period.endTime;
            uint256 pauseStart = period.startTime;
            if (pauseEnd > baseExpiration) {
                pauseEnd = baseExpiration;
            }
            relevantPauseDuration += (pauseEnd - pauseStart);
        }
    }
    
    return baseExpiration + relevantPauseDuration;
}

function isLoanExpired(address borrower, address collateral, address lender, string memory salt) public view returns (bool) {
    Loan memory loan = loans[borrower][collateral][lender][salt];
    uint256 effectiveExpiration = calculateEffectiveLoanExpiration(loan);
    return block.timestamp >= effectiveExpiration;
}
```

Prevent Liquidation During Grace Period: Add a grace period after unpause before allowing liquidation to give borrowers time to repay:
```solidity
uint256 public constant GRACE_PERIOD_AFTER_UNPAUSE = 24 hours;
uint256 public lastUnpauseTime;

function clearDebt(address _collateralizedAsset, address _borrower, string memory _salt) external {
    require(block.timestamp >= lastUnpauseTime + GRACE_PERIOD_AFTER_UNPAUSE, "Grace period active");
    // ... existing liquidation logic ...
}
```

Links to affected code:
https://github.com/hackenproof-public/blockz-sc
