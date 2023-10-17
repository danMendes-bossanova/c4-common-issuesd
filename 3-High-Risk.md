# High Risk Issues

## H001 - Unsafe ERC20 Operation(s)

### Description


ERC20 operations can present security challenges due to variations 
in their implementations and potential vulnerabilities within the standard. 
For a tech-savvy audience, it's essential to address these concerns.

It is therefore recommended to always either use OpenZeppelin's `SafeERC20`
library or at least to wrap each operation in a `require` statement.

To circumvent ERC20's `approve` functions race-condition vulnerability use
OpenZeppelin's `SafeERC20` library's `safe{Increase|Decrease}Allowance`
functions.

In case the vulnerability is of no danger for your implementation, provide
enough documentation explaining the reasonings.

### Example

🤦 Bad:
```solidity
IERC20(token).transferFrom(msg.sender, address(this), amount);
```

🚀 Good (using OpenZeppelin's `SafeERC20`):
```solidity
import {SafeERC20} from "openzeppelin/token/utils/SafeERC20.sol";

// ...

IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
```

🚀 Good (using `require`):
```solidity
bool success = IERC20(token).transferFrom(msg.sender, address(this), amount);
require(success, "ERC20 transfer failed");
```

### Background Information

- [OpenZeppelin's IERC20 documentation](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/IERC20.sol#L43)


## H002 - Loans can be rolled an unlimited number of times

### Description

Loans can be rolled an unlimited number of times, without letting the lender decide if has been done too many times already.

The lender is expected to be able to toggle whether a loan can be rolled or not, but once it's enabled, there is no way to prevent the borrower from rolling an unlimited number of times in the same transaction or in quick succession.

If the lender is giving an interest-free loan and assumes that allowing a roll will only extend the term by one, they'll potentially be forced to wait until the end of the universe if the borrower chooses to roll an excessive number of times.

If the borrower is using a quickly-depreciating collateral, the lender may be happy to allow one a one-term extension, but will lose money if the term is rolled multiple times and the borrower defaults thereafter.

The initial value of loan.rollable is always true, so unless the lender calls toggleRoll() in the same transaction that they call clear(), a determined attacker will be able to roll as many times as they wish.

### Example

🤦 Bad:
```solidity
141    
142            loan.amount += newDebt;
143            loan.expiry += req.duration;
144            loan.collateral += newCollateral;
145            
147:       }
```

🚀 Good:
```solidity
+   loan.rollable = false;
    loan.amount += newDebt;
    loan.expiry += req.duration;
    loan.collateral += newCollateral;
```

### Background Information

https://github.com/sherlock-audit/2023-01-cooler-judging#issue-h-2-loans-can-be-rolled-an-unlimited-number-of-times


## H003 - Fully repaying a loan will result in debt payment being lost

### Description

When a loan is fully repaid the loan storage is deleted. Since loan is a storage reference to the loan, loan.lender will return address(0) after the loan has been deleted. This will result in the debt being transferred to address(0) instead of the lender. Some ERC20 tokens will revert when being sent to address(0) but a large number will simply be sent there and lost forever.

In Cooler#repay the loan storage associated with the loanID being repaid is deleted. loan is a storage reference so when loans[loanID] is deleted so is loan. The result is that loan.lender is now address(0) and the loan payment will be sent there instead.

### Example

🤦 Bad:
```solidity

    if (repaid == loan.amount) delete loans[loanID];
    else {
        loan.amount -= repaid;
        loan.collateral -= decollateralized;
    }

```

🚀 Good:
```solidity
-   if (repaid == loan.amount) delete loans[loanID];
+   if (repaid == loan.amount) {
+       debt.transferFrom(msg.sender, loan.lender, loan.amount);
+       collateral.transfer(owner, loan.collateral);
+       delete loans[loanID];
+       return;
+   }
```

### Background Information

https://github.com/sherlock-audit/2023-01-cooler-judging#issue-h-3-fully-repaying-a-loan-will-result-in-debt-payment-being-lost


## H004 - Lender force Loan become default

### Description

in repay() directly transfer the debt token to Lender, but did not consider that Lender can not accept the token (in contract blacklist), resulting in repay() always revert, and finally the Loan can only expire, Loan be default.

The only way for the borrower to get the collateral token back is to repay the amount owed via repay(). Currently in the repay() method transfers the debt token directly to the Lender. This has a problem: if the Lender is blacklisted by the debt token now, the debtToken.transferFrom() method will fail and the repay() method will always fail and finally the Loan will default. Example: Assume collateral token = ETH,debt token = USDC, owner = alice 1.alice call request() to loan 2000 usdc , duration = 1 mon 2.bob call clear(): loanID =1 3.bob transfer loan[1].lender = jack by Cooler.approve/transfer
Note: jack has been in USDC's blacklist for some reason before or bob in USDC's blacklist for some reason now, it doesn't need transfer 'lender') 4.Sometime before the expiration date, alice call repay(id=1) , it will always revert, Because usdc.transfer(jack) will revert 5.after 1 mon, loan[1] default, jack call defaulted() get collateral token

Lender forced Loan become default for get collateral token, owner lost collateral token

### Example

🤦 Bad:
```solidity
 debt.transferFrom(msg.sender, loan.lender, repaid);
```

🚀 Good:
```solidity
mapping(address => uint) repayedAmount;

function claimRepayedAmount() external {
    debt.safeTransfer(msg.sender, repayedAmount);
    repayedAmount[msg.sender] = 0;
}
```


## H005 - StakedCitadel depositors can be attacked by the first depositor with depressing of vault token denomination

### Vulnerability details
**Impact**

An attacker can become the first depositor for a recently created StakedCitadel contract, providing a tiny amount of Citadel tokens by calling deposit(1) (raw values here, 1 is 1 wei, 1e18 is 1 Citadel as it has 18 decimals). Then the attacker can directly transfer, for example, 10^6*1e18 - 1 Citadel to StakedCitadel, effectively setting the cost of 1 of the vault token to be 10^6 * 1e18 Citadel. The attacker will still own 100% of the StakedCitadel's pool being the only depositor.

All subsequent depositors will have their Citadel token investments rounded to 10^6 * 1e18, due to the lack of precision which initial tiny deposit caused, with the remainder divided between all current depositors, i.e. the subsequent depositors lose value to the attacker.

For example, if the second depositor brings in 1.9*10^6 * 1e18 Citadel, only 1 of new vault to be issued as 1.9*10^6 * 1e18 divided by 10^6 * 1e18 will yield just 1, which means that 2.9*10^6 * 1e18 total Citadel pool will be divided 50/50 between the second depositor and the attacker, as each have 1 wei of the total 2 wei of vault tokens, i.e. the depositor lost and the attacker gained 0.45*10^6 * 1e18 Citadel tokens.

As there are no penalties to exit with StakedCitadel.withdraw(), the attacker can remain staked for an arbitrary time, gathering the share of all new deposits' remainder amounts.

Placing severity to be high as this is principal funds loss scenario for many users (most of depositors), easily executable, albeit only for the new StakedCitadel contract.

### Proof of Concept

deposit() -> _depositFor() -> _mintSharesFor() call doesn't require minimum amount and mints according to the provided amount:

deposit:

https://github.com/code-423n4/2022-04-badger-citadel/blob/main/src/StakedCitadel.sol#L309-L311

_depositFor:

https://github.com/code-423n4/2022-04-badger-citadel/blob/main/src/StakedCitadel.sol#L764-L777

_mintSharesFor:

https://github.com/code-423n4/2022-04-badger-citadel/blob/main/src/StakedCitadel.sol#L881-L892

When StakedCitadel is new the _pool = balance() is just initially empty contract balance:

https://github.com/code-423n4/2022-04-badger-citadel/blob/main/src/StakedCitadel.sol#L293-L295

Any deposit lower than total attacker's stake will be fully stolen from the depositor as 0 vault tokens will be issued in this case.

### References

The issue is similar to the TOB-YEARN-003 one of the Trail of Bits audit of Yearn Finance:

https://github.com/yearn/yearn-security/tree/master/audits/20210719_ToB_yearn_vaultsv2

### Recommended Mitigation Steps

A minimum for deposit value can drastically reduce the economic viability of the attack. I.e. deposit() -> ... can require each amount to surpass the threshold, and then an attacker would have to provide too big direct investment to capture any meaningful share of the subsequent deposits.

An alternative is to require only the first depositor to freeze big enough initial amount of liquidity. This approach has been used long enough by various projects, for example in Uniswap V2:

https://github.com/Uniswap/v2-core/blob/master/contracts/UniswapV2Pair.sol#L119-L121

🤦 Bad:
```solidity
 currentBalance = vault.balanceOfJPEG() + jpeg.balanceOf(address(this));
uint256 newRewards = currentBalance - previousBalance;
```

No funds can be withdrawn anymore as the withdraw functions first trigger an _update.

The currentBalance < previousBalance case can, for example, be triggerd by decreasing the vault.balanceOfJPEG() due to calling yVault.setController:

🚀 @audit:
```solidity
function setController(address _controller) public onlyOwner {
    // @audit can reduce balanceofJpeg which breaks other masterchef contract
    require(_controller != address(0), "INVALID_CONTROLLER");
    controller = IController(_controller);
}

function balanceOfJPEG() external view returns (uint256) {
    // @audit new controller could return a smaller balance
    return controller.balanceOfJPEG(address(token));
}
```

### Background Information

- [Chemical - w2](https://github.com/code-423n4/2022-04-badger-citadel-findings/issues/217)

## H006 - Truncation in OrderValidator can lead to resetting the fill and selling more tokens

### Vulnerability details
**Impact**

A partial order's fractions (numerator and denominator) can be reset to 0 due to a truncation. This can be used to craft malicious orders:
    1. Consider user Alice, who has 100 ERC1155 tokens, who approved all of their tokens to the 'marketplaceContract'.
    2. Alice places a PARTIAL_OPEN order with 10 ERC1155 tokens and consideration of ETH.
    3. Malory tries to fill the order in the following way:
       1. Malory tries to fill 50% of the order, but instead of providing the fraction 1 / 2, Bob provides 2**118 / 2**119. This sets the totalFilled to 2**118 and totalSize to 2**119.
       2. Malory tries to fill 10% of the order, by providing 1 / 10. The computation 2**118 / 2**119 + 1 / 10 is done by "cross multiplying" the denominators, leading to the acutal fraction being numerator = (2**118 * 10 + 2**119) and denominator = 2**119 * 10.
       3. Because of the uint120 truncation in OrderValidator.sol#L228-L248, the numerator and denominator are truncated to 0 and 0 respectively.
       4. Bob can now continue filling the order and draining any approved (1000 tokens in total) of the above ERC1155 tokens, for the same consideration amount!

### Proof of Concept

For a full POC: https://gist.github.com/hrkrshnn/7c51b23f7c43c55ba0f8157c3b298409

The following change would make the above POC fail:

🤦 POC:
```solidity
 modified   contracts/lib/OrderValidator.sol
@@ -225,6 +225,8 @@ contract OrderValidator is Executor, ZoneInteraction {
                 // Update order status and fill amount, packing struct values.
                 _orderStatus[orderHash].isValidated = true;
                 _orderStatus[orderHash].isCancelled = false;
+                require(filledNumerator + numerator <= type(uint120).max, "overflow");
+                require(denominator <= type(uint120).max, "overflow");
                 _orderStatus[orderHash].numerator = uint120(
                     filledNumerator + numerator
                 );
@@ -234,6 +236,8 @@ contract OrderValidator is Executor, ZoneInteraction {
             // Update order status and fill amount, packing struct values.
             _orderStatus[orderHash].isValidated = true;
             _orderStatus[orderHash].isCancelled = false;
+            require(numerator <= type(uint120).max, "overflow");
+            require(denominator <= type(uint120).max, "overflow");
             _orderStatus[orderHash].numerator = uint120(numerator);
             _orderStatus[orderHash].denominator = uint120(denominator);
         }
```

### Tools Used

Manual review

### Recommended Mitigation Steps

A basic fix for this would involve adding the above checks for overflow / truncation and reverting in that case. However, we think the mechanism is still flawed in some respects and require more changes to fully fix it. See a related issue: "A malicious filler can fill a partial order in such a way that the rest cannot be filled by anyone" that points out a related but a more fundamental issue with the mechanism.

### Background Information

- [Chemical - w2](https://github.com/code-423n4/2022-05-opensea-seaport-findings/issues/77)

## H007 - yVault: First depositor can break minting of shares

### Vulnerability details
**Impact**

The attack vector and impact is the same as [TOB-YEARN-003](https://github.com/yearn/yearn-security/blob/master/audits/20210719_ToB_yearn_vaultsv2/ToB_-_Yearn_Vault_v_2_Smart_Contracts_Audit_Report.pdf), where users may not receive shares in exchange for their deposits if the total asset amount has been manipulated through a large “donation”.

### Proof of Concept

 - Attacker deposits 1 wei to mint 1 share
 - Attacker transfers exorbitant amount to the StrategyPUSDConvex contract to greatly inflate the share’s price. Note that the strategy deposits its entire balance into Convex when its deposit() function is called.
 - Subsequent depositors instead have to deposit an equivalent sum to avoid minting 0 shares. Otherwise, their deposits accrue to the attacker who holds the only share.

Insert this test into yVault.ts.

🚀 @audit:
```solidity
 it.only("will cause 0 share issuance", async () => {
  // mint 10k + 1 wei tokens to user1
  // mint 10k tokens to owner
  let depositAmount = units(10_000);
  await token.mint(user1.address, depositAmount.add(1));
  await token.mint(owner.address, depositAmount);
  // token approval to yVault
  await token.connect(user1).approve(yVault.address, 1);
  await token.connect(owner).approve(yVault.address, depositAmount);
  
  // 1. user1 mints 1 wei = 1 share
  await yVault.connect(user1).deposit(1);
  
  // 2. do huge transfer of 10k to strategy
  // to greatly inflate share price (1 share = 10k + 1 wei)
  await token.connect(user1).transfer(strategy.address, depositAmount);
  
  // 3. owner deposits 10k
  await yVault.connect(owner).deposit(depositAmount);
  // receives 0 shares in return
  expect(await yVault.balanceOf(owner.address)).to.equal(0);

  // user1 withdraws both his and owner's deposits
  // total amt: 20k + 1 wei
  await expect(() => yVault.connect(user1).withdrawAll())
    .to.changeTokenBalance(token, user1, depositAmount.mul(2).add(1));
});
```

### Recommended Mitigation Steps

   1. Uniswap V2 solved this problem by sending the first 1000 LP tokens to the zero address. The same can be done in this case i.e. when totalSupply() == 0, send the first min liquidity LP tokens to the zero address to enable share dilution.
   2. Ensure the number of shares to be minted is non-zero: require(_shares != 0, "zero shares minted");

### Background Information

- [Chemical - w2](https://github.com/code-423n4/2022-04-jpegd-findings/issues/12)
