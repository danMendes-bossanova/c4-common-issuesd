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


## H005 - Setting new controller can break YVaultLPFarming

### Description

The accruals in yVaultLPFarming will fail if currentBalance < previousBalance in _computeUpdate.

### POC

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

- [Chemical - w2](https://github.com/code-423n4/2022-04-jpegd-findings/issues/80)
