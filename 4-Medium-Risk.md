# Medium Risk Issues

## M001 - Cooler.roll() wouldn't work as expected when newCollateral = 0.

### Description

Cooler.roll() is used to increase the loan duration by transferring the additional collateral.

But there will be some problems when newCollateral = 0.

In roll(), it transfers the newCollateral amount of collateral to the contract.

After the borrower repaid most of the debts, loan.amount might be very small and newCollateral for the original interest might be 0 because of the rounding issue.

Then as we can see from this one, some tokens might revert for 0 amount and roll() wouldn't work as expected.

There will be 2 impacts.

When the borrower tries to extend the loan using roll(), it will revert with the weird tokens when newCollateral = 0.
After the borrower noticed he couldn't repay anymore(so the lender will default the loan), the borrower can call roll() again when newCollateral = 0. In this case, the borrower doesn't lose anything but the lender must wait for req.duration again to default the loan.

### Example

🤦 Bad:
```solidity
   safeTransferETH(msg.sender, value)
   deposits[msg.sender] = 0;
```

🚀 Good (using OpenZeppelin's `SafeERC20`):
```solidity
   deposits[msg.sender] = 0; // changing state before external call
   safeTransferETH(msg.sender, value)
```

### Background Information

https://github.com/sherlock-audit/2023-01-cooler-judging#issue-m-1-coolerroll-wouldnt-work-as-expected-when-newcollateral--0


## M002 - Loan is rollable by default

### Description

Making the loan rollable by default gives an unfair early advantage to the borrowers.

Lenders who do not want the loans to be used more than once, have to bundle their transactions. Otherwise, it is possible that someone might roll their loan, especially if the capital requirements are not huge because anyone can roll any loan.

### Example

🤦 Bad:
```solidity
Loan(req, req.amount + interest, collat, expiration, true, msg.sender)
```

🚀 Good:
```solidity
Loan(req, req.amount + interest, collat, expiration, false, msg.sender)
```

### Background Information

https://github.com/sherlock-audit/2023-01-cooler-judging#issue-m-2-loan-is-rollable-by-default

## M003 - Repaying loans with small amounts of debt tokens can lead to underflowing in the roll function

### Description

Due to precision issues when repaying a loan with small amounts of debt tokens, the loan.amount can be reduced whereas the loan.collateral remains unchanged. This can lead to underflowing in the roll function.

The decollateralized calculation in the repay function rounds down to zero if the repaid amount is small enough. This allows iteratively repaying a loan with very small amounts of debt tokens without reducing the collateral.

The consequence is that the roll function can revert due to underflowing the newCollateral calculation once the loan.collateral is greater than collateralFor(loan.amount, req.loanToCollateral) (loan.amount is reduced by repaying the loan)

As any ERC-20 tokens with different decimals can be used, this precision issue is amplified if the decimals of the collateral and debt tokens differ greatly.

The roll function can revert due to underflowing the newCollateral calculation if the repay function is (iteratively) called with small amounts of debt tokens.

### Example

🤦 Bad:
```solidity
function refund(uint256 refundAmount, address payable to) internal {
   to.transfer(refundAmount);
}
```

🚀 Good:
```solidity
function refund(uint256 refundAmount, address payable to) internal {
   (bool success, ) = to.call{value: refundAmount}(""); 
   require(success, "Transfer failed");
}
```

### Background Information

https://github.com/sherlock-audit/2023-01-cooler-judging#issue-m-3-repaying-loans-with-small-amounts-of-debt-tokens-can-lead-to-underflowing-in-the-roll-function

## M004 - Dust amounts can cause payments to fail, leading to default

### Description

Dust amounts can cause payments to fail, leading to default

In order for a loan to close, the exact right number of wei of the debt token must be sent to match the remaining loan amount. If more is sent, the balance underflows, reverting the transaction.

An attacker can send dust amounts right before a loan is due, front-running any payments also destined for the final block before default. If the attacker's transaction goes in first, the borrower will be unable to pay back the loan before default, and will lose thier remaining collateral. This may be the whole loan amount.

### Example

🤦 Bad:
```solidity

function calculateFinalFee(uint256 value) public view returns (uint256) { 
   return value > maxAmountForFee ? fee : 0;
}
```

🚀 Good:
```solidity
function calculateFinalFee(uint256 value) public view returns (uint256) { 
   return value > maxAmountForFee ? 0 : fee;
}
```

### Background Information

### Background Information

https://github.com/sherlock-audit/2023-01-cooler-judging#issue-m-3-repaying-loans-with-small-amounts-of-debt-tokens-can-lead-to-underflowing-in-the-roll-function

## M005 - DAI/gOHM exchange rate may be stale

### Description

The maxLTC variable is a constant which implies a specific DAI/gOHM echange rate. The exchange rate has already changed so the current value in use will be wrong, and any value chosen now will eventually be out of date.

The ClearingHouse allows any loan to go through (assuming the operator approves it, and the operator is likely some sort of keeper program), and decides whether the terms are fair based on the hard-coded maxLTC, which will be (and is already - gOHM is currently worth $2,600) out of date.

If the code had been using a Chainlink oracle, this issue would be equivalent to not checking whether the price used to determine the loan-to-collateral ratio was stale, which is a Medium-severity issue.

It's not clear who or what exactly will be in control of the operator address which will make the clear() calls, but it will likely be a keeper which, unless programmed otherwise, would blindly approve such loans. Even if the operator is an actual person, the fact that there are coded checks for the maxLTC, means that the person/keeper can't be fully trusted, or that the code is attempting to protect against mistakes, so this category of mistake should also be added.

Under-collateralized loans will be given, and borrowers will purposely take loans default, since they can use the loan amount to buy more collateral than they would lose during default.

### Example

🤦 Bad:
```solidity
mapping (address => uint256) public balanceOf;

function transferFrom(address _from, address _to, uint256 _value) {
   require(balanceOf[_from] >= _value);
   balanceOf[_from] -= _value;
   balanceOf[_to] += _value;
}
```

🚀 Good (using OpenZeppelin's `SafeERC20`):
```solidity
mapping (address => uint256) public balanceOf;

function transferFrom(address _from, address _to, uint256 _value) {
   require(balanceOf[_from] >= _value, "Low balance");
   require(balanceOf[_to] + _value >= balanceOf[_to], "overflow");

   balanceOf[_from] -= _value;
   balanceOf[_to] += _value;
}
```

### Background Information

https://github.com/sherlock-audit/2023-01-cooler-judging#issue-m-1-coolerroll-wouldnt-work-as-expected-when-newcollateral--0

