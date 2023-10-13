# Gas Optimizations

## G001 - Don't Initialize Variables with Default Value

### Description

Uninitialized variables are assigned with the types default value.

Explicitly initializing a variable with it's default value costs unnecessary gas.

### Example

🤦 Bad:
```solidity
uint256 x = 0;
bool y = false;
```

🚀 Good:
```solidity
uint256 x;
bool y;
```

### Background Information

- [Mudit Gupta's Blog](https://mudit.blog/solidity-tips-and-tricks-to-save-gas-and-reduce-bytecode-size/)


## G002 - Cache Array Length Outside of Loop

### Description

Caching the array length outside a loop saves reading it on each iteration, as
long as the array's length is not changed during the loop.

### Example

🤦 Bad:
```solidity
for (uint256 i = 0; i < array.length; i++) {
    // invariant: array's length is not changed
}
```

🚀 Good:
```solidity
uint256 len = array.length
for (uint256 i = 0; i < len; i++) {
    // invariant: array's length is not changed
}
```

### Background Information

- [Issue submitted by WatchPug](https://github.com/code-423n4/2021-11-badgerzaps-findings/issues/36)


## G003 - Use `!= 0` instead of `> 0` for Unsigned Integer Comparison

### Description

When dealing with unsigned integer types, comparisons with `!= 0` are cheaper
than with `> 0`.

### Example

🤦 Bad:
```solidity
// `a` being of type unsigned integer
require(a > 0, "!a > 0");
```

🚀 Good:
```solidity
// `a` being of type unsigned integer
require(a != 0, "!a > 0");
```

### Background Information

TODO


## G004 - Remove Unused Variables

### Description

Removing unused variables saves gas, especially for state variables, i.e.
variables saved in storage.


## G005 - Make Variable `constant`/`immutable`

### Description

Making variables constant/immutable, if possible, saves gas as all variables
get replaced by the values assigned to them.

### Background Information

- [Solidity docs](https://docs.soliditylang.org/en/latest/contracts.html?highlight=constant#constant)
- [RariCapitals solcurity](https://github.com/Rari-Capital/solcurity#variables)


## G006 - Use `immutable` for OpenZeppelin `AccessControl`'s Roles Declarations

### Description

⚡️ Only valid for solidity versions `<0.6.12` ⚡️

Access roles marked as `constant` results in computing the `keccak256` operation
each time the variable is used because assigned operations for `constant`
variables are re-evaluated every time.

Changing the variables to `immutable` results in computing the hash only once
on deployment, leading to gas savings.

### Example

🤦 Bad:
```solidity
bytes32 public constant GOVERNOR_ROLE = keccak256("GOVERNOR_ROLE");
```

🚀 Good:
```solidity
bytes32 public immutable GOVERNOR_ROLE = keccak256("GOVERNOR_ROLE");
```

### Background Information

- [Solidity issue](https://github.com/ethereum/solidity/issues/9232)


## G007 - Long Revert Strings

### Description

Shortening revert strings to fit in 32 bytes will decrease gas costs for
deployment and gas costs when the revert condition has been met.

If the contract(s) in scope allow using Solidity `>=0.8.4`, consider using
[Custom Errors](https://blog.soliditylang.org/2021/04/21/custom-errors/) as
they are more gas efficient while allowing developers to describe the error
in detail using [NatSpec](https://docs.soliditylang.org/en/latest/natspec-format.html).

### Example

🤦 Bad:
```solidity
require(condition, "UniswapV3: The reentrancy guard. A transaction cannot re-enter the pool mid-swap");
```

🚀 Good (with shorter string):
```solidity
// TODO: Provide link to a reference of error codes
require(condition, "LOK");
```

🚀 Good (with custom errors):
```solidity
/// @notice A transaction cannot re-enter the pool mid-swap.
error NoReentrancy();

// ...

if (!condition) {
    revert NoReentrancy();
}
```

### Background Information

- [C4 Issue with a deeper explanation](https://github.com/code-423n4/2021-09-sushimiso-findings/issues/134)
- [Uniswap V3 Error Code](https://docs.uniswap.org/protocol/reference/error-codes)


## G008 - Use Shift Right/Left instead of Division/Multiplication if possible

### Description

A division/multiplication by any number `x` being a power of 2 can be
calculated by shifting `log2(x)` to the right/left.

While the `DIV` opcode uses 5 gas, the `SHR` opcode only uses 3 gas.
Furthermore, Solidity's division operation also includes a division-by-0
prevention which is bypassed using shifting.

### Example

🤦 Bad:
```solidity
uint256 b = a / 2;
uint256 c = a / 4;
uint256 d = a * 8;
```

🚀 Good:
```solidity
uint256 b = a >> 1;
uint256 c = a >> 2;
uint256 d = a << 3;
```

### Background Information

- [EVM Opcodes](https://www.evm.codes/)


## G009 - Make Function `external` instead of `public`

### Description

⚡️ Only valid for solidity versions `<0.6.9` ⚡️

The restriction that `public` functions can not take `calldata` arguments was
lifted in version `0.6.9`.

For solidity versions `<0.6.9`, `public` functions had to copy the arguments
to memory.

### Background Information

- [StackOverflow answer re `solc >=0.6.9`](https://ethereum.stackexchange.com/questions/107578/does-using-external-over-public-in-a-library-reduce-any-gas-costs/107939#107939)
- [Gustavo (Gus) Guimaraes post](https://gus-tavo-guim.medium.com/public-vs-external-functions-in-solidity-b46bcf0ba3ac)
- [StackOverflow answer](https://ethereum.stackexchange.com/questions/19380/external-vs-public-best-practices?answertab=active#tab-top)


## G010 - Make Function `payable`

### Description

⚡️ Community sentiment suggests to not accept this optimization due to security risks ⚡️

Functions marked as `payable` are slightly cheaper than non-`payable` ones,
because the Solidity compiler inserts a check into non-`payable` functions
requiring `msg.value` to be zero.

However, keep in mind that this optimization opens the door for a whole set of
security considerations involving Ether held in contracts.

### Background Information

- [Solidity Compiler Discussion](https://github.com/ethereum/solidity/issues/12539)


## G011 - Unnecessary checked arithmetic in for loop

### Description

A lot of times there is no risk that the loop counter can overflow.

Using Solidity's `unchecked` block saves the overflow checks.

### Example

🤦 Bad:
```solidity
uint len = supportedTokens.length;
for (uint i; i < len; i++) {
    // ...
}
```

🚀 Good:
```solidity
uint len = supportedTokens.length;
for (uint i; i < len; ) {
    // ...

    unchecked { i++; }
}
```

### Background Information

- [C4 Issue](https://github.com/code-423n4/2021-12-perennial-findings/issues/34)


## G012 - Use Prefix Increment instead of Postfix Increment if possible

### Description

The difference between the prefix increment and postfix increment expression
lies in the return value of the expression.

The prefix increment expression (`++i`) returns the _updated_ value after it's
incremented. The postfix increment expression (`i++`) returns the _original_
value.

The prefix increment expression is cheaper in terms of gas.

Consider using the prefix increment expression whenever the return value is
not needed.

_Note_ to be careful using this optimization whenever the expression's return
value is used afterwards, e.g. `uint a = i++` and `uint a = ++i` result in
different values for `a`.

### Example

🤦 Bad:
```solidity
for (uint i; i < len; i++) {
    if (i % 2 == 0) {
        counter++;
    }
    // ...
}
```

🚀 Good:
```solidity
for (uint i; i < len; ++i) {
    if (i % 2 == 0) {
        ++counter;
    }
    // ...
}
```

### Background information

- [Miguel's "Gas Optimizations for the Rest of Us" article](https://m1guelpf.blog/d0gBiaUn48Odg8G2rhs3xLIjaL8MfrWReFkjg8TmDoM)


### Impact of Gas Optimizations

| Optimization | Gas Savings |
|---|---|
| **G001 - Don't Initialize Variables with Default Value** | 1-3 gas per variable |
| **G002 - Cache Array Length Outside of Loop** | 1-2 gas per loop iteration |
| **G003 - Use != 0 instead of > 0 for Unsigned Integer Comparison** | 1-2 gas per comparison |
| **G004 - Remove Unused Variables** | 1-2 gas per variable |
| **G005 - Make Variable constant/immutable** | 1-2 gas per variable |
| **G006 - Use immutable for OpenZeppelin AccessControl's Roles Declarations** | 1-2 gas per role declaration |
| **G007 - Shorten Revert Strings to Fit in 32 Bytes** | 1-2 gas per revert |
| **G008 - Use Shift Right/Left instead of Division/Multiplication if possible** | 1-2 gas per operation |
| **G009 - Make Function external instead of public** | 1-2 gas per function call |
| **G010 - Make Function payable** | 1-2 gas per function call |
| **G011 - Unnecessary checked arithmetic in for loop** | 1-2 gas per loop iteration |
| **G012 - Use Prefix Increment instead of Postfix Increment if possible** | 1 gas per loop iteration |