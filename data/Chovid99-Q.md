# Unnecessary swap at `_removeCalldataCheck`

In this [LOCs](https://github.com/code-423n4/2024-10-kleidi/blob/main/src/Timelock.sol#L1218-L1219), it is used to pop the index by swapping the removed element with the last index. However, the `if` condition in here is actually still do `swap` if the removed element is the last index. The correct `if` condition in here should be `if (calldataChecks.length - 1 != index)`, so that it will only do the swap only if the index != last element.

# Unnecessary swap at `removeCalldataCheckDatahash`

In this [LOCs](https://github.com/code-423n4/2024-10-kleidi/blob/main/src/Timelock.sol#L905-L919), it does unnecessary swap when the indexCheck is the last element.