# Redundant LOCs at `_addCalldataCheck`.

We can remove this [LOCs](https://github.com/code-423n4/2024-10-kleidi/blob/main/src/Timelock.sol#L1089-L1090) because `indexes` and `targetIndex` is actually has the same value with variable `callDataChecks` and `listLength` defined at this [LOCs](https://github.com/code-423n4/2024-10-kleidi/blob/main/src/Timelock.sol#L1058-L1060).

# Redundant removal at `_removeCalldataCheck`.

At this [LOCs](https://github.com/code-423n4/2024-10-kleidi/blob/main/src/Timelock.sol#L1218-L1219), if we remove the last element, it still do the `swap` because of incorrect `if` condition. The correct `if` condition should be `if (calldataChecks.length - 1 != index`, so that we don't do `swap` during removal of last element.
