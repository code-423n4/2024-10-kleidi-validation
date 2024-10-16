# Gas optimization at `_addCalldataCheck`.

We can remove this [LOCs](https://github.com/code-423n4/2024-10-kleidi/blob/main/src/Timelock.sol#L1089-L1090) because `indexes` and `targetIndex` is actually has the same value with variable `callDataChecks` and `listLength` defined at this [LOCs](https://github.com/code-423n4/2024-10-kleidi/blob/main/src/Timelock.sol#L1058-L1060).
