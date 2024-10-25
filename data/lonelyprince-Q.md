## [QA-0] RecoverySpellFactory::calculateAddress() - Inefficient duplicate owner check

### Description
`calculateAddress` function checks for duplicate owner address using an O(N^2) algorithm which can be optimised to O(NlogN).

### Reference
https://github.com/code-423n4/2024-10-kleidi/blob/ab89bcb443249e1524496b694ddb19e298dca799/src/RecoverySpellFactory.sol#L97-L103

### Recommendation
There is already a method implemented for checking duplicate addresses in `createRecoverySpell` which uses transient storage. The same can be implemented in `calculateAddress` function. The already implemented algorithm is time efficient and memory safe.

Reference: https://github.com/code-423n4/2024-10-kleidi/blob/ab89bcb443249e1524496b694ddb19e298dca799/src/RecoverySpellFactory.sol#L58-L71


## [QA-1] Timelock::_removeCalldataCheck() - Last index can be directly popped without copying

### Description
`_removeCalldataCheck` function overwrites the index to be removed with the last index data and then pops the last index from calldataChecks. But when the index to be removed is the last index then it can be directly popped.

### Reference
https://github.com/code-423n4/2024-10-kleidi/blob/ab89bcb443249e1524496b694ddb19e298dca799/src/Timelock.sol#L1218

### Recommendation
```
function _removeCalldataCheck(
        address contractAddress,
        bytes4 selector,
        uint256 index
    ) private {
        -- snipped --
        /// pop the index without swap if index is same as last index
        if(index == calldataChecks.length - 1) {
            calldataChecks.pop(); 
        }
        -- snipped -- 
}
```
