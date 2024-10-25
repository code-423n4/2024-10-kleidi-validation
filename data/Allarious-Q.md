


- Can be more efficient in [BytesHelper::sliceBytes](https://github.com/code-423n4/2024-10-kleidi/blob/ab89bcb443249e1524496b694ddb19e298dca799/src/BytesHelper.sol#L35-L58)
replace
```solidity
        uint256 length = end - start;
        bytes memory sliced = new bytes(length);

        for (uint256 i = 0; i < length; i++) {
            sliced[i] = toSlice[i + start];
        }
```
With the simpler loop that begins at index start
```solidity
        bytes memory sliced = new bytes(length);

        for (uint256 i = start; i < end; i++) {
            sliced[i] = toSlice[i + start];
        }
```

- The [`_afterCall`](https://github.com/code-423n4/2024-10-kleidi/blob/ab89bcb443249e1524496b694ddb19e298dca799/src/BytesHelper.sol#L1010-L1016) function can put a minimum cap on the expiration period. While this is intended as `expirationPeriod` is compared against `MIN_DELAY` in the `updateExpirationPeriod` function and the constructor, makes updating the `expirationPeriod` harder since the transaction would fail if `block.timestamp - timestamp[id] < new expirationPeriod`

- The process of [removing a `calldataCheck` entry](https://github.com/code-423n4/2024-10-kleidi/blob/ab89bcb443249e1524496b694ddb19e298dca799/src/BytesHelper.sol#L905-L917) in `removeCalldataCheckDatahash` and `_removeCalldataCheck` can become more efficient by skipping the replacement in case `index == length - 1`.

- Line 1090 in Timelock is redundant, and can just use previously stored `calldataChecks` instead.
- Consider clearly mentioning that the initial setup of the protocol can be front-run by the hotsigners and assets should be sent to the timelock only after validation all the parameters are correctly set. Hotsigners can potentially front-run and set the `contractAddresses`, and their calldata checks as they desire.
- `ScheduleBatch` and `schedule` can make the same transaction with all the parameters including `salt`, while this is not possible via only `schedule`
- Setting a new pause guardian via a recovery spell can help the system have a guardian at all times. In the current situation, after the pause and recovery of a wallet, previous guardian is deleted.