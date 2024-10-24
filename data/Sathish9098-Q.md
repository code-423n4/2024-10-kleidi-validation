##

## [L-] Unrestricted Guardian Transition Without Enforcing Paused State

When ``pauseStartTime`` is set to ``0`` and a ``new guardian`` address is assigned, it implies that the contract is unpaused. However, in the current implementation, the ``setGuardian`` function can be invoked regardless of the contract's paused state. This creates a discrepancy where the function can execute even when the contract is already ``unpaused``, making the pause logic ineffective. There is no state validation to ensure the contract is paused before changing the guardian, meaning the function bypasses any constraints tied to the pause mechanism. As a result, assigning a new guardian and resetting the pause timer can occur during normal operations, which undermines the intended control flow and governance consistency.

```solidity
FILE: 2024-10-kleidi/src/Timelock.sol

 /// @notice function to grant the guardian to a new address
    /// resets the pauseStartTime to 0, which unpauses the contract
    /// @param newGuardian the address of the new guardian
    function setGuardian(address newGuardian) public onlyTimelock {
        /// if a new guardian is granted, the contract is automatically unpaused
        _setPauseTime(0);

        _grantGuardian(newGuardian);
    }

```

### Recommended Mitigation
If the intention newGuardian is only changed after contract paused then impement ``whenPaused`` Modifier or check ``pauseStartTime`` is already not ``0``



## [L-] No Maximum Expiration Period Leads to Indefinite Timelocked Actions

In the current implementation, the ``_expirationPeriod`` only has a minimum limit check, with no upper bound. This allows extremely large values (even years or infinite periods) to be setresulting in:

- Timelocked actions might never expire, staying in the system indefinitely.

### POC

```solidity
FILE:2024-10-kleidi/src/Timelock.sol 

 require(
            _expirationPeriod >= MIN_DELAY,
            "Timelock: expiration period too short"
        );
        expirationPeriod = _expirationPeriod;

```
https://github.com/code-423n4/2024-10-kleidi/blob/ab89bcb443249e1524496b694ddb19e298dca799/src/Timelock.sol#L289-L292

### Recommended Mitigation
Incorporate maximum value check to avoid unintended consequences 

```solidity
require(
            _expirationPeriod >= MIN_DELAY && ,_expirationPeriod <= MAX_EXPIRATION_DELAY,
            "Timelock: expiration period too short or too long "
        );

```

##

## [L-] Risk of DoS from Large Enumerable Sets in State-Modifying Functions

The protocol uses OpenZeppelin's EnumerableSet for managing [_liveProposals](https://github.com/code-423n4/2024-10-kleidi/blob/ab89bcb443249e1524496b694ddb19e298dca799/src/Timelock.sol#L107)

### Impact

- As the sets grow larger, operations become increasingly gas-intensive.

- EnumerableSet is primarily designed for efficient membership checks, not for maintaining ordered lists

>> Also, using an Enumerable set can cause a Dos in the contract if the set grows large enough and it’s used in a function that modifies the state of the contract, this is commented in the openzeppelin documentation and it’s something to keep in mind for future iterations of the contracts

```Solidity
FILE: 2024-10-kleidi/src/Timelock.sol

/// @notice store list of all live proposals, remove from set once executed or cancelled
    EnumerableSet.Bytes32Set private _liveProposals;

```
https://github.com/code-423n4/2024-10-kleidi/blob/ab89bcb443249e1524496b694ddb19e298dca799/src/Timelock.sol#L106-L107

##

## [L-] Inconsistency between ``isOperationReady()`` and ``isOperationExpired()`` checks 

The expiration logic considers ``>=`` (inclusive), meaning the operation expires the moment the expiration timestamp is reached.

But the ready logic uses ``>`` (exclusive), meaning the operation is not ready right when it’s at the expiration timestamp.

This creates an inconsistency: At the exact expiration timestamp, the operation will not be ready but won’t be marked expired until the next block.

The inconsistence checks are  ``timestamp + expirationPeriod > block.timestamp`` and ``block.timestamp >= timestamp + expirationPeriod``


```solidity
FILE:2024-10-kleidi/src/Timelock.sol

 function isOperationReady(bytes32 id) public view returns (bool) {
        /// cache timestamp, save up to 2 extra SLOADs
        uint256 timestamp = timestamps[id];
        return timestamp > _DONE_TIMESTAMP && timestamp <= block.timestamp
            && timestamp + expirationPeriod > block.timestamp;
    }

 function isOperationExpired(bytes32 id) public view returns (bool) {
        /// if operation is done, save an extra SLOAD
        uint256 timestamp = timestamps[id];

        /// if timestamp is 0, the operation is not scheduled, revert
        require(timestamp != 0, "Timelock: operation non-existent");
        require(timestamp != 1, "Timelock: operation already executed");

        return block.timestamp >= timestamp + expirationPeriod;
    }

```
https://github.com/code-423n4/2024-10-kleidi/blob/ab89bcb443249e1524496b694ddb19e298dca799/src/Timelock.sol#L421

### Recommended Mitigation
isOperationExpired() only expire after ``timestamp + expirationPeriod`` passed instead of of expire in equal value 

##

## [L-] DoS Risk Due to Unbounded Enumerable Set Growth in ``getAllProposals()``

If the number of proposals grows indefinitely, calling this function could exceed the block gas limit, resulting in a Denial of Service (DoS).

EnumerableSet's values() function returns the entire set in a single call, which means the more proposals in the set, the higher the gas consumption.

```solidity
FILE:2024-10-kleidi/src/Timelock.sol

function getAllProposals() external view returns (bytes32[] memory) {
        return _liveProposals.values();
    }

```
https://github.com/code-423n4/2024-10-kleidi/blob/ab89bcb443249e1524496b694ddb19e298dca799/src/Timelock.sol#L360-L362

##

## [L-] Misleading Comment in ``isOperation`` Function

The comment states: "Cancelled operations will return false."
However, this function only checks if the timestamp for the given id is greater than 0. If the contract is paused (or the relevant state is modified to make it temporarily inactive), this might also cause the operation to appear invalid (returning false), even though it wasn’t necessarily cancelled.

If the contract is paused then the timestamp[id] value cleared and become 0.

```diff
FILE: 2024-10-kleidi/src/Timelock.sol

    /// @dev Returns whether an id corresponds to a registered operation. This
    /// includes Pending, Ready, Done and Expired operations.
-    /// Cancelled operations will return false.
+    /// Operations will return false if they are cancelled or if the contract is paused.
    function isOperation(bytes32 id) public view returns (bool) {
        return timestamps[id] > 0;
    }

```

##

## [L-] 








