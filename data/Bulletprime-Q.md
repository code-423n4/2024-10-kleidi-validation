|  | issues | instance |
|---|---|---|
|[L-01] | Unsed Returns from Function call | 1 |
|[L-02] | Increasing length of array in a loop | 2 | 
|[L-03] | Unsafe Downcast | 1 |
| [L-04]| No Access Control on Payable Fallback| 1 |


Details 

|[L-01] | Unsed Returns from Function call : The function `cancel` Calls a function without checking the return value, the return value should be captured by the caller so as to avoid inadvertent logical errors in protocol execution. In most situations, failures to properly check function return values leads to contract exploits and possible loss of funds.

Impact: Unintended contract behaiviour, contract exploit.

```solidity
File: ./src/Timelock.sol
 function cancel(bytes32 id) external onlySafe whenNotPaused {
        require(
            isOperation(id) && _liveProposals.remove(id),
```

Tool Used 
Manual Review

Recommendation: Always handle the return values of function calls that provide them, including functions that return multiple values.





Details

|[L-02] |Increasing length of array in a loop: The function 'getCalldataChecks' is designed to retrieve and return data, `indexes` The function then iterates over each `Index` structure in indexes, Using an array inwhich the length grow as a loop variable.

Impact: Can lead to DOS and potential gas griefing if `indexes.length` elements is too large.

```solidity
File: ./src/Timelock.sol
  for (uint256 i = 0; i < indexes.length; i++) { @audit 
            indexDatas[i] = IndexData(
                indexes[i].startIndex,
                indexes[i].endIndex,
                indexes[i].dataHashes.values()
            );
        }
    }
```
```solidity
File: ./src/Timelock.sol
for (uint256 i = 0; i < indexes.length; i++) { @audit
                if (
                    indexes[i].startIndex == startIndex
                        && indexes[i].endIndex == endIndex
                ) {
                    targetIndex = i;
                    found = true;
                    break;
                }
```
Tool Used 
Manual Review
(Additional intance in automated findings)




Details

|[L-03] | Unsafe Downcast ;  a narrowing type cast from a higher to a lower bit can inadvertently truncate bits and cause the value after the cast to not be equivalent to that before the cast. The narrowing downcast can result in silent overflow due to bit truncation.

Impact : Logical Errors during execution.

```solidity
File: ./src/create2Helper.sol
 uint160(
            uint256(
                 keccak256(
                    abi.encodePacked(
                        bytes1(0xff),
                       creator,
                        salt,
                        keccak256(
                            abi.encodePacked(creationCode, constructorParams)
                        )
```
``` solidity
File: ./src/create2Helper.sol
                        bytes1(0xff),
                        params.creator,
                        params.salt,
                        keccak256(
                            abi.encodePacked(
                                params.creationCode, params.constructorParams
                            )
```
Tool Used 
Manual Review

Recommendation: Avoid performing narrowing downcasts if possible, or check values before casting.





Details 

| [L-04]| No Access Control on Payable Fallback : The `receive()` function used by the Timelock contract to accept ether does not control access in any way, meaning that any users who are not registered can be able to call this function externally and send ether to the contract. Using a payable fallback, including receive with no access control may lead to inadvertently locked funds. if the contract is intended to be used in a context where only certain addresses should be able to send Ether, then the lack of access control could cause uintended behaviours, otherwise it should be clearly stated in the documentations or comments.

Impact :Sending ether with no withdrawal mechanism, potentially locking it permanently unless the contract also implemented some emergency recovery mechanism.

```solidity
File: ./src/Timelock.sol
receive() external payable {
        emit NativeTokensReceived(msg.sender, msg.value);
    }
}
```

