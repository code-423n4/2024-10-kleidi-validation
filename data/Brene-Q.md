## Issue Overview
The Timelock contract is designed to receive and hold ETH, as evidenced by its [`receive()`](https://github.com/code-423n4/2024-10-kleidi/blob/ab89bcb443249e1524496b694ddb19e298dca799/src/Timelock.sol#L1330-L1343) function. However, there is no explicit mechanism to withdraw this ETH from the contract. This discrepancy between the ability to receive funds and the lack of a clear withdrawal process presents a potential issue in fund management and contract functionality.
```solidity
    function tokensReceived(
        address,
        address,
        address,
        uint256,
        bytes calldata,
        bytes calldata
    ) external pure {}


    /// @dev Timelock can receive/hold ETH, emit an event when this happens for
    /// offchain tracking
    receive() external payable {
        emit NativeTokensReceived(msg.sender, msg.value);
    }
```
The contract can receive ETH and emits an event for off-chain tracking. However, no corresponding withdrawal function is present.
Implications

1. **Locked Funds**: Without a clear withdrawal mechanism, ETH sent to this contract could potentially become locked, rendering it inaccessible.

2. **Unclear Intentions**: The ability to receive ETH without a defined process for its use or withdrawal creates ambiguity in the contract's intended functionality.

3. **Potential Misuse**: If ETH can be received but not withdrawn, it might lead to unintended accumulation of funds in the contract.

**Possible Solutions**
Leverage the existing `execute` and `executeBatch` functions for ETH withdrawals. This approach maintains consistency with the contract's current design but requires scheduling and waiting for the timelock period.