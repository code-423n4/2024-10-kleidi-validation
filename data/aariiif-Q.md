## L-01 - Re-Pausing When Already Paused
`pause()` function allows the pause guardian to pause the contract multiple times, even when it is already paused. This can lead to unexpected behavior and potentially disrupt the normal operation of the Timelock contract.

The `pause()` function does not check the current pause state before executing the pause logic. It unconditionally calls `super.pause()`, which pauses the contract regardless of its current state.

https://github.com/code-423n4/2024-10-kleidi/blob/ab89bcb443249e1524496b694ddb19e298dca799/src/Timelock.sol#L687-L700
```solidity
// <@Issue: Does not check if contract is already paused before executing pause logic
function pause() public override {
    /// check that msg.sender is the pause guardian, pause the contract
    super.pause();

    bytes32[] memory proposals = _liveProposals.values();
    for (uint256 i = 0; i < proposals.length; i++) {
        bytes32 id = proposals[i];

        delete timestamps[id];
        assert(_liveProposals.remove(id));

        emit Cancelled(id);
    }
}
```

## Remediation
```diff
function pause() public override {
+   require(!paused(), "Timelock: already paused");
    /// check that msg.sender is the pause guardian, pause the contract
    super.pause();

    bytes32[] memory proposals = _liveProposals.values();
    for (uint256 i = 0; i < proposals.length; i++) {
        bytes32 id = proposals[i];

        delete timestamps[id];
        assert(_liveProposals.remove(id));

        emit Cancelled(id);
    }
}
```