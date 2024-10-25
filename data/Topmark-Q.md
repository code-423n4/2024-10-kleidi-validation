### Report 1:
#### Admin Role Can Not transfer or Renounce Role
The code below shows how a role owner can renounce its role in the Timelock contract, however the contract is too rigid as it can be noted that an Admin cannot Renounce its Role which is understandable since the contract cant function without the admin. However the Protocol should adjust the code to ensure that admin can transfers to a new Admin when necessary to prevent break of contract if Admin is predisposed 
https://github.com/code-423n4/2024-10-kleidi/blob/main/src/Timelock.sol#L787-L795
```solidity
    function renounceRole(bytes32 role, address account)
        public
        override(AccessControl, IAccessControl)
    {
        require(
>>>            role != DEFAULT_ADMIN_ROLE, "Timelock: cannot renounce admin role"
        );
        super.renounceRole(role, account);
    }
```
###  Report 2:
#### Dos on Expired Operation that Needs Reschedule
A look at the Timelock contract at https://github.com/code-423n4/2024-10-kleidi/blob/main/src/Timelock.sol#L674 shows that when expired cleanup is done the timestamp is not deleted which is as designed by protocol but this would be a problem for operations that needs to be rescheduled as pointer in the schedule function as provided below would revert this possibility. Protocol should delete timestamp too during cleanup
https://github.com/code-423n4/2024-10-kleidi/blob/main/src/Timelock.sol#L1001
```solidity
     function _schedule(bytes32 id, uint256 delay) private {
        /// this line is never reachable as no duplicate id's are enforced before this call is made
>>>        require(!isOperation(id), "Timelock: operation already scheduled");
        /// this line is reachable
        require(delay >= minDelay, "Timelock: insufficient delay");
        timestamps[id] = block.timestamp + delay;
    }
```