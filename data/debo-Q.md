# L1 - Title: Reliance on block.timestamp for Control Flow

### Risk Rating: Low

### Issue Type: Timing

### Affected lines of code: https://github.com/code-423n4/2024-10-kleidi/blob/ab89bcb443249e1524496b694ddb19e298dca799/src/RecoverySpell.sol#L180-L183

### Vulnerable Code
```Solidity
// https://github.com/code-423n4/2024-10-kleidi/blob/ab89bcb443249e1524496b694ddb19e298dca799/src/RecoverySpell.sol#L180-L183

        require(
            block.timestamp > recoveryInitiated + delay,
            "RecoverySpell: Recovery not ready"
        );
```

### Description

The RecoverySpell smart contract utilizes block.timestamp to manage the initiation and execution of the recovery process. 

Specifically, the contract sets the recoveryInitiated state variable to the current block timestamp during deployment. 

And later uses it to enforce a delay before allowing the execution of the recovery. 

The relevant code snippets are:
```Solidity
// Constructor sets the initiation time
recoveryInitiated = block.timestamp;

// In executeRecovery function
require(
    block.timestamp > recoveryInitiated + delay,
    "RecoverySpell: Recovery not ready"
);
```

### Impact

Using block.timestamp for controlling critical contract functions introduces potential vulnerabilities.

Due to the inherent unpredictability and manipulability of block timestamps in Ethereum:

#### Miner Manipulation 

Miners have the ability to slightly adjust the block.timestamp within a permissible range. 

This can lead to scenarios where the recovery process is executed earlier or later than intended, potentially bypassing intended delays.

#### Inaccurate Time Representation

The reliance on block.timestamp assumes a level of precision that isn’t guaranteed. 

Network latency and block propagation times can result in discrepancies, making time-dependent logic unreliable.

#### Security Risks

If the recovery mechanism is a critical security feature, manipulating the timing could allow malicious actors to execute recovery actions at inopportune moments, undermining the contract’s security guarantees.

## Recommendation

To mitigate the risks associated with using block.timestamp for control flow, consider the following recommendation:

#### Use Decentralized Oracles for Time Verification

Integrate a trusted oracle service (e.g., Chainlink) to provide reliable and tamper-resistant time data.

This approach ensures that time-dependent operations are based on verifiable external data, reducing reliance on potentially manipulable on-chain timestamps.

## Reference
```Solidity
https://solodit.cyfrin.io/issues/m-06-blocktimestamp-or-deadline-code4rena-amun-amun-contest-git
```