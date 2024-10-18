Prepared by: [Vesko]()
Lead Auditors: 
- Veselin Vachkov

# Table of Contents
- [Table of Contents](#table-of-contents)
- [Disclaimer](#disclaimer)
- [Risk Classification](#risk-classification)
  - [Issues found](#issues-found)
  - [Findings](#findings)
  - [Medium](#medium)
  - [M-1: `abi.encodePacked()` should not be used with dynamic types when passing the result to a hash function such as `keccak256()`](#m-1-abiencodepacked-should-not-be-used-with-dynamic-types-when-passing-the-result-to-a-hash-function-such-as-keccak256)
  - [Informational](#informational)
    - [\[I-1\] Owner checks twice: once in `RecoverySpellFactory:createRecoverySpell` and once in `RecoverySpellFactory:calculateAddress`](#i-1-owner-checks-twice-once-in-recoveryspellfactorycreaterecoveryspell-and-once-in-recoveryspellfactorycalculateaddress)
    - [\[I-2\]: Unused Imports](#i-2-unused-imports)
  - [Gas](#gas)
    - [\[G-1\] State variable could be declared constant in `SystemDeploy`](#g-1-state-variable-could-be-declared-constant-in-systemdeploy)


# Disclaimer

The Veselin's team makes all effort to find as many vulnerabilities in the code in the given time period, but holds no responsibilities for the findings provided in this document. A security audit by the team is not an endorsement of the underlying business or product. The audit was time-boxed and the review of the code was solely on the security aspects of the Solidity implementation of the contracts.

# Risk Classification

|            |        | Impact |        |     |
| ---------- | ------ | ------ | ------ | --- |
|            |        | High   | Medium | Low |
|            | High   | H      | H/M    | M   |
| Likelihood | Medium | H/M    | M      | M/L |
|            | Low    | M      | M/L    | L   |

We use the [CodeHawks](https://docs.codehawks.com/hawks-auditors/how-to-evaluate-a-finding-severity) severity matrix to determine severity. See the documentation for more details.


## Issues found
|Severtity|Number of issues found|
| ------- | -------------------- |
| High    | 0                    |
| Medium  | 0                    |
| Low     | 0                    |
| Info    | 2                    |
| Gas     | 1                    |
| Total   | 4                    |

## Findings

## Informational

### [I-1] Owner checks twice: once in `RecoverySpellFactory:createRecoverySpell` and once in `RecoverySpellFactory:calculateAddress`

**Recommended Mitigation:** 
  - Consider refactoring the duplicate check into a private function to maintain DRY (Don't Repeat Yourself) principles.

### [I-2]: Unused Imports

Redundant import statement. Consider removing it.

<details><summary>6 Found Instances</summary>


- Found in src/Guard.sol [Line: 5](src/Guard.sol)

  ```solidity
  import {Safe} from "@safe/Safe.sol";
  ```

- Found in src/InstanceDeployer.sol [Line: 12](src/InstanceDeployer.sol)

  ```solidity
  import {Guard} from "src/Guard.sol";
  ```

- Found in src/InstanceDeployer.sol [Line: 15](src/InstanceDeployer.sol)

  ```solidity
  import {calculateCreate2Address, Create2Params} from "src/utils/Create2Helper.sol";
  ```

- Found in src/Timelock.sol [Line: 19](src/Timelock.sol)

  ```solidity
  import {Safe} from "@safe/Safe.sol";
  ```

- Found in src/TimelockFactory.sol [Line: 4](src/TimelockFactory.sol)

  ```solidity
  import {calculateCreate2Address} from "src/utils/Create2Helper.sol";
  ```

- Found in src/deploy/SystemDeploy.s.sol [Line: 8](src/deploy/SystemDeploy.s.sol)

  ```solidity
  import {Timelock} from "src/Timelock.sol";
  ```

</details>

## Gas

### [G-1] State variable could be declared constant in `SystemDeploy`

**Description:**
```solidity
bytes32 public salt =
        0x0000000000000000000000000000000000000000000000000000000000003afe;
```

**Recommended Mitigation:** 
  - State variables that are not updated following deployment should be declared constant to save gas.
