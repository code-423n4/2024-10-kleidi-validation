# InstanceDeployer.sol


## Front-running of Safe Creation

> uint256 creationSalt = uint256(
    keccak256(
        abi.encode(
            instance.owners,
            instance.threshold,
            instance.timelockParams.minDelay,
            instance.timelockParams.expirationPeriod,
            instance.timelockParams.pauser,
            instance.timelockParams.pauseDuration,
            instance.timelockParams.hotSigners
        )
    )
);

> instance.timelockParams.salt = bytes32(creationSalt);

> try SafeProxyFactory(safeProxyFactory).createProxyWithNonce(
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

   > emit SafeCreationFailed(
        msg.sender,
        block.timestamp,
        address(walletInstance.safe),
        safeInitdata,
        creationSalt
    );
}

In the catch block, the contract attempts to calculate the create2 address that would have been used by the factory and checks if a Safe already exists at that address. However, this fallback mechanism doesn't effectively stop front-running; it just detects it. This means an attacker could potentially front-run the deployment with identical parameters and block legitimate users from deploying the Safe.

## Improper Role Assignment


> require(
    walletInstance.timelock.hasRole(
        walletInstance.timelock.HOT_SIGNER_ROLE(), msg.sender
    ),
    "InstanceDeployer: sender must be hot signer"
);


The problem arises if there's a failure to properly assign the HOT_SIGNER_ROLE at the time of timelock creation or if there is an unintentional way for unauthorized users to assign this role to themselves. If an attacker gains control over the role assignment process (for example, by front-running or manipulating the inputs to timelock.initialize), they could take control of the system. There is insufficient validation of the initialization process, an attacker might manipulate this initialization

# RecoverySpell.sol


## Owner Enumeration via Recovery Signatures

>for (uint256 i = 0; i < v.length; i++) {
    address recoveredAddress = ECDSA.recover(digest, v[i], r[i], s[i]);
    bool valid;

    assembly ("memory-safe") {
        valid := tload(recoveredAddress)
        if eq(valid, 1) { tstore(recoveredAddress, 0) }
    }
    require(
        valid && recoveredAddress != address(0),
        "RecoverySpell: Invalid signature"
    );
}

This code uses a storage check (tload) to verify that the recovered addresses from the signatures are valid owners. An attacker could exploit this to brute-force or guess valid owner addresses, potentially creating an off-chain enumeration attack.

If valid addresses can be easily guessed, it would expose sensitive information about who the current owners are. This could lead to targeted phishing or social engineering attacks.

Avoid directly storing and checking owner addresses. Instead, store a hashed version of the addresses in storage and use a merkle tree to verify ownership.

## Lack of Owner Removal or Signature Reuse Check

> for (uint256 i = 0; i < v.length; i++) {
    address recoveredAddress = ECDSA.recover(digest, v[i], r[i], s[i]);
    ...
    require(
        valid && recoveredAddress != address(0),
        "RecoverySpell: Invalid signature"
    );
}

There is no explicit check that ensures owners who have been removed in the recovery process cannot sign future recovery transactions. This might allow a previously removed owner to continue participating in critical processes such as recovery.

If a previously removed owner still holds valid keys, they could participate in future recoveries despite no longer being a legitimate owner, leading to unauthorized control over the Safe.


## Race Condition on Recovery Execution

> require(
   block.timestamp > recoveryInitiated + delay,
   "RecoverySpell: Recovery not ready"
);


The contract checks whether the delay period has passed before allowing the recovery process to proceed. However, this creates a race condition where an attacker might be able to initiate their own recovery immediately after the delay, effectively hijacking the recovery process.

If multiple parties attempt to execute recovery transactions simultaneously, or if the attacker can act faster once the delay passes, they could prevent legitimate recovery attempts or execute unauthorized actions on the Safe.

No Ownership Check for executeRecovery: The function can be called by anyone once the delay expires, which allows an external attacker to execute the recovery, potentially disrupting or taking over the Safe’s control.

Potential Exploitation: If the attacker gets ahead, they could finalize the recovery in a way that benefits them, such as altering the Safe’s ownership to include themselves or bypassing the legitimate owners.


## Possibility of Replay Attacks

> bytes32 public constant RECOVERY_TYPEHASH = keccak256(
    "Recovery(address safe,uint256 newSafeThreshold,uint256 newRecoveryThreshold,uint256 delay)"
);

The contract does not handle replay protection across chains, meaning an attacker could replay the same transaction across multiple chains or even the same chain under specific conditions.

If the contract is deployed on multiple blockchains an attacker could take a valid signature from one chain and reuse it on another chain.

In this scenario, the attacker would not need to modify the signature, as the recovery process relies on the same signature verification logic on all chains. The signature could be valid across multiple chains if there is no differentiation between them.


# SystemDeploy.s.sol


##  Front-Running in TimelockFactory and RecoverySpellFactory Creation


In the deploy() function, the TimelockFactory, RecoverySpellFactory, Guard, and other contracts are deployed using the salt value defined in the contract. While this ensures deterministic deployment, an attacker could front-run the deployment process. Since the salt value is predictable (hardcoded in the contract), a malicious actor could deploy contracts with the same salt before the system does, causing the system to link to the attacker's contracts instead of the intended ones.

## Lack of Role-Based Access Control

There is no role-based access control mechanism in place for the deployment process. Anyone can call the deploy() function to re-deploy the contracts, which could allow unauthorized actors to interfere with the system.
