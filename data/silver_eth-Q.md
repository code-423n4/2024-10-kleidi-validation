[L1] 
Whitelisting upgradeable protocols might invalidate calldata checks 
Assuming the function selector remains the same, this allows hot signers to grief the cold signers 
assuming the current implementation of a protocol uses a following implementation
```
function deposit(address assetIn,address assetOut,uint amount)
```
and there is a check to ensure assetOut is always weth 
then there is an upgrade where the protocol decides that the only acceptable assetOut is usdc, but instead of changing the selector, the assetOut is replaced with onBehalf
```
function deposit(address assetIn,address onBehalf,uint amount)
```
this would cause all reward tokens to be sent to the weth address 

There might also be cases where the function params are the same but the way they are used in the code is different 
```
function deposit(address assetIn,address assetOut,uint amount)
```
 remains the same 
perhaps the whitelisted protocol only up only a percent of amount before but now allows itself to use up the entire amount
 
[I1] Unnecessary code lenght check in instanceDeployer
https://github.com/code-423n4/2024-10-kleidi/blob/ab89bcb443249e1524496b694ddb19e298dca799/src/InstanceDeployer.sol#L247-L248

When data is sent via a high level call to an address without data eg an eoa or the zero address, the transaction reverts 

https://github.com/code-423n4/2024-10-kleidi/blob/ab89bcb443249e1524496b694ddb19e298dca799/src/InstanceDeployer.sol#L218-L229

here a call is made to ensure the factory is the safeOwner and to initialize the timelock, as both calls are high level, there is certainty that there is code at the addresses 
