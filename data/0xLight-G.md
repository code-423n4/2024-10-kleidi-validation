## The modifire that used only once can put into the function to save gas

### Impacted function

`https://github.com/code-423n4/2024-10-kleidi/blob/ab89bcb443249e1524496b694ddb19e298dca799/src/ConfigurablePause.sol#L59`

`https://github.com/code-423n4/2024-10-kleidi/blob/ab89bcb443249e1524496b694ddb19e298dca799/src/ConfigurablePause.sol#L78`

### The way to change

Delete this modifire,add the logic into the function

```
function pause() public virtual {
require(!paused(), "Pausable: paused");
//
.....  omit other code ......
//
}
```