1. There are some problems with the annotation, [it is -1 instead of =1](https://github.com/code-423n4/2024-10-kleidi/blob/ab89bcb443249e1524496b694ddb19e298dca799/src/RecoverySpell.sol#L249-L250).
2. The [document](https://code4rena.com/audits/2024-10-kleidi) says that the delay should be between 1-30 days, but it is not. It is just that minDelay is between 1-30 days. The actual delay [may be greater than 30 days](https://github.com/code-423n4/2024-10-kleidi/blob/ab89bcb443249e1524496b694ddb19e298dca799/src/Timelock.sol#L536).