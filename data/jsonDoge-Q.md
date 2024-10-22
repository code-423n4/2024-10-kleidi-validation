## Summary

The user can incur dramatic gas costs (or even impossible to complete) if he has too many calldata checks on the last array and deletes the first element.

## Vulnerability details

During `removeCalldataCheck` if there is more than one existing calldata checks it enters a loop where the last check dataHashes are copied into the removed check place. This is done so later a .pop() could be called.

Problem is that if the last element (last check) contains multiple dataHashes and the first check has 1 element, this move starts incurring quite the gas cost.

Using anvil and forge an example of 10 datahashes added to the last element incurred ~500k gas. And if it had more each dataHash addition would another 50k of gas. Since the 

## Impact

User may not be able to remove the check due to gas cost. But it is still possible to workaround this issue by manually removing the hashes from the last check and then calling the removal - quite annoying though since they will have to be re-added later.

## Tools Used

Manual review + foundry script

## POC

The Timelock has been modified to remove modifiers preventing direct calls. The script below prints out:
```
== Logs ==
  ---Adding first 4-5 byte check
  124199
  ---Adding second 9-13 bytes checks
  103809
  59471
  59962
  60453
  60945
  61436
  61927
  62418
  62910
  63401
  ---Removing first check
  496454 // <- cost of removing the first check
```

```
pragma solidity 0.8.25;

import "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import "forge-std/Test.sol";

import {Timelock} from "src/Timelock.sol";

contract GasTest is Script, Test {
    Timelock public timelock;

    function run() public {
        deploy();

        console.logString("---Adding first 4-5 byte check");

        add(4, 5, abi.encodePacked(bytes1(0x00)));

        bytes memory randomBytes = new bytes(4);
        randomBytes = abi.encodePacked(
            bytes1(0x00),
            bytes3(0x000000)
        );

        console.logString("---Adding second 9-13 bytes checks");
        add(9, 13, randomBytes);
        randomBytes[0] = bytes1(uint8(randomBytes[0]) + 1);

        add(9, 13, randomBytes);
        randomBytes[0] = bytes1(uint8(randomBytes[0]) + 1);

        add(9, 13, randomBytes);
        randomBytes[0] = bytes1(uint8(randomBytes[0]) + 1);

        add(9, 13, randomBytes);
        randomBytes[0] = bytes1(uint8(randomBytes[0]) + 1);

        add(9, 13, randomBytes);
        randomBytes[0] = bytes1(uint8(randomBytes[0]) + 1);

        add(9, 13, randomBytes);
        randomBytes[0] = bytes1(uint8(randomBytes[0]) + 1);

        add(9, 13, randomBytes);
        randomBytes[0] = bytes1(uint8(randomBytes[0]) + 1);

        add(9, 13, randomBytes);
        randomBytes[0] = bytes1(uint8(randomBytes[0]) + 1);

        add(9, 13, randomBytes);
        randomBytes[0] = bytes1(uint8(randomBytes[0]) + 1);

        add(9, 13, randomBytes);
        randomBytes[0] = bytes1(uint8(randomBytes[0]) + 1);

        console.logString("---Removing first check");

        removeCalldataCheck();
    }

    function deploy() public {
        vm.startBroadcast();
        timelock = new Timelock(
            address(0x0),
            1 days,
            1 days,
            address(0x0),
            1 days,
            new address[](0)
        );
        vm.stopBroadcast();
    }

    function add(
        uint16 startIndex,
        uint16 endIndex,
        bytes memory calldataMatch
    ) public {
        vm.startBroadcast();

        address[] memory targetAddresses = new address[](1);
        targetAddresses[0] = address(0x1);

        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = bytes4(0x42424242);

        /// compare first 20 bytes
        uint16[] memory startIndexes = new uint16[](1);
        startIndexes[0] = startIndex;

        uint16[] memory endIndexes = new uint16[](1);
        endIndexes[0] = endIndex;

        uint256 numberOfMatches = 1;

        bytes[][] memory checkedCalldatas = new bytes[][](1);
        checkedCalldatas[0] = new bytes[](numberOfMatches);

        checkedCalldatas[0][0] = calldataMatch;

        uint gas = gasleft();
        timelock.addCalldataChecks(
            targetAddresses,
            selectors,
            startIndexes,
            endIndexes,
            checkedCalldatas
        );
        console.logUint(gas - gasleft());

        vm.stopBroadcast();
    }

    function removeCalldataCheck() public {
        vm.startBroadcast();

        uint gas = gasleft();

        timelock.removeCalldataCheck(address(0x1), bytes4(0x42424242), 0);
        console.logUint(gas - gasleft());
        vm.stopBroadcast();
    }
}
```

## Recommendations

Consider optimizing the removal process to avoid iteration and copying of unlimited values. Or add a limit to how many checks can be done on a single portion of bytes.