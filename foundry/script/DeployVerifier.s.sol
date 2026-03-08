// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script} from "forge-std/Script.sol";
import {Halo2Verifier} from "../src/Verifier.sol";

contract DeployVerifier is Script {
    Halo2Verifier public verifier;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        verifier = new Halo2Verifier();

        vm.stopBroadcast();
    }
}
