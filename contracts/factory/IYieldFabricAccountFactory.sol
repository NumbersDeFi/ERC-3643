// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/// @dev Minimal provenance interface implemented by YieldFabric's account factory.
interface IYieldFabricAccountFactory {
    function accountDeploymentCapability() external view returns (bytes32);

    function isAccount(address account) external view returns (bool);
}
