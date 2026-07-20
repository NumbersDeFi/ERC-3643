// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/// @dev Minimal provenance interface implemented by YieldFabric's atomic IdentityFactory.
interface IYieldFabricIdentityFactory {
    function identityBootstrapCapability() external view returns (bytes32);

    function identityConfiguration(address identity)
        external
        view
        returns (address account, address ownerKey);
}
