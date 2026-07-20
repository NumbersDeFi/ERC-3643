// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/// @dev Minimal account linkage/ownership surface used for Claim Issuer consent.
interface IYieldFabricAccount {
    function owners(address owner) external view returns (bool);

    function ownerCount() external view returns (uint256);

    function identityContract() external view returns (address);
}
