// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.17;

import "./IdentityRegistry.sol";

/**
 * @title ExemptIdentityRegistry
 * @dev IdentityRegistry implementation that treats exactly two immutable
 *      protocol-infrastructure contracts as verified. Every other address uses
 *      the full ERC-3643 claim-validation and revocation path in the parent.
 */
contract ExemptIdentityRegistry is IdentityRegistry {
    address public immutable systemVault;
    address public immutable systemSwap;

    /// @notice The immutable exemption cannot be repaired in proxy storage, so
    ///         reject every cheaply detectable deployment error up front.
    error InvalidSystemExemption();

    constructor(address _systemVault, address _systemSwap) {
        if (
            _systemVault == address(0) ||
            _systemSwap == address(0) ||
            _systemVault == _systemSwap ||
            _systemVault.code.length == 0 ||
            _systemSwap.code.length == 0
        ) revert InvalidSystemExemption();

        systemVault = _systemVault;
        systemSwap = _systemSwap;
    }

    function isVerified(address _userAddress) public view override returns (bool) {
        if (_userAddress == systemVault || _userAddress == systemSwap) {
            return true;
        }
        return super.isVerified(_userAddress);
    }
}
