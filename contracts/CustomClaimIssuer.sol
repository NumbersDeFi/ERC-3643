// SPDX-License-Identifier: MIT
/**
 * @title CustomClaimIssuer
 * @dev Extends ONCHAINID ClaimIssuer with removeClaimFromIdentity, clearRevokedSignature,
 *      and factory-authorized attachment of another proven account identity.
 *      removeClaimFromIdentity: issuer can remove a revoked claim from the target's identity (issuer has full control).
 *      clearRevokedSignature: clear a previously revoked signature so the same claim can be
 *      re-issued (use before re-issue after revoke).
 */
pragma solidity ^0.8.17;

import "@onchain-id/solidity/contracts/ClaimIssuer.sol";
import "./interface/IAccountRemoveByIssuer.sol";

error CallerMustBeAttachmentFactory();
error InvalidAttachmentIdentity();
error AttachmentKeySetupFailed();

contract CustomClaimIssuer is ClaimIssuer {
    uint256 private constant _MANAGEMENT_KEY = 1;
    uint256 private constant _ECDSA_KEY = 1;

    /// @dev The factory is a coordinator only. It is removed as a MANAGEMENT
    ///      key after construction, but its immutable code remains the sole
    ///      caller allowed to submit a provenance- and signature-checked attachment.
    address private immutable _ATTACHMENT_FACTORY;

    event ClaimUnrevoked(bytes signature);
    event ManagementIdentityAttached(address indexed identity);

    constructor(address initialManagementKey) ClaimIssuer(initialManagementKey) {
        _ATTACHMENT_FACTORY = initialManagementKey;
    }

    /**
     * @notice Add another legitimate account identity as a MANAGEMENT key.
     * @dev The immutable attachment factory validates IdentityFactory and
     *      AccountFactory provenance and consumes the owner EIP-712 authorization
     *      before calling. Repeating an already-completed exact attachment is a
     *      safe no-op.
     */
    function attachManagementIdentity(address identity) external delegatedOnly returns (bool) {
        if (msg.sender != _ATTACHMENT_FACTORY) revert CallerMustBeAttachmentFactory();
        if (identity == address(0) || identity == address(this)) revert InvalidAttachmentIdentity();

        bytes32 identityKey = _addressKey(identity);
        if (_hasExactPurpose(identityKey, _MANAGEMENT_KEY)) return true;

        // Identity.onlyManager explicitly permits an internal self-call. Using
        // the inherited addKey path preserves ERC-734 storage and KeyAdded events.
        if (!this.addKey(identityKey, _MANAGEMENT_KEY, _ECDSA_KEY)) {
            revert AttachmentKeySetupFailed();
        }
        if (!_hasExactPurpose(identityKey, _MANAGEMENT_KEY)) revert AttachmentKeySetupFailed();

        emit ManagementIdentityAttached(identity);
        return true;
    }

    /**
     * @dev Remove a claim from the target account's identity. Only the claim issuer (this contract)
     *      can remove; the target's account restricts removeClaimByIssuer to msg.sender == claim.issuer.
     *      Callable only by MANAGEMENT key (e.g. issuer's account via execute(ClaimIssuer, 0, removeClaimFromIdentity(...))).
     *      Use after revokeClaimBySignature so the target becomes unverified immediately without the target clicking "Remove".
     */
    function removeClaimFromIdentity(address targetAccount, bytes32 claimId) external delegatedOnly onlyManager {
        IAccountRemoveByIssuer(targetAccount).removeClaimByIssuer(claimId);
    }

    /**
     * @dev Clear a previously revoked signature so the same claim can be re-issued.
     *      Only MANAGEMENT key can call (e.g. issuer's account via execute(ClaimIssuer, 0, clearRevokedSignature(sig))).
     *      Use before re-issuing after revoke: clears revokedClaims[sig], then issuer signs same (identity, topic, data),
     *      target adds the claim, and isClaimValid passes.
     */
    function clearRevokedSignature(bytes calldata signature) external delegatedOnly onlyManager {
        revokedClaims[signature] = false;
        emit ClaimUnrevoked(signature);
    }

    function _hasExactPurpose(bytes32 key, uint256 purpose) internal view returns (bool) {
        uint256[] memory purposes = this.getKeyPurposes(key);
        for (uint256 i = 0; i < purposes.length; ) {
            if (purposes[i] == purpose) return true;
            unchecked {
                ++i;
            }
        }
        return false;
    }

    function _addressKey(address key) internal pure returns (bytes32) {
        return keccak256(abi.encode(key));
    }
}
