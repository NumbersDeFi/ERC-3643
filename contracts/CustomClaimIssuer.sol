// SPDX-License-Identifier: MIT
/**
 * @title CustomClaimIssuer
 * @dev ONCHAINID ClaimIssuer semantics on a proxy-ready Identity base, extended
 *      with removeClaimFromIdentity, clearRevokedSignature, and factory-authorized
 *      attachment of another proven account identity.
 *      removeClaimFromIdentity: issuer can remove a revoked claim from the target's identity (issuer has full control).
 *      clearRevokedSignature: clear a previously revoked signature so the same claim can be
 *      re-issued (use before re-issue after revoke).
 *
 *      Inherits Identity DIRECTLY instead of the vendored ClaimIssuer because
 *      ClaimIssuer's constructor pins `Identity(initialManagementKey, false)`,
 *      which cannot produce the inert library-mode implementation the EIP-1167
 *      clone pattern requires. The claim-revocation logic below is a verbatim
 *      copy of @onchain-id/solidity/contracts/ClaimIssuer.sol (v2.2.1); keep it
 *      in lockstep if that dependency is ever upgraded.
 */
pragma solidity ^0.8.17;

import "@onchain-id/solidity/contracts/Identity.sol";
import "@onchain-id/solidity/contracts/interface/IClaimIssuer.sol";
import "./interface/IAccountRemoveByIssuer.sol";

error CallerMustBeAttachmentFactory();
error InvalidAttachmentIdentity();
error AttachmentKeySetupFailed();

contract CustomClaimIssuer is IClaimIssuer, Identity {
    uint256 private constant _MANAGEMENT_KEY = 1;
    uint256 private constant _ECDSA_KEY = 1;

    mapping(bytes => bool) public revokedClaims;

    /// @dev The factory is a coordinator only. It is removed as a MANAGEMENT
    ///      key after bootstrap, but its immutable code remains the sole
    ///      caller allowed to submit a provenance- and signature-checked attachment.
    ///      Immutables live in the implementation's CODE, so every EIP-1167
    ///      clone shares this value — by construction the ClaimIssuerFactory
    ///      that deployed the implementation from its own constructor.
    address private immutable _ATTACHMENT_FACTORY;

    event ClaimUnrevoked(bytes signature);
    event ManagementIdentityAttached(address indexed identity);

    /**
     * @param initialManagementKey MANAGEMENT key for a direct (non-proxy)
     *        deployment; also recorded as the immutable attachment factory.
     * @param _isLibrary true deploys the inert clone implementation: never
     *        initialized, `delegatedOnly` calls forbidden. Clones start with
     *        zeroed storage and MUST call `initialize` (inherited from
     *        Identity) in the same transaction that creates them.
     */
    constructor(address initialManagementKey, bool _isLibrary)
        Identity(initialManagementKey, _isLibrary)
    {
        _ATTACHMENT_FACTORY = initialManagementKey;
    }

    // ─────────────────────────────────────────────────────────────────────
    // Verbatim ClaimIssuer body (@onchain-id/solidity v2.2.1)
    // ─────────────────────────────────────────────────────────────────────

    /**
     *  @dev See {IClaimIssuer-revokeClaimBySignature}.
     */
    function revokeClaimBySignature(bytes calldata signature) external override delegatedOnly onlyManager {
        require(!revokedClaims[signature], "Conflict: Claim already revoked");

        revokedClaims[signature] = true;

        emit ClaimRevoked(signature);
    }

    /**
     *  @dev See {IClaimIssuer-revokeClaim}.
     */
    function revokeClaim(bytes32 _claimId, address _identity) external override delegatedOnly onlyManager returns(bool) {
        uint256 foundClaimTopic;
        uint256 scheme;
        address issuer;
        bytes memory sig;
        bytes memory data;

        ( foundClaimTopic, scheme, issuer, sig, data, ) = Identity(_identity).getClaim(_claimId);

        require(!revokedClaims[sig], "Conflict: Claim already revoked");

        revokedClaims[sig] = true;
        emit ClaimRevoked(sig);
        return true;
    }

    /**
     *  @dev See {IClaimIssuer-isClaimValid}.
     */
    function isClaimValid(
        IIdentity _identity,
        uint256 claimTopic,
        bytes memory sig,
        bytes memory data)
    public override(Identity, IClaimIssuer) view returns (bool claimValid)
    {
        bytes32 dataHash = keccak256(abi.encode(_identity, claimTopic, data));
        // Use abi.encodePacked to concatenate the message prefix and the message to sign.
        bytes32 prefixedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", dataHash));

        // Recover address of data signer
        address recovered = getRecoveredAddress(sig, prefixedHash);

        // Take hash of recovered address
        bytes32 hashedAddr = keccak256(abi.encode(recovered));

        // Does the trusted identifier have they key which signed the user's claim?
        //  && (isClaimRevoked(_claimId) == false)
        if (keyHasPurpose(hashedAddr, 3) && (isClaimRevoked(sig) == false)) {
            return true;
        }

        return false;
    }

    /**
     *  @dev See {IClaimIssuer-isClaimRevoked}.
     */
    function isClaimRevoked(bytes memory _sig) public override view returns (bool) {
        if (revokedClaims[_sig]) {
            return true;
        }

        return false;
    }

    // ─────────────────────────────────────────────────────────────────────
    // YieldFabric extensions
    // ─────────────────────────────────────────────────────────────────────

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
