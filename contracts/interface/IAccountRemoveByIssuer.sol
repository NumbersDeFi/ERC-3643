// SPDX-License-Identifier: MIT
/**
 * @title IAccountRemoveByIssuer
 * @dev Minimal interface for an account/identity that allows the claim issuer to remove a claim.
 *      Used by CustomClaimIssuer.removeClaimFromIdentity so the issuer can remove the claim
 *      from the target's identity when revoking (without the target's action).
 */
pragma solidity ^0.8.17;

interface IAccountRemoveByIssuer {
    function removeClaimByIssuer(bytes32 _claimId) external returns (bool);
}
