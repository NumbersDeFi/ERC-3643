// SPDX-License-Identifier: MIT
/**
 * @title CustomClaimIssuer
 * @dev Extends ONCHAINID ClaimIssuer with removeClaimFromIdentity and clearRevokedSignature.
 *      removeClaimFromIdentity: issuer can remove a revoked claim from the target's identity (issuer has full control).
 *      clearRevokedSignature: clear a previously revoked signature so the same claim can be re-issued (use before re-issue after revoke).
 */
pragma solidity ^0.8.17;

import "@onchain-id/solidity/contracts/ClaimIssuer.sol";
import "./interface/IAccountRemoveByIssuer.sol";

contract CustomClaimIssuer is ClaimIssuer {

    event ClaimUnrevoked(bytes signature);

    // solhint-disable-next-line no-empty-blocks
    constructor(address initialManagementKey) ClaimIssuer(initialManagementKey) {}

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
}
