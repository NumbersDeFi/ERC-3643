// SPDX-License-Identifier: MIT
/**
 * @title ClaimIssuerFactory
 * @dev Deploys one Claim Issuer per owner. Owner is set as management key and CLAIM key (can sign claims).
 *      Each user can issue their own claims; token issuers add trusted Claim Issuer addresses to their TIR.
 *
 *      Access control: createClaimIssuer / createClaimIssuerWithAccount are restricted to the factory
 *      owner() and to addresses on the _deployers allow-list. The expected runtime caller is a
 *      relay worker (added via addDeployer at deploy time); see scripts/deploy_clean.ts. This mirrors
 *      the deployer-allow-list pattern used by TREXGateway in this same package.
 *
 *      Write-once: _claimIssuerByOwner is not overwritten — subsequent calls for the same owner
 *      revert with AlreadyExists. This prevents capability-stripping replays where an attacker
 *      front-runs / overwrites a legitimate entry.
 */
pragma solidity ^0.8.17;

import "@onchain-id/solidity/contracts/ClaimIssuer.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "../CustomClaimIssuer.sol";

contract ClaimIssuerFactory is Ownable {
    error InvalidOwner();
    error FailedToDeploy();
    error KeySetupFailed();
    error NotDeployer();
    error AlreadyExists();

    /// owner => Claim Issuer contract address (for resolve when issuing claims)
    mapping(address => address) private _claimIssuerByOwner;

    /// authorized callers of createClaimIssuer / createClaimIssuerWithAccount (in addition to owner())
    mapping(address => bool) private _deployers;

    // Signature kept at 2 args (ClaimIssuerCreated(address,address)) for ABI compatibility with the
    // existing Rust log scanner at yieldfabric-vault::contracts::claim_issuer_factory::get_owner_of_claim_issuer.
    // The `account` argument (when distinct from `owner`) is exposed via the separate event below.
    event ClaimIssuerCreated(address indexed claimIssuer, address indexed owner);
    event ClaimIssuerAccountAttached(address indexed claimIssuer, address indexed account);
    event DeployerAdded(address indexed deployer);
    event DeployerRemoved(address indexed deployer);

    modifier onlyDeployer() {
        if (msg.sender != owner() && !_deployers[msg.sender]) revert NotDeployer();
        _;
    }

    /// @dev Authorize `deployer` to call createClaimIssuer / createClaimIssuerWithAccount.
    ///      Typical use: the deploy script adds the relay worker address(es) immediately after deploying
    ///      the factory, so the worker can create Claim Issuers during user onboarding.
    function addDeployer(address deployer) external onlyOwner {
        _deployers[deployer] = true;
        emit DeployerAdded(deployer);
    }

    function removeDeployer(address deployer) external onlyOwner {
        _deployers[deployer] = false;
        emit DeployerRemoved(deployer);
    }

    function isDeployer(address a) external view returns (bool) {
        return _deployers[a];
    }

    /**
     * @dev Deploy a new Claim Issuer for the given owner.
     *      The owner becomes management key (can add/remove keys, revoke claims) and CLAIM key (can sign claims).
     * @param owner_ Address that will own and control the Claim Issuer (e.g. account first owner).
     * @return claimIssuer Address of the new Claim Issuer.
     */
    function createClaimIssuer(address owner_) external onlyDeployer returns (address claimIssuer) {
        return _createClaimIssuerInternal(owner_, address(0));
    }

    /**
     * @dev Deploy a Claim Issuer for the given owner and also add the identity as MANAGEMENT key.
     *      Same as createClaimIssuer but additionally adds the identity so revoke via
     *      account.execute(ClaimIssuer, 0, revokeClaimBySignature(sig)) works (Account.execute
     *      delegates to the identity, so msg.sender at the Claim Issuer is the identity).
     * @param owner_ EOA that owns the Claim Issuer (signs claims via getClaimIssuer(owner)).
     * @param account Identity (ONCHAINID) contract address; added as MANAGEMENT so revoke via account works.
     * @return claimIssuer Address of the new Claim Issuer.
     */
    function createClaimIssuerWithAccount(address owner_, address account)
        external
        onlyDeployer
        returns (address claimIssuer)
    {
        return _createClaimIssuerInternal(owner_, account);
    }

    function _createClaimIssuerInternal(address owner_, address account) internal returns (address claimIssuer) {
        if (owner_ == address(0)) revert InvalidOwner();
        // Write-once: refuse to overwrite an existing registration. Off-chain code should call
        // getClaimIssuer(owner_) first and reuse the existing CI rather than redeploying.
        if (_claimIssuerByOwner[owner_] != address(0)) revert AlreadyExists();

        CustomClaimIssuer ci = new CustomClaimIssuer(address(this));
        claimIssuer = address(ci);
        _claimIssuerByOwner[owner_] = claimIssuer;

        bytes32 ownerKeyHash = keccak256(abi.encode(owner_));
        bytes32 factoryKeyHash = keccak256(abi.encode(address(this)));

        // Add owner: MANAGEMENT first, then CLAIM (same key, two purposes). Order avoids edge cases in some ONCHAINID versions.
        if (!ci.addKey(ownerKeyHash, 1, 1)) revert KeySetupFailed();
        if (!ci.addKey(ownerKeyHash, 3, 1)) revert KeySetupFailed();
        // Add account as MANAGEMENT only when distinct from owner (otherwise addKey(ownerKeyHash, 1, 1) would conflict).
        bool accountAttached = false;
        if (account != address(0) && account != owner_) {
            bytes32 accountKeyHash = keccak256(abi.encode(account));
            if (!ci.addKey(accountKeyHash, 1, 1)) revert KeySetupFailed();
            accountAttached = true;
        }
        if (!ci.removeKey(factoryKeyHash, 1)) revert KeySetupFailed();

        emit ClaimIssuerCreated(claimIssuer, owner_);
        if (accountAttached) emit ClaimIssuerAccountAttached(claimIssuer, account);
        return claimIssuer;
    }

    /**
     * @dev Return the Claim Issuer contract address for an owner, or address(0) if none.
     */
    function getClaimIssuer(address owner_) external view returns (address) {
        return _claimIssuerByOwner[owner_];
    }
}
