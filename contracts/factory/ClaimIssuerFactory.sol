// SPDX-License-Identifier: MIT
/**
 * @title ClaimIssuerFactory
 * @notice Deploys one Claim Issuer per owner without granting the gas-paying
 *         relayer any key or factory authority.
 *
 * `createClaimIssuerWithAccount` requires an EIP-712 authorization from the
 * claimed owner over the exact factory-proven identity and account. A relay may
 * submit that authorization and pay gas, but cannot alter its parameters or
 * preoccupy an owner's write-once slot with an attacker-controlled identity.
 */
pragma solidity ^0.8.17;

import "@onchain-id/solidity/contracts/interface/IIdentity.sol";
import "@openzeppelin/contracts/proxy/Clones.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import "../CustomClaimIssuer.sol";
import "./IYieldFabricAccount.sol";
import "./IYieldFabricAccountFactory.sol";
import "./IYieldFabricIdentityFactory.sol";

error InvalidOwner();
error InvalidIdentityFactory();
error InvalidAccountFactory();
error CallerMustBeOwner();
error CallerMustBeAccountFactory();
error UntrustedIdentity();
error UntrustedAccount();
error IdentityOwnerMismatch();
error AccountOwnerMismatch();
error AccountMustHaveSingleOwner();
error AuthorizationExpired();
error InvalidOwnerAuthorization();
error KeySetupFailed();
error InvalidTerminalKeyState();
error AlreadyExists();
error ClaimIssuerNotFound();
error ClaimIssuerAliasConflict(address aliasAddress, address existingClaimIssuer);
error CallerMustBeClaimIssuerAccount();

contract ClaimIssuerFactory is EIP712 {
    uint256 private constant _MANAGEMENT_KEY = 1;
    uint256 private constant _CLAIM_KEY = 3;
    uint256 private constant _ECDSA_KEY = 1;

    bytes32 private constant _IDENTITY_FACTORY_CAPABILITY =
        keccak256("yieldfabric.identity-factory.atomic-account-owner.v1");
    bytes32 private constant _ACCOUNT_FACTORY_CAPABILITY =
        keccak256("yieldfabric.account-factory.parameter-bound.v1");
    bytes32 private constant _PROVENANCED_CREATION_CAPABILITY =
        keccak256("yieldfabric.claim-issuer-factory.owner-authorized-reused-identity.v7");
    bytes32 private constant _ENTITY_CREATION_CAPABILITY =
        keccak256("yieldfabric.claim-issuer-factory.entity-owner-authorized.v2");
    bytes32 private constant _CREATE_CLAIM_ISSUER_TYPEHASH = keccak256(
        "CreateClaimIssuer(address owner,address identity,address account,uint256 nonce,bytes32 salt,uint256 deadline)"
    );
    bytes32 private constant _ATTACH_IDENTITY_TYPEHASH = keccak256(
        // solhint-disable-next-line max-line-length
        "AttachClaimIssuerIdentity(address owner,address claimIssuer,address identity,address account,uint256 nonce,bytes32 salt,uint256 deadline)"
    );
    bytes32 private constant _ENTITY_AUTHORIZATION_TYPEHASH = keccak256(
        // solhint-disable-next-line max-line-length
        "EntityClaimIssuerAuthorization(uint256 operation,address identity,address account,address signer,uint256 nonce,bytes32 salt,uint256 deadline)"
    );

    IYieldFabricIdentityFactory private immutable _IDENTITY_FACTORY;
    IYieldFabricAccountFactory private immutable _ACCOUNT_FACTORY;

    /// @dev Inert library-mode CustomClaimIssuer deployed once from this
    ///      constructor; every Claim Issuer this factory creates is an EIP-1167
    ///      clone of it. This keeps the ~13 KB CustomClaimIssuer runtime out of
    ///      every per-account deployment (~2.6M gas of code deposit each) and
    ///      out of this factory's own runtime code (which previously sat within
    ///      148 bytes of the EIP-170 limit).
    address private immutable _CLAIM_ISSUER_IMPLEMENTATION;

    /// owner => Claim Issuer contract address (for resolve when issuing claims)
    mapping(address => address) private _claimIssuerByOwner;
    mapping(address => uint256) public nonces;
    mapping(address => uint256) public attachmentNonces;

    // Entity-scoped Claim Issuers intentionally use a separate namespace from
    // the personal owner mapping above. This is what permits an account owner
    // to have a personal ClaimIssuer and to authorize a distinct group/entity
    // ClaimIssuer without either registration overwriting the other.
    mapping(address => address) private _entityClaimIssuerByAlias;
    mapping(address => address) private _entityOfClaimIssuer;

    // Signature intentionally remains ClaimIssuerCreated(address,address) for
    // ABI compatibility with the existing event-based owner resolver.
    event ClaimIssuerCreated(address indexed claimIssuer, address indexed owner);
    event ClaimIssuerAccountAttached(address indexed claimIssuer, address indexed account);
    event ClaimIssuerOwnerAliasBound(
        address indexed claimIssuer,
        address indexed account,
        address indexed owner
    );

    constructor(address identityFactory_, address accountFactory_)
        EIP712("YieldFabric ClaimIssuerFactory", "1")
    {
        if (identityFactory_ == address(0) || identityFactory_.code.length == 0) {
            revert InvalidIdentityFactory();
        }
        if (accountFactory_ == address(0) || accountFactory_.code.length == 0) {
            revert InvalidAccountFactory();
        }

        try IYieldFabricIdentityFactory(identityFactory_).identityBootstrapCapability()
            returns (bytes32 capability)
        {
            if (capability != _IDENTITY_FACTORY_CAPABILITY) revert InvalidIdentityFactory();
        } catch {
            revert InvalidIdentityFactory();
        }
        try IYieldFabricAccountFactory(accountFactory_).accountDeploymentCapability()
            returns (bytes32 capability)
        {
            if (capability != _ACCOUNT_FACTORY_CAPABILITY) revert InvalidAccountFactory();
        } catch {
            revert InvalidAccountFactory();
        }

        _IDENTITY_FACTORY = IYieldFabricIdentityFactory(identityFactory_);
        _ACCOUNT_FACTORY = IYieldFabricAccountFactory(accountFactory_);

        // Library mode: the implementation records _initialized = true with
        // _canInteract = false, so it can never be initialized or interacted
        // with directly. Its immutable attachment factory is this factory.
        _CLAIM_ISSUER_IMPLEMENTATION = address(new CustomClaimIssuer(address(this), true));
    }

    /**
     * @notice Deploy a Claim Issuer without attaching an identity.
     * @dev This fallback cannot safely be relayed because there is no on-chain
     *      identity provenance to authenticate `owner_`; only the owner itself
     *      may call it.
     */
    function createClaimIssuer(address owner_) external returns (address claimIssuer) {
        _validateOwner(owner_);
        if (msg.sender != owner_) revert CallerMustBeOwner();
        return _createClaimIssuer(owner_, address(0), address(0));
    }

    /**
     * @notice Deploy a Claim Issuer and add a proven ONCHAINID as MANAGEMENT.
     * @dev The identity is accepted only when the trusted factories prove the
     *      exact linkage and the live account/identity both recognize `owner_`.
     *      The EIP-712 owner authorization binds chain, factory, account,
     *      identity, nonce, salt, and deadline. The relay only broadcasts it.
     * @param owner_ Owner key that controls and signs through the Claim Issuer.
     * @param identity Factory-proven ONCHAINID used by the ConfidentialAccount.
     * @param account Exact factory-created account linked to `identity`.
     * @param authorizationSalt Application correlation/idempotency commitment.
     * @param deadline Last timestamp at which the authorization is valid.
     * @param ownerAuthorization EOA or ERC-1271 owner signature over the typed data.
     */
    function createClaimIssuerWithAccount(
        address owner_,
        address identity,
        address account,
        bytes32 authorizationSalt,
        uint256 deadline,
        bytes calldata ownerAuthorization
    )
        external
        returns (address claimIssuer)
    {
        _validateOwner(owner_);
        _validateTrustedIdentity(owner_, identity, account);
        _consumeOwnerAuthorization(
            owner_, identity, account, authorizationSalt, deadline, ownerAuthorization
        );

        return _createClaimIssuer(owner_, identity, account);
    }

    /**
     * @notice Signatureless fresh-account bootstrap used only inside the
     *         account factory's atomic new-identity deployment transaction.
     * @dev The account factory has already parameter-bound and initialized the
     *      exact account. Personal mode requires one owner so a co-owner cannot
     *      receive personal Claim Issuer control through this no-signature path.
     *      Entity mode instead gives the stable ONCHAINID MANAGEMENT and the
     *      designated account owner CLAIM only, allowing group accounts without
     *      consuming or overwriting that owner's personal singleton. In neither
     *      mode does the transaction submitter receive a key.
     */
    function createClaimIssuerForNewAccount(
        address owner_,
        address identity,
        address account,
        bool entityScoped
    )
        external
        returns (address claimIssuer)
    {
        if (msg.sender != address(_ACCOUNT_FACTORY)) revert CallerMustBeAccountFactory();
        _validateOwner(owner_);
        _validateTrustedIdentity(owner_, identity, account);
        if (entityScoped) return _deployEntityClaimIssuer(identity, account, owner_);
        if (IYieldFabricAccount(account).ownerCount() != 1) revert AccountMustHaveSingleOwner();

        claimIssuer = _claimIssuerByOwner[owner_];
        if (claimIssuer != address(0)) {
            CustomClaimIssuer existing = CustomClaimIssuer(claimIssuer);
            if (!_hasExactPurpose(existing, _addressKey(identity), _MANAGEMENT_KEY)) {
                if (!existing.attachManagementIdentity(identity)) revert KeySetupFailed();
                emit ClaimIssuerAccountAttached(claimIssuer, identity);
            }
            _assertTerminalKeyState(
                existing,
                _addressKey(owner_),
                _addressKey(address(this)),
                identity,
                true
            );
            _bindStableAliases(claimIssuer, identity, account);
            return claimIssuer;
        }
        return _createClaimIssuer(owner_, identity, account);
    }

    /**
     * @notice Attach another factory-proven account identity to an existing
     *         Claim Issuer using an authorization signed by its owner.
     * @dev Any address may broadcast and fund the transaction. The typed
     *      authorization is verified by this factory and binds the
     *      owner, Claim Issuer, identity, account, nonce, salt, deadline, chain,
     *      and Claim Issuer address. An already-completed exact attachment is
     *      idempotent and consumes no additional nonce.
     */
    function attachIdentityToClaimIssuer(
        address owner_,
        address identity,
        address account,
        bytes32 authorizationSalt,
        uint256 deadline,
        bytes calldata ownerAuthorization
    ) external returns (address claimIssuer) {
        _validateOwner(owner_);
        claimIssuer = _claimIssuerByOwner[owner_];
        if (claimIssuer == address(0)) revert ClaimIssuerNotFound();
        _validateTrustedIdentity(owner_, identity, account);

        IIdentity claimIssuerIdentity = IIdentity(claimIssuer);
        _requireExactPurpose(claimIssuerIdentity, _addressKey(owner_), _MANAGEMENT_KEY);
        if (_hasExactPurpose(claimIssuerIdentity, _addressKey(identity), _MANAGEMENT_KEY)) {
            _bindStableAliases(claimIssuer, identity, account);
            return claimIssuer;
        }

        _consumeAttachmentAuthorization(
            owner_,
            claimIssuer,
            identity,
            account,
            authorizationSalt,
            deadline,
            ownerAuthorization
        );
        if (!CustomClaimIssuer(claimIssuer).attachManagementIdentity(identity)) revert KeySetupFailed();
        _requireExactPurpose(claimIssuerIdentity, _addressKey(identity), _MANAGEMENT_KEY);
        _bindStableAliases(claimIssuer, identity, account);

        emit ClaimIssuerAccountAttached(claimIssuer, identity);
    }

    /**
     * @notice Create a Claim Issuer whose authority belongs to a stable entity
     *         identity rather than to the EOA authorizing deployment.
     * @dev A direct account owner signs parameter-bound EIP-712 data and may
     *      use any relay to submit it. The factory-proven linked ONCHAINID receives
     *      MANAGEMENT, while `claimSigner` receives CLAIM only. Neither the
     *      authorizing owner, transaction sender, account factory, nor this
     *      factory receives authority implicitly. Personal ClaimIssuer aliases
     *      are stored separately and cannot be overwritten by this operation.
     *
     *      Exact redelivery after successful creation is a no-op. In
     *      particular, it cannot restore a claim key removed during a later key
     *      rotation and consumes no additional nonce.
     */
    // solhint-disable-next-line function-max-lines, code-complexity
    function createEntityClaimIssuer(
        address identity,
        address account,
        address claimSigner,
        bytes32 authorizationSalt,
        uint256 deadline,
        bytes calldata ownerAuthorization
    ) external returns (address claimIssuer) {
        claimIssuer = _entityClaimIssuerByAlias[identity];
        if (claimIssuer != address(0)) {
            if (_entityOfClaimIssuer[claimIssuer] != identity) revert InvalidTerminalKeyState();
            _validateStableAccountLink(identity, account);
            address existing = _entityClaimIssuerByAlias[account];
            if (existing == claimIssuer) return claimIssuer;
            if (existing != address(0)) {
                revert AlreadyExists();
            }
            _validateTrustedIdentity(claimSigner, identity, account);
            _consumeEntityAuthorization(
                2,
                identity,
                account,
                claimSigner,
                authorizationSalt,
                deadline,
                ownerAuthorization
            );
            _entityClaimIssuerByAlias[account] = claimIssuer;
            return claimIssuer;
        }

        if (claimSigner == identity) revert InvalidOwner();
        _validateTrustedIdentity(claimSigner, identity, account);
        _consumeEntityAuthorization(
            1,
            identity,
            account,
            claimSigner,
            authorizationSalt,
            deadline,
            ownerAuthorization
        );

        return _deployEntityClaimIssuer(identity, account, claimSigner);
    }

    /**
     * @notice Bind a newly installed account owner to the account's existing
     *         Claim Issuer without changing ClaimIssuer authority.
     * @dev The caller must be a factory-proven account already carrying the
     *      stable account + ONCHAINID aliases, and `owner_` must be a live
     *      account owner. The complete live control spine is checked at call
     *      time: account -> ONCHAINID, owner -> ONCHAINID, ONCHAINID -> Claim
     *      Issuer, and owner -> Claim Issuer MANAGEMENT + CLAIM. In normal use
     *      this call is one operation in a successor-owner-signed account
     *      meta-transaction. It is idempotent and never overwrites an alias
     *      belonging to another Claim Issuer.
     */
    function bindOwnerAlias(address owner_) external returns (address claimIssuer) {
        _validateOwner(owner_);
        if (!_ACCOUNT_FACTORY.isAccount(msg.sender)) revert CallerMustBeClaimIssuerAccount();

        claimIssuer = _claimIssuerByOwner[msg.sender];
        address identity = IYieldFabricAccount(msg.sender).identityContract();
        if (
            claimIssuer == address(0) ||
            identity == address(0) ||
            _claimIssuerByOwner[identity] != claimIssuer
        ) {
            revert CallerMustBeClaimIssuerAccount();
        }
        if (!IYieldFabricAccount(msg.sender).owners(owner_)) revert AccountOwnerMismatch();

        IIdentity linkedIdentity = IIdentity(identity);
        IIdentity claimIssuerIdentity = IIdentity(claimIssuer);
        _requireExactPurpose(linkedIdentity, _addressKey(msg.sender), _MANAGEMENT_KEY);
        _requireExactPurpose(linkedIdentity, _addressKey(owner_), _MANAGEMENT_KEY);
        _requireExactPurpose(claimIssuerIdentity, _addressKey(identity), _MANAGEMENT_KEY);
        _requireExactPurpose(claimIssuerIdentity, _addressKey(owner_), _MANAGEMENT_KEY);
        _requireExactPurpose(claimIssuerIdentity, _addressKey(owner_), _CLAIM_KEY);

        _bindStableAlias(owner_, claimIssuer);
        emit ClaimIssuerOwnerAliasBound(claimIssuer, msg.sender, owner_);
    }

    /// @notice Resolve only entity-scoped aliases; personal aliases are isolated.
    function getEntityClaimIssuer(address identityOrAccount) external view returns (address) {
        return _entityClaimIssuerByAlias[identityOrAccount];
    }

    /// @notice Prove the stable identity that a factory-created entity issuer belongs to.
    function getEntityOfClaimIssuer(address claimIssuer) external view returns (address) {
        return _entityOfClaimIssuer[claimIssuer];
    }

    /// @notice Return the Claim Issuer for an owner, or address(0) if absent.
    function getClaimIssuer(address owner_) external view returns (address) {
        return _claimIssuerByOwner[owner_];
    }

    function identityFactory() external view returns (address) {
        return address(_IDENTITY_FACTORY);
    }

    function accountFactory() external view returns (address) {
        return address(_ACCOUNT_FACTORY);
    }

    function claimIssuerAuthorizationDigest(
        address owner_,
        address identity,
        address account,
        uint256 nonce,
        bytes32 authorizationSalt,
        uint256 deadline
    ) external view returns (bytes32) {
        return _authorizationDigest(
            owner_, identity, account, nonce, authorizationSalt, deadline
        );
    }

    function identityAttachmentAuthorizationDigest(
        address owner_,
        address claimIssuer,
        address identity,
        address account,
        uint256 nonce,
        bytes32 authorizationSalt,
        uint256 deadline
    ) external view returns (bytes32) {
        return _attachmentAuthorizationDigest(
            owner_,
            claimIssuer,
            identity,
            account,
            nonce,
            authorizationSalt,
            deadline
        );
    }

    /// @notice Versioned runtime/deployment handshake for the safe creation path.
    function claimIssuerFactoryCapability() external pure returns (bytes32) {
        return _PROVENANCED_CREATION_CAPABILITY;
    }

    function entityClaimIssuerFactoryCapability() external pure returns (bytes32) {
        return _ENTITY_CREATION_CAPABILITY;
    }

    /// @notice Implementation contract every created Claim Issuer clone delegates to.
    function claimIssuerImplementation() external view returns (address) {
        return _CLAIM_ISSUER_IMPLEMENTATION;
    }

    /**
     * @dev Clone the inert implementation and initialize it in the same
     *      transaction. Initialization grants this factory the sole MANAGEMENT
     *      key — exactly the state the previous full `new CustomClaimIssuer`
     *      constructor produced — so the bootstrap key dance at the call sites
     *      is unchanged and `_assertTerminalKeyState` still proves the factory
     *      key was removed.
     */
    function _newClaimIssuer() internal returns (CustomClaimIssuer claimIssuer) {
        claimIssuer = CustomClaimIssuer(Clones.clone(_CLAIM_ISSUER_IMPLEMENTATION));
        claimIssuer.initialize(address(this));
    }

    function _createClaimIssuer(address owner_, address identity, address account)
        internal
        returns (address claimIssuer)
    {
        if (_claimIssuerByOwner[owner_] != address(0)) revert AlreadyExists();

        CustomClaimIssuer ci = _newClaimIssuer();
        claimIssuer = address(ci);

        bytes32 ownerKeyHash = _addressKey(owner_);
        bytes32 factoryKeyHash = _addressKey(address(this));

        _addKey(ci, ownerKeyHash, _MANAGEMENT_KEY);
        _addKey(ci, ownerKeyHash, _CLAIM_KEY);

        bool identityAttached = identity != address(0) && identity != owner_;
        if (identityAttached) {
            _addKey(ci, _addressKey(identity), _MANAGEMENT_KEY);
        }
        _removeKey(ci, factoryKeyHash, _MANAGEMENT_KEY);

        _assertTerminalKeyState(ci, ownerKeyHash, factoryKeyHash, identity, identityAttached);

        _claimIssuerByOwner[owner_] = claimIssuer;
        _bindStableAliases(claimIssuer, identity, account);
        emit ClaimIssuerCreated(claimIssuer, owner_);
        if (identityAttached) emit ClaimIssuerAccountAttached(claimIssuer, identity);
    }

    function _deployEntityClaimIssuer(address identity, address account, address claimSigner)
        internal
        returns (address claimIssuer)
    {
        // Entity aliases are write-once. The atomic path supplies unused fresh
        // addresses; the signed path must still be unable to overwrite aliases
        // already committed to a different entity ClaimIssuer.
        if (
            _entityClaimIssuerByAlias[identity] != address(0) ||
            _entityClaimIssuerByAlias[account] != address(0)
        ) revert AlreadyExists();

        claimIssuer = address(_newClaimIssuer());
        _addKey(CustomClaimIssuer(claimIssuer), _addressKey(identity), _MANAGEMENT_KEY);
        _addKey(CustomClaimIssuer(claimIssuer), _addressKey(claimSigner), _CLAIM_KEY);
        _removeKey(
            CustomClaimIssuer(claimIssuer),
            _addressKey(address(this)),
            _MANAGEMENT_KEY
        );
        _entityClaimIssuerByAlias[identity] = claimIssuer;
        _entityClaimIssuerByAlias[account] = claimIssuer;
        _entityOfClaimIssuer[claimIssuer] = identity;
    }

    /**
     * @dev Bind the account and its ONCHAINID to the same Claim Issuer as the
     *      bootstrap owner. These aliases survive EOA key rotation and let
     *      callers resolve by the stable account/identity instead of a stale
     *      historical key. Never overwrite a pre-existing, different mapping.
     */
    function _bindStableAliases(address claimIssuer, address identity, address account) internal {
        _bindStableAlias(account, claimIssuer);
        _bindStableAlias(identity, claimIssuer);
    }

    function _bindStableAlias(address aliasAddress, address claimIssuer) internal {
        if (aliasAddress == address(0)) return;
        address existing = _claimIssuerByOwner[aliasAddress];
        if (existing != address(0) && existing != claimIssuer) {
            revert ClaimIssuerAliasConflict(aliasAddress, existing);
        }
        _claimIssuerByOwner[aliasAddress] = claimIssuer;
    }

    function _addKey(CustomClaimIssuer claimIssuer, bytes32 key, uint256 purpose) internal {
        if (!claimIssuer.addKey(key, purpose, _ECDSA_KEY)) revert KeySetupFailed();
    }

    function _removeKey(CustomClaimIssuer claimIssuer, bytes32 key, uint256 purpose) internal {
        if (!claimIssuer.removeKey(key, purpose)) revert KeySetupFailed();
    }

    function _consumeOwnerAuthorization(
        address owner_,
        address identity,
        address account,
        bytes32 authorizationSalt,
        uint256 deadline,
        bytes calldata ownerAuthorization
    ) internal {
        if (block.timestamp > deadline) revert AuthorizationExpired();
        uint256 nonce = nonces[owner_];
        bytes32 digest = _authorizationDigest(
            owner_, identity, account, nonce, authorizationSalt, deadline
        );
        // SignatureChecker may call an ERC-1271 owner. Advance first to prevent
        // same-nonce reentrancy; a revert restores the nonce on invalid input.
        nonces[owner_] = nonce + 1;
        if (!SignatureChecker.isValidSignatureNow(owner_, digest, ownerAuthorization)) {
            revert InvalidOwnerAuthorization();
        }
    }

    function _consumeAttachmentAuthorization(
        address owner_,
        address claimIssuer,
        address identity,
        address account,
        bytes32 authorizationSalt,
        uint256 deadline,
        bytes calldata ownerAuthorization
    ) internal {
        if (block.timestamp > deadline) revert AuthorizationExpired();
        uint256 nonce = attachmentNonces[owner_];
        bytes32 digest = _attachmentAuthorizationDigest(
            owner_,
            claimIssuer,
            identity,
            account,
            nonce,
            authorizationSalt,
            deadline
        );
        // SignatureChecker may call an ERC-1271 owner. Advance first to prevent
        // same-nonce reentrancy; a revert restores the nonce on invalid input.
        attachmentNonces[owner_] = nonce + 1;
        if (!SignatureChecker.isValidSignatureNow(owner_, digest, ownerAuthorization)) {
            revert InvalidOwnerAuthorization();
        }
    }

    function _consumeEntityAuthorization(
        uint256 operation,
        address identity,
        address account,
        address signer,
        bytes32 authorizationSalt,
        uint256 deadline,
        bytes calldata ownerAuthorization
    ) internal {
        _validateOwner(signer);
        if (block.timestamp > deadline) revert AuthorizationExpired();
        uint256 nonce = nonces[identity];
        bytes32 digest = _entityAuthorizationDigest(
            operation,
            identity,
            account,
            signer,
            nonce,
            authorizationSalt,
            deadline
        );
        nonces[identity] = nonce + 1;
        if (!SignatureChecker.isValidSignatureNow(signer, digest, ownerAuthorization)) {
            revert InvalidOwnerAuthorization();
        }
    }

    function _validateOwner(address owner_) internal view {
        if (owner_ == address(0) || owner_ == address(this)) revert InvalidOwner();
    }

    function _validateTrustedIdentity(address owner_, address identity, address account) internal view {
        _validateStableAccountLink(identity, account);
        if (!_hasExactPurpose(IIdentity(identity), _addressKey(account), _MANAGEMENT_KEY)) {
            revert UntrustedAccount();
        }
        if (!IYieldFabricAccount(account).owners(owner_)) revert AccountOwnerMismatch();

        // When IdentityFactory has provenance, its configuration describes the
        // ORIGINAL manager account and bootstrap owner. Both are historical:
        // account ownership and identity keys may legitimately rotate. Use the
        // immutable mapping only to prove origin, and separately rely on the
        // CURRENT new-account owner, live new-account MANAGEMENT key, and EIP-712
        // authorization checked above. A zero configuration is an imported
        // ONCHAINID and uses those same live proofs.
        (address configuredAccount,) =
            _IDENTITY_FACTORY.identityConfiguration(identity);
        if (configuredAccount != address(0)) {
            if (!_ACCOUNT_FACTORY.isAccount(configuredAccount)) revert UntrustedIdentity();
            if (IYieldFabricAccount(configuredAccount).identityContract() != identity) {
                revert UntrustedIdentity();
            }
        }
    }

    function _validateStableAccountLink(address identity, address account) internal view {
        if (!_ACCOUNT_FACTORY.isAccount(account)) revert UntrustedAccount();
        if (IYieldFabricAccount(account).identityContract() != identity) revert UntrustedAccount();
    }

    function _authorizationDigest(
        address owner_,
        address identity,
        address account,
        uint256 nonce,
        bytes32 authorizationSalt,
        uint256 deadline
    ) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                _CREATE_CLAIM_ISSUER_TYPEHASH,
                owner_,
                identity,
                account,
                nonce,
                authorizationSalt,
                deadline
            )
        );
        return _hashTypedDataV4(structHash);
    }

    function _attachmentAuthorizationDigest(
        address owner_,
        address claimIssuer,
        address identity,
        address account,
        uint256 nonce,
        bytes32 authorizationSalt,
        uint256 deadline
    ) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                _ATTACH_IDENTITY_TYPEHASH,
                owner_,
                claimIssuer,
                identity,
                account,
                nonce,
                authorizationSalt,
                deadline
            )
        );
        return _hashTypedDataV4(structHash);
    }

    function _entityAuthorizationDigest(
        uint256 operation,
        address identity,
        address account,
        address signer,
        uint256 nonce,
        bytes32 authorizationSalt,
        uint256 deadline
    ) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                _ENTITY_AUTHORIZATION_TYPEHASH,
                operation,
                identity,
                account,
                signer,
                nonce,
                authorizationSalt,
                deadline
            )
        );
        return _hashTypedDataV4(structHash);
    }

    function _assertTerminalKeyState(
        CustomClaimIssuer claimIssuer,
        bytes32 ownerKeyHash,
        bytes32 factoryKeyHash,
        address identity,
        bool identityAttached
    ) internal view {
        _requireExactPurpose(claimIssuer, ownerKeyHash, _MANAGEMENT_KEY);
        _requireExactPurpose(claimIssuer, ownerKeyHash, _CLAIM_KEY);
        if (claimIssuer.keyHasPurpose(factoryKeyHash, _MANAGEMENT_KEY)) revert InvalidTerminalKeyState();
        if (identityAttached) _requireExactPurpose(claimIssuer, _addressKey(identity), _MANAGEMENT_KEY);
    }

    function _requireExactPurpose(IIdentity identity, bytes32 key, uint256 purpose) internal view {
        if (!_hasExactPurpose(identity, key, purpose)) revert InvalidTerminalKeyState();
    }

    function _hasExactPurpose(IIdentity identity, bytes32 key, uint256 purpose)
        internal
        view
        returns (bool)
    {
        uint256[] memory purposes = identity.getKeyPurposes(key);
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
