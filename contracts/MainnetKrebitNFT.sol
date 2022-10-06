// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlEnumerableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC1155/ERC1155Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC1155/extensions/ERC1155PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC1155/extensions/ERC1155BurnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC1155/extensions/ERC1155SupplyUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/math/SafeMathUpgradeable.sol";

/// @custom:security-contact contact@krebit.co
contract MainnetKrebitNFT is
    Initializable,
    ContextUpgradeable,
    AccessControlEnumerableUpgradeable,
    ERC1155Upgradeable,
    ERC1155PausableUpgradeable,
    ERC1155BurnableUpgradeable,
    ERC1155SupplyUpgradeable,
    UUPSUpgradeable
{
    using SafeMathUpgradeable for uint256;

    bytes32 public constant GOVERN_ROLE = keccak256("GOVERN_ROLE");
    bytes32 public constant PREDICATE_ROLE = keccak256("PREDICATE_ROLE");

    /**
     * @notice collection metadata uri "ipfs://<hash>"
     */
    string private _contractURI;

    /**
     * @dev Throws if the sender is not the Govern.
     */
    function _checkGovern() internal view virtual {
        require(
            hasRole(GOVERN_ROLE, _msgSender()),
            "KrebitNFT: must have govern role"
        );
    }

    /**
     * @dev Throws if called by any account other than the owner.
     */
    modifier onlyGovern() {
        _checkGovern();
        _;
    }

    modifier onlyPredicate() {
        require(
            hasRole(PREDICATE_ROLE, _msgSender()),
            "DummyMintableERC1155: INSUFFICIENT_PERMISSIONS"
        );
        _;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(string memory uri, string memory collectionURI)
        public
        virtual
        initializer
    {
        __KrebitNFT_init(uri, collectionURI);
    }

    function __KrebitNFT_init(string memory uri, string memory collectionURI)
        internal
        onlyInitializing
    {
        __ERC1155_init_unchained(uri);
        __AccessControl_init_unchained();
        __Pausable_init_unchained();
        __ERC1155Burnable_init_unchained();
        __ERC1155Supply_init_unchained();
        _contractURI = collectionURI;
        __KrebitNFT_init_unchained();
    }

    function __KrebitNFT_init_unchained() internal onlyInitializing {
        _setupRole(DEFAULT_ADMIN_ROLE, _msgSender());
        _setupRole(GOVERN_ROLE, _msgSender());
    }

    /**
     * @notice Function that should revert when `msg.sender` is not authorized to upgrade the contract. Called by
     * {upgradeTo} and {upgradeToAndCall}.
     *
     * See {UUPSUpgradeable-_authorizeUpgrade}.
     *
     * Requirements:
     *
     * - the caller must have the `GOVERN_ROLE`.
     */
    function _authorizeUpgrade(address) internal view override {
        _checkGovern();
    }

    function setURI(string memory newuri) public onlyGovern {
        _setURI(newuri);
    }

    function contractURI() public view returns (string memory) {
        return _contractURI;
    }

    function setContractURI(string memory newuri) public onlyGovern {
        _contractURI = newuri;
    }

    /**
     * @notice Pauses all token transfers.
     *
     * See {ERC1155Pausable} and {Pausable-_pause}.
     *
     * Requirements:
     *
     * - the caller must have the `GOVERN_ROLE`.
     */
    function pause() public virtual onlyGovern {
        _pause();
    }

    /**
     * @notice Unpauses all token transfers.
     *
     * See {ERC1155Pausable} and {Pausable-_unpause}.
     *
     * Requirements:
     *
     * - the caller must have the `GOVERN_ROLE`.
     */
    function unpause() public virtual onlyGovern {
        _unpause();
    }

    function getTokenId(string memory credentialSubjectType)
        public
        view
        virtual
        returns (uint256)
    {
        return uint256(keccak256(abi.encode(credentialSubjectType)));
    }

    function balanceOfCredential(
        address account,
        string memory credentialSubjectType
    ) public view virtual returns (uint256) {
        require(
            account != address(0),
            "ERC1155: address zero is not a valid owner"
        );

        return balanceOf(account, getTokenId(credentialSubjectType));
    }

    function _beforeTokenTransfer(
        address operator,
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    )
        internal
        override(
            ERC1155PausableUpgradeable,
            ERC1155Upgradeable,
            ERC1155SupplyUpgradeable
        )
        whenNotPaused
    {
        super._beforeTokenTransfer(operator, from, to, ids, amounts, data);
        require(
            hasRole(GOVERN_ROLE, _msgSender()) ||
                from == address(0) ||
                to == address(0),
            "KrebitNFT: Transfers not supported"
        );
    }

    function mint(
        address account,
        uint256 id,
        uint256 amount,
        bytes calldata data
    ) external onlyPredicate {
        _mint(account, id, amount, data);
    }

    function mintBatch(
        address to,
        uint256[] calldata ids,
        uint256[] calldata amounts,
        bytes calldata data
    ) external onlyPredicate {
        _mintBatch(to, ids, amounts, data);
    }

    // The following functions are overrides required by Solidity.

    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(ERC1155Upgradeable, AccessControlEnumerableUpgradeable)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }

    uint256[50] private __gap;
}
