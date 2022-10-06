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
import "@openzeppelin/contracts-upgradeable/security/PullPaymentUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";

import "./VCTypes.sol";

interface IKRBToken {
    function getVCStatus(VCTypes.VerifiableCredential memory vc)
        external
        view
        returns (string memory);

    function validateSignedData(
        address signer,
        bytes32 structHash,
        bytes memory signature
    ) external view;

    function registerVC(
        VCTypes.VerifiableCredential memory vc,
        bytes memory proofValue
    ) external payable returns (bool);
}

/// @custom:security-contact contact@krebit.co
contract KrebitNFT is
    Initializable,
    ContextUpgradeable,
    AccessControlEnumerableUpgradeable,
    ERC1155Upgradeable,
    ERC1155PausableUpgradeable,
    ERC1155BurnableUpgradeable,
    ERC1155SupplyUpgradeable,
    UUPSUpgradeable,
    PullPaymentUpgradeable,
    ReentrancyGuardUpgradeable
{
    using SafeMathUpgradeable for uint256;

    bytes32 public constant GOVERN_ROLE = keccak256("GOVERN_ROLE");
    bytes32 public constant DEPOSITOR_ROLE = keccak256("DEPOSITOR_ROLE");

    /**
     * @notice Krebit KRB Contract interface
     */
    IKRBToken _KrebitContract;

    /**
     * @notice collection metadata uri "ipfs://<hash>"
     */
    string private _contractURI;

    /**
     * @notice ERC2771
     */
    address public trustedForwarder;

    /**
     * @notice set the cost to mint each NFT
     */
    uint256 public price;

    /**
     * @notice Total fees collected by the contract
     */
    uint256 public feesAvailableForWithdraw; //wei

    /**
     * @notice Forcing register to KRB contract or not
     */
    bool public forceRegister;

    /**
     * @dev For config updates
     */
    event Updated();

    mapping(uint256 => bool) public credentialMinted;

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

    modifier onlyDepositor() {
        require(
            hasRole(DEPOSITOR_ROLE, _msgSender()),
            "ChildMintableERC1155: INSUFFICIENT_PERMISSIONS"
        );
        _;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(
        string memory uri,
        string memory collectionURI,
        uint256 initialPrice,
        address krebitAddress
    ) public virtual initializer {
        __KrebitNFT_init(uri, collectionURI, initialPrice, krebitAddress);
    }

    function __KrebitNFT_init(
        string memory uri,
        string memory collectionURI,
        uint256 initialPrice,
        address krebitAddress
    ) internal onlyInitializing {
        __ERC1155_init_unchained(uri);
        __AccessControl_init_unchained();
        __Pausable_init_unchained();
        __ERC1155Burnable_init_unchained();
        __ERC1155Supply_init_unchained();
        _KrebitContract = IKRBToken(krebitAddress);
        _contractURI = collectionURI;
        price = initialPrice;
        forceRegister = true;
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

    /**
     * @notice ERC2771 Meta-Transactions support.
     */
    function isTrustedForwarder(address forwarder)
        public
        view
        virtual
        returns (bool)
    {
        return forwarder == trustedForwarder;
    }

    /**
     * @notice ERC2771 Meta-Transactions support.
     */
    function _msgSender()
        internal
        view
        virtual
        override(ContextUpgradeable)
        returns (address sender)
    {
        if (isTrustedForwarder(msg.sender)) {
            // The assembly code is more direct than the Solidity version using `abi.decode`.
            /// @solidity memory-safe-assembly
            assembly {
                sender := shr(96, calldataload(sub(calldatasize(), 20)))
            }
        } else {
            return super._msgSender();
        }
    }

    /**
     * @notice ERC2771 Meta-Transactions support.
     */
    function _msgData()
        internal
        view
        virtual
        override(ContextUpgradeable)
        returns (bytes calldata)
    {
        if (isTrustedForwarder(msg.sender)) {
            return msg.data[:msg.data.length - 20];
        } else {
            return super._msgData();
        }
    }

    function setTrustedForwarder(address newTrustedForwarder)
        public
        onlyGovern
    {
        trustedForwarder = newTrustedForwarder;

        emit Updated();
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

    function setforceRegister(bool force) public onlyGovern {
        forceRegister = force;
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

    //set the cost of an NFT
    function setPrice(uint256 newPrice) public onlyGovern {
        price = newPrice;
        emit Updated();
    }

    function getTokenId(string memory credentialSubjectType)
        public
        view
        virtual
        returns (uint256)
    {
        return uint256(keccak256(abi.encode(credentialSubjectType)));
    }

    /**
     *
     * @notice Creates 1 token for `to` based on Verifiable Credential
     *
     * See {ERC1155-_mint}.
     *
     * Requirements:
     *
     * - the caller must be the vc.credentialSubject address
     * - the vc must have been issued in the KRB contract
     */
    function mintWithCredential(
        address to,
        string memory credentialSubjectType,
        VCTypes.VerifiableCredential memory vc,
        bytes memory proofValue,
        bytes memory data
    ) public payable whenNotPaused {
        require(
            hasRole(GOVERN_ROLE, _msgSender()) ||
                vc.credentialSubject.ethereumAddress == _msgSender(),
            "KRBToken: sender must be the credentialSubject address"
        );
        require(
            vc.credentialSubject.ethereumAddress == to,
            "Mint to address must be the vc.credentialSubject address"
        );
        VCTypes.validateVC(vc);

        require(
            keccak256(abi.encode(vc.credentialSubject._type)) ==
                keccak256(abi.encode(credentialSubjectType)),
            "vc.credentialSubject._type doesn't match credentialSubjectType"
        );

        uint256 uuid = uint256(VCTypes.getVerifiableCredential(vc));
        require(!credentialMinted[uuid], "Credential already minted");

        if (
            forceRegister &&
            keccak256(abi.encode(_KrebitContract.getVCStatus(vc))) ==
            keccak256(abi.encode("None"))
        ) {
            bool registered = _KrebitContract.registerVC{
                value: vc.credentialSubject.price
            }(vc, proofValue);
            require(registered, "Credential failed to be registered");
            require(
                msg.value.sub(vc.credentialSubject.price) >= price,
                "Amount sent is less than the mint price"
            );
            feesAvailableForWithdraw = feesAvailableForWithdraw.add(
                msg.value.sub(vc.credentialSubject.price)
            );
        } else {
            _KrebitContract.validateSignedData(
                vc.issuer.ethereumAddress,
                VCTypes.getVerifiableCredential(vc),
                proofValue
            );
            require(
                msg.value >= price,
                "Amount sent is less than the mint price"
            );
            feesAvailableForWithdraw = feesAvailableForWithdraw.add(msg.value);
        }

        //Mint Credential as NFT:
        _mint(to, getTokenId(credentialSubjectType), 1, data);
        credentialMinted[uuid] = true;
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

    /**
     * @notice Withdraw fees collected by the contract.
     * Requirements:
     * - Only the DAO govern can call this.
     */
    function withdrawFees(address payable _to, uint256 _amount)
        external
        nonReentrant
        onlyGovern
    {
        require(_amount <= feesAvailableForWithdraw); /// @dev Also prevents underflow
        feesAvailableForWithdraw = feesAvailableForWithdraw.sub(_amount);
        _asyncTransfer(_to, _amount);
    }

    /**
     * @notice called when tokens are deposited on root chain
     * @dev Should be callable only by ChildChainManager
     * Should handle deposit by minting the required tokens for user
     * Make sure minting is done only by this function
     * @param user user address for whom deposit is being done
     * @param depositData abi encoded ids array and amounts array
     */
    function deposit(address user, bytes calldata depositData)
        external
        onlyDepositor
    {
        (
            uint256[] memory ids,
            uint256[] memory amounts,
            bytes memory data
        ) = abi.decode(depositData, (uint256[], uint256[], bytes));

        require(
            user != address(0),
            "ChildMintableERC1155: INVALID_DEPOSIT_USER"
        );

        _mintBatch(user, ids, amounts, data);
    }

    /**
     * @notice called when user wants to withdraw single token back to root chain
     * @dev Should burn user's tokens. This transaction will be verified when exiting on root chain
     * @param id id to withdraw
     * @param amount amount to withdraw
     */
    function withdrawSingle(uint256 id, uint256 amount) external {
        _burn(_msgSender(), id, amount);
    }

    /**
     * @notice called when user wants to batch withdraw tokens back to root chain
     * @dev Should burn user's tokens. This transaction will be verified when exiting on root chain
     * @param ids ids to withdraw
     * @param amounts amounts to withdraw
     */
    function withdrawBatch(uint256[] calldata ids, uint256[] calldata amounts)
        external
    {
        _burnBatch(_msgSender(), ids, amounts);
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
