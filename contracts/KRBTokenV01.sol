/// SPDX-License-Identifier: MIT
/// @title KRB Token Protocol v 0.1 - http://krebit.id
/// @author Krebit Inc. <contact@krebit.co>

pragma solidity ^0.8.0;

/// @dev OpenZeppelin Upgradeable Contracts v4.4.1
import "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20BurnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/draft-EIP712Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlEnumerableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/ECDSAUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/math/SafeMathUpgradeable.sol";

import "./VCTypesV01.sol";

/**
 * @notice {ERC20} token with OpenZeppelin Extensions:
 *
 * - Initializable,
 * - ContextUpgradeable,
 * - UUPSUpgradeable
 * - AccessControlEnumerableUpgradeable,
 * - ERC20BurnableUpgradeable,
 * - ERC20PausableUpgradeable,
 * - EIP712Upgradeable,
 *
 * This contract uses {AccessControlEnumerable} to lock permissioned functions using the
 * different roles:
 *
 * The account that deploys the contract will be granted the govern role,
 * as well as the default admin role, which will let it grant govern roles
 * to other accounts.
 */
contract KRBTokenV01 is
    Initializable,
    ContextUpgradeable,
    AccessControlEnumerableUpgradeable,
    ERC20BurnableUpgradeable,
    ERC20PausableUpgradeable,
    EIP712Upgradeable,
    UUPSUpgradeable
{
    using SafeMathUpgradeable for uint256;

    bytes32 public constant GOVERN_ROLE = keccak256("GOVERN_ROLE");

    /**
     * @notice Min Balance to Transfer
     */
    uint256 public minBalanceToTransfer;
    /**
     * @notice  Min Balance to Receive
     */
    uint256 public minBalanceToReceive;
    /**
     * @notice Min Balance to Issue Verifiable Credentials
     */
    uint256 public minBalanceToIssue;
    /**
     * @notice  Min Value to Issue Verifiable Credentials
     */
    uint256 public minPriceToIssue;
    /**
     * @notice  Min Stake to Issue Verifiable Credentials
     */
    uint256 public minStakeToIssue;
    /**
     * @notice  Max Stake to Issue Verifiable Credentials
     */
    uint256 public maxStakeToIssue;
    /**
     * @notice  Fee to Issue Verifiable Credentials
     */
    uint256 public feePercentage;
    /**
     * @notice Total fees collected by the contract
     */
    uint256 public feesAvailableForWithdraw; //wei

    /**
     * @dev For config updates
     */
    event Updated(string change);

    //// @dev https://www.w3.org/TR/vc-data-model/#status
    enum Status {
        None,
        Issued,
        Disputed,
        Revoked,
        Suspended,
        Expired
    }
    struct VerifiableData {
        Status credentialStatus;
        bytes32 disputedBy;
    }

    /// @dev Mapping of rewarded VCTypesV01.VerifiableCredentials. Key is a hash of the vc data
    mapping(bytes32 => VerifiableData) public registry;

    /**
     * @dev The stakes for each Issuer.
     */
    mapping(address => uint256) internal stakes;

    event Issued(bytes32 uuid, VCTypesV01.VerifiableCredential vc);
    event Disputed(bytes32 uuid, bytes32 disputedBy);
    event Revoked(bytes32 uuid, string reason);
    event Suspended(bytes32 uuid, string reason);
    event Expired(bytes32 uuid);
    event Deleted(bytes32 uuid, string reason);

    event Staked(address indexed from, address indexed to, uint256 value);

    function initialize() public virtual initializer {
        __KRBTokenV01_init("Krebit", "KRB");
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() initializer {}

    /**
     * @notice Initializes the contract.
     *
     * See {ERC20-constructor}.
     */
    function __KRBTokenV01_init(string memory name, string memory symbol)
        internal
        onlyInitializing
    {
        __Context_init_unchained();
        __ERC165_init_unchained();
        __AccessControl_init_unchained();
        __AccessControlEnumerable_init_unchained();
        __ERC20_init_unchained(name, symbol);
        __ERC20Burnable_init_unchained();
        __Pausable_init_unchained();
        __ERC20Pausable_init_unchained();
        __EIP712_init_unchained(name, "0.1"); //version
        __KRBTokenV01_init_unchained(name, symbol);
    }

    /**
    
    * @notice Grants `DEFAULT_ADMIN_ROLE`, `GOVERN_ROLE` and `PAUSER_ROLE` to the
     * account that deploys the contract.
     *
     * - minBalanceToTransfer : 100 KRB
     * - minBalanceToReceive : 100 KRB
     * - feePercentage : 10 %
     * - minBalanceToIssue : 100 KRB
     * - minPriceToIssue : 0.0001 ETH
     * - minStakeToIssue : 1 KRB
     * - maxStakeToIssue : 10 KRB
     */

    function __KRBTokenV01_init_unchained(
        string memory name,
        string memory symbol
    ) internal onlyInitializing {
        _setupRole(DEFAULT_ADMIN_ROLE, _msgSender());
        _setupRole(GOVERN_ROLE, _msgSender());

        minBalanceToTransfer = 100 * 10**decimals(); /// @dev 100 KRB
        minBalanceToReceive = 100 * 10**decimals(); /// @dev 100 KRB

        feePercentage = 10; /// @dev 10 %

        minBalanceToIssue = 100 * 10**decimals(); /// @dev 100 KRB

        minPriceToIssue = 100 * 10**12; /// @dev wei = 0.0001 ETH

        minStakeToIssue = 1 * 10**decimals(); /// @dev 1 KRB
        maxStakeToIssue = 10 * 10**decimals(); /// @dev 10 KRB
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
        require(
            hasRole(GOVERN_ROLE, _msgSender()),
            "KRBToken: must have govern role to upgrade"
        );
    }

    /**
     * @notice Updates `minBalanceToTransfer` to `newMinBalance`.
     * @param newMinBalance The new min baance to Transfer.
     *
     * - emits Updated("minBalanceToTransfer")
     *
     * Requirements:
     *
     * - the caller must have the `GOVERN_ROLE`.
     */
    function updateMinBalanceToTransfer(uint256 newMinBalance) public {
        require(
            hasRole(GOVERN_ROLE, _msgSender()),
            "KRBToken: must have govern role to change minBalance"
        );
        minBalanceToTransfer = newMinBalance;
        emit Updated("minBalanceToTransfer");
    }

    /**
     * @notice Updates `minBalanceToReceive` to `newMinBalance`.
     * @param newMinBalance The new min baance to Receive.
     *
     * - emits Updated("minBalanceToReceive")
     *
     * Requirements:
     *
     * - the caller must have the `GOVERN_ROLE`.
     */
    function updateMinBalanceToReceive(uint256 newMinBalance) public {
        require(
            hasRole(GOVERN_ROLE, _msgSender()),
            "KRBToken: must have govern role to change minBalance"
        );
        minBalanceToReceive = newMinBalance;
        emit Updated("minBalanceToReceive");
    }

    /**
     * @dev Checks min balances before Issue / Mint / Transfer.
     *
     * Requirements:
     *
     * - the caller must have the `GOVERN_ROLE`.
     */
    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 amount
    ) internal virtual override(ERC20Upgradeable, ERC20PausableUpgradeable) {
        super._beforeTokenTransfer(from, to, amount);
        //Check minimum balance
        require(
            hasRole(GOVERN_ROLE, _msgSender()) ||
                from == address(0) ||
                to == address(0) ||
                balanceOf(from) >= minBalanceToTransfer,
            "KRBToken: sender does not have enough balance"
        );
        require(
            hasRole(GOVERN_ROLE, _msgSender()) ||
                from == address(0) ||
                to == address(0) ||
                balanceOf(to) >= minBalanceToReceive,
            "KRBToken: recipient does not have enough balance"
        );
    }

    /**
     *
     * @notice Creates `amount` new tokens for `to`.
     *
     * See {ERC20-_mint}.
     *
     * Requirements:
     *
     * - the caller must have the `GOVERN_ROLE`.
     */
    function mint(address to, uint256 amount) public virtual {
        require(
            hasRole(GOVERN_ROLE, _msgSender()),
            "KRBToken: must have govern role to mint"
        );
        _mint(to, amount);
    }

    /**
     * @notice Destroys `_stake` token stake from `issuer`
     * @param issuer The issuer address
     * @param stake The KRB stake to burn
     *
     * - emits Updated("minBalanceToReceive")
     *
     * Requirements:
     * - the caller must have the `GOVERN_ROLE`.
     */
    function burnStake(address issuer, uint256 stake) public virtual {
        require(
            hasRole(GOVERN_ROLE, _msgSender()),
            "KRBToken: must have govern role to burn"
        );
        require(
            issuer != address(0),
            "KRBToken: burn stake from the zero address"
        );

        //remove Issuer stake
        if (stakes[issuer] >= stake) {
            stakes[issuer] = stakes[issuer].sub(stake);
            emit Staked(issuer, address(0), stake);
        }
    }

    /**
     * @notice Pauses all token transfers.
     *
     * See {ERC20Pausable} and {Pausable-_pause}.
     *
     * Requirements:
     *
     * - the caller must have the `PAUSER_ROLE`.
     */
    function pause() public virtual {
        require(
            hasRole(GOVERN_ROLE, _msgSender()),
            "KRBToken: must have govern role to pause"
        );
        _pause();
    }

    /**
     * @notice Unpauses all token transfers.
     *
     * See {ERC20Pausable} and {Pausable-_unpause}.
     *
     * Requirements:
     *
     * - the caller must have the `PAUSER_ROLE`.
     */
    function unpause() public virtual {
        require(
            hasRole(GOVERN_ROLE, _msgSender()),
            "KRBToken: must have govern role to unpause"
        );
        _unpause();
    }

    /**
     * @notice A method to retrieve the stake for an issuer.
     * @param issuer The issuer to retrieve the stake for.
     * @return stake The amount of KRB staked.
     */
    function stakeOf(address issuer) public view returns (uint256) {
        return stakes[issuer];
    }

    /**
     * @notice Returns the domain separator for the current chain.
     *
     * See {IERC20Permit-DOMAIN_SEPARATOR}.
     */
    /// @dev solhint-disable-next-line func-name-mixedcase
    function DOMAIN_SEPARATOR() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    /**
     * @dev Checks if the provided address signed a hashed message (`hash`) with
     * `signature`.
     *
     * See  {EIP-712} and {ERC-3009}.
     *
     */
    function validateSignedData(
        address signer,
        bytes32 structHash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal view {
        bytes32 digest = _hashTypedDataV4(structHash);
        address recoveredAddress = ecrecover(digest, v, r, s);

        /// @dev Explicitly disallow authorizations for address(0) as ecrecover returns address(0) on malformed messages
        require(
            recoveredAddress != address(0),
            "KRBToken: invalid signature address(0)"
        );
        require(
            recoveredAddress == signer,
            "KRBToken: recovered address differs from expected signer"
        );
    }

    /**
     * @dev Checks if the provided address signed a hashed message (`hash`) with
     * `signature`.
     *
     * See  {EIP-712} and {EIP-3009}.
     *
     */
    function validateSignedData(
        address signer,
        bytes32 structHash,
        bytes memory signature
    ) internal view {
        bytes32 digest = _hashTypedDataV4(structHash);

        address recoveredAddress = ECDSAUpgradeable.recover(digest, signature);

        /// @dev Explicitly disallow authorizations for address(0) as ecrecover returns address(0) on malformed messages
        require(
            recoveredAddress != address(0),
            "KRBToken: invalid signature address(0)"
        );
        require(
            recoveredAddress == signer,
            "KRBToken: recovered address differs from expected signer"
        );
    }

    /**
     * @notice Updates `feePercentage` to `newFeePercentage`.
     * @param newFeePercentage new protocol fee percentage (0 -100)
     *
     * - emits Updated("feePercentage");
     *
     * Requirements:
     *
     * - the caller must have the `GOVERN_ROLE`.
     */
    function updateFeePercentage(uint256 newFeePercentage) public {
        require(
            hasRole(GOVERN_ROLE, _msgSender()),
            "KRBToken: must have govern role to change feePercentage"
        );
        require(
            newFeePercentage >= 0 || newFeePercentage <= 100,
            "KRBToken: bad percentage value"
        );
        feePercentage = newFeePercentage;
        emit Updated("feePercentage");
    }

    /**
     * @notice Updates `minBalanceToIssue` to `newMinBalance`.
     * @param newMinBalance New min Balance to Issue
     *
     * - emits Updated("minBalanceToIssue")
     *
     * Requirements:
     *
     * - the caller must have the `GOVERN_ROLE`.
     */
    function updateMinBalanceToIssue(uint256 newMinBalance) public {
        require(
            hasRole(GOVERN_ROLE, _msgSender()),
            "KRBToken: must have govern role to change minBalance"
        );
        minBalanceToIssue = newMinBalance;
        emit Updated("minBalanceToIssue");
    }

    /**
     * @notice Updates `minPriceToIssue` to `newMinPrice`.
     * @param newMinPrice New min price to Issue
     *
     * - emits Updated("minPriceToIssue")
     *
     * Requirements:
     *
     * - the caller must have the `GOVERN_ROLE`.
     */
    function updateMinPriceToIssue(uint256 newMinPrice) public {
        require(
            hasRole(GOVERN_ROLE, _msgSender()),
            "KRBToken: must have govern role to change minPriceToIssue"
        );
        minPriceToIssue = newMinPrice;
        emit Updated("minPriceToIssue");
    }

    /**
     * @notice Updates `minStakeToIssue` and `maxStakeToIssue`.
     * @param newMinStake new min stake to issue
     * @param newMinStake new max stake to issue
     *
     * - emits Updated("minStakeToIssue")
     * - emits Updated("maxStakeToIssue")
     *
     * Requirements:
     *
     * - the caller must have the `GOVERN_ROLE`.
     * - newMaxStake > newMinStake
     */
    function updateStakeToIssue(uint256 newMinStake, uint256 newMaxStake)
        public
    {
        require(
            hasRole(GOVERN_ROLE, _msgSender()),
            "KRBToken: must have govern role to change minStake"
        );
        require(
            newMaxStake > newMinStake,
            "KRBToken: newMaxStake must be greater or equal than newMinStake"
        );
        minStakeToIssue = newMinStake;
        emit Updated("minStakeToIssue");
        maxStakeToIssue = newMaxStake;
        emit Updated("maxStakeToIssue");
    }

    /**
     * @dev Validates that the `VerifiableCredential` conforms to the Krebit Protocol.

     *
     */
    function _validateVC(VCTypesV01.VerifiableCredential memory vc)
        internal
        view
    {
        require(
            vc.issuer.ethereumAddress != address(0),
            "KRBToken: bad issuer address"
        );
        require(
            vc.credentialSubject.ethereumAddress != address(0),
            "KRBToken: bad credentialSubject address"
        );
        require(
            vc.credentialSubject.trust >= 0 ||
                vc.credentialSubject.trust <= 100,
            "KRBToken: bad trust percentage value"
        );
        require(
            keccak256(abi.encodePacked(vc.issuer.id)) !=
                keccak256(abi.encodePacked(vc.credentialSubject.id)),
            "KRBToken: issuer DID is the same as credentialSubject"
        );
        require(
            vc.issuer.ethereumAddress != vc.credentialSubject.ethereumAddress,
            "KRBToken: issuer address is the same as credentialSubject"
        );
        require(
            balanceOf(vc.issuer.ethereumAddress) >= minBalanceToIssue,
            "KRBToken: issuer does not have enough balance"
        );
        require(
            block.timestamp > vc.credentialSubject.nbf,
            "KRBToken: VC issuanceDate is in the future"
        );
        require(
            block.timestamp < vc.credentialSubject.exp,
            "KRBToken: VC has already expired"
        );
    }

    /**
     * @dev Calculates the KRB reward as defined by tht Krebit Protocol
     * Formula:  Krebit = Risk * Trust %

     *
     */
    function _getReward(uint256 _stake, uint256 _trust)
        internal
        pure
        returns (uint256)
    {
        //Formula:  Krebit = Risk * Trust %
        return
            SafeMathUpgradeable.div(
                SafeMathUpgradeable.mul(_stake, _trust),
                100
            );
    }

    /**
     * @dev Calculates the ETH fee as percentage of price
     * Formula:  fee = price * feePercentage %

     *
     */
    function _getFee(uint256 _price) internal view returns (uint256) {
        return
            SafeMathUpgradeable.div(
                SafeMathUpgradeable.mul(_price, feePercentage),
                100
            );
    }

    /**
     * @notice Validates that the `VerifiableCredential` conforms to the VCTypes.
     @param vc Verifiable Credential

     *
     */
    function getUuid(VCTypesV01.VerifiableCredential memory vc)
        public
        pure
        returns (bytes32)
    {
        return VCTypesV01.getVerifiableCredential(vc);
    }

    /**
     * @notice Get the status of a Verifiable Credential
     * @param uuid The verifiable Credential uuid
     *
     * @return status Verifiable credential Status: None, Issued, Disputed, Revoked, Suspended, Expired
     *
     */
    function getVCStatusByUUid(bytes32 uuid)
        public
        view
        returns (string memory)
    {
        Status temp = registry[uuid].credentialStatus;
        if (temp == Status.None) return "None";
        if (temp == Status.Issued) return "Issued";
        if (temp == Status.Disputed) return "Disputed";
        if (temp == Status.Revoked) return "Revoked";
        if (temp == Status.Suspended) return "Suspended";
        if (temp == Status.Expired) return "Expired";
        return "Error";
    }

    /**
     * @notice Get the status of a Verifiable Credential
     * @param vc The verifiable Credential
     *
     * @return status Verifiable credential Status: None, Issued, Disputed, Revoked, Suspended, Expired
     *
     */
    function getVCStatus(VCTypesV01.VerifiableCredential memory vc)
        public
        view
        returns (string memory)
    {
        bytes32 uuid = getUuid(vc);
        return getVCStatusByUUid(uuid);
    }

    function _issueVC(bytes32 uuid, VCTypesV01.VerifiableCredential memory vc)
        internal
        returns (bool)
    {
        require(
            registry[uuid].credentialStatus == Status.None,
            "KRBToken: Verifiable Credential hash already been issued"
        );
        _validateVC(vc);

        uint256 _stake = vc.credentialSubject.stake * 10**decimals();
        require(
            _stake >= minStakeToIssue && _stake <= maxStakeToIssue,
            "KRBToken: stake must be between minStakeToIssue and maxStakeToIssue"
        );
        /// @dev Create the stake for the issuer
        _burn(vc.issuer.ethereumAddress, _stake);
        stakes[vc.issuer.ethereumAddress] = stakes[vc.issuer.ethereumAddress]
            .add(_stake);
        emit Staked(vc.issuer.ethereumAddress, address(0), _stake);
        registry[uuid] = VerifiableData(Status.Issued, 0x0);
        emit Issued(uuid, vc);

        //Mint rewards
        uint256 _reward = _getReward(_stake, vc.credentialSubject.trust);
        _mint(vc.credentialSubject.ethereumAddress, _reward);
        _mint(vc.issuer.ethereumAddress, _reward);

        //distribute fees
        uint256 _fee = _getFee(vc.credentialSubject.price);
        address payable issuer = payable(vc.issuer.ethereumAddress);
        issuer.transfer(msg.value - _fee);
        feesAvailableForWithdraw += _fee;

        return true;
    }

    function _revokeVC(
        bytes32 uuid,
        VCTypesV01.VerifiableCredential memory vc,
        string memory reason
    ) internal returns (bool) {
        require(
            registry[uuid].credentialStatus == Status.Issued,
            "KRBToken: state is not Issued"
        );

        registry[uuid].credentialStatus = Status.Revoked;
        emit Revoked(uuid, reason);

        uint256 _stake = vc.credentialSubject.stake * 10**decimals();
        uint256 _reward = _getReward(_stake, vc.credentialSubject.trust);

        //remove Issuer stake
        if (stakes[vc.issuer.ethereumAddress] >= _stake) {
            stakes[vc.issuer.ethereumAddress] = stakes[
                vc.issuer.ethereumAddress
            ].sub(_stake);
            emit Staked(address(0), vc.issuer.ethereumAddress, _stake);
        }
        _mint(vc.issuer.ethereumAddress, _stake);

        //discard rewards
        _burn(vc.credentialSubject.ethereumAddress, _reward);
        _burn(vc.issuer.ethereumAddress, _reward);

        return true;
    }

    function _suspendVC(
        bytes32 uuid,
        VCTypesV01.VerifiableCredential memory vc,
        string memory reason
    ) internal returns (bool) {
        require(
            registry[uuid].credentialStatus == Status.Issued,
            "KRBToken: state is not Issued"
        );

        registry[uuid].credentialStatus = Status.Suspended;
        emit Suspended(uuid, reason);

        uint256 _stake = vc.credentialSubject.stake * 10**decimals();
        uint256 _reward = _getReward(_stake, vc.credentialSubject.trust);

        //remove Issuer stake
        if (stakes[vc.issuer.ethereumAddress] >= _stake) {
            stakes[vc.issuer.ethereumAddress] = stakes[
                vc.issuer.ethereumAddress
            ].sub(_stake);
            emit Staked(address(0), vc.issuer.ethereumAddress, _stake);
        }
        _mint(vc.issuer.ethereumAddress, _stake);

        //reward from subject is lost
        _burn(vc.credentialSubject.ethereumAddress, _reward);

        return true;
    }

    function _deleteVC(
        bytes32 uuid,
        VCTypesV01.VerifiableCredential memory vc,
        string memory reason
    ) internal returns (bool) {
        require(
            registry[uuid].credentialStatus == Status.Issued,
            "KRBToken: state is not Issued"
        );

        registry[uuid].credentialStatus = Status.None;
        emit Deleted(uuid, reason);

        uint256 _stake = vc.credentialSubject.stake * 10**decimals();
        uint256 _reward = _getReward(_stake, vc.credentialSubject.trust);

        //remove Issuer stake
        if (stakes[vc.issuer.ethereumAddress] >= _stake) {
            stakes[vc.issuer.ethereumAddress] = stakes[
                vc.issuer.ethereumAddress
            ].sub(_stake);
            emit Staked(address(0), vc.issuer.ethereumAddress, _stake);
        }
        _mint(vc.issuer.ethereumAddress, _stake);

        //discard rewards
        _burn(vc.credentialSubject.ethereumAddress, _reward);
        _burn(vc.issuer.ethereumAddress, _reward);

        return true;
    }

    /**
     * @notice Mark a Verifiable Credential as Expired
     * @param vc The verifiable Credential
     *
     */
    function expiredVC(VCTypesV01.VerifiableCredential memory vc)
        external
        returns (bool)
    {
        bytes32 uuid = getUuid(vc);

        if (block.timestamp > vc.credentialSubject.exp) {
            uint256 _stake = vc.credentialSubject.stake * 10**decimals();
            //remove Issuer stake
            if (stakes[vc.issuer.ethereumAddress] >= _stake) {
                stakes[vc.issuer.ethereumAddress] = stakes[
                    vc.issuer.ethereumAddress
                ].sub(_stake);
                emit Staked(address(0), vc.issuer.ethereumAddress, _stake);
            }
            _mint(vc.issuer.ethereumAddress, _stake);
            //rewards remain unless VC is disputed
            registry[uuid].credentialStatus = Status.Expired;
            emit Expired(uuid);
        }
        return (block.timestamp > vc.credentialSubject.exp);
    }

    function _issueVCWithAuthorization(
        VCTypesV01.VerifiableCredential memory vc,
        bytes memory proofValue
    ) internal returns (bool) {
        bytes32 uuid = getUuid(vc);

        validateSignedData(vc.issuer.ethereumAddress, uuid, proofValue);

        _issueVC(uuid, vc);

        return true;
    }

    /**
     * @notice Register a Verifiable Credential
     * @param vc The verifiable Credential
     * @param proofValue EIP712-VC proofValue
     *
     * Requirements:
     * - proofValue must be the Issuer's signature of the VC
     * - sender must be the credentialSubject address
     * - msg.value must be greater than minPriceToIssue
     *
     */
    function registerVC(
        VCTypesV01.VerifiableCredential memory vc,
        bytes memory proofValue
    ) public payable returns (bool) {
        require(
            vc.credentialSubject.ethereumAddress == _msgSender(),
            "KRBToken: sender must be the credentialSubject address"
        );
        require(
            vc.credentialSubject.price == msg.value,
            "KRBToken: msg.value does not match credentialSubject.price"
        );
        require(
            msg.value >= minPriceToIssue,
            "KRBToken: msg.value must be greater than minPriceToIssue"
        );

        _issueVCWithAuthorization(vc, proofValue);

        return true;
    }

    /**
     * @notice Delete a Verifiable Credential
     * @param vc The verifiable Credential
     * @param reason Reason for deleting
     *
     * Requirements:
     * -  sender must be the credentialSubject address
     *
     */
    function deleteVC(
        VCTypesV01.VerifiableCredential memory vc,
        string memory reason
    ) public returns (bool) {
        require(
            vc.credentialSubject.ethereumAddress == _msgSender(),
            "KRBToken: sender must be the credentialSubject address"
        );

        _deleteVC(getUuid(vc), vc, reason);

        return true;
    }

    /**
     * @notice Revoke a Verifiable Credential
     * @param vc The verifiable Credential
     * @param reason Reason for revoking
     *
     * Requirements:
     * -  sender must be the issuer address
     *
     */
    function revokeVC(
        VCTypesV01.VerifiableCredential memory vc,
        string memory reason
    ) public returns (bool) {
        require(
            vc.issuer.ethereumAddress == _msgSender(),
            "KRBToken: sender must be the issuer address"
        );
        _revokeVC(getUuid(vc), vc, reason);

        return true;
    }

    /**
     * @notice Suspend a Verifiable Credential
     * @param vc The verifiable Credential
     * @param reason Reason for suspending
     *
     * Requirements:
     * -  sender must be the issuer address
     *
     */
    function suspendVC(
        VCTypesV01.VerifiableCredential memory vc,
        string memory reason
    ) public returns (bool) {
        require(
            vc.issuer.ethereumAddress == _msgSender(),
            "KRBToken: sender must be the issuer address"
        );
        _suspendVC(getUuid(vc), vc, reason);

        return true;
    }

    /**
     * @notice Called by DAO Govern arbitration to resolve a dispute
     * @param vc The verifiable Credential
     * @param disputeVC Dispute Credential
     *
     * Requirements:
     * -  sender must be the DAO Govern address
     *
     */
    function disputeVCByGovern(
        VCTypesV01.VerifiableCredential memory vc,
        VCTypesV01.VerifiableCredential memory disputeVC
    ) public returns (bool) {
        require(
            hasRole(GOVERN_ROLE, _msgSender()),
            "KRBToken: must have govern role to resolve dispute"
        );
        require(
            keccak256(abi.encodePacked(disputeVC._type)) ==
                keccak256(
                    abi.encodePacked(
                        '["VerifiableCredential","DisputeCredential"]'
                    )
                ),
            "KRBToken: dispute claim type must be DisputeCredential"
        );
        require(
            disputeVC.issuer.ethereumAddress == _msgSender(),
            "KRBToken: issuer must be the Govern address"
        );

        bytes32 uuid = getUuid(vc);
        require(
            keccak256(abi.encodePacked(disputeVC.credentialSubject.id)) ==
                keccak256(abi.encodePacked(vc.id)),
            "KRBToken: disputeVC credentialSubject id differes from VC id"
        );

        require(
            registry[uuid].credentialStatus != Status.None &&
                registry[uuid].credentialStatus != Status.Disputed,
            "KRBToken: VC state already disputed"
        );

        bytes32 disputeUuid = getUuid(disputeVC);
        registry[uuid].credentialStatus = Status.Disputed;
        registry[uuid].disputedBy = disputeUuid;
        emit Disputed(uuid, disputeUuid);

        registry[disputeUuid].credentialStatus = Status.Issued;
        emit Issued(disputeUuid, disputeVC);

        uint256 _stake = vc.credentialSubject.stake * 10**decimals();
        //Slash stake from Issuer
        if (stakes[vc.issuer.ethereumAddress] >= _stake) {
            stakes[vc.issuer.ethereumAddress] = stakes[
                vc.issuer.ethereumAddress
            ].sub(_stake);
            emit Staked(address(0), vc.issuer.ethereumAddress, _stake);
        }

        //Revert rewards from issuer and credentialSubject
        uint256 _reward = _getReward(_stake, vc.credentialSubject.trust);
        _burn(vc.credentialSubject.ethereumAddress, _reward);
        _burn(vc.issuer.ethereumAddress, _reward);

        /// @dev Reward disputer
        uint256 _disputeStake = disputeVC.credentialSubject.stake *
            10**decimals();
        uint256 _disputeReward = _getReward(
            _disputeStake,
            disputeVC.credentialSubject.trust
        );
        _mint(disputeVC.credentialSubject.ethereumAddress, _disputeReward);

        return true;
    }

    /**
     * @notice Withdraw fees collected by the contract.
     * Requirements:
     * - Only the DAO govern can call this.
     */
    function withdrawFees(address payable _to, uint256 _amount) external {
        require(
            hasRole(GOVERN_ROLE, _msgSender()),
            "KRBToken: must have govern role to withdraw"
        );
        require(_amount <= feesAvailableForWithdraw); /// @dev Also prevents underflow
        feesAvailableForWithdraw -= _amount;
        _to.transfer(_amount);
    }

    uint256[50] private __gap;
}
