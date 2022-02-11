/*
// SPDX-License-Identifier: MIT
@author Krebit Inc. http://krebit.co
*/

pragma solidity ^0.8.0;

// OpenZeppelin Upgradeable Contracts v4.4.1
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
 * @dev {ERC20} token, including:
 *
 *  - ability for holders to burn (destroy) their tokens
 *  - a govern role that allows for token minting (creation)
 *  - a govern role that allows to stop all token transfers
 *  - ERC-3009 transferWithAuthorization()
 *  - minBalanceToTransfer
 *  - minBalanceToReceive
 *  - burnWithAuthorization()
 *
 * This contract uses {AccessControl} to lock permissioned functions using the
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
    bytes32 public constant GOVERN_ROLE = keccak256("GOVERN_ROLE");

    // Min Balance to Transfer
    uint256 public minBalanceToTransfer;
    // Min Balance to Receive
    uint256 public minBalanceToReceive;

    // Min Balance to Issue Verifiable Credentials
    uint256 public minBalanceToIssue;
    // Min Stake to Issue Verifiable Credentials
    uint256 public minStakeToIssue;
    // Max Stake to Issue Verifiable Credentials
    uint256 public maxStakeToIssue;
    // Fee to Issue Verifiable Credentials
    uint256 public feePercentage;
    uint256 public feesAvailableForWithdraw; //wei

    event Updated(string change);

    // https://www.w3.org/TR/vc-data-model/#status
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

    // Mapping of rewarded VCTypesV01.VerifiableCredentials. Key is a hash of the vc data
    mapping(bytes32 => VerifiableData) public registry;

    event Issued(bytes32 uuid, VCTypesV01.VerifiableCredential vc);
    event Disputed(bytes32 uuid, bytes32 disputedBy);
    event Revoked(bytes32 uuid, string reason);
    event Suspended(bytes32 uuid, string reason);
    event Expired(bytes32 uuid);
    event Deleted(bytes32 uuid, string reason);

    function initialize() public virtual initializer {
        __KRBTokenV01_init("Krebit", "KRB");
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() initializer {}

    /**
     * @dev Grants `DEFAULT_ADMIN_ROLE`, `GOVERN_ROLE` and `PAUSER_ROLE` to the
     * account that deploys the contract.
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

    function __KRBTokenV01_init_unchained(
        string memory name,
        string memory symbol
    ) internal onlyInitializing {
        _setupRole(DEFAULT_ADMIN_ROLE, _msgSender());
        _setupRole(GOVERN_ROLE, _msgSender());

        minBalanceToTransfer = 100 * 10**decimals(); // 100 KRB
        minBalanceToReceive = 100 * 10**decimals(); // 100 KRB

        feePercentage = 10; // 10 %

        minBalanceToIssue = 100 * 10**decimals(); // 100 KRB

        minStakeToIssue = 1 * 10**decimals(); // 1 KRB
        maxStakeToIssue = 10 * 10**decimals(); // 10 KRB
    }

    /**
     * @dev Function that should revert when `msg.sender` is not authorized to upgrade the contract. Called by
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
     * @dev Updates `minBalanceToTransfer` to `newMinBalance`.
     *
     * See http://docs.krebit.co
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
     * @dev Updates `minBalanceToReceive` to `newMinBalance`.
     *
     * See http://docs.krebit.co
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
     * See http://docs.krebit.co
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
     * @dev Creates `amount` new tokens for `to`.
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
     * @dev Pauses all token transfers.
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
     * @dev Unpauses all token transfers.
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
     * @dev Returns the domain separator for the current chain.
     *
     * See {IERC20Permit-DOMAIN_SEPARATOR}.
     */
    // solhint-disable-next-line func-name-mixedcase
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

        // Explicitly disallow authorizations for address(0) as ecrecover returns address(0) on malformed messages
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

        // Explicitly disallow authorizations for address(0) as ecrecover returns address(0) on malformed messages
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
     * @dev Updates `feePercentage` to `newFeePercentage`.
     *
     * See http://docs.krebit.co
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
     * @dev Updates `minBalanceToIssue` to `newMinBalance`.
     *
     * See http://docs.krebit.co
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
     * @dev Updates `minStakeToIssue` and `maxStakeToIssue`.
     *
     * See http://docs.krebit.co
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
     * See http://docs.krebit.co
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
     * See http://docs.krebit.co
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
     * See http://docs.krebit.co
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
     * @dev Validates that the `VerifiableCredential` conforms to the VCTypes.
     *
     * See http://docs.krebit.co
     *
     */
    function getUuid(VCTypesV01.VerifiableCredential memory vc)
        public
        pure
        returns (bytes32)
    {
        return VCTypesV01.getVerifiableCredential(vc);
    }

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

        registry[uuid] = VerifiableData(Status.Issued, 0x0);
        emit Issued(uuid, vc);

        uint256 _reward = _getReward(_stake, vc.credentialSubject.trust);
        _mint(vc.credentialSubject.ethereumAddress, _reward);
        _mint(vc.issuer.ethereumAddress, _reward);

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

        //issuer stake remains unless VC is disputed
        registry[uuid].credentialStatus = Status.Suspended;
        emit Suspended(uuid, reason);

        uint256 _stake = vc.credentialSubject.stake * 10**decimals();
        uint256 _reward = _getReward(_stake, vc.credentialSubject.trust);

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

        //discard rewards
        _burn(vc.credentialSubject.ethereumAddress, _reward);
        _burn(vc.issuer.ethereumAddress, _reward);

        return true;
    }

    function expiredVC(VCTypesV01.VerifiableCredential memory vc)
        external
        returns (bool)
    {
        bytes32 uuid = getUuid(vc);

        if (block.timestamp > vc.credentialSubject.exp) {
            //issuer stake remains unless VC is disputed
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

        _issueVCWithAuthorization(vc, proofValue);

        return true;
    }

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

    function disputeVCByGovern(
        /**
         * Called by Govern arbitration to resolve a dispute
         */
        VCTypesV01.VerifiableCredential memory vc,
        VCTypesV01.VerifiableCredential memory disputeVC
    ) public returns (bool) {
        require(
            hasRole(GOVERN_ROLE, _msgSender()),
            "KRBToken: must have govern role to resolve dispute"
        );
        require(
            keccak256(abi.encodePacked(disputeVC._type)) ==
                keccak256(abi.encodePacked("DisputeCredential")),
            "KRBToken: dispute claim type must be DisputeCredential"
        );
        require(
            disputeVC.issuer.ethereumAddress == _msgSender(),
            "KRBToken: issuer must be the Govern address"
        );

        bytes32 uuid = getUuid(vc);
        /* TODO fix comparisson
        require(
            keccak256(abi.encodePacked(disputeVC.credentialSubject.id)) ==
                bytes32(abi.encodePacked(uuid)),
            "KRBToken: disputeVC credentialSubject differes from VC uuid"
        ); */

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
        _burn(vc.issuer.ethereumAddress, _stake);

        //Revert rewards from issuer and credentialSubject
        uint256 _reward = _getReward(_stake, vc.credentialSubject.trust);
        _burn(vc.credentialSubject.ethereumAddress, _reward);
        _burn(vc.issuer.ethereumAddress, _reward);

        return true;
    }

    /**
     * Withdraw fees collected by the contract. Only the govern can call this.
     */
    function withdrawFees(address payable _to, uint256 _amount) external {
        require(
            hasRole(GOVERN_ROLE, _msgSender()),
            "KRBToken: must have govern role to withdraw"
        );
        require(_amount <= feesAvailableForWithdraw); // Also prevents underflow
        feesAvailableForWithdraw -= _amount;
        _to.transfer(_amount);
    }

    uint256[50] private __gap;
}
