/*
// SPDX-License-Identifier: MIT
@author Krebit Inc. https://krebit.co
Based on LocalCryptos Escrow
Pay in Ethereum for digital or real-world goods and services
*/

pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "@openzeppelin/contracts/utils/Context.sol";
import "@openzeppelin/contracts/access/AccessControlEnumerable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/PullPayment.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

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

interface ERC20 {
    function transfer(address _to, uint256 _value)
        external
        returns (bool success);

    function transferFrom(
        address _from,
        address _to,
        uint256 _value
    ) external returns (bool success);

    function approve(address _spender, uint256 _value)
        external
        returns (bool success);

    function balanceOf(address account) external view returns (uint256);
}

contract KrebitEscrow is
    Context,
    AccessControlEnumerable,
    ReentrancyGuard,
    PullPayment
{
    using SafeMath for uint256;

    bytes32 public constant GOVERN_ROLE = keccak256("GOVERN_ROLE");

    /**
     * @notice ERC2771
     */
    address public trustedForwarder;

    uint256 public feePercentage;
    uint256 public referralPercentage;
    uint256 public feesAvailableForWithdraw;

    /**
     * @notice Krebit KRB Contract interface
     */
    IKRBToken _KrebitContract;

    enum Status {
        None,
        Created,
        Delivered,
        BuyerCanceled,
        SellerCanceled,
        Released,
        DisputeResolved
    }

    struct Escrow {
        Status dealStatus;
        // The timestamp in which the buyer can cancel the deal if the seller has not yet marked as delivered. Set to 0 on marked delivered or dispute
        // 1 = unlimited cancel time
        uint256 buyerCanCancelAfter;
        bytes32 referral;
    }
    // Mapping of active deals. Key is a hash of the deal data
    mapping(bytes32 => Escrow) public escrows;

    event Created(
        bytes32 _dealHash,
        VCTypes.VerifiableCredential dealCredential
    );
    event BuyerCancelDisabled(bytes32 _dealHash);
    event CancelledByBuyer(bytes32 _dealHash);
    event CancelledBySeller(bytes32 _dealHash);
    event Released(bytes32 _dealHash);
    event DisputeResolved(bytes32 _dealHash);

    /**
     * @dev For config updates
     */
    event Updated();

    /**
     * @dev Throws if the sender is not the Govern.
     */
    function _checkGovern() internal view virtual {
        require(hasRole(GOVERN_ROLE, _msgSender()), "Must have govern role");
    }

    /**
     * @dev Throws if called by any account other than the govern.
     */
    modifier onlyGovern() {
        _checkGovern();
        _;
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
        override(Context)
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
        override(Context)
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

    constructor(address _krebitAddress) {
        /**
         * Initialize the contract.
         */
        _setupRole(GOVERN_ROLE, _msgSender());
        feePercentage = 4; /// @dev 4 %
        referralPercentage = 1; /// @dev 1 %
        _KrebitContract = IKRBToken(_krebitAddress);
    }

    /**
     * Create a new escrow and add it to `escrows`.
     * _dealHash is created by hashing _dealID, _buyer, _seller and _value variables. These variables must be supplied on future contract calls.
     */
    function createEscrow(
        VCTypes.VerifiableCredential memory referralCredential,
        VCTypes.VerifiableCredential memory dealCredential,
        bytes memory dealProof
    ) external payable {
        //Check seller has a Referral credential with status "Issued"
        require(
            keccak256(abi.encode(referralCredential.credentialSubject._type)) ==
                keccak256(abi.encode("Referral")) ||
                keccak256(
                    abi.encode(referralCredential.credentialSubject._type)
                ) ==
                keccak256(abi.encode("Review")),
            "referralCredential.credentialSubject._type is not Referral or Review"
        );
        VCTypes.validateVC(referralCredential);
        // referralCredential.credentialSubject.ethereumAddress == _seller
        require(
            referralCredential.credentialSubject.ethereumAddress ==
                dealCredential.issuer.ethereumAddress,
            "Seller must be the credentialSubject of the referral credential"
        );
        require(
            keccak256(
                abi.encode(_KrebitContract.getVCStatus(referralCredential))
            ) == keccak256(abi.encode("Issued")),
            "referralCredential is not in Issued state"
        );
        bytes32 _referralHash = VCTypes.getVerifiableCredential(
            referralCredential
        );

        //Check deal credential (no need to be issued)
        require(
            keccak256(abi.encode(dealCredential.credentialSubject._type)) ==
                keccak256(abi.encode("Deal")),
            "dealCredential.credentialSubject._type is not Deal"
        );
        VCTypes.validateVC(dealCredential);
        // dealCredential.issuer.ethereumAddress == _seller
        _KrebitContract.validateSignedData(
            dealCredential.issuer.ethereumAddress,
            VCTypes.getVerifiableCredential(dealCredential),
            dealProof
        );
        // dealCredential.credentialSubject.ethereumAddress == _buyer
        require(
            dealCredential.credentialSubject.ethereumAddress == _msgSender(),
            "Sender must be the dealcredential subject address (buyer)"
        );
        bytes32 _dealHash = VCTypes.getVerifiableCredential(dealCredential);
        require(
            escrows[_dealHash].dealStatus == Status.None,
            "Deal already exists"
        );
        // Check sent eth against signed _value and make sure is not 0
        require(
            msg.value == dealCredential.credentialSubject.price &&
                msg.value > 0,
            "Wrong value"
        );
        escrows[_dealHash] = Escrow(
            Status.Created,
            dealCredential.credentialSubject.exp,
            _referralHash
        );
        emit Created(_dealHash, dealCredential);
    }

    /**
     * @notice Validates that the `VerifiableCredential` conforms to the VCTypes.
     @param dealCredential Verifiable Credential

     *
     */
    function getUuid(VCTypes.VerifiableCredential memory dealCredential)
        public
        pure
        returns (bytes32)
    {
        return VCTypes.getVerifiableCredential(dealCredential);
    }

    /**
     * @notice Get the status of a Deal
     * @param dealCredential The verifiable Credential
     *
     * @return status true/false
     *
     */
    function getDealStatus(VCTypes.VerifiableCredential memory dealCredential)
        public
        view
        returns (string memory)
    {
        bytes32 _dealHash = VCTypes.getVerifiableCredential(dealCredential);
        Status temp = escrows[_dealHash].dealStatus;
        if (temp == Status.None) return "None";
        if (temp == Status.Created) return "Created";
        if (temp == Status.Delivered) return "Delivered";
        if (temp == Status.BuyerCanceled) return "BuyerCanceled";
        if (temp == Status.SellerCanceled) return "SellerCanceled";
        if (temp == Status.Released) return "Released";
        if (temp == Status.DisputeResolved) return "DisputeResolved";
        return "Error";
    }

    /**
     * Stops the buyer from cancelling the deal.
     * Can only be called the seller.
     * Used to mark the deal as delivered, or if the seller has a dispute.
     */
    function disableBuyerCancel(
        VCTypes.VerifiableCredential memory dealCredential
    ) external returns (bool) {
        require(
            dealCredential.issuer.ethereumAddress == _msgSender(),
            "Sender must be the dealCredential issuer address (seller)"
        );
        //Disable with a _Review credential?
        bytes32 _dealHash = VCTypes.getVerifiableCredential(dealCredential);

        require(
            escrows[_dealHash].dealStatus == Status.Created,
            "Deal can't be marked as Delivered"
        );
        escrows[_dealHash].dealStatus = Status.Delivered;
        emit BuyerCancelDisabled(_dealHash);
        return true;
    }

    /**
     * Called by the buyer to releases the funds for a successful deal.
     * Deletes the deal from the `escrows` mapping.
     */
    function release(
        VCTypes.VerifiableCredential memory referralCredential,
        VCTypes.VerifiableCredential memory dealCredential,
        address payable _referrer
    ) external nonReentrant returns (bool) {
        require(
            dealCredential.credentialSubject.ethereumAddress == _msgSender(),
            "Sender must be the dealcredentialSubject address (buyer)"
        );
        bytes32 _dealHash = VCTypes.getVerifiableCredential(dealCredential);

        require(
            escrows[_dealHash].dealStatus == Status.Created ||
                escrows[_dealHash].dealStatus == Status.Delivered,
            "Deal can't be released"
        );
        bytes32 _referralHash = VCTypes.getVerifiableCredential(
            referralCredential
        );
        require(
            escrows[_dealHash].referral == _referralHash,
            "Wrong referralCredential"
        );

        escrows[_dealHash].dealStatus = Status.Released;
        emit Released(_dealHash);
        address payable _seller = payable(
            dealCredential.issuer.ethereumAddress
        );

        if (_referrer != payable(referralCredential.issuer.ethereumAddress)) {
            /*string memory referrerIssuer = string.concat(
                '\\"onBehalveOfIssuer\\":{\\"id\\":\\"did:pkh:eip155:1:',
                abi.encodePacked(referrerAddress)
            );*/
            string memory referrerAddress = Strings.toHexString(
                uint256(uint160(address(_referrer))),
                20
            );
            require(
                containsString(
                    referrerAddress,
                    referralCredential.credentialSubject.value
                ),
                string.concat(
                    "referralCredential.credentialSubject.value doesn't match: ",
                    referrerAddress
                )
            );
        }

        transferMinusFee(
            _seller,
            dealCredential.credentialSubject.price,
            _referrer
        );
        return true;
    }

    /**
     * Cancels the deal and returns the ether to the buyer.
     * Can only be called the seller.
     */
    function sellerCancel(
        VCTypes.VerifiableCredential memory referralCredential,
        VCTypes.VerifiableCredential memory dealCredential,
        address payable _referrer
    ) external nonReentrant returns (bool) {
        require(
            dealCredential.issuer.ethereumAddress == _msgSender(),
            "Sender must be the dealCredential issuer address (seller)"
        );

        bytes32 _dealHash = VCTypes.getVerifiableCredential(dealCredential);

        require(
            escrows[_dealHash].dealStatus == Status.Created,
            "Deal can't be canceled"
        );

        bytes32 _referralHash = VCTypes.getVerifiableCredential(
            referralCredential
        );
        require(
            escrows[_dealHash].referral == _referralHash,
            "Wrong referralCredential"
        );
        escrows[_dealHash].dealStatus = Status.SellerCanceled;
        emit CancelledBySeller(_dealHash);
        address payable _buyer = payable(
            dealCredential.credentialSubject.ethereumAddress
        );
        if (_referrer != payable(referralCredential.issuer.ethereumAddress)) {
            /*string memory referrerIssuer = string.concat(
                '\\"onBehalveOfIssuer\\":{\\"id\\":\\"did:pkh:eip155:1:',
                abi.encodePacked(referrerAddress)
            );*/
            string memory referrerAddress = Strings.toHexString(
                uint256(uint160(address(_referrer))),
                20
            );
            require(
                containsString(
                    referrerAddress,
                    referralCredential.credentialSubject.value
                ),
                string.concat(
                    "referralCredential.credentialSubject.value doesn't match: ",
                    referrerAddress
                )
            );
        }
        transferMinusFee(
            _buyer,
            dealCredential.credentialSubject.price,
            _referrer
        );
        return true;
    }

    /**
     * Cancels the deal and returns the ether to the buyer.
     * Can only be called the buyer.
     * Can only be called if the delivery window was missed by the seller
     */
    function buyerCancel(
        VCTypes.VerifiableCredential memory referralCredential,
        VCTypes.VerifiableCredential memory dealCredential,
        address payable _referrer
    ) external nonReentrant returns (bool) {
        require(
            dealCredential.credentialSubject.ethereumAddress == _msgSender(),
            "Sender must be the dealcredentialSubject address (buyer)"
        );
        bytes32 _referralHash = VCTypes.getVerifiableCredential(
            referralCredential
        );
        bytes32 _dealHash = VCTypes.getVerifiableCredential(dealCredential);

        require(
            escrows[_dealHash].dealStatus == Status.Created,
            "Deal can't be canceled"
        );
        require(
            escrows[_dealHash].referral == _referralHash,
            "Wrong referralCredential"
        );
        require(
            escrows[_dealHash].buyerCanCancelAfter <= block.timestamp,
            "Deal can't be canceled yet"
        );
        escrows[_dealHash].dealStatus = Status.BuyerCanceled;
        emit CancelledByBuyer(_dealHash);
        address payable _buyer = payable(
            dealCredential.credentialSubject.ethereumAddress
        );
        if (_referrer != payable(referralCredential.issuer.ethereumAddress)) {
            /*string memory referrerIssuer = string.concat(
                '\\"onBehalveOfIssuer\\":{\\"id\\":\\"did:pkh:eip155:1:',
                abi.encodePacked(referrerAddress)
            );*/
            string memory referrerAddress = Strings.toHexString(
                uint256(uint160(address(_referrer))),
                20
            );
            require(
                containsString(
                    referrerAddress,
                    referralCredential.credentialSubject.value
                ),
                string.concat(
                    "referralCredential.credentialSubject.value doesn't match: ",
                    referrerAddress
                )
            );
        }
        transferMinusFee(
            _buyer,
            dealCredential.credentialSubject.price,
            _referrer
        );
        return true;
    }

    /**
     * Called by the arbitrator to resolve a dispute
     */
    function resolveDispute(
        VCTypes.VerifiableCredential memory dealCredential,
        uint8 _sellerPercent
    ) external nonReentrant onlyGovern {
        bytes32 _dealHash = VCTypes.getVerifiableCredential(dealCredential);

        require(
            escrows[_dealHash].dealStatus == Status.Delivered,
            "Deal can't be resolved via dispute"
        );
        require(_sellerPercent <= 100);
        uint256 _value = dealCredential.credentialSubject.price;
        uint256 _fee = SafeMath.div(SafeMath.mul(_value, feePercentage), 100);
        require(_value - _fee <= _value); // Prevent underflow
        feesAvailableForWithdraw += _fee; // Add the the pot for krebit to withdraw

        escrows[_dealHash].dealStatus = Status.DisputeResolved;
        emit DisputeResolved(_dealHash);
        address payable _seller = payable(
            dealCredential.issuer.ethereumAddress
        );
        address payable _buyer = payable(
            dealCredential.credentialSubject.ethereumAddress
        );
        _asyncTransfer(_seller, ((_value - _fee) * _sellerPercent) / 100);
        _asyncTransfer(
            _buyer,
            ((_value - _fee) * (100 - _sellerPercent)) / 100
        );
    }

    function transferMinusFee(
        address payable _to,
        uint256 _value,
        address payable _referrer
    ) private {
        uint256 _fee = SafeMath.div(SafeMath.mul(_value, feePercentage), 100);
        uint256 _referral = SafeMath.div(
            SafeMath.mul(_value, referralPercentage),
            100
        );
        if (_value - _fee - _referral > _value) return; // Prevent underflow
        feesAvailableForWithdraw += _fee; // Add the the pot for krebit to withdraw
        _asyncTransfer(_to, _value - _fee - _referral);
        _asyncTransfer(_referrer, _referral);
    }

    /**
     * Withdraw fees collected by the contract. Only the govern can call this.
     */
    function withdrawFees(address payable _to, uint256 _amount)
        external
        nonReentrant
        onlyGovern
    {
        require(_amount <= feesAvailableForWithdraw); // Also prevents underflow
        feesAvailableForWithdraw -= _amount;
        _asyncTransfer(_to, _amount);
    }

    //set the feePercentage
    function setFeePercentage(uint256 newFeePercentage) public onlyGovern {
        feePercentage = newFeePercentage;
        emit Updated();
    }

    //set the referralPercentage
    function setReferralPercentage(uint256 newReferralPercentage)
        public
        onlyGovern
    {
        referralPercentage = newReferralPercentage;
        emit Updated();
    }

    /**
     * If ERC20 tokens are sent to this contract, they will be trapped forever.
     * This function is way for us to withdraw them so we can get them back to their rightful govern
     */
    function transferToken(
        ERC20 _tokenContract,
        address _transferTo,
        uint256 _value
    ) external onlyGovern {
        _tokenContract.transfer(_transferTo, _value);
    }

    /**
     * If ERC20 tokens are sent to this contract, they will be trapped forever.
     * This function is way for us to withdraw them so we can get them back to their rightful govern
     */
    function transferTokenFrom(
        ERC20 _tokenContract,
        address _transferTo,
        address _transferFrom,
        uint256 _value
    ) external onlyGovern {
        _tokenContract.transferFrom(_transferTo, _transferFrom, _value);
    }

    /**
     * If ERC20 tokens are sent to this contract, they will be trapped forever.
     * This function is way for us to withdraw them so we can get them back to their rightful govern
     */
    function approveToken(
        ERC20 _tokenContract,
        address _spender,
        uint256 _value
    ) external onlyGovern {
        _tokenContract.approve(_spender, _value);
    }

    /**
     * @notice finds a string on another string
     */
    function containsString(string memory what, string memory where)
        internal
        pure
        returns (bool found)
    {
        bytes memory whatBytes = bytes(what);
        bytes memory whereBytes = bytes(where);

        if (whereBytes.length < whatBytes.length) {
            return false;
        }

        found = false;
        for (uint256 i = 0; i <= whereBytes.length - whatBytes.length; i++) {
            bool flag = true;
            for (uint256 j = 0; j < whatBytes.length; j++)
                if (whereBytes[i + j] != whatBytes[j]) {
                    flag = false;
                    break;
                }
            if (flag) {
                found = true;
                break;
            }
        }
        return found;
    }
}
