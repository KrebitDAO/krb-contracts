/// SPDX-License-Identifier: MIT
/// @title NFT Drop with Krebit Protocol v 0.1 - http://krebit.id
/// @author Krebit Inc. <contact@krebit.co>

pragma solidity ^0.8.4;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721Enumerable.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721Royalty.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721Burnable.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "@openzeppelin/contracts/security/PullPayment.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

import "./VCTypes.sol";

interface IKRBToken {
    function getVCStatus(VCTypes.VerifiableCredential memory vc)
        external
        view
        returns (string memory);
}

/// @custom:security-contact contact@krebit.co
/**
 * @title KRBCredentialNFT contract
 * @dev This is the implementation of the ERC721 Krebit Verifiable-Credentials Non-Fungible Token.
 */
contract KRBCredentialNFT is
    ERC721,
    ERC721Enumerable,
    ERC721Royalty,
    Pausable,
    AccessControl,
    ERC721Burnable,
    PullPayment,
    ReentrancyGuard
{
    using SafeMath for uint256;

    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant ROYALTY_SETTER_ROLE =
        keccak256("ROYALTY_SETTER_ROLE");

    /**
     * @notice Krebit KRB Contract interface
     */
    IKRBToken _KrebitContract;

    /**
     * @notice token metadata uri "ipfs://<hash>/"
     */
    string private _baseTokenURI;
    /**
     * @notice collection metadata uri "ipfs://<hash>"
     */
    string private _metadataURI;

    /**
     * @notice set the cost to mint each NFT
     */
    uint256 public price;

    /**
     * @notice Total fees collected by the contract
     */
    uint256 public feesAvailableForWithdraw; //wei

    /**
     * @notice Required credential type"
     */
    string public requiredCredentialType;

    /**
     * @notice Required credential value"
     */
    string public requiredCredentialValue;

    /**
     * @dev For config updates
     */
    event Updated();

    /**
     * @dev Grants `DEFAULT_ADMIN_ROLE`, `MINTER_ROLE` and `PAUSER_ROLE` to the
     * account that deploys the contract.
     *
     * Token URIs will be autogenerated based on `baseURI` and their token IDs.
     * See {ERC721-tokenURI}.
     */
    constructor(
        string memory name,
        string memory symbol,
        string memory baseTokenURI,
        string memory metadataURI,
        uint256 initialPrice,
        address krebitAddress,
        string memory credentialType,
        string memory credentialValue
    ) ERC721(name, symbol) {
        _baseTokenURI = baseTokenURI;
        _metadataURI = metadataURI;
        requiredCredentialType = credentialType;
        requiredCredentialValue = credentialValue;
        price = initialPrice;
        _KrebitContract = IKRBToken(krebitAddress);

        _grantRole(DEFAULT_ADMIN_ROLE, _msgSender());
        _grantRole(PAUSER_ROLE, _msgSender());
        _grantRole(ROYALTY_SETTER_ROLE, _msgSender());
    }

    function _baseURI() internal view virtual override returns (string memory) {
        return _baseTokenURI;
    }

    function contractURI() public view returns (string memory) {
        return _metadataURI;
    }

    //set the cost of an NFT
    function setPrice(uint256 newPrice) public onlyRole(ROYALTY_SETTER_ROLE) {
        price = newPrice;
        emit Updated();
    }

    function pause() public onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() public onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    //set the required credential type and value
    function setRequiredCredential(
        string memory credentialType,
        string memory credentialValue
    ) public onlyRole(DEFAULT_ADMIN_ROLE) {
        requiredCredentialType = credentialType;
        requiredCredentialValue = credentialValue;
        emit Updated();
    }

    function mintWithCredential(
        address to,
        uint256 tokenId,
        VCTypes.VerifiableCredential memory vc
    ) public payable whenNotPaused {
        require(
            vc.credentialSubject.ethereumAddress == to,
            "Mint to address must be the vc.credentialSubject address"
        );
        VCTypes.validateVC(vc);

        require(
            keccak256(abi.encodePacked(_KrebitContract.getVCStatus(vc))) ==
                keccak256(abi.encodePacked("Issued")),
            "Credential is not in Issued state"
        );

        require(
            containsString(requiredCredentialType, vc._type),
            string.concat(
                "vc._type doesn't match requiredCredentialType: ",
                requiredCredentialType
            )
        );

        require(
            containsString(requiredCredentialValue, vc.credentialSubject.value),
            string.concat(
                "vc.credentialSubject.value doesn't match requiredCredentialValue: ",
                requiredCredentialValue
            )
        );

        require(msg.value >= price, "Amount sent is less than the mint price");

        feesAvailableForWithdraw = feesAvailableForWithdraw.add(msg.value);
        //TODO: mint Credential as NFT:
        //tokenId = _KrebitContract.getUuid(vc):
        _safeMint(to, tokenId);
    }

    /**
     * @dev Set the default royalty payment information.
     * @param receiver Address that should receive the royalties
     * @param feeNumerator Royalty fee
     */
    function setDefaultRoyalty(address receiver, uint96 feeNumerator)
        public
        onlyRole(ROYALTY_SETTER_ROLE)
    {
        _setDefaultRoyalty(receiver, feeNumerator);
    }

    /**
     * @notice Withdraw fees collected by the contract.
     */
    function withdrawFees(address payable _to, uint256 _amount)
        external
        nonReentrant
        onlyRole(ROYALTY_SETTER_ROLE)
    {
        require(_amount <= feesAvailableForWithdraw); /// @dev Also prevents underflow
        feesAvailableForWithdraw = feesAvailableForWithdraw.sub(_amount);
        _asyncTransfer(_to, _amount);
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

    // The following functions are overrides required by Solidity.

    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 tokenId
    ) internal override(ERC721, ERC721Enumerable) whenNotPaused {
        super._beforeTokenTransfer(from, to, tokenId);
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(ERC721, ERC721Enumerable, ERC721Royalty, AccessControl)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }

    function _burn(uint256 tokenId) internal override(ERC721, ERC721Royalty) {
        super._burn(tokenId);
    }
}
