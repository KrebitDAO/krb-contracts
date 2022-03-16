/*
// SPDX-License-Identifier: MIT
@author Krebit Inc. http://krebit.co

Implements: W3C verifiable Credentials
https://www.w3.org/TR/vc-data-model
*/

import "@openzeppelin/contracts-upgradeable/utils/math/SafeMathUpgradeable.sol";

pragma solidity ^0.8.0;

library VCTypesV01 {
    // bytes32 private constant ISSUER_TYPEHASH = keccak256("Issuer(string id,address ethereumAddress)")
    bytes32 private constant ISSUER_TYPEHASH =
        0xabb691e6e52ceb1ff8b3df91dc14323057e88efa3252486ed994fd62706cdfaa;
    // bytes32 private constant SIGNATURE_TYPEHASH = keccak256("Signature(uint8 v,bytes32 r,bytes32 s)")
    bytes32 private constant SIGNATURE_TYPEHASH =
        0xcea59b5eccb60256d918b7a2e778f6161148c37e6dada57c32e20db10c50b631;
    // bytes32 private constant VERIFIABLE_CREDENTIAL_TYPEHASH = keccak256("VerifiableCredential(string _context,string _type,string id,Issuer issuer,CredentialSubject credentialSubject,CredentialSchema credentialSchema,string issuanceDate,string expirationDate)CredentialSchema(string id,string _type)CredentialSubject(string id,address ethereumAddress,string _type,string typeSchema,string value,string encrypted,uint8 trust,uint256 stake,uint256 price,uint256 nbf,uint256 exp)Issuer(string id,address ethereumAddress)")
    bytes32 private constant VERIFIABLE_CREDENTIAL_TYPEHASH =
        0x63c4847aa3662952b34b8f76f3abc371c24535ee34fce5b3df34d029db924d4e;
    // bytes32 private constant CREDENTIAL_SCHEMA_TYPEHASH = keccak256("CredentialSchema(string id,string _type)")
    bytes32 private constant CREDENTIAL_SCHEMA_TYPEHASH =
        0x1a58b7c56676b62343f37f4f3603a07ae6dd78bea300689bcefef0f9498c6cc9;
    // bytes32 private constant CREDENTIAL_SUBJECT_TYPEHASH = keccak256("CredentialSubject(string id,address ethereumAddress,string _type,string typeSchema,string value,string encrypted,uint8 trust,uint256 stake,uint256 price,uint256 nbf,uint256 exp)")
    bytes32 private constant CREDENTIAL_SUBJECT_TYPEHASH =
        0x4b87db6c5998f503ac6519b5a7d74efcf2a230368deeaf54dd8bf078da459ff7;

    struct Issuer {
        string id;
        address ethereumAddress;
    }

    struct CredentialSubject {
        string id;
        address ethereumAddress;
        string _type;
        string typeSchema;
        string value;
        string encrypted;
        uint8 trust; // 0 to 10
        uint256 stake; // minStakeToIssue - maxStakeToIssue
        uint256 price; // wei
        uint256 nbf;
        uint256 exp;
    }

    struct CredentialSchema {
        string id;
        string _type;
    }

    struct VerifiableCredential {
        string _context;
        string _type;
        string id;
        Issuer issuer;
        CredentialSubject credentialSubject;
        CredentialSchema credentialSchema;
        string issuanceDate;
        string expirationDate;
    }

    /**
     * @dev Validates that the `VerifiableCredential` conforms to the Krebit Protocol.

     *
     */
    function validateVC(VerifiableCredential memory vc) internal view {
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
            vc.credentialSubject.price == msg.value,
            "KRBToken: msg.value does not match credentialSubject.price"
        );
        require(
            vc.issuer.ethereumAddress != vc.credentialSubject.ethereumAddress,
            "KRBToken: issuer address is the same as credentialSubject"
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
    function getReward(uint256 _stake, uint256 _trust)
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

    function _getIssuer(Issuer memory identity)
        internal
        pure
        returns (bytes32)
    {
        return
            keccak256(
                abi.encode(
                    ISSUER_TYPEHASH,
                    keccak256(bytes(identity.id)),
                    identity.ethereumAddress
                )
            );
    }

    function _getCredentialSubject(CredentialSubject memory credentialSubject)
        internal
        pure
        returns (bytes32)
    {
        return
            keccak256(
                abi.encode(
                    CREDENTIAL_SUBJECT_TYPEHASH,
                    keccak256(bytes(credentialSubject.id)),
                    credentialSubject.ethereumAddress,
                    keccak256(bytes(credentialSubject._type)),
                    keccak256(bytes(credentialSubject.typeSchema)),
                    keccak256(bytes(credentialSubject.value)),
                    keccak256(bytes(credentialSubject.encrypted)),
                    credentialSubject.trust,
                    credentialSubject.stake,
                    credentialSubject.price,
                    credentialSubject.nbf,
                    credentialSubject.exp
                )
            );
    }

    function _getCredentialSchema(CredentialSchema memory credentialSchema)
        internal
        pure
        returns (bytes32)
    {
        return
            keccak256(
                abi.encode(
                    CREDENTIAL_SCHEMA_TYPEHASH,
                    keccak256(bytes(credentialSchema.id)),
                    keccak256(bytes(credentialSchema._type))
                )
            );
    }

    function getVerifiableCredential(VerifiableCredential memory vc)
        internal
        pure
        returns (bytes32)
    {
        return
            keccak256(
                abi.encode(
                    VERIFIABLE_CREDENTIAL_TYPEHASH,
                    keccak256(bytes(vc._context)),
                    keccak256(bytes(vc._type)),
                    keccak256(bytes(vc.id)),
                    _getIssuer(vc.issuer),
                    _getCredentialSubject(vc.credentialSubject),
                    _getCredentialSchema(vc.credentialSchema),
                    keccak256(bytes(vc.issuanceDate)),
                    keccak256(bytes(vc.expirationDate))
                )
            );
    }
}
