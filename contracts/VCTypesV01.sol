/*
// SPDX-License-Identifier: MIT
@author Krebit Inc. http://krebit.co

Implements: W3C verifiable Credentials
https://www.w3.org/TR/vc-data-model
*/

pragma solidity ^0.8.0;

library VCTypesV01 {
    // bytes32 private constant ISSUER_TYPEHASH = keccak256("Issuer(string id,address ethereumAddress)")
    bytes32 private constant ISSUER_TYPEHASH =
        0xabb691e6e52ceb1ff8b3df91dc14323057e88efa3252486ed994fd62706cdfaa;
    // bytes32 private constant SIGNATURE_TYPEHASH = keccak256("Signature(uint8 v,bytes32 r,bytes32 s)")
    bytes32 private constant SIGNATURE_TYPEHASH =
        0xcea59b5eccb60256d918b7a2e778f6161148c37e6dada57c32e20db10c50b631;
    // bytes32 private constant VERIFIABLE_CREDENTIAL_TYPEHASH = keccak256("VerifiableCredential(string _context,string _type,string id,Issuer issuer,CredentialSubject credentialSubject,CredentialSchema credentialSchema,string issuanceDate,string expirationDate)CredentialSchema(string id,string _type)CredentialSubject(string id,address ethereumAddress,string _type,string value,string encrypted,uint8 trust,uint256 stake,uint256 nbf,uint256 exp)Issuer(string id,address ethereumAddress)")
    bytes32 private constant VERIFIABLE_CREDENTIAL_TYPEHASH =
        0xbe684d190ad65920edc3ded7384f6a383db54390d51a4039cd9804738787aa73;
    // bytes32 private constant CREDENTIAL_SCHEMA_TYPEHASH = keccak256("CredentialSchema(string id,string _type)")
    bytes32 private constant CREDENTIAL_SCHEMA_TYPEHASH =
        0x1a58b7c56676b62343f37f4f3603a07ae6dd78bea300689bcefef0f9498c6cc9;
    // bytes32 private constant CREDENTIAL_SUBJECT_TYPEHASH = keccak256("CredentialSubject(string id,address ethereumAddress,string _type,string value,string encrypted,uint8 trust,uint256 stake,uint256 nbf,uint256 exp)")
    bytes32 private constant CREDENTIAL_SUBJECT_TYPEHASH =
        0x21b75bdb9e47bcd33a79c50900ab5c955f98112af76c96fd28afba4ed7457c28;

    struct Issuer {
        string id;
        address ethereumAddress;
    }

    struct CredentialSubject {
        string id;
        address ethereumAddress;
        string _type;
        string value;
        string encrypted;
        uint8 trust; // 0 to 10
        uint256 stake; // minStakeToIssue - maxStakeToIssue
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
                    keccak256(bytes(credentialSubject.value)),
                    keccak256(bytes(credentialSubject.encrypted)),
                    credentialSubject.trust,
                    credentialSubject.stake,
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
