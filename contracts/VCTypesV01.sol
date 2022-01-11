/*
// SPDX-License-Identifier: MIT
@author Krebit Inc. http://krebit.co

Implements: W3C verifiable Credentials
https://www.w3.org/TR/vc-data-model
*/

pragma solidity ^0.8.0;

library VCTypesV01 {
    // bytes32 private constant DID_TYPEHASH = keccak256("DID(string id,address ethereumAddress)")
    bytes32 private constant DID_TYPEHASH =
        0x304f3eff6220233b75d7dc77d27667479afb7c7142d792a0764be0316759ca5f;
    // bytes32 private constant SIGNATURE_TYPEHASH = keccak256("Signature(uint8 v,bytes32 r,bytes32 s)")
    bytes32 private constant SIGNATURE_TYPEHASH =
        0xcea59b5eccb60256d918b7a2e778f6161148c37e6dada57c32e20db10c50b631;
    // bytes32 private constant VERIFIABLE_CREDENTIAL_TYPEHASH = keccak256("VerifiableCredential(string id,string anchorCommit,DID issuer,DID credentialSubject,string claimType,string claimHash,uint256 issuanceDate,uint256 expirationDate,uint8 trust,uint256 stake,uint8 actionByte)DID(string id,address ethereumAddress)")
    bytes32 private constant VERIFIABLE_CREDENTIAL_TYPEHASH =
        0x7e68611f408624477ff4977f9c2c492993b2407a8a699b96906609c0db8bee98;
    //bytes32 private constant VERIFIABLE_PRESENTATION_TYPEHASH = keccak256("VerifiablePresentation(VerifiableCredential vc,Signature proof)VerifiableCredential(string id,string anchorCommit,DID issuer,DID credentialSubject,string claimType,string claimHash,uint256 issuanceDate,uint256 expirationDate,uint8 trust,uint256 stake,uint8 actionByte)DID(string id,address ethereumAddress)Signature(uint8 v,bytes32 r,bytes32 s)")
    bytes32 private constant VERIFIABLE_PRESENTATION_TYPEHASH =
        0x408b37d8702862c926116f9cd5d43aba52487eb81d17b3120d2873d13e134970;

    /**
     * @param v The recovery ID.
     * @param r The x-coordinate of the nonce R.
     * @param s The signature data.
     */
    struct Signature {
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    struct DID {
        string id;
        address ethereumAddress;
    }

    struct VerifiableCredential {
        string id;
        string anchorCommit;
        DID issuer;
        DID credentialSubject;
        string claimType;
        string claimHash;
        uint256 issuanceDate;
        uint256 expirationDate;
        uint8 trust; // 0 to 10
        uint256 stake; // minStakeToIssue - maxStakeToIssue
        uint8 actionByte;
    }

    struct VerifiablePresentation {
        VerifiableCredential vc;
        Signature proof; //issuer signature
    }

    uint8 constant ACTION_ISSUE = 0x01;
    uint8 constant ACTION_REVOKE = 0x02;
    uint8 constant ACTION_SUSPEND = 0x03;
    uint8 constant ACTION_DELETE = 0x04;

    function _getDID(DID memory identity) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    DID_TYPEHASH,
                    keccak256(bytes(identity.id)),
                    identity.ethereumAddress
                )
            );
    }

    function _getProof(Signature memory proof) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(SIGNATURE_TYPEHASH, proof.v, proof.r, proof.s)
            );
    }

    function getVerifiablePresentation(VerifiablePresentation memory vp)
        internal
        pure
        returns (bytes32)
    {
        return
            keccak256(
                abi.encode(
                    VERIFIABLE_PRESENTATION_TYPEHASH,
                    getVerifiableCredential(vp.vc),
                    _getProof(vp.proof)
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
                    keccak256(bytes(vc.id)),
                    keccak256(bytes(vc.anchorCommit)),
                    _getDID(vc.issuer),
                    _getDID(vc.credentialSubject),
                    keccak256(bytes(vc.claimType)),
                    keccak256(bytes(vc.claimHash)),
                    vc.issuanceDate,
                    vc.expirationDate,
                    vc.trust,
                    vc.stake,
                    ACTION_ISSUE
                )
            );
    }

    function getRevokation(VerifiableCredential memory vc)
        internal
        pure
        returns (bytes32)
    {
        return
            keccak256(
                abi.encode(
                    VERIFIABLE_CREDENTIAL_TYPEHASH,
                    keccak256(bytes(vc.id)),
                    keccak256(bytes(vc.anchorCommit)),
                    _getDID(vc.issuer),
                    _getDID(vc.credentialSubject),
                    keccak256(bytes(vc.claimType)),
                    keccak256(bytes(vc.claimHash)),
                    vc.issuanceDate,
                    vc.expirationDate,
                    vc.trust,
                    vc.stake,
                    ACTION_REVOKE
                )
            );
    }

    function getSuspension(VerifiableCredential memory vc)
        internal
        pure
        returns (bytes32)
    {
        return
            keccak256(
                abi.encode(
                    VERIFIABLE_CREDENTIAL_TYPEHASH,
                    keccak256(bytes(vc.id)),
                    keccak256(bytes(vc.anchorCommit)),
                    _getDID(vc.issuer),
                    _getDID(vc.credentialSubject),
                    keccak256(bytes(vc.claimType)),
                    keccak256(bytes(vc.claimHash)),
                    vc.issuanceDate,
                    vc.expirationDate,
                    vc.trust,
                    vc.stake,
                    ACTION_SUSPEND
                )
            );
    }

    function getDeletion(VerifiableCredential memory vc)
        internal
        pure
        returns (bytes32)
    {
        return
            keccak256(
                abi.encode(
                    VERIFIABLE_CREDENTIAL_TYPEHASH,
                    keccak256(bytes(vc.id)),
                    keccak256(bytes(vc.anchorCommit)),
                    _getDID(vc.issuer),
                    _getDID(vc.credentialSubject),
                    keccak256(bytes(vc.claimType)),
                    keccak256(bytes(vc.claimHash)),
                    vc.issuanceDate,
                    vc.expirationDate,
                    vc.trust,
                    vc.stake,
                    ACTION_DELETE
                )
            );
    }
}
