using System;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Numerics;
using Nethereum.Hex.HexTypes;
using Nethereum.ABI.FunctionEncoding.Attributes;

namespace KrbContracts.Contracts.KRBTokenV01.ContractDefinition
{
    public partial class VerifiableCredential : VerifiableCredentialBase { }

    public class VerifiableCredentialBase 
    {
        [Parameter("string", "_context", 1)]
        public virtual string Context { get; set; }
        [Parameter("string", "_type", 2)]
        public virtual string Type { get; set; }
        [Parameter("string", "id", 3)]
        public virtual string Id { get; set; }
        [Parameter("tuple", "issuer", 4)]
        public virtual Issuer Issuer { get; set; }
        [Parameter("tuple", "credentialSubject", 5)]
        public virtual CredentialSubject CredentialSubject { get; set; }
        [Parameter("tuple", "credentialSchema", 6)]
        public virtual CredentialSchema CredentialSchema { get; set; }
        [Parameter("string", "issuanceDate", 7)]
        public virtual string IssuanceDate { get; set; }
        [Parameter("string", "expirationDate", 8)]
        public virtual string ExpirationDate { get; set; }
    }
}
