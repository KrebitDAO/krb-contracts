using System;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Numerics;
using Nethereum.Hex.HexTypes;
using Nethereum.ABI.FunctionEncoding.Attributes;

namespace KrbContracts.Contracts.KRBTokenV01.ContractDefinition
{
    public partial class CredentialSubject : CredentialSubjectBase { }

    public class CredentialSubjectBase 
    {
        [Parameter("string", "id", 1)]
        public virtual string Id { get; set; }
        [Parameter("address", "ethereumAddress", 2)]
        public virtual string EthereumAddress { get; set; }
        [Parameter("string", "_type", 3)]
        public virtual string Type { get; set; }
        [Parameter("string", "typeSchema", 4)]
        public virtual string TypeSchema { get; set; }
        [Parameter("string", "value", 5)]
        public virtual string Value { get; set; }
        [Parameter("string", "encrypted", 6)]
        public virtual string Encrypted { get; set; }
        [Parameter("uint8", "trust", 7)]
        public virtual byte Trust { get; set; }
        [Parameter("uint256", "stake", 8)]
        public virtual BigInteger Stake { get; set; }
        [Parameter("uint256", "price", 9)]
        public virtual BigInteger Price { get; set; }
        [Parameter("uint256", "nbf", 10)]
        public virtual BigInteger Nbf { get; set; }
        [Parameter("uint256", "exp", 11)]
        public virtual BigInteger Exp { get; set; }
    }
}
