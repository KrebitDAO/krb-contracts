using System;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Numerics;
using Nethereum.Hex.HexTypes;
using Nethereum.ABI.FunctionEncoding.Attributes;

namespace KrbContracts.Contracts.KRBTokenV01.ContractDefinition
{
    public partial class Issuer : IssuerBase { }

    public class IssuerBase 
    {
        [Parameter("string", "id", 1)]
        public virtual string Id { get; set; }
        [Parameter("address", "ethereumAddress", 2)]
        public virtual string EthereumAddress { get; set; }
    }
}
