using System;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Numerics;
using Nethereum.Hex.HexTypes;
using Nethereum.ABI.FunctionEncoding.Attributes;
using Nethereum.Web3;
using Nethereum.RPC.Eth.DTOs;
using Nethereum.Contracts.CQS;
using Nethereum.Contracts.ContractHandlers;
using Nethereum.Contracts;
using System.Threading;
using KrbContracts.Contracts.KRBTokenV01.ContractDefinition;

namespace KrbContracts.Contracts.KRBTokenV01
{
    public partial class KRBTokenV01Service
    {
        public static Task<TransactionReceipt> DeployContractAndWaitForReceiptAsync(Nethereum.Web3.Web3 web3, KRBTokenV01Deployment kRBTokenV01Deployment, CancellationTokenSource cancellationTokenSource = null)
        {
            return web3.Eth.GetContractDeploymentHandler<KRBTokenV01Deployment>().SendRequestAndWaitForReceiptAsync(kRBTokenV01Deployment, cancellationTokenSource);
        }

        public static Task<string> DeployContractAsync(Nethereum.Web3.Web3 web3, KRBTokenV01Deployment kRBTokenV01Deployment)
        {
            return web3.Eth.GetContractDeploymentHandler<KRBTokenV01Deployment>().SendRequestAsync(kRBTokenV01Deployment);
        }

        public static async Task<KRBTokenV01Service> DeployContractAndGetServiceAsync(Nethereum.Web3.Web3 web3, KRBTokenV01Deployment kRBTokenV01Deployment, CancellationTokenSource cancellationTokenSource = null)
        {
            var receipt = await DeployContractAndWaitForReceiptAsync(web3, kRBTokenV01Deployment, cancellationTokenSource);
            return new KRBTokenV01Service(web3, receipt.ContractAddress);
        }

        protected Nethereum.Web3.Web3 Web3{ get; }

        public ContractHandler ContractHandler { get; }

        public KRBTokenV01Service(Nethereum.Web3.Web3 web3, string contractAddress)
        {
            Web3 = web3;
            ContractHandler = web3.Eth.GetContractHandler(contractAddress);
        }

        public Task<byte[]> DefaultAdminRoleQueryAsync(DefaultAdminRoleFunction defaultAdminRoleFunction, BlockParameter blockParameter = null)
        {
            return ContractHandler.QueryAsync<DefaultAdminRoleFunction, byte[]>(defaultAdminRoleFunction, blockParameter);
        }

        
        public Task<byte[]> DefaultAdminRoleQueryAsync(BlockParameter blockParameter = null)
        {
            return ContractHandler.QueryAsync<DefaultAdminRoleFunction, byte[]>(null, blockParameter);
        }

        public Task<byte[]> DomainSeparatorQueryAsync(DomainSeparatorFunction domainSeparatorFunction, BlockParameter blockParameter = null)
        {
            return ContractHandler.QueryAsync<DomainSeparatorFunction, byte[]>(domainSeparatorFunction, blockParameter);
        }

        
        public Task<byte[]> DomainSeparatorQueryAsync(BlockParameter blockParameter = null)
        {
            return ContractHandler.QueryAsync<DomainSeparatorFunction, byte[]>(null, blockParameter);
        }

        public Task<byte[]> GovernRoleQueryAsync(GovernRoleFunction governRoleFunction, BlockParameter blockParameter = null)
        {
            return ContractHandler.QueryAsync<GovernRoleFunction, byte[]>(governRoleFunction, blockParameter);
        }

        
        public Task<byte[]> GovernRoleQueryAsync(BlockParameter blockParameter = null)
        {
            return ContractHandler.QueryAsync<GovernRoleFunction, byte[]>(null, blockParameter);
        }

        public Task<BigInteger> AllowanceQueryAsync(AllowanceFunction allowanceFunction, BlockParameter blockParameter = null)
        {
            return ContractHandler.QueryAsync<AllowanceFunction, BigInteger>(allowanceFunction, blockParameter);
        }

        
        public Task<BigInteger> AllowanceQueryAsync(string owner, string spender, BlockParameter blockParameter = null)
        {
            var allowanceFunction = new AllowanceFunction();
                allowanceFunction.Owner = owner;
                allowanceFunction.Spender = spender;
            
            return ContractHandler.QueryAsync<AllowanceFunction, BigInteger>(allowanceFunction, blockParameter);
        }

        public Task<string> ApproveRequestAsync(ApproveFunction approveFunction)
        {
             return ContractHandler.SendRequestAsync(approveFunction);
        }

        public Task<TransactionReceipt> ApproveRequestAndWaitForReceiptAsync(ApproveFunction approveFunction, CancellationTokenSource cancellationToken = null)
        {
             return ContractHandler.SendRequestAndWaitForReceiptAsync(approveFunction, cancellationToken);
        }

        public Task<string> ApproveRequestAsync(string spender, BigInteger amount)
        {
            var approveFunction = new ApproveFunction();
                approveFunction.Spender = spender;
                approveFunction.Amount = amount;
            
             return ContractHandler.SendRequestAsync(approveFunction);
        }

        public Task<TransactionReceipt> ApproveRequestAndWaitForReceiptAsync(string spender, BigInteger amount, CancellationTokenSource cancellationToken = null)
        {
            var approveFunction = new ApproveFunction();
                approveFunction.Spender = spender;
                approveFunction.Amount = amount;
            
             return ContractHandler.SendRequestAndWaitForReceiptAsync(approveFunction, cancellationToken);
        }

        public Task<BigInteger> BalanceOfQueryAsync(BalanceOfFunction balanceOfFunction, BlockParameter blockParameter = null)
        {
            return ContractHandler.QueryAsync<BalanceOfFunction, BigInteger>(balanceOfFunction, blockParameter);
        }

        
        public Task<BigInteger> BalanceOfQueryAsync(string account, BlockParameter blockParameter = null)
        {
            var balanceOfFunction = new BalanceOfFunction();
                balanceOfFunction.Account = account;
            
            return ContractHandler.QueryAsync<BalanceOfFunction, BigInteger>(balanceOfFunction, blockParameter);
        }

        public Task<string> BurnRequestAsync(BurnFunction burnFunction)
        {
             return ContractHandler.SendRequestAsync(burnFunction);
        }

        public Task<TransactionReceipt> BurnRequestAndWaitForReceiptAsync(BurnFunction burnFunction, CancellationTokenSource cancellationToken = null)
        {
             return ContractHandler.SendRequestAndWaitForReceiptAsync(burnFunction, cancellationToken);
        }

        public Task<string> BurnRequestAsync(BigInteger amount)
        {
            var burnFunction = new BurnFunction();
                burnFunction.Amount = amount;
            
             return ContractHandler.SendRequestAsync(burnFunction);
        }

        public Task<TransactionReceipt> BurnRequestAndWaitForReceiptAsync(BigInteger amount, CancellationTokenSource cancellationToken = null)
        {
            var burnFunction = new BurnFunction();
                burnFunction.Amount = amount;
            
             return ContractHandler.SendRequestAndWaitForReceiptAsync(burnFunction, cancellationToken);
        }

        public Task<string> BurnFromRequestAsync(BurnFromFunction burnFromFunction)
        {
             return ContractHandler.SendRequestAsync(burnFromFunction);
        }

        public Task<TransactionReceipt> BurnFromRequestAndWaitForReceiptAsync(BurnFromFunction burnFromFunction, CancellationTokenSource cancellationToken = null)
        {
             return ContractHandler.SendRequestAndWaitForReceiptAsync(burnFromFunction, cancellationToken);
        }

        public Task<string> BurnFromRequestAsync(string account, BigInteger amount)
        {
            var burnFromFunction = new BurnFromFunction();
                burnFromFunction.Account = account;
                burnFromFunction.Amount = amount;
            
             return ContractHandler.SendRequestAsync(burnFromFunction);
        }

        public Task<TransactionReceipt> BurnFromRequestAndWaitForReceiptAsync(string account, BigInteger amount, CancellationTokenSource cancellationToken = null)
        {
            var burnFromFunction = new BurnFromFunction();
                burnFromFunction.Account = account;
                burnFromFunction.Amount = amount;
            
             return ContractHandler.SendRequestAndWaitForReceiptAsync(burnFromFunction, cancellationToken);
        }

        public Task<string> BurnStakeRequestAsync(BurnStakeFunction burnStakeFunction)
        {
             return ContractHandler.SendRequestAsync(burnStakeFunction);
        }

        public Task<TransactionReceipt> BurnStakeRequestAndWaitForReceiptAsync(BurnStakeFunction burnStakeFunction, CancellationTokenSource cancellationToken = null)
        {
             return ContractHandler.SendRequestAndWaitForReceiptAsync(burnStakeFunction, cancellationToken);
        }

        public Task<string> BurnStakeRequestAsync(string issuer, BigInteger stake)
        {
            var burnStakeFunction = new BurnStakeFunction();
                burnStakeFunction.Issuer = issuer;
                burnStakeFunction.Stake = stake;
            
             return ContractHandler.SendRequestAsync(burnStakeFunction);
        }

        public Task<TransactionReceipt> BurnStakeRequestAndWaitForReceiptAsync(string issuer, BigInteger stake, CancellationTokenSource cancellationToken = null)
        {
            var burnStakeFunction = new BurnStakeFunction();
                burnStakeFunction.Issuer = issuer;
                burnStakeFunction.Stake = stake;
            
             return ContractHandler.SendRequestAndWaitForReceiptAsync(burnStakeFunction, cancellationToken);
        }

        public Task<byte> DecimalsQueryAsync(DecimalsFunction decimalsFunction, BlockParameter blockParameter = null)
        {
            return ContractHandler.QueryAsync<DecimalsFunction, byte>(decimalsFunction, blockParameter);
        }

        
        public Task<byte> DecimalsQueryAsync(BlockParameter blockParameter = null)
        {
            return ContractHandler.QueryAsync<DecimalsFunction, byte>(null, blockParameter);
        }

        public Task<string> DecreaseAllowanceRequestAsync(DecreaseAllowanceFunction decreaseAllowanceFunction)
        {
             return ContractHandler.SendRequestAsync(decreaseAllowanceFunction);
        }

        public Task<TransactionReceipt> DecreaseAllowanceRequestAndWaitForReceiptAsync(DecreaseAllowanceFunction decreaseAllowanceFunction, CancellationTokenSource cancellationToken = null)
        {
             return ContractHandler.SendRequestAndWaitForReceiptAsync(decreaseAllowanceFunction, cancellationToken);
        }

        public Task<string> DecreaseAllowanceRequestAsync(string spender, BigInteger subtractedValue)
        {
            var decreaseAllowanceFunction = new DecreaseAllowanceFunction();
                decreaseAllowanceFunction.Spender = spender;
                decreaseAllowanceFunction.SubtractedValue = subtractedValue;
            
             return ContractHandler.SendRequestAsync(decreaseAllowanceFunction);
        }

        public Task<TransactionReceipt> DecreaseAllowanceRequestAndWaitForReceiptAsync(string spender, BigInteger subtractedValue, CancellationTokenSource cancellationToken = null)
        {
            var decreaseAllowanceFunction = new DecreaseAllowanceFunction();
                decreaseAllowanceFunction.Spender = spender;
                decreaseAllowanceFunction.SubtractedValue = subtractedValue;
            
             return ContractHandler.SendRequestAndWaitForReceiptAsync(decreaseAllowanceFunction, cancellationToken);
        }

        public Task<string> DeleteVCRequestAsync(DeleteVCFunction deleteVCFunction)
        {
             return ContractHandler.SendRequestAsync(deleteVCFunction);
        }

        public Task<TransactionReceipt> DeleteVCRequestAndWaitForReceiptAsync(DeleteVCFunction deleteVCFunction, CancellationTokenSource cancellationToken = null)
        {
             return ContractHandler.SendRequestAndWaitForReceiptAsync(deleteVCFunction, cancellationToken);
        }

        public Task<string> DeleteVCRequestAsync(VerifiableCredential vc, string reason)
        {
            var deleteVCFunction = new DeleteVCFunction();
                deleteVCFunction.Vc = vc;
                deleteVCFunction.Reason = reason;
            
             return ContractHandler.SendRequestAsync(deleteVCFunction);
        }

        public Task<TransactionReceipt> DeleteVCRequestAndWaitForReceiptAsync(VerifiableCredential vc, string reason, CancellationTokenSource cancellationToken = null)
        {
            var deleteVCFunction = new DeleteVCFunction();
                deleteVCFunction.Vc = vc;
                deleteVCFunction.Reason = reason;
            
             return ContractHandler.SendRequestAndWaitForReceiptAsync(deleteVCFunction, cancellationToken);
        }

        public Task<string> DisputeVCByGovernRequestAsync(DisputeVCByGovernFunction disputeVCByGovernFunction)
        {
             return ContractHandler.SendRequestAsync(disputeVCByGovernFunction);
        }

        public Task<TransactionReceipt> DisputeVCByGovernRequestAndWaitForReceiptAsync(DisputeVCByGovernFunction disputeVCByGovernFunction, CancellationTokenSource cancellationToken = null)
        {
             return ContractHandler.SendRequestAndWaitForReceiptAsync(disputeVCByGovernFunction, cancellationToken);
        }

        public Task<string> DisputeVCByGovernRequestAsync(VerifiableCredential vc, VerifiableCredential disputeVC)
        {
            var disputeVCByGovernFunction = new DisputeVCByGovernFunction();
                disputeVCByGovernFunction.Vc = vc;
                disputeVCByGovernFunction.DisputeVC = disputeVC;
            
             return ContractHandler.SendRequestAsync(disputeVCByGovernFunction);
        }

        public Task<TransactionReceipt> DisputeVCByGovernRequestAndWaitForReceiptAsync(VerifiableCredential vc, VerifiableCredential disputeVC, CancellationTokenSource cancellationToken = null)
        {
            var disputeVCByGovernFunction = new DisputeVCByGovernFunction();
                disputeVCByGovernFunction.Vc = vc;
                disputeVCByGovernFunction.DisputeVC = disputeVC;
            
             return ContractHandler.SendRequestAndWaitForReceiptAsync(disputeVCByGovernFunction, cancellationToken);
        }

        public Task<string> ExpiredVCRequestAsync(ExpiredVCFunction expiredVCFunction)
        {
             return ContractHandler.SendRequestAsync(expiredVCFunction);
        }

        public Task<TransactionReceipt> ExpiredVCRequestAndWaitForReceiptAsync(ExpiredVCFunction expiredVCFunction, CancellationTokenSource cancellationToken = null)
        {
             return ContractHandler.SendRequestAndWaitForReceiptAsync(expiredVCFunction, cancellationToken);
        }

        public Task<string> ExpiredVCRequestAsync(VerifiableCredential vc)
        {
            var expiredVCFunction = new ExpiredVCFunction();
                expiredVCFunction.Vc = vc;
            
             return ContractHandler.SendRequestAsync(expiredVCFunction);
        }

        public Task<TransactionReceipt> ExpiredVCRequestAndWaitForReceiptAsync(VerifiableCredential vc, CancellationTokenSource cancellationToken = null)
        {
            var expiredVCFunction = new ExpiredVCFunction();
                expiredVCFunction.Vc = vc;
            
             return ContractHandler.SendRequestAndWaitForReceiptAsync(expiredVCFunction, cancellationToken);
        }

        public Task<BigInteger> FeePercentageQueryAsync(FeePercentageFunction feePercentageFunction, BlockParameter blockParameter = null)
        {
            return ContractHandler.QueryAsync<FeePercentageFunction, BigInteger>(feePercentageFunction, blockParameter);
        }

        
        public Task<BigInteger> FeePercentageQueryAsync(BlockParameter blockParameter = null)
        {
            return ContractHandler.QueryAsync<FeePercentageFunction, BigInteger>(null, blockParameter);
        }

        public Task<BigInteger> FeesAvailableForWithdrawQueryAsync(FeesAvailableForWithdrawFunction feesAvailableForWithdrawFunction, BlockParameter blockParameter = null)
        {
            return ContractHandler.QueryAsync<FeesAvailableForWithdrawFunction, BigInteger>(feesAvailableForWithdrawFunction, blockParameter);
        }

        
        public Task<BigInteger> FeesAvailableForWithdrawQueryAsync(BlockParameter blockParameter = null)
        {
            return ContractHandler.QueryAsync<FeesAvailableForWithdrawFunction, BigInteger>(null, blockParameter);
        }

        public Task<byte[]> GetRoleAdminQueryAsync(GetRoleAdminFunction getRoleAdminFunction, BlockParameter blockParameter = null)
        {
            return ContractHandler.QueryAsync<GetRoleAdminFunction, byte[]>(getRoleAdminFunction, blockParameter);
        }

        
        public Task<byte[]> GetRoleAdminQueryAsync(byte[] role, BlockParameter blockParameter = null)
        {
            var getRoleAdminFunction = new GetRoleAdminFunction();
                getRoleAdminFunction.Role = role;
            
            return ContractHandler.QueryAsync<GetRoleAdminFunction, byte[]>(getRoleAdminFunction, blockParameter);
        }

        public Task<string> GetRoleMemberQueryAsync(GetRoleMemberFunction getRoleMemberFunction, BlockParameter blockParameter = null)
        {
            return ContractHandler.QueryAsync<GetRoleMemberFunction, string>(getRoleMemberFunction, blockParameter);
        }

        
        public Task<string> GetRoleMemberQueryAsync(byte[] role, BigInteger index, BlockParameter blockParameter = null)
        {
            var getRoleMemberFunction = new GetRoleMemberFunction();
                getRoleMemberFunction.Role = role;
                getRoleMemberFunction.Index = index;
            
            return ContractHandler.QueryAsync<GetRoleMemberFunction, string>(getRoleMemberFunction, blockParameter);
        }

        public Task<BigInteger> GetRoleMemberCountQueryAsync(GetRoleMemberCountFunction getRoleMemberCountFunction, BlockParameter blockParameter = null)
        {
            return ContractHandler.QueryAsync<GetRoleMemberCountFunction, BigInteger>(getRoleMemberCountFunction, blockParameter);
        }

        
        public Task<BigInteger> GetRoleMemberCountQueryAsync(byte[] role, BlockParameter blockParameter = null)
        {
            var getRoleMemberCountFunction = new GetRoleMemberCountFunction();
                getRoleMemberCountFunction.Role = role;
            
            return ContractHandler.QueryAsync<GetRoleMemberCountFunction, BigInteger>(getRoleMemberCountFunction, blockParameter);
        }

        public Task<byte[]> GetUuidQueryAsync(GetUuidFunction getUuidFunction, BlockParameter blockParameter = null)
        {
            return ContractHandler.QueryAsync<GetUuidFunction, byte[]>(getUuidFunction, blockParameter);
        }

        
        public Task<byte[]> GetUuidQueryAsync(VerifiableCredential vc, BlockParameter blockParameter = null)
        {
            var getUuidFunction = new GetUuidFunction();
                getUuidFunction.Vc = vc;
            
            return ContractHandler.QueryAsync<GetUuidFunction, byte[]>(getUuidFunction, blockParameter);
        }

        public Task<string> GetVCStatusQueryAsync(GetVCStatusFunction getVCStatusFunction, BlockParameter blockParameter = null)
        {
            return ContractHandler.QueryAsync<GetVCStatusFunction, string>(getVCStatusFunction, blockParameter);
        }

        
        public Task<string> GetVCStatusQueryAsync(VerifiableCredential vc, BlockParameter blockParameter = null)
        {
            var getVCStatusFunction = new GetVCStatusFunction();
                getVCStatusFunction.Vc = vc;
            
            return ContractHandler.QueryAsync<GetVCStatusFunction, string>(getVCStatusFunction, blockParameter);
        }

        public Task<string> GrantRoleRequestAsync(GrantRoleFunction grantRoleFunction)
        {
             return ContractHandler.SendRequestAsync(grantRoleFunction);
        }

        public Task<TransactionReceipt> GrantRoleRequestAndWaitForReceiptAsync(GrantRoleFunction grantRoleFunction, CancellationTokenSource cancellationToken = null)
        {
             return ContractHandler.SendRequestAndWaitForReceiptAsync(grantRoleFunction, cancellationToken);
        }

        public Task<string> GrantRoleRequestAsync(byte[] role, string account)
        {
            var grantRoleFunction = new GrantRoleFunction();
                grantRoleFunction.Role = role;
                grantRoleFunction.Account = account;
            
             return ContractHandler.SendRequestAsync(grantRoleFunction);
        }

        public Task<TransactionReceipt> GrantRoleRequestAndWaitForReceiptAsync(byte[] role, string account, CancellationTokenSource cancellationToken = null)
        {
            var grantRoleFunction = new GrantRoleFunction();
                grantRoleFunction.Role = role;
                grantRoleFunction.Account = account;
            
             return ContractHandler.SendRequestAndWaitForReceiptAsync(grantRoleFunction, cancellationToken);
        }

        public Task<bool> HasRoleQueryAsync(HasRoleFunction hasRoleFunction, BlockParameter blockParameter = null)
        {
            return ContractHandler.QueryAsync<HasRoleFunction, bool>(hasRoleFunction, blockParameter);
        }

        
        public Task<bool> HasRoleQueryAsync(byte[] role, string account, BlockParameter blockParameter = null)
        {
            var hasRoleFunction = new HasRoleFunction();
                hasRoleFunction.Role = role;
                hasRoleFunction.Account = account;
            
            return ContractHandler.QueryAsync<HasRoleFunction, bool>(hasRoleFunction, blockParameter);
        }

        public Task<string> IncreaseAllowanceRequestAsync(IncreaseAllowanceFunction increaseAllowanceFunction)
        {
             return ContractHandler.SendRequestAsync(increaseAllowanceFunction);
        }

        public Task<TransactionReceipt> IncreaseAllowanceRequestAndWaitForReceiptAsync(IncreaseAllowanceFunction increaseAllowanceFunction, CancellationTokenSource cancellationToken = null)
        {
             return ContractHandler.SendRequestAndWaitForReceiptAsync(increaseAllowanceFunction, cancellationToken);
        }

        public Task<string> IncreaseAllowanceRequestAsync(string spender, BigInteger addedValue)
        {
            var increaseAllowanceFunction = new IncreaseAllowanceFunction();
                increaseAllowanceFunction.Spender = spender;
                increaseAllowanceFunction.AddedValue = addedValue;
            
             return ContractHandler.SendRequestAsync(increaseAllowanceFunction);
        }

        public Task<TransactionReceipt> IncreaseAllowanceRequestAndWaitForReceiptAsync(string spender, BigInteger addedValue, CancellationTokenSource cancellationToken = null)
        {
            var increaseAllowanceFunction = new IncreaseAllowanceFunction();
                increaseAllowanceFunction.Spender = spender;
                increaseAllowanceFunction.AddedValue = addedValue;
            
             return ContractHandler.SendRequestAndWaitForReceiptAsync(increaseAllowanceFunction, cancellationToken);
        }

        public Task<string> InitializeRequestAsync(InitializeFunction initializeFunction)
        {
             return ContractHandler.SendRequestAsync(initializeFunction);
        }

        public Task<TransactionReceipt> InitializeRequestAndWaitForReceiptAsync(InitializeFunction initializeFunction, CancellationTokenSource cancellationToken = null)
        {
             return ContractHandler.SendRequestAndWaitForReceiptAsync(initializeFunction, cancellationToken);
        }

        public Task<string> InitializeRequestAsync(string name, string symbol, string version)
        {
            var initializeFunction = new InitializeFunction();
                initializeFunction.Name = name;
                initializeFunction.Symbol = symbol;
                initializeFunction.Version = version;
            
             return ContractHandler.SendRequestAsync(initializeFunction);
        }

        public Task<TransactionReceipt> InitializeRequestAndWaitForReceiptAsync(string name, string symbol, string version, CancellationTokenSource cancellationToken = null)
        {
            var initializeFunction = new InitializeFunction();
                initializeFunction.Name = name;
                initializeFunction.Symbol = symbol;
                initializeFunction.Version = version;
            
             return ContractHandler.SendRequestAndWaitForReceiptAsync(initializeFunction, cancellationToken);
        }

        public Task<BigInteger> MaxStakeToIssueQueryAsync(MaxStakeToIssueFunction maxStakeToIssueFunction, BlockParameter blockParameter = null)
        {
            return ContractHandler.QueryAsync<MaxStakeToIssueFunction, BigInteger>(maxStakeToIssueFunction, blockParameter);
        }

        
        public Task<BigInteger> MaxStakeToIssueQueryAsync(BlockParameter blockParameter = null)
        {
            return ContractHandler.QueryAsync<MaxStakeToIssueFunction, BigInteger>(null, blockParameter);
        }

        public Task<BigInteger> MinBalanceToIssueQueryAsync(MinBalanceToIssueFunction minBalanceToIssueFunction, BlockParameter blockParameter = null)
        {
            return ContractHandler.QueryAsync<MinBalanceToIssueFunction, BigInteger>(minBalanceToIssueFunction, blockParameter);
        }

        
        public Task<BigInteger> MinBalanceToIssueQueryAsync(BlockParameter blockParameter = null)
        {
            return ContractHandler.QueryAsync<MinBalanceToIssueFunction, BigInteger>(null, blockParameter);
        }

        public Task<BigInteger> MinBalanceToReceiveQueryAsync(MinBalanceToReceiveFunction minBalanceToReceiveFunction, BlockParameter blockParameter = null)
        {
            return ContractHandler.QueryAsync<MinBalanceToReceiveFunction, BigInteger>(minBalanceToReceiveFunction, blockParameter);
        }

        
        public Task<BigInteger> MinBalanceToReceiveQueryAsync(BlockParameter blockParameter = null)
        {
            return ContractHandler.QueryAsync<MinBalanceToReceiveFunction, BigInteger>(null, blockParameter);
        }

        public Task<BigInteger> MinBalanceToTransferQueryAsync(MinBalanceToTransferFunction minBalanceToTransferFunction, BlockParameter blockParameter = null)
        {
            return ContractHandler.QueryAsync<MinBalanceToTransferFunction, BigInteger>(minBalanceToTransferFunction, blockParameter);
        }

        
        public Task<BigInteger> MinBalanceToTransferQueryAsync(BlockParameter blockParameter = null)
        {
            return ContractHandler.QueryAsync<MinBalanceToTransferFunction, BigInteger>(null, blockParameter);
        }

        public Task<BigInteger> MinPriceToIssueQueryAsync(MinPriceToIssueFunction minPriceToIssueFunction, BlockParameter blockParameter = null)
        {
            return ContractHandler.QueryAsync<MinPriceToIssueFunction, BigInteger>(minPriceToIssueFunction, blockParameter);
        }

        
        public Task<BigInteger> MinPriceToIssueQueryAsync(BlockParameter blockParameter = null)
        {
            return ContractHandler.QueryAsync<MinPriceToIssueFunction, BigInteger>(null, blockParameter);
        }

        public Task<BigInteger> MinStakeToIssueQueryAsync(MinStakeToIssueFunction minStakeToIssueFunction, BlockParameter blockParameter = null)
        {
            return ContractHandler.QueryAsync<MinStakeToIssueFunction, BigInteger>(minStakeToIssueFunction, blockParameter);
        }

        
        public Task<BigInteger> MinStakeToIssueQueryAsync(BlockParameter blockParameter = null)
        {
            return ContractHandler.QueryAsync<MinStakeToIssueFunction, BigInteger>(null, blockParameter);
        }

        public Task<string> MintRequestAsync(MintFunction mintFunction)
        {
             return ContractHandler.SendRequestAsync(mintFunction);
        }

        public Task<TransactionReceipt> MintRequestAndWaitForReceiptAsync(MintFunction mintFunction, CancellationTokenSource cancellationToken = null)
        {
             return ContractHandler.SendRequestAndWaitForReceiptAsync(mintFunction, cancellationToken);
        }

        public Task<string> MintRequestAsync(string to, BigInteger amount)
        {
            var mintFunction = new MintFunction();
                mintFunction.To = to;
                mintFunction.Amount = amount;
            
             return ContractHandler.SendRequestAsync(mintFunction);
        }

        public Task<TransactionReceipt> MintRequestAndWaitForReceiptAsync(string to, BigInteger amount, CancellationTokenSource cancellationToken = null)
        {
            var mintFunction = new MintFunction();
                mintFunction.To = to;
                mintFunction.Amount = amount;
            
             return ContractHandler.SendRequestAndWaitForReceiptAsync(mintFunction, cancellationToken);
        }

        public Task<string> NameQueryAsync(NameFunction nameFunction, BlockParameter blockParameter = null)
        {
            return ContractHandler.QueryAsync<NameFunction, string>(nameFunction, blockParameter);
        }

        
        public Task<string> NameQueryAsync(BlockParameter blockParameter = null)
        {
            return ContractHandler.QueryAsync<NameFunction, string>(null, blockParameter);
        }

        public Task<string> PauseRequestAsync(PauseFunction pauseFunction)
        {
             return ContractHandler.SendRequestAsync(pauseFunction);
        }

        public Task<string> PauseRequestAsync()
        {
             return ContractHandler.SendRequestAsync<PauseFunction>();
        }

        public Task<TransactionReceipt> PauseRequestAndWaitForReceiptAsync(PauseFunction pauseFunction, CancellationTokenSource cancellationToken = null)
        {
             return ContractHandler.SendRequestAndWaitForReceiptAsync(pauseFunction, cancellationToken);
        }

        public Task<TransactionReceipt> PauseRequestAndWaitForReceiptAsync(CancellationTokenSource cancellationToken = null)
        {
             return ContractHandler.SendRequestAndWaitForReceiptAsync<PauseFunction>(null, cancellationToken);
        }

        public Task<bool> PausedQueryAsync(PausedFunction pausedFunction, BlockParameter blockParameter = null)
        {
            return ContractHandler.QueryAsync<PausedFunction, bool>(pausedFunction, blockParameter);
        }

        
        public Task<bool> PausedQueryAsync(BlockParameter blockParameter = null)
        {
            return ContractHandler.QueryAsync<PausedFunction, bool>(null, blockParameter);
        }

        public Task<BigInteger> PaymentsQueryAsync(PaymentsFunction paymentsFunction, BlockParameter blockParameter = null)
        {
            return ContractHandler.QueryAsync<PaymentsFunction, BigInteger>(paymentsFunction, blockParameter);
        }

        
        public Task<BigInteger> PaymentsQueryAsync(string dest, BlockParameter blockParameter = null)
        {
            var paymentsFunction = new PaymentsFunction();
                paymentsFunction.Dest = dest;
            
            return ContractHandler.QueryAsync<PaymentsFunction, BigInteger>(paymentsFunction, blockParameter);
        }

        public Task<string> RegisterVCRequestAsync(RegisterVCFunction registerVCFunction)
        {
             return ContractHandler.SendRequestAsync(registerVCFunction);
        }

        public Task<TransactionReceipt> RegisterVCRequestAndWaitForReceiptAsync(RegisterVCFunction registerVCFunction, CancellationTokenSource cancellationToken = null)
        {
             return ContractHandler.SendRequestAndWaitForReceiptAsync(registerVCFunction, cancellationToken);
        }

        public Task<string> RegisterVCRequestAsync(VerifiableCredential vc, byte[] proofValue)
        {
            var registerVCFunction = new RegisterVCFunction();
                registerVCFunction.Vc = vc;
                registerVCFunction.ProofValue = proofValue;
            
             return ContractHandler.SendRequestAsync(registerVCFunction);
        }

        public Task<TransactionReceipt> RegisterVCRequestAndWaitForReceiptAsync(VerifiableCredential vc, byte[] proofValue, CancellationTokenSource cancellationToken = null)
        {
            var registerVCFunction = new RegisterVCFunction();
                registerVCFunction.Vc = vc;
                registerVCFunction.ProofValue = proofValue;
            
             return ContractHandler.SendRequestAndWaitForReceiptAsync(registerVCFunction, cancellationToken);
        }

        public Task<RegistryOutputDTO> RegistryQueryAsync(RegistryFunction registryFunction, BlockParameter blockParameter = null)
        {
            return ContractHandler.QueryDeserializingToObjectAsync<RegistryFunction, RegistryOutputDTO>(registryFunction, blockParameter);
        }

        public Task<RegistryOutputDTO> RegistryQueryAsync(byte[] returnValue1, BlockParameter blockParameter = null)
        {
            var registryFunction = new RegistryFunction();
                registryFunction.ReturnValue1 = returnValue1;
            
            return ContractHandler.QueryDeserializingToObjectAsync<RegistryFunction, RegistryOutputDTO>(registryFunction, blockParameter);
        }

        public Task<string> RenounceRoleRequestAsync(RenounceRoleFunction renounceRoleFunction)
        {
             return ContractHandler.SendRequestAsync(renounceRoleFunction);
        }

        public Task<TransactionReceipt> RenounceRoleRequestAndWaitForReceiptAsync(RenounceRoleFunction renounceRoleFunction, CancellationTokenSource cancellationToken = null)
        {
             return ContractHandler.SendRequestAndWaitForReceiptAsync(renounceRoleFunction, cancellationToken);
        }

        public Task<string> RenounceRoleRequestAsync(byte[] role, string account)
        {
            var renounceRoleFunction = new RenounceRoleFunction();
                renounceRoleFunction.Role = role;
                renounceRoleFunction.Account = account;
            
             return ContractHandler.SendRequestAsync(renounceRoleFunction);
        }

        public Task<TransactionReceipt> RenounceRoleRequestAndWaitForReceiptAsync(byte[] role, string account, CancellationTokenSource cancellationToken = null)
        {
            var renounceRoleFunction = new RenounceRoleFunction();
                renounceRoleFunction.Role = role;
                renounceRoleFunction.Account = account;
            
             return ContractHandler.SendRequestAndWaitForReceiptAsync(renounceRoleFunction, cancellationToken);
        }

        public Task<string> RevokeRoleRequestAsync(RevokeRoleFunction revokeRoleFunction)
        {
             return ContractHandler.SendRequestAsync(revokeRoleFunction);
        }

        public Task<TransactionReceipt> RevokeRoleRequestAndWaitForReceiptAsync(RevokeRoleFunction revokeRoleFunction, CancellationTokenSource cancellationToken = null)
        {
             return ContractHandler.SendRequestAndWaitForReceiptAsync(revokeRoleFunction, cancellationToken);
        }

        public Task<string> RevokeRoleRequestAsync(byte[] role, string account)
        {
            var revokeRoleFunction = new RevokeRoleFunction();
                revokeRoleFunction.Role = role;
                revokeRoleFunction.Account = account;
            
             return ContractHandler.SendRequestAsync(revokeRoleFunction);
        }

        public Task<TransactionReceipt> RevokeRoleRequestAndWaitForReceiptAsync(byte[] role, string account, CancellationTokenSource cancellationToken = null)
        {
            var revokeRoleFunction = new RevokeRoleFunction();
                revokeRoleFunction.Role = role;
                revokeRoleFunction.Account = account;
            
             return ContractHandler.SendRequestAndWaitForReceiptAsync(revokeRoleFunction, cancellationToken);
        }

        public Task<string> RevokeVCRequestAsync(RevokeVCFunction revokeVCFunction)
        {
             return ContractHandler.SendRequestAsync(revokeVCFunction);
        }

        public Task<TransactionReceipt> RevokeVCRequestAndWaitForReceiptAsync(RevokeVCFunction revokeVCFunction, CancellationTokenSource cancellationToken = null)
        {
             return ContractHandler.SendRequestAndWaitForReceiptAsync(revokeVCFunction, cancellationToken);
        }

        public Task<string> RevokeVCRequestAsync(VerifiableCredential vc, string reason)
        {
            var revokeVCFunction = new RevokeVCFunction();
                revokeVCFunction.Vc = vc;
                revokeVCFunction.Reason = reason;
            
             return ContractHandler.SendRequestAsync(revokeVCFunction);
        }

        public Task<TransactionReceipt> RevokeVCRequestAndWaitForReceiptAsync(VerifiableCredential vc, string reason, CancellationTokenSource cancellationToken = null)
        {
            var revokeVCFunction = new RevokeVCFunction();
                revokeVCFunction.Vc = vc;
                revokeVCFunction.Reason = reason;
            
             return ContractHandler.SendRequestAndWaitForReceiptAsync(revokeVCFunction, cancellationToken);
        }

        public Task<BigInteger> StakeOfQueryAsync(StakeOfFunction stakeOfFunction, BlockParameter blockParameter = null)
        {
            return ContractHandler.QueryAsync<StakeOfFunction, BigInteger>(stakeOfFunction, blockParameter);
        }

        
        public Task<BigInteger> StakeOfQueryAsync(string issuer, BlockParameter blockParameter = null)
        {
            var stakeOfFunction = new StakeOfFunction();
                stakeOfFunction.Issuer = issuer;
            
            return ContractHandler.QueryAsync<StakeOfFunction, BigInteger>(stakeOfFunction, blockParameter);
        }

        public Task<bool> SupportsInterfaceQueryAsync(SupportsInterfaceFunction supportsInterfaceFunction, BlockParameter blockParameter = null)
        {
            return ContractHandler.QueryAsync<SupportsInterfaceFunction, bool>(supportsInterfaceFunction, blockParameter);
        }

        
        public Task<bool> SupportsInterfaceQueryAsync(byte[] interfaceId, BlockParameter blockParameter = null)
        {
            var supportsInterfaceFunction = new SupportsInterfaceFunction();
                supportsInterfaceFunction.InterfaceId = interfaceId;
            
            return ContractHandler.QueryAsync<SupportsInterfaceFunction, bool>(supportsInterfaceFunction, blockParameter);
        }

        public Task<string> SuspendVCRequestAsync(SuspendVCFunction suspendVCFunction)
        {
             return ContractHandler.SendRequestAsync(suspendVCFunction);
        }

        public Task<TransactionReceipt> SuspendVCRequestAndWaitForReceiptAsync(SuspendVCFunction suspendVCFunction, CancellationTokenSource cancellationToken = null)
        {
             return ContractHandler.SendRequestAndWaitForReceiptAsync(suspendVCFunction, cancellationToken);
        }

        public Task<string> SuspendVCRequestAsync(VerifiableCredential vc, string reason)
        {
            var suspendVCFunction = new SuspendVCFunction();
                suspendVCFunction.Vc = vc;
                suspendVCFunction.Reason = reason;
            
             return ContractHandler.SendRequestAsync(suspendVCFunction);
        }

        public Task<TransactionReceipt> SuspendVCRequestAndWaitForReceiptAsync(VerifiableCredential vc, string reason, CancellationTokenSource cancellationToken = null)
        {
            var suspendVCFunction = new SuspendVCFunction();
                suspendVCFunction.Vc = vc;
                suspendVCFunction.Reason = reason;
            
             return ContractHandler.SendRequestAndWaitForReceiptAsync(suspendVCFunction, cancellationToken);
        }

        public Task<string> SymbolQueryAsync(SymbolFunction symbolFunction, BlockParameter blockParameter = null)
        {
            return ContractHandler.QueryAsync<SymbolFunction, string>(symbolFunction, blockParameter);
        }

        
        public Task<string> SymbolQueryAsync(BlockParameter blockParameter = null)
        {
            return ContractHandler.QueryAsync<SymbolFunction, string>(null, blockParameter);
        }

        public Task<BigInteger> TotalSupplyQueryAsync(TotalSupplyFunction totalSupplyFunction, BlockParameter blockParameter = null)
        {
            return ContractHandler.QueryAsync<TotalSupplyFunction, BigInteger>(totalSupplyFunction, blockParameter);
        }

        
        public Task<BigInteger> TotalSupplyQueryAsync(BlockParameter blockParameter = null)
        {
            return ContractHandler.QueryAsync<TotalSupplyFunction, BigInteger>(null, blockParameter);
        }

        public Task<string> TransferRequestAsync(TransferFunction transferFunction)
        {
             return ContractHandler.SendRequestAsync(transferFunction);
        }

        public Task<TransactionReceipt> TransferRequestAndWaitForReceiptAsync(TransferFunction transferFunction, CancellationTokenSource cancellationToken = null)
        {
             return ContractHandler.SendRequestAndWaitForReceiptAsync(transferFunction, cancellationToken);
        }

        public Task<string> TransferRequestAsync(string recipient, BigInteger amount)
        {
            var transferFunction = new TransferFunction();
                transferFunction.Recipient = recipient;
                transferFunction.Amount = amount;
            
             return ContractHandler.SendRequestAsync(transferFunction);
        }

        public Task<TransactionReceipt> TransferRequestAndWaitForReceiptAsync(string recipient, BigInteger amount, CancellationTokenSource cancellationToken = null)
        {
            var transferFunction = new TransferFunction();
                transferFunction.Recipient = recipient;
                transferFunction.Amount = amount;
            
             return ContractHandler.SendRequestAndWaitForReceiptAsync(transferFunction, cancellationToken);
        }

        public Task<string> TransferFromRequestAsync(TransferFromFunction transferFromFunction)
        {
             return ContractHandler.SendRequestAsync(transferFromFunction);
        }

        public Task<TransactionReceipt> TransferFromRequestAndWaitForReceiptAsync(TransferFromFunction transferFromFunction, CancellationTokenSource cancellationToken = null)
        {
             return ContractHandler.SendRequestAndWaitForReceiptAsync(transferFromFunction, cancellationToken);
        }

        public Task<string> TransferFromRequestAsync(string sender, string recipient, BigInteger amount)
        {
            var transferFromFunction = new TransferFromFunction();
                transferFromFunction.Sender = sender;
                transferFromFunction.Recipient = recipient;
                transferFromFunction.Amount = amount;
            
             return ContractHandler.SendRequestAsync(transferFromFunction);
        }

        public Task<TransactionReceipt> TransferFromRequestAndWaitForReceiptAsync(string sender, string recipient, BigInteger amount, CancellationTokenSource cancellationToken = null)
        {
            var transferFromFunction = new TransferFromFunction();
                transferFromFunction.Sender = sender;
                transferFromFunction.Recipient = recipient;
                transferFromFunction.Amount = amount;
            
             return ContractHandler.SendRequestAndWaitForReceiptAsync(transferFromFunction, cancellationToken);
        }

        public Task<string> UnpauseRequestAsync(UnpauseFunction unpauseFunction)
        {
             return ContractHandler.SendRequestAsync(unpauseFunction);
        }

        public Task<string> UnpauseRequestAsync()
        {
             return ContractHandler.SendRequestAsync<UnpauseFunction>();
        }

        public Task<TransactionReceipt> UnpauseRequestAndWaitForReceiptAsync(UnpauseFunction unpauseFunction, CancellationTokenSource cancellationToken = null)
        {
             return ContractHandler.SendRequestAndWaitForReceiptAsync(unpauseFunction, cancellationToken);
        }

        public Task<TransactionReceipt> UnpauseRequestAndWaitForReceiptAsync(CancellationTokenSource cancellationToken = null)
        {
             return ContractHandler.SendRequestAndWaitForReceiptAsync<UnpauseFunction>(null, cancellationToken);
        }

        public Task<string> UpdateParametersRequestAsync(UpdateParametersFunction updateParametersFunction)
        {
             return ContractHandler.SendRequestAsync(updateParametersFunction);
        }

        public Task<TransactionReceipt> UpdateParametersRequestAndWaitForReceiptAsync(UpdateParametersFunction updateParametersFunction, CancellationTokenSource cancellationToken = null)
        {
             return ContractHandler.SendRequestAndWaitForReceiptAsync(updateParametersFunction, cancellationToken);
        }

        public Task<string> UpdateParametersRequestAsync(BigInteger newMinBalanceToTransfer, BigInteger newMinBalanceToReceive, BigInteger newMinBalanceToIssue, BigInteger newFeePercentage, BigInteger newMinPrice, BigInteger newMinStake, BigInteger newMaxStake)
        {
            var updateParametersFunction = new UpdateParametersFunction();
                updateParametersFunction.NewMinBalanceToTransfer = newMinBalanceToTransfer;
                updateParametersFunction.NewMinBalanceToReceive = newMinBalanceToReceive;
                updateParametersFunction.NewMinBalanceToIssue = newMinBalanceToIssue;
                updateParametersFunction.NewFeePercentage = newFeePercentage;
                updateParametersFunction.NewMinPrice = newMinPrice;
                updateParametersFunction.NewMinStake = newMinStake;
                updateParametersFunction.NewMaxStake = newMaxStake;
            
             return ContractHandler.SendRequestAsync(updateParametersFunction);
        }

        public Task<TransactionReceipt> UpdateParametersRequestAndWaitForReceiptAsync(BigInteger newMinBalanceToTransfer, BigInteger newMinBalanceToReceive, BigInteger newMinBalanceToIssue, BigInteger newFeePercentage, BigInteger newMinPrice, BigInteger newMinStake, BigInteger newMaxStake, CancellationTokenSource cancellationToken = null)
        {
            var updateParametersFunction = new UpdateParametersFunction();
                updateParametersFunction.NewMinBalanceToTransfer = newMinBalanceToTransfer;
                updateParametersFunction.NewMinBalanceToReceive = newMinBalanceToReceive;
                updateParametersFunction.NewMinBalanceToIssue = newMinBalanceToIssue;
                updateParametersFunction.NewFeePercentage = newFeePercentage;
                updateParametersFunction.NewMinPrice = newMinPrice;
                updateParametersFunction.NewMinStake = newMinStake;
                updateParametersFunction.NewMaxStake = newMaxStake;
            
             return ContractHandler.SendRequestAndWaitForReceiptAsync(updateParametersFunction, cancellationToken);
        }

        public Task<string> UpgradeToRequestAsync(UpgradeToFunction upgradeToFunction)
        {
             return ContractHandler.SendRequestAsync(upgradeToFunction);
        }

        public Task<TransactionReceipt> UpgradeToRequestAndWaitForReceiptAsync(UpgradeToFunction upgradeToFunction, CancellationTokenSource cancellationToken = null)
        {
             return ContractHandler.SendRequestAndWaitForReceiptAsync(upgradeToFunction, cancellationToken);
        }

        public Task<string> UpgradeToRequestAsync(string newImplementation)
        {
            var upgradeToFunction = new UpgradeToFunction();
                upgradeToFunction.NewImplementation = newImplementation;
            
             return ContractHandler.SendRequestAsync(upgradeToFunction);
        }

        public Task<TransactionReceipt> UpgradeToRequestAndWaitForReceiptAsync(string newImplementation, CancellationTokenSource cancellationToken = null)
        {
            var upgradeToFunction = new UpgradeToFunction();
                upgradeToFunction.NewImplementation = newImplementation;
            
             return ContractHandler.SendRequestAndWaitForReceiptAsync(upgradeToFunction, cancellationToken);
        }

        public Task<string> UpgradeToAndCallRequestAsync(UpgradeToAndCallFunction upgradeToAndCallFunction)
        {
             return ContractHandler.SendRequestAsync(upgradeToAndCallFunction);
        }

        public Task<TransactionReceipt> UpgradeToAndCallRequestAndWaitForReceiptAsync(UpgradeToAndCallFunction upgradeToAndCallFunction, CancellationTokenSource cancellationToken = null)
        {
             return ContractHandler.SendRequestAndWaitForReceiptAsync(upgradeToAndCallFunction, cancellationToken);
        }

        public Task<string> UpgradeToAndCallRequestAsync(string newImplementation, byte[] data)
        {
            var upgradeToAndCallFunction = new UpgradeToAndCallFunction();
                upgradeToAndCallFunction.NewImplementation = newImplementation;
                upgradeToAndCallFunction.Data = data;
            
             return ContractHandler.SendRequestAsync(upgradeToAndCallFunction);
        }

        public Task<TransactionReceipt> UpgradeToAndCallRequestAndWaitForReceiptAsync(string newImplementation, byte[] data, CancellationTokenSource cancellationToken = null)
        {
            var upgradeToAndCallFunction = new UpgradeToAndCallFunction();
                upgradeToAndCallFunction.NewImplementation = newImplementation;
                upgradeToAndCallFunction.Data = data;
            
             return ContractHandler.SendRequestAndWaitForReceiptAsync(upgradeToAndCallFunction, cancellationToken);
        }

        public Task<string> WithdrawFeesRequestAsync(WithdrawFeesFunction withdrawFeesFunction)
        {
             return ContractHandler.SendRequestAsync(withdrawFeesFunction);
        }

        public Task<TransactionReceipt> WithdrawFeesRequestAndWaitForReceiptAsync(WithdrawFeesFunction withdrawFeesFunction, CancellationTokenSource cancellationToken = null)
        {
             return ContractHandler.SendRequestAndWaitForReceiptAsync(withdrawFeesFunction, cancellationToken);
        }

        public Task<string> WithdrawFeesRequestAsync(string to, BigInteger amount)
        {
            var withdrawFeesFunction = new WithdrawFeesFunction();
                withdrawFeesFunction.To = to;
                withdrawFeesFunction.Amount = amount;
            
             return ContractHandler.SendRequestAsync(withdrawFeesFunction);
        }

        public Task<TransactionReceipt> WithdrawFeesRequestAndWaitForReceiptAsync(string to, BigInteger amount, CancellationTokenSource cancellationToken = null)
        {
            var withdrawFeesFunction = new WithdrawFeesFunction();
                withdrawFeesFunction.To = to;
                withdrawFeesFunction.Amount = amount;
            
             return ContractHandler.SendRequestAndWaitForReceiptAsync(withdrawFeesFunction, cancellationToken);
        }

        public Task<string> WithdrawPaymentsRequestAsync(WithdrawPaymentsFunction withdrawPaymentsFunction)
        {
             return ContractHandler.SendRequestAsync(withdrawPaymentsFunction);
        }

        public Task<TransactionReceipt> WithdrawPaymentsRequestAndWaitForReceiptAsync(WithdrawPaymentsFunction withdrawPaymentsFunction, CancellationTokenSource cancellationToken = null)
        {
             return ContractHandler.SendRequestAndWaitForReceiptAsync(withdrawPaymentsFunction, cancellationToken);
        }

        public Task<string> WithdrawPaymentsRequestAsync(string payee)
        {
            var withdrawPaymentsFunction = new WithdrawPaymentsFunction();
                withdrawPaymentsFunction.Payee = payee;
            
             return ContractHandler.SendRequestAsync(withdrawPaymentsFunction);
        }

        public Task<TransactionReceipt> WithdrawPaymentsRequestAndWaitForReceiptAsync(string payee, CancellationTokenSource cancellationToken = null)
        {
            var withdrawPaymentsFunction = new WithdrawPaymentsFunction();
                withdrawPaymentsFunction.Payee = payee;
            
             return ContractHandler.SendRequestAndWaitForReceiptAsync(withdrawPaymentsFunction, cancellationToken);
        }
    }
}
