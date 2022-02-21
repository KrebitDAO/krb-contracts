
{ERC20} token, including:

 - ability for holders to burn (destroy) their tokens
 - a govern role that allows for token minting (creation)
 - a govern role that allows to stop all token transfers
 - ERC-3009 transferWithAuthorization()
 - minBalanceToTransfer
 - minBalanceToReceive
 - burnWithAuthorization()

This contract uses {AccessControl} to lock permissioned functions using the
different roles:

The account that deploys the contract will be granted the govern role,
as well as the default admin role, which will let it grant govern roles
to other accounts.

## Functions
### initialize
```solidity
  function initialize(
  ) public
```




### constructor
```solidity
  function constructor(
  ) public
```




### __KRBTokenV01_init
```solidity
  function __KRBTokenV01_init(
  ) internal
```

Grants `DEFAULT_ADMIN_ROLE`, `GOVERN_ROLE` and `PAUSER_ROLE` to the
account that deploys the contract.

See {ERC20-constructor}.


### __KRBTokenV01_init_unchained
```solidity
  function __KRBTokenV01_init_unchained(
  ) internal
```




### _authorizeUpgrade
```solidity
  function _authorizeUpgrade(
  ) internal
```

Function that should revert when `msg.sender` is not authorized to upgrade the contract. Called by
{upgradeTo} and {upgradeToAndCall}.

See {UUPSUpgradeable-_authorizeUpgrade}.

Requirements:

- the caller must have the `GOVERN_ROLE`.


### updateMinBalanceToTransfer
```solidity
  function updateMinBalanceToTransfer(
  ) public
```

Updates `minBalanceToTransfer` to `newMinBalance`.


Requirements:

- the caller must have the `GOVERN_ROLE`.


### updateMinBalanceToReceive
```solidity
  function updateMinBalanceToReceive(
  ) public
```

Updates `minBalanceToReceive` to `newMinBalance`.


Requirements:

- the caller must have the `GOVERN_ROLE`.


### _beforeTokenTransfer
```solidity
  function _beforeTokenTransfer(
  ) internal
```

Checks min balances before Issue / Mint / Transfer.


Requirements:

- the caller must have the `GOVERN_ROLE`.


### mint
```solidity
  function mint(
  ) public
```

Creates `amount` new tokens for `to`.

See {ERC20-_mint}.

Requirements:

- the caller must have the `GOVERN_ROLE`.


### pause
```solidity
  function pause(
  ) public
```

Pauses all token transfers.

See {ERC20Pausable} and {Pausable-_pause}.

Requirements:

- the caller must have the `PAUSER_ROLE`.


### unpause
```solidity
  function unpause(
  ) public
```

Unpauses all token transfers.

See {ERC20Pausable} and {Pausable-_unpause}.

Requirements:

- the caller must have the `PAUSER_ROLE`.


### DOMAIN_SEPARATOR
```solidity
  function DOMAIN_SEPARATOR(
  ) external returns (bytes32)
```

Returns the domain separator for the current chain.

See {IERC20Permit-DOMAIN_SEPARATOR}.


### validateSignedData
```solidity
  function validateSignedData(
  ) internal
```

Checks if the provided address signed a hashed message (`hash`) with
`signature`.

See  {EIP-712} and {ERC-3009}.



### validateSignedData
```solidity
  function validateSignedData(
  ) internal
```

Checks if the provided address signed a hashed message (`hash`) with
`signature`.

See  {EIP-712} and {EIP-3009}.



### updateFeePercentage
```solidity
  function updateFeePercentage(
  ) public
```

Updates `feePercentage` to `newFeePercentage`.


Requirements:

- the caller must have the `GOVERN_ROLE`.


### updateMinBalanceToIssue
```solidity
  function updateMinBalanceToIssue(
  ) public
```

Updates `minBalanceToIssue` to `newMinBalance`.


Requirements:

- the caller must have the `GOVERN_ROLE`.


### updateStakeToIssue
```solidity
  function updateStakeToIssue(
  ) public
```

Updates `minStakeToIssue` and `maxStakeToIssue`.


Requirements:

- the caller must have the `GOVERN_ROLE`.
- newMaxStake > newMinStake


### _validateVC
```solidity
  function _validateVC(
  ) internal
```

Validates that the `VerifiableCredential` conforms to the Krebit Protocol.




### _getReward
```solidity
  function _getReward(
  ) internal returns (uint256)
```

Calculates the KRB reward as defined by tht Krebit Protocol
Formula:  Krebit = Risk * Trust %




### _getFee
```solidity
  function _getFee(
  ) internal returns (uint256)
```

Calculates the ETH fee as percentage of price
Formula:  fee = price * feePercentage %




### getUuid
```solidity
  function getUuid(
  ) public returns (bytes32)
```

Validates that the `VerifiableCredential` conforms to the VCTypes.




### getVCStatusByUUid
```solidity
  function getVCStatusByUUid(
  ) public returns (string)
```




### getVCStatus
```solidity
  function getVCStatus(
  ) public returns (string)
```




### _issueVC
```solidity
  function _issueVC(
  ) internal returns (bool)
```




### _revokeVC
```solidity
  function _revokeVC(
  ) internal returns (bool)
```




### _suspendVC
```solidity
  function _suspendVC(
  ) internal returns (bool)
```




### _deleteVC
```solidity
  function _deleteVC(
  ) internal returns (bool)
```




### expiredVC
```solidity
  function expiredVC(
  ) external returns (bool)
```




### _issueVCWithAuthorization
```solidity
  function _issueVCWithAuthorization(
  ) internal returns (bool)
```




### registerVC
```solidity
  function registerVC(
  ) public returns (bool)
```




### deleteVC
```solidity
  function deleteVC(
  ) public returns (bool)
```




### revokeVC
```solidity
  function revokeVC(
  ) public returns (bool)
```




### suspendVC
```solidity
  function suspendVC(
  ) public returns (bool)
```




### disputeVCByGovern
```solidity
  function disputeVCByGovern(
  ) public returns (bool)
```




### withdrawFees
```solidity
  function withdrawFees(
  ) external
```
Withdraw fees collected by the contract. Only the govern can call this.



## Events
### Updated
```solidity
  event Updated(
  )
```



### Issued
```solidity
  event Issued(
  )
```



### Disputed
```solidity
  event Disputed(
  )
```



### Revoked
```solidity
  event Revoked(
  )
```



### Suspended
```solidity
  event Suspended(
  )
```



### Expired
```solidity
  event Expired(
  )
```



### Deleted
```solidity
  event Deleted(
  )
```



