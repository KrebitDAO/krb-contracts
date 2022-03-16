{ERC20} token with OpenZeppelin Extensions:

- Initializable,
- ContextUpgradeable,
- UUPSUpgradeable
- AccessControlEnumerableUpgradeable,
- ERC20BurnableUpgradeable,
- ERC20PausableUpgradeable,
- EIP712Upgradeable,
- PullPaymentUpgradeable,
- ReentrancyGuardUpgradeable

This contract uses {AccessControlEnumerable} to lock permissioned functions using the
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

### \_\_KRBTokenV01_init

```solidity
  function __KRBTokenV01_init(
  ) internal
```

Initializes the contract.

See {ERC20-constructor}.

### \_\_KRBTokenV01_init_unchained

```solidity
  function __KRBTokenV01_init_unchained(
  ) internal
```

Grants `DEFAULT_ADMIN_ROLE`, `GOVERN_ROLE` and `PAUSER_ROLE` to the
account that deploys the contract.

- minBalanceToTransfer : 100 KRB
- minBalanceToReceive : 100 KRB
- feePercentage : 10 %
- minBalanceToIssue : 100 KRB
- minPriceToIssue : 0.0001 ETH
- minStakeToIssue : 1 KRB
- maxStakeToIssue : 10 KRB

### \_authorizeUpgrade

```solidity
  function _authorizeUpgrade(
  ) internal
```

Function that should revert when `msg.sender` is not authorized to upgrade the contract. Called by
{upgradeTo} and {upgradeToAndCall}.

See {UUPSUpgradeable-\_authorizeUpgrade}.

Requirements:

- the caller must have the `GOVERN_ROLE`.

### updateParameters

```solidity
  function updateParameters(
    uint256 newMinBalanceToTransfer,
    uint256 newMinBalanceToReceive,
    uint256 newMinBalanceToIssue,
    uint256 newFeePercentage,
    uint256 newMinPrice,
    uint256 newMinStake,
    uint256 newMinStake
  ) public
```

Updates all Protocol Parameters

#### Parameters:

| Name                      | Type    | Description                          |
| :------------------------ | :------ | :----------------------------------- |
| `newMinBalanceToTransfer` | uint256 | The new min baance to Transfer.      |
| `newMinBalanceToReceive`  | uint256 | The new min balance to Receive.      |
| `newMinBalanceToIssue`    | uint256 | New min Balance to Issue             |
| `newFeePercentage`        | uint256 | new protocol fee percentage (0 -100) |
| `newMinPrice`             | uint256 | New min price to Issue               |
| `newMinStake`             | uint256 | new min stake to issue               |
| `newMinStake`             | uint256 | new max stake to issue               |

- emits Updated()

Requirements:

- the caller must have the `GOVERN_ROLE`.
- newMaxStake > newMinStake

### \_beforeTokenTransfer

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

See {ERC20-\_mint}.

Requirements:

- the caller must have the `GOVERN_ROLE`.

### burnStake

```solidity
  function burnStake(
    address issuer,
    uint256 stake
  ) public
```

Destroys `_stake` token stake from `issuer`

#### Parameters:

| Name     | Type    | Description           |
| :------- | :------ | :-------------------- |
| `issuer` | address | The issuer address    |
| `stake`  | uint256 | The KRB stake to burn |

- emits Updated("minBalanceToReceive")

Requirements:

- the caller must have the `GOVERN_ROLE`.

### pause

```solidity
  function pause(
  ) public
```

Pauses all token transfers.

See {ERC20Pausable} and {Pausable-\_pause}.

Requirements:

- the caller must have the `PAUSER_ROLE`.

### unpause

```solidity
  function unpause(
  ) public
```

Unpauses all token transfers.

See {ERC20Pausable} and {Pausable-\_unpause}.

Requirements:

- the caller must have the `PAUSER_ROLE`.

### stakeOf

```solidity
  function stakeOf(
    address issuer
  ) public returns (uint256)
```

A method to retrieve the stake for an issuer.

#### Parameters:

| Name     | Type    | Description                           |
| :------- | :------ | :------------------------------------ |
| `issuer` | address | The issuer to retrieve the stake for. |

#### Return Values:

| Name    | Type    | Description               |
| :------ | :------ | :------------------------ |
| `stake` | address | The amount of KRB staked. |

### DOMAIN_SEPARATOR

```solidity
  function DOMAIN_SEPARATOR(
  ) external returns (bytes32)
```

solhint-disable-next-line func-name-mixedcase

### validateSignedData

```solidity
  function validateSignedData(
  ) internal
```

Checks if the provided address signed a hashed message (`hash`) with
`signature`.

See {EIP-712} and {EIP-3009}.

### getUuid

```solidity
  function getUuid(
  ) public returns (bytes32)
```

Validates that the `VerifiableCredential` conforms to the VCTypes.
@param vc Verifiable Credential

### getVCStatus

```solidity
  function getVCStatus(
    struct VCTypesV01.VerifiableCredential vc
  ) public returns (string)
```

Get the status of a Verifiable Credential

#### Parameters:

| Name | Type                                   | Description               |
| :--- | :------------------------------------- | :------------------------ |
| `vc` | struct VCTypesV01.VerifiableCredential | The verifiable Credential |

#### Return Values:

| Name     | Type                                   | Description                                                                       |
| :------- | :------------------------------------- | :-------------------------------------------------------------------------------- |
| `status` | struct VCTypesV01.VerifiableCredential | Verifiable credential Status: None, Issued, Disputed, Revoked, Suspended, Expired |

### registerVC

```solidity
  function registerVC(
    struct VCTypesV01.VerifiableCredential vc,
    bytes proofValue
  ) public returns (bool)
```

Register a Verifiable Credential

Calculates and distributes the ETH fee as percentage of price
Formula: fee = price \* feePercentage %

#### Parameters:

| Name         | Type                                   | Description               |
| :----------- | :------------------------------------- | :------------------------ |
| `vc`         | struct VCTypesV01.VerifiableCredential | The verifiable Credential |
| `proofValue` | bytes                                  | EIP712-VC proofValue      |

Requirements:

- proofValue must be the Issuer's signature of the VC
- sender must be the credentialSubject address
- msg.value must be greater than minPriceToIssue

### deleteVC

```solidity
  function deleteVC(
    struct VCTypesV01.VerifiableCredential vc,
    string reason
  ) public returns (bool)
```

Delete a Verifiable Credential

#### Parameters:

| Name     | Type                                   | Description               |
| :------- | :------------------------------------- | :------------------------ |
| `vc`     | struct VCTypesV01.VerifiableCredential | The verifiable Credential |
| `reason` | string                                 | Reason for deleting       |

Requirements:

- sender must be the credentialSubject address

### revokeVC

```solidity
  function revokeVC(
    struct VCTypesV01.VerifiableCredential vc,
    string reason
  ) public returns (bool)
```

Revoke a Verifiable Credential

#### Parameters:

| Name     | Type                                   | Description               |
| :------- | :------------------------------------- | :------------------------ |
| `vc`     | struct VCTypesV01.VerifiableCredential | The verifiable Credential |
| `reason` | string                                 | Reason for revoking       |

Requirements:

- sender must be the issuer address

### suspendVC

```solidity
  function suspendVC(
    struct VCTypesV01.VerifiableCredential vc,
    string reason
  ) public returns (bool)
```

Suspend a Verifiable Credential

#### Parameters:

| Name     | Type                                   | Description               |
| :------- | :------------------------------------- | :------------------------ |
| `vc`     | struct VCTypesV01.VerifiableCredential | The verifiable Credential |
| `reason` | string                                 | Reason for suspending     |

Requirements:

- sender must be the issuer address

### expiredVC

```solidity
  function expiredVC(
    struct VCTypesV01.VerifiableCredential vc
  ) external returns (bool)
```

Mark a Verifiable Credential as Expired

#### Parameters:

| Name | Type                                   | Description               |
| :--- | :------------------------------------- | :------------------------ |
| `vc` | struct VCTypesV01.VerifiableCredential | The verifiable Credential |

### disputeVCByGovern

```solidity
  function disputeVCByGovern(
    struct VCTypesV01.VerifiableCredential vc,
    struct VCTypesV01.VerifiableCredential disputeVC
  ) public returns (bool)
```

Called by DAO Govern arbitration to resolve a dispute

#### Parameters:

| Name        | Type                                   | Description               |
| :---------- | :------------------------------------- | :------------------------ |
| `vc`        | struct VCTypesV01.VerifiableCredential | The verifiable Credential |
| `disputeVC` | struct VCTypesV01.VerifiableCredential | Dispute Credential        |

Requirements:

- sender must be the DAO Govern address

### withdrawFees

```solidity
  function withdrawFees(
  ) external
```

Withdraw fees collected by the contract.
Requirements:

- Only the DAO govern can call this.

## Events

### Updated

```solidity
  event Updated(
  )
```

For config updates

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

### Staked

```solidity
  event Staked(
  )
```
