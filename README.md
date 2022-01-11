# <img src="krebit-icon.png" alt="Krebit" height="40px" align="left"> Krebit Contracts

[![Docs](https://img.shields.io/badge/docs-%F0%9F%93%84-blue)](https://docs.krebit.co)

This repository hosts the [Krebit] protocol contracts, based on [OpenZeppelin Contracts].

[krebit]: http://krebit.co
[openzeppelin contracts]: https://github.com/OpenZeppelin/openzeppelin-contracts

It follows all of the rules for [Writing Upgradeable Contracts]: constructors are replaced by initializer functions, state variables are initialized in initializer functions, and we additionally check for storage incompatibilities across minor versions.

[writing upgradeable contracts]: https://docs.openzeppelin.com/upgrades-plugins/writing-upgradeable

## Overview

### Installation

```console
$ npm install
```

### Compiling and Testing

Runing the full test suite:

```console
$ npx hardhat test

```

### Deployment to Testnet

To send transactions in a testnet, you will need a new Ethereum account. There are many ways to do this: here we will use the mnemonics package, which will output a fresh mnemonic (a set of 12 words) we will use to derive our accounts:

```console
$ npx mnemonics
drama film snack motion ...
```

While you can spin up your own Geth or OpenEthereum node connected to a testnet, the easiest way to access a testnet is via a public node service such as Alchemy or Infura. We will also use an Etherscan API key for verifying the contract code.

Rename the file .env_sample to .env and provide the required variables:

```.env
INFURA_PROJECT_ID=""
ETHERSCAN_API_KEY=""
ALCHEMY_API_KEY=""

MNEMONIC=""
```

Update the hardhat.config.js configuration file with a new network connection to the testnet. Here we will use Rinkeby, but you can use whichever you want:

```hardhat.config.js
networks: {
    rinkeby: {
      url: `https://eth-rinkeby.alchemyapi.io/v2/${process.env.ALCHEMY_API_KEY}`,
      accounts: { mnemonic: process.env.MNEMONIC },
    },
  },
```

#### Deploying:

```console
$ npx hardhat run --network rinkeby scripts/deploy_upgradeable.js

```

#### Verifying in Etherscan:

```console
$  npx hardhat verify --network rinkeby <contract address>

```

#### Upgrading:

```console
$ npx hardhat run --network rinkeby scripts/upgrade.js

```

> **Current Deployments**
>
> The file .openzeppelin/rinkeby.json keeps track of the current deployed version and previously upgraded implementations

## Learn More

The guides in the [docs site](http://docs.krebit.co) will teach about different concepts of the Krebit Protocol.

## Security

> **Caution**
>
> These contracts have not been audited! use at your own responsibility.

Please report any security issues you find directly to contact@krebit.co

Critical bug fixes will be backported to past major releases.

## Contribute

Krebit Contracts exists thanks to its contributors. There are many ways you can participate and help build public goods. Check out the [Krebit Gitcoin Grants](https://gitcoin.co/grants/3522/krebit)!

## License

Krebit Contracts is released under the [MIT License](LICENSE).
