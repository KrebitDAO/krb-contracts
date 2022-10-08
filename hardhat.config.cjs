//  hardhat.config.js

require("@nomiclabs/hardhat-waffle");
require("@openzeppelin/hardhat-upgrades");
require("@nomiclabs/hardhat-etherscan");
require("@nomicfoundation/hardhat-chai-matchers");
require("dotenv").config();

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    version: "0.8.12",
    settings: {
      optimizer: {
        enabled: true,
        runs: 50,
      },
    },
  },
  networks: {
    goerli: {
      url: `https://eth-goerli.g.alchemy.com/v2/${process.env.ALCHEMY_API_KEY}`,
      accounts: { mnemonic: process.env.MNEMONIC },
    },
    matic: {
      url: `https://rpc-mainnet.maticvigil.com/v1/${process.env.POLYGON_PRIVATE_KEY}`,
      accounts: { mnemonic: process.env.MNEMONIC },
    },
    polygonMumbai: {
      url: `https://rpc-mumbai.maticvigil.com/v1/${process.env.POLYGON_PRIVATE_KEY}`,
      accounts: { mnemonic: process.env.MNEMONIC },
    },
  },
  etherscan: {
    // Your API key for Etherscan
    // Obtain one at https://etherscan.io/
    apiKey: {
      goerli: process.env.ETHERSCAN_API_KEY,
      matic: process.env.POLYGONSCAN_API_KEY,
      polygonMumbai: process.env.POLYGONSCAN_API_KEY,
    },
  },
};
