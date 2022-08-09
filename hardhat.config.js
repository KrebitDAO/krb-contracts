//  hardhat.config.js

require("@nomiclabs/hardhat-waffle");
require("@openzeppelin/hardhat-upgrades");
require("@nomiclabs/hardhat-etherscan");

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
    rinkeby: {
      url: `https://eth-rinkeby.alchemyapi.io/v2/${process.env.ALCHEMY_API_KEY}`,
      accounts: { mnemonic: process.env.MNEMONIC },
    },
    xdai: {
      url: `https://xdai.poanetwork.dev/`,
      accounts: { mnemonic: process.env.MNEMONIC },
    },
    matic: {
      url: "https://rpc-mumbai.maticvigil.com",
      accounts: { mnemonic: process.env.MNEMONIC },
    },
  },
  etherscan: {
    // Your API key for Etherscan
    // Obtain one at https://etherscan.io/
    apiKey: {
      rinkeby: process.env.ETHERSCAN_API_KEY,
      xdai: "api-key",
      polygonMumbai: process.env.POLYGONSCAN_API_KEY,
    },
  },
};
