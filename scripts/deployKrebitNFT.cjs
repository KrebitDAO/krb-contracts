const { ethers, upgrades } = require("hardhat");

async function main() {
  this.accounts = await ethers.provider.listAccounts();
  console.log("Deploying from address:", this.accounts[0]);
  const KrebitNFTV01 = await ethers.getContractFactory("KrebitNFTV01");
  console.log("Deploying KrebitNFTV01...");

  const krbNFT = await upgrades.deployProxy(
    KrebitNFTV01,
    [
      "ipfs://QmeXtnaY4gLasVMpevXUyQhnmoVmvqtSqfSdpKTbPuToxp/{id}",
      "ipfs://QmbMxWXQWvJTWJMoyXmjEox5NwgqggB8KsVswsHf2XQLxB",
      0,
      "0xee524d0b396C8F9BcfD7Ac336d17aa0397a32CbE",
    ],
    {
      kind: "uups",
    }
  );

  await krbNFT.deployed();
  console.log("KrebitNFTV01 deployed to:", krbNFT.address);
}

main();
