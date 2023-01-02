const { ethers } = require("hardhat");

async function main() {
  this.accounts = await ethers.provider.listAccounts();
  console.log("Deploying from address:", this.accounts[0]);
  const KrebitEscrow = await ethers.getContractFactory("KrebitEscrow");
  console.log("Deploying KrebitEscrow...");
  const krbEscrow = await KrebitEscrow.deploy(
    "0xdb13a2df867495da84764c55d0e82ded180f7f6d"
  );
  await krbEscrow.deployed();
  console.log("KrebitEscrow deployed to:", krbEscrow.address);
}

main();
