const { ethers } = require("hardhat");

async function main() {
  this.accounts = await ethers.provider.listAccounts();
  console.log("Deploying from address:", this.accounts[0]);
  const KrebitEscrow = await ethers.getContractFactory("KrebitEscrow");
  console.log("Deploying KrebitEscrow...");
  //Polygon
  const krbEscrow = await KrebitEscrow.deploy(
    "0xdEb4810c8AB3f9De3F253064A40b1D0c8703fbbf"
  );
  //Mumbai
  /*const krbEscrow = await KrebitEscrow.deploy(
    "0x3210e026f93ed87B51b9798012727df6C8C9bAaA"
  );*/
  await krbEscrow.deployed();
  console.log("KrebitEscrow deployed to:", krbEscrow.address);
}

main();
