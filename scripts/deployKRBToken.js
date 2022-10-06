const { ethers, upgrades } = require("hardhat");

async function main() {
  this.accounts = await ethers.provider.listAccounts();
  console.log("Deploying from address:", this.accounts[0]);
  const KRBToken = await ethers.getContractFactory("KRBToken");
  console.log("Deploying KRBToken...");
  const krbToken = await upgrades.deployProxy(
    KRBToken,
    ["Krebit", "KRB", "1.0"],
    { kind: "uups" }
  );
  await krbToken.deployed();
  console.log("KRBToken deployed to:", krbToken.address);
}

main();
