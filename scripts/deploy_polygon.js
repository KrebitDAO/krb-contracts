// scripts/deploy_xdai.js
const { ethers, upgrades } = require("hardhat");

async function main() {
  const KRBTokenV01 = await ethers.getContractFactory("KRBTokenV01");
  console.log("Deploying KRBTokenV01...");
  const krbToken = await upgrades.deployProxy(
    KRBTokenV01,
    ["Krebit", "KRB", "0.1"],
    { kind: "uups" }
  );
  await krbToken.deployed();
  console.log("KRBTokenV01 deployed to:", krbToken.address);
}

main();
