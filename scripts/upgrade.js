// scripts/upgrade.js
const { ethers, upgrades } = require("hardhat");

async function main() {
  const KRBTokenV1 = await ethers.getContractFactory("KRBTokenV1");
  console.log("Upgrading KRBTokenV01...");
  const res = await upgrades.upgradeProxy(
    "0x6628511A835dc37dbd3Ea92F9F1e80F868860319",
    KRBTokenV1
  );
  console.log("upgraded to KRBTokenV1", res);
}

main();
