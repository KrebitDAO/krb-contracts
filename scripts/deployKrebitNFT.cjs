const { ethers, upgrades } = require("hardhat");

async function main() {
  this.accounts = await ethers.provider.listAccounts();
  console.log("Deploying from address:", this.accounts[0]);
  const KrebitNFT = await ethers.getContractFactory("MainnetKrebitNFT");
  console.log("Deploying MainnetKrebitNFT...");

  const krbNFT = await upgrades.deployProxy(
    KrebitNFT,
    [
      "https://node401.krebit.id/metadata/{id}",
      "ipfs://QmVqGEjneXJv1C8UkXYfjPyUmYAJce6todRRJGm8FajNKL/contract.json",
    ],
    {
      kind: "uups",
    }
  );

  await krbNFT.deployed();
  console.log("MainnetKrebitNFT deployed to:", krbNFT.address);
}

main();
