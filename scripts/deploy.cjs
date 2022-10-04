const { ethers, upgrades } = require("hardhat");

async function main() {
  this.accounts = await ethers.provider.listAccounts();
  console.log("Deploying from address:", this.accounts[0]);

  const KRBTokenV01 = await ethers.getContractFactory("KRBTokenV01");
  console.log("Deploying KRBTokenV01...");
  const krbToken = await upgrades.deployProxy(
    KRBTokenV01,
    ["Krebit", "KRB", "0.1"],
    { kind: "uups" }
  );
  await krbToken.deployed();
  console.log("KRBTokenV01 deployed to:", krbToken.address);

  // Mint 1000 KRB to node401
  await krbToken.mint(
    "0x661f52D8D111ECcF62872bDDb2E70C12d8b4b860",
    (200 * 10 ** 18).toString()
  );

  const KrebitNFTV01 = await ethers.getContractFactory("KrebitNFTV01");
  console.log("Deploying KrebitNFTV01...");

  const krbNFT = await upgrades.deployProxy(
    KrebitNFTV01,
    [
      "https://node401.krebit.id/metadata/{id}",
      "ipfs://QmVqGEjneXJv1C8UkXYfjPyUmYAJce6todRRJGm8FajNKL/contract.json",
      0,
      krbToken.address,
    ],
    {
      kind: "uups",
    }
  );

  await krbNFT.deployed();
  console.log("KrebitNFTV01 deployed to:", krbNFT.address);

  krbToken.grantRole(ethers.utils.id("GOVERN_ROLE"), krbNFT.address);
}

main();
