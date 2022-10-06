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

  // Mint 1000 KRB to node401
  await krbToken.mint(
    "0x661f52D8D111ECcF62872bDDb2E70C12d8b4b860",
    (200 * 10 ** 18).toString()
  );

  const KrebitNFT = await ethers.getContractFactory("KrebitNFT");
  console.log("Deploying KrebitNFT...");

  const krbNFT = await upgrades.deployProxy(
    KrebitNFT,
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
  console.log("KrebitNFT deployed to:", krbNFT.address);

  krbToken.grantRole(ethers.utils.id("GOVERN_ROLE"), krbNFT.address);
}

main();
