// scripts/deploy_rinkeby.js
const { ethers } = require("hardhat");

async function main() {
  const KRBCredentialNFT = await ethers.getContractFactory("KRBCredentialNFT");
  console.log("Deploying KRBCredentialNFT...");
  const krbNFT = await KRBCredentialNFT.deploy(
    "TestBuddies",
    "krbNFT",
    "ipfs://QmS66LWcinekhXibiiZwJvtHNuCHxzZvedneQDZW1ximPJ/",
    "https://gateway.pinata.cloud/ipfs/QmUBq5SxiZz4Q9auTpkXH2tY7JL4qBJEBEYw4ux7E2Fa7n",
    100 * 10 ** 12,
    "0xdb13a2df867495da84764c55d0e82ded180f7f6d"
  );
  await krbNFT.deployed();
  console.log("KRBCredentialNFT deployed to:", krbNFT.address);
}

main();
