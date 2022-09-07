// scripts/deploy_rinkeby.js
const { ethers } = require("hardhat");

async function main() {
  const CredentialNFTDrop = await ethers.getContractFactory(
    "CredentialNFTDrop"
  );
  console.log("Deploying CredentialNFTDrop...");
  const krbNFT = await CredentialNFTDrop.deploy(
    "TestBuddies",
    "krbNFT",
    "ipfs://QmS66LWcinekhXibiiZwJvtHNuCHxzZvedneQDZW1ximPJ/",
    "https://nft-drop-verifiable-credentials.vercel.app/api/rare-buddies",
    100 * 10 ** 12,
    "0xdb13a2df867495da84764c55d0e82ded180f7f6d",
    "olderThan",
    "21"
  );
  await krbNFT.deployed();
  console.log("CredentialNFTDrop deployed to:", krbNFT.address);
}

main();
