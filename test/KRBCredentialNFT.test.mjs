import pkg from "hardhat";
const { ethers, upgrades } = pkg;
import { expect } from "chai";

import eip712vc from "@krebitdao/eip712-vc";
const {
  EIP712VC,
  DEFAULT_CONTEXT,
  EIP712_CONTEXT,
  DEFAULT_VC_TYPE,
  getKrebitCredentialTypes,
  getEIP712Credential,
} = eip712vc;

describe("KRBCredentialNFT", function () {
  before(async function () {
    this.accounts = await ethers.provider.listAccounts();

    this.KRBTokenV01 = await ethers.getContractFactory("KRBTokenV01");
    this.krbToken = await upgrades.deployProxy(
      this.KRBTokenV01,
      ["Krebit", "rKRB", "0.1"],
      {
        kind: "uups",
      }
    );
    await this.krbToken.deployed();

    this.KRBCredentialNFT = await ethers.getContractFactory("KRBCredentialNFT");
    console.log("Deploying KRBCredentialNFT...");
    this.krbNFT = await this.KRBCredentialNFT.deploy(
      "KRBCredentialNFT",
      "krbNFT",
      "ipfs://QmS66LWcinekhXibiiZwJvtHNuCHxzZvedneQDZW1ximPJ/",
      "ipfs:///QmS66LWcinekhXibiiZwJvtHNuCHxzZvedneQDZW1ximPJ/contract.json",
      100 * 10 ** 12,
      this.krbToken.address,
      "olderThan",
      "21"
    );
    await this.krbNFT.deployed();
    console.log("KRBCredentialNFT deployed to:", this.krbNFT.address);

    //accounts[1] is the VC Issuer
    this.issuer = ethers.provider.getSigner(this.accounts[1]);
    const KRBTokenV01Issuer = await ethers.getContractFactory(
      "KRBTokenV01",
      this.issuer
    );
    this.krbTokenIssuer = await KRBTokenV01Issuer.attach(this.krbToken.address);

    //accounts[2] is the VC Credential Subject (user)
    this.subject = ethers.provider.getSigner(this.accounts[2]);
    const KRBTokenV01Subject = await ethers.getContractFactory(
      "KRBTokenV01",
      this.subject
    );
    this.krbTokenSubject = await KRBTokenV01Subject.attach(
      this.krbToken.address
    );

    this.domain = {
      name: "Krebit",
      version: "0.1",
      chainId: await this.issuer.getChainId(),
      verifyingContract: this.krbToken.address,
    };
  });
  it("symbol", async function () {
    expect(await this.krbNFT.symbol()).to.equal("krbNFT");
  });

  it("mints KRB to Issuer", async function () {
    await this.krbToken.mint(this.accounts[1], (200 * 10 ** 18).toString());
    expect((await this.krbToken.totalSupply()).toString()).to.equal(
      (200 * 10 ** 18).toString() // 200 KRB
    );
  });

  it("price to mint", async function () {
    expect(await this.krbNFT.price()).to.equal(
      ethers.utils.parseEther("0.0001").toString()
    );
  });

  it("contractURI", async function () {
    expect(await this.krbNFT.contractURI()).to.equal(
      "ipfs:///QmS66LWcinekhXibiiZwJvtHNuCHxzZvedneQDZW1ximPJ/contract.json"
    );
  });

  it("update price to mint to 0.001 eth", async function () {
    await expect(
      this.krbNFT.setPrice(ethers.utils.parseEther("0.0002").toString())
    ).to.emit(this.krbNFT, "Updated");
    expect(await this.krbNFT.price()).to.equal(
      ethers.utils.parseEther("0.0002").toString()
    );
  });
});
