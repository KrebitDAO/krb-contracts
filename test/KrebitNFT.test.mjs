import pkg from "hardhat";
const { ethers, upgrades } = pkg;
import { expect } from "chai";

import {
  EIP712VC,
  DEFAULT_CONTEXT,
  EIP712_CONTEXT,
  DEFAULT_VC_TYPE,
  getKrebitCredentialTypes,
  getEIP712Credential,
} from "@krebitdao/eip712-vc";

//import krebit from "@krebitdao/reputation-passport";
import LitJsSdk from "lit-js-sdk/build/index.node.js";

describe("KrebitNFT", function () {
  before(async function () {
    this.accounts = await ethers.provider.listAccounts();

    this.KRBToken = await ethers.getContractFactory("KRBToken");
    this.krbToken = await upgrades.deployProxy(
      this.KRBToken,
      ["Krebit", "rKRB", "0.1"],
      {
        kind: "uups",
      }
    );
    await this.krbToken.deployed();

    this.KrebitNFT = await ethers.getContractFactory("KrebitNFT");
    console.log("Deploying KrebitNFT...");

    this.krbNFT = await upgrades.deployProxy(
      this.KrebitNFT,
      [
        "ipfs://QmS66LWcinekhXibiiZwJvtHNuCHxzZvedneQDZW1ximPJ/{id}",
        "ipfs://QmS66LWcinekhXibiiZwJvtHNuCHxzZvedneQDZW1ximPJ/contract.json",
        100 * 10 ** 12,
        this.krbToken.address,
      ],
      {
        kind: "uups",
      }
    );

    await this.krbNFT.deployed();
    console.log("KrebitNFT deployed to:", this.krbNFT.address);

    //accounts[1] is the VC Issuer
    this.issuer = ethers.provider.getSigner(this.accounts[1]);
    const KRBTokenIssuer = await ethers.getContractFactory(
      "KRBToken",
      this.issuer
    );
    this.krbTokenIssuer = await KRBTokenIssuer.attach(this.krbToken.address);

    //accounts[2] is the VC Credential Subject (user)
    this.subject = ethers.provider.getSigner(this.accounts[2]);
    const KRBTokenSubject = await ethers.getContractFactory(
      "KRBToken",
      this.subject
    );
    this.krbTokenSubject = await KRBTokenSubject.attach(this.krbToken.address);
    const KrebitNFTSubject = await ethers.getContractFactory(
      "KrebitNFT",
      this.subject
    );
    this.krbNFTSubject = await KrebitNFTSubject.attach(this.krbNFT.address);

    this.domain = {
      name: "Krebit",
      version: "0.1",
      chainId: await this.issuer.getChainId(),
      verifyingContract: this.krbToken.address,
    };

    // The data to sign
    let issuanceDate = Date.now();
    let expirationDate = new Date();
    expirationDate.setFullYear(expirationDate.getFullYear() + 3);

    let credential = {
      "@context": [DEFAULT_CONTEXT, EIP712_CONTEXT],
      type: [DEFAULT_VC_TYPE, "ageGT21"],
      id: "https://example.org/person/1234",
      issuer: {
        id: "did:issuer",
        ethereumAddress: this.accounts[1],
      },
      credentialSubject: {
        id: "did:user",
        ethereumAddress: this.accounts[2],
        type: "ageGT21",
        value: '{"value":"21","evidence":""}',
        typeSchema: "ceramic://def",
        encrypted: "null",
        trust: 50,
        stake: 6,
        price: ethers.utils.parseEther("0.0002").toString(),
        nbf: Math.floor(issuanceDate / 1000),
        exp: Math.floor(expirationDate.getTime() / 1000),
      },
      credentialSchema: {
        id: "https://krebit.id/schemas/v1",
        type: "Eip712SchemaValidator2021",
      },
      issuanceDate: new Date(issuanceDate).toISOString(),
      expirationDate: new Date(expirationDate).toISOString(),
    };

    this.eip712credential = getEIP712Credential(credential);
  });

  it("mints KRB to Issuer", async function () {
    await this.krbToken.mint(this.accounts[1], (200 * 10 ** 18).toString());
    expect((await this.krbToken.totalSupply()).toString()).to.equal(
      (200 * 10 ** 18).toString() // 200 KRB
    );
  });

  it("grantRole to KrebitNFT contract", async function () {
    await expect(
      this.krbToken.grantRole(
        ethers.utils.id("GOVERN_ROLE"),
        this.krbNFT.address
      )
    ).to.emit(this.krbToken, "RoleGranted");
  });

  it("price to mint", async function () {
    expect(await this.krbNFT.price()).to.equal(
      ethers.utils.parseEther("0.0001").toString()
    );
  });

  it("contractURI", async function () {
    expect(await this.krbNFT.contractURI()).to.equal(
      "ipfs://QmS66LWcinekhXibiiZwJvtHNuCHxzZvedneQDZW1ximPJ/contract.json"
    );
  });

  it("update price to mint to 0.002 eth", async function () {
    await expect(
      this.krbNFT.setPrice(ethers.utils.parseEther("0.0002").toString())
    ).to.emit(this.krbNFT, "Updated");
    expect(await this.krbNFT.price()).to.equal(
      ethers.utils.parseEther("0.0002").toString()
    );
  });

  it("getTokenId", async function () {
    let tokenID = ethers.utils.keccak256(
      ethers.utils.defaultAbiCoder.encode(["string"], ["ageGT21"])
    );
    expect(await this.krbNFT.getTokenId("ageGT21")).to.equal(tokenID);
  });

  it("token uri", async function () {
    let tokenID = ethers.utils.keccak256(
      ethers.utils.defaultAbiCoder.encode(["string"], ["ageGT21"])
    );
    expect(await this.krbNFT.uri(tokenID)).to.equal(
      "ipfs://QmS66LWcinekhXibiiZwJvtHNuCHxzZvedneQDZW1ximPJ/{id}"
    );
  });

  it("tokenId not minted yet", async function () {
    expect(
      (
        await this.krbNFT.balanceOfCredential(this.accounts[2], "ageGT21")
      ).toString()
    ).to.equal((0).toString());
  });

  it("mints credential for other address reverts", async function () {
    await expect(
      this.krbNFT.mintWithCredential(
        this.accounts[3],
        "ageGT21",
        this.eip712credential,
        0x0,
        0x0,
        {
          value: ethers.utils.parseEther("0.0002").toString(),
        }
      )
    ).to.be.revertedWith(
      "Mint to address must be the vc.credentialSubject address"
    );
  });

  it("registerVC and mint with eip712-vc", async function () {
    let krebitTypes = getKrebitCredentialTypes();

    let eip712vc = new EIP712VC(this.domain);

    const vc = await eip712vc.createEIP712VerifiableCredential(
      this.eip712credential,
      krebitTypes,
      async (data) => {
        return await this.issuer._signTypedData(
          this.domain,
          krebitTypes,
          this.eip712credential
        );
      }
    );

    const w3Credential = {
      ...credential,
      proof: verifiableCredential.proof,
    };

    const Issuer = new krebit.core.Krebit({
      wallet: this.issuer,
      ethProvider: ethers.provider,
      network: "mumbai",
      address: this.issuer.address,
      ceramicUrl: "https://ceramic-clay.3boxlabs.com",
      litSdk: LitJsSdk,
    });

    console.log(
      "Verifying w3Credential:",
      await Issuer.checkCredential(w3Credential)
    );

    let tokenID = ethers.utils.keccak256(
      ethers.utils.defaultAbiCoder.encode(["string"], ["ageGT21"])
    );
    await expect(
      this.krbNFT.mintWithCredential(
        this.accounts[2],
        "ageGT21",
        this.eip712credential,
        vc.proof.proofValue,
        0x0,
        {
          value: ethers.utils.parseEther("0.0004").toString(),
        }
      )
    )
      .to.emit(this.krbNFT, "TransferSingle")
      .withArgs(
        this.accounts[0],
        ethers.constants.AddressZero,
        this.accounts[2],
        tokenID,
        (1).toString() // amount = 1,
      );

    expect(await this.krbToken.getVCStatus(this.eip712credential)).to.equal(
      "Issued"
    );
    expect(
      (await this.krbToken.balanceOf(this.accounts[2])).toString()
    ).to.equal((3 * 10 ** 18).toString()); // 3 KRB
    expect(
      (await this.krbToken.balanceOf(this.accounts[1])).toString()
    ).to.equal((197 * 10 ** 18).toString()); // 197 KRB
    expect((await this.krbToken.stakeOf(this.accounts[1])).toString()).to.equal(
      (6 * 10 ** 18).toString()
    ); // 6 KRB
  });

  it("balanceOf", async function () {
    expect(await this.krbToken.getVCStatus(this.eip712credential)).to.equal(
      "Issued"
    );
    expect(
      (
        await this.krbNFT.balanceOfCredential(this.accounts[2], "ageGT21")
      ).toString()
    ).to.equal((1).toString());

    expect(
      (await this.krbToken.balanceOf(this.accounts[2])).toString()
    ).to.equal((3 * 10 ** 18).toString()); // 3 KRB
    expect(
      (await this.krbToken.balanceOf(this.accounts[1])).toString()
    ).to.equal((197 * 10 ** 18).toString()); // 197 KRB
    expect((await this.krbToken.stakeOf(this.accounts[1])).toString()).to.equal(
      (6 * 10 ** 18).toString()
    ); // 6 KRB
  });

  it("mints same credential reverts", async function () {
    await expect(
      this.krbNFT.mintWithCredential(
        this.accounts[2],
        "ageGT21",
        this.eip712credential,
        0x0,
        0x0,
        {
          value: ethers.utils.parseEther("0.0002").toString(),
        }
      )
    ).to.be.revertedWith("Credential already minted");
  });

  it("safeTransferFrom reverts", async function () {
    let tokenID = ethers.utils.keccak256(
      ethers.utils.defaultAbiCoder.encode(["string"], ["ageGT21"])
    );
    await expect(
      this.krbNFTSubject.safeTransferFrom(
        this.accounts[2],
        this.accounts[3],
        tokenID,
        1,
        0x0
      )
    ).to.be.revertedWith("KrebitNFT: Transfers not supported");
  });

  it("burn", async function () {
    let tokenID = ethers.utils.keccak256(
      ethers.utils.defaultAbiCoder.encode(["string"], ["ageGT21"])
    );
    expect(
      (await this.krbNFTSubject.burn(this.accounts[2], tokenID, 1)).toString()
    )
      .to.emit(this.krbNFT, "TransferSingle")
      .withArgs(
        this.accounts[2],
        this.accounts[2],
        ethers.constants.AddressZero,
        tokenID,
        (1).toString() // amount = 1,
      );
  });
});
