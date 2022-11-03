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

const vcTypes = {
  VerifiableCredential: [
    { name: "_context", type: "string" },
    { name: "_type", type: "string" },
    { name: "id", type: "string" },
    { name: "issuer", type: "Issuer" },
    { name: "credentialSubject", type: "CredentialSubject" },
    { name: "credentialSchema", type: "CredentialSchema" },
    { name: "issuanceDate", type: "string" },
    { name: "expirationDate", type: "string" },
  ],
  CredentialSchema: [
    { name: "id", type: "string" },
    { name: "_type", type: "string" },
  ],
  CredentialSubject: [
    { name: "id", type: "string" },
    { name: "ethereumAddress", type: "address" },
    { name: "_type", type: "string" },
    { name: "typeSchema", type: "string" },
    { name: "value", type: "string" },
    { name: "encrypted", type: "string" },
    { name: "trust", type: "uint8" },
    { name: "stake", type: "uint256" },
    { name: "price", type: "uint256" },
    { name: "nbf", type: "uint256" },
    { name: "exp", type: "uint256" },
  ],
  Issuer: [
    { name: "id", type: "string" },
    { name: "ethereumAddress", type: "address" },
  ],
};

describe("KRBToken", function () {
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

    this.verifiableCredential = {
      _context:
        "https://www.w3.org/2018/credentials/v1,https://raw.githubusercontent.com/w3c-ccg/ethereum-eip712-proofValue-2021-spec/main/contexts/v1/index.json",
      _type: "12345",
      id: "ceramic://doc1",
      issuer: {
        id: "did:issuer",
        ethereumAddress: this.accounts[1],
      },
      credentialSubject: {
        id: "did:user",
        ethereumAddress: this.accounts[2],
        _type: "fullName",
        typeSchema: "ceramic://def",
        value: "encrypted",
        encrypted:
          "0x0c94bf56745f8d3d9d49b77b345c780a0c11ea997229f925f39a1946d51856fb",
        trust: 50,
        stake: 6,
        price: ethers.utils.parseEther("0.0001").toString(),
        nbf: Math.floor(issuanceDate / 1000),
        exp: Math.floor(expirationDate.getTime() / 1000),
      },
      credentialSchema: {
        id: "https://krebit.id/schemas/v1",
        _type: "Eip712SchemaValidator2021",
      },
      issuanceDate: new Date(issuanceDate).toISOString(),
      expirationDate: new Date(expirationDate).toISOString(),
      proof: {
        verificationMethod: "did:issuer#key-1",
        ethereumAddress: this.accounts[1],
        created: new Date(issuanceDate).toISOString(),
        proofPurpose: "assertionMethod",
        type: "EthereumEip712Signature2021",
      },
    };
  });

  it("symbol", async function () {
    expect(await this.krbToken.symbol()).to.equal("rKRB");
  });

  it("minBalanceToTransfer", async function () {
    expect(await this.krbToken.minBalanceToTransfer()).to.equal(
      (100 * 10 ** 18).toString()
    );
  });

  it("minBalanceToReceive", async function () {
    expect(await this.krbToken.minBalanceToReceive()).to.equal(
      (100 * 10 ** 18).toString()
    );
  });

  it("minBalanceToIssue", async function () {
    expect(await this.krbToken.minBalanceToIssue()).to.equal(
      (100 * 10 ** 18).toString()
    );
  });

  it("feePercentage", async function () {
    expect(await this.krbToken.feePercentage()).to.equal((10).toString());
  });

  it("minPriceToIssue", async function () {
    expect(await this.krbToken.minPriceToIssue()).to.equal(
      ethers.utils.parseEther("0").toString()
    );
  });

  it("minStakeToIssue", async function () {
    expect(await this.krbToken.minStakeToIssue()).to.equal(
      (1 * 10 ** 18).toString()
    );
  });

  it("maxStakeToIssue", async function () {
    expect(await this.krbToken.maxStakeToIssue()).to.equal(
      (10 * 10 ** 18).toString()
    );
  });

  it("updateParameters from non-Govern role", async function () {
    await expect(
      this.krbTokenIssuer.updateParameters(
        (2 * 10 ** 18).toString(),
        (2 * 10 ** 18).toString(),
        (2 * 10 ** 18).toString(),
        (20).toString(),
        ethers.utils.parseEther("0.0002").toString(),
        ethers.utils.parseEther("0.0002").toString(),
        (3 * 10 ** 18).toString(),
        (100 * 10 ** 18).toString(),
        ethers.constants.AddressZero
      )
    ).to.be.revertedWith("KRBToken: must have govern role");
    expect(await this.krbToken.minBalanceToTransfer()).to.equal(
      (100 * 10 ** 18).toString()
    );
    expect(await this.krbToken.minBalanceToReceive()).to.equal(
      (100 * 10 ** 18).toString()
    );
    expect(await this.krbToken.feePercentage()).to.equal((10).toString());
    expect(await this.krbToken.minPriceToIssue()).to.equal(
      ethers.utils.parseEther("0").toString()
    );
  });

  it("updateParameters", async function () {
    await expect(
      this.krbToken.updateParameters(
        (2 * 10 ** 18).toString(),
        (2 * 10 ** 18).toString(),
        (2 * 10 ** 18).toString(),
        (20).toString(),
        ethers.utils.parseEther("0.0002").toString(),
        ethers.utils.parseEther("0.0002").toString(),
        (3 * 10 ** 18).toString(),
        (100 * 10 ** 18).toString(),
        ethers.constants.AddressZero
      )
    ).to.emit(this.krbToken, "Updated");
    expect(await this.krbToken.minBalanceToTransfer()).to.equal(
      (2 * 10 ** 18).toString()
    );
    expect(await this.krbToken.minBalanceToReceive()).to.equal(
      (2 * 10 ** 18).toString()
    );
    expect(await this.krbToken.minBalanceToIssue()).to.equal(
      (2 * 10 ** 18).toString()
    );
    expect(await this.krbToken.feePercentage()).to.equal((20).toString());
    expect(await this.krbToken.minPriceToIssue()).to.equal(
      ethers.utils.parseEther("0.0002").toString()
    );
    expect(await this.krbToken.minStakeToIssue()).to.equal(
      (3 * 10 ** 18).toString()
    );
    expect(await this.krbToken.maxStakeToIssue()).to.equal(
      (100 * 10 ** 18).toString()
    );
  });

  it("updateStakeToIssue negative", async function () {
    await expect(
      this.krbToken.updateParameters(
        (2 * 10 ** 18).toString(),
        (2 * 10 ** 18).toString(),
        (2 * 10 ** 18).toString(),
        (20).toString(),
        ethers.utils.parseEther("0.0002").toString(),
        ethers.utils.parseEther("0.0002").toString(),
        (10 * 10 ** 18).toString(),
        (1 * 10 ** 18).toString(),
        ethers.constants.AddressZero
      )
    ).to.be.revertedWith(
      "KRBToken: newMaxStake must be greater or equal than newMinStake"
    );
  });

  it("mints", async function () {
    await this.krbToken.mint(this.accounts[1], (100 * 10 ** 18).toString());
    expect((await this.krbToken.totalSupply()).toString()).to.equal(
      (100 * 10 ** 18).toString() // 100 KRB
    );
  });

  it("mints emits Transfer", async function () {
    await expect(
      this.krbToken.mint(this.accounts[1], (100 * 10 ** 18).toString())
    )
      .to.emit(this.krbToken, "Transfer")
      .withArgs(
        ethers.constants.AddressZero,
        this.accounts[1],
        (100 * 10 ** 18).toString() // 100  KRB
      );
  });

  it("balaceOf", async function () {
    expect(
      (await this.krbToken.balanceOf(this.accounts[1])).toString()
    ).to.equal((200 * 10 ** 18).toString()); // 200 KRB
  });

  it("upgrades", async function () {
    const krbTokenV1 = await ethers.getContractFactory("KRBToken", {
      libraries: {
        //VCTypes: this.VCTypes.address,
      },
    });
    this.upgraded = await upgrades.upgradeProxy(
      this.krbToken.address,
      krbTokenV1
    );

    expect(
      (await this.upgraded.balanceOf(this.accounts[1])).toString()
    ).to.equal((200 * 10 ** 18).toString()); // 200 KRB
  });

  it("getDomainSeparator", async function () {
    let hashDomain = ethers.utils._TypedDataEncoder.hashDomain(
      this.domain,
      vcTypes,
      this.verifiableCredential
    );
    expect(await this.krbToken.DOMAIN_SEPARATOR()).to.equal(hashDomain);
  });

  it("getVCStatus", async function () {
    expect(await this.krbToken.getVCStatus(this.verifiableCredential)).to.equal(
      "None"
    );
  });

  it("revokeVC not issued", async function () {
    await expect(
      this.krbTokenIssuer.revokeVC(this.verifiableCredential, "Test Revokation")
    ).to.be.revertedWith("KRBToken: state is not Issued");
  });

  it("registerVC with less price", async function () {
    let proofValue = await this.issuer._signTypedData(
      this.domain,
      vcTypes,
      this.verifiableCredential
    );

    expect(
      await ethers.utils.verifyTypedData(
        this.domain,
        vcTypes,
        this.verifiableCredential,
        proofValue
      )
    ).to.equal(this.accounts[1]);

    let issuerBalance = await ethers.provider.getBalance(this.accounts[1]);
    //console.log(issuerBalance);

    let uuid = await this.krbToken.getUuid(this.verifiableCredential);
    //console.log("uuid:", uuid);
    await expect(
      this.krbTokenSubject.registerVC(this.verifiableCredential, proofValue, {
        value: ethers.utils.parseEther("0.0001").toString(),
      })
    ).to.be.revertedWith(
      "KRBToken: msg.value must be greater than minPriceToIssue"
    );
  });

  it("registerVC with wrong price", async function () {
    let proofValue = await this.issuer._signTypedData(
      this.domain,
      vcTypes,
      this.verifiableCredential
    );

    expect(
      await ethers.utils.verifyTypedData(
        this.domain,
        vcTypes,
        this.verifiableCredential,
        proofValue
      )
    ).to.equal(this.accounts[1]);

    let issuerBalance = await ethers.provider.getBalance(this.accounts[1]);
    //console.log(issuerBalance);

    let uuid = await this.krbToken.getUuid(this.verifiableCredential);
    //console.log("uuid:", uuid);
    await expect(
      this.krbTokenSubject.registerVC(this.verifiableCredential, proofValue, {
        value: ethers.utils.parseEther("0.0002").toString(),
      })
    ).to.be.revertedWith(
      "KRBToken: msg.value does not match credentialSubject.price"
    );
  });

  it("update MinPriceToIssue to 0.001 eth", async function () {
    await expect(
      this.krbToken.updateParameters(
        (2 * 10 ** 18).toString(),
        (2 * 10 ** 18).toString(),
        (2 * 10 ** 18).toString(),
        (20).toString(),
        ethers.utils.parseEther("0.0001").toString(),
        ethers.utils.parseEther("0.0002").toString(),
        (3 * 10 ** 18).toString(),
        (100 * 10 ** 18).toString(),
        ethers.constants.AddressZero
      )
    ).to.emit(this.krbToken, "Updated");
    expect(await this.krbToken.minPriceToIssue()).to.equal(
      ethers.utils.parseEther("0.0001").toString()
    );
  });

  it("registerVC during pause", async function () {
    await this.krbToken.pause();

    let proofValue = await this.issuer._signTypedData(
      this.domain,
      vcTypes,
      this.verifiableCredential
    );

    expect(
      await ethers.utils.verifyTypedData(
        this.domain,
        vcTypes,
        this.verifiableCredential,
        proofValue
      )
    ).to.equal(this.accounts[1]);

    let issuerBalance = await ethers.provider.getBalance(this.accounts[1]);
    //console.log(issuerBalance);

    let uuid = await this.krbToken.getUuid(this.verifiableCredential);
    //console.log("uuid:", uuid);
    await expect(
      this.krbTokenSubject.registerVC(this.verifiableCredential, proofValue, {
        value: ethers.utils.parseEther("0.0001").toString(),
      })
    ).to.be.revertedWith("ERC20Pausable: token transfer while paused");
  });

  it("unpause", async function () {
    await this.krbToken.unpause();
  });

  it("registerVC", async function () {
    let proofValue = await this.issuer._signTypedData(
      this.domain,
      vcTypes,
      this.verifiableCredential
    );

    expect(
      await ethers.utils.verifyTypedData(
        this.domain,
        vcTypes,
        this.verifiableCredential,
        proofValue
      )
    ).to.equal(this.accounts[1]);

    /*
    console.log(this.domain);
    console.log(this.verifiableCredential);
    console.log(this.accounts);
    console.log(proofValue);
    */

    let issuerBalance = await ethers.provider.getBalance(this.accounts[1]);
    //console.log(issuerBalance);

    let uuid = await this.krbToken.getUuid(this.verifiableCredential);
    //console.log("uuid:", uuid);
    await expect(
      await this.krbTokenSubject.registerVC(
        this.verifiableCredential,
        proofValue,
        {
          value: ethers.utils.parseEther("0.0001").toString(), // gwei = 0.0001 ETH
        }
      )
    ).to.emit(this.krbToken, "Issued");
    //.withArgs(uuid, this.verifiableCredential);
    expect(await this.krbToken.getVCStatus(this.verifiableCredential)).to.equal(
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
    /*expect(
      (await ethers.provider.getBalance(this.accounts[1])).toString()
    ).to.equal((issuerBalance + 80 * 1000).toString());*/
    expect(
      (await ethers.provider.getBalance(this.krbToken.address)).toString()
    ).to.equal(ethers.utils.parseEther("0.00002").toString());
  });

  it("registerVC already issued", async function () {
    let proofValue = await this.issuer._signTypedData(
      this.domain,
      vcTypes,
      this.verifiableCredential
    );

    await expect(
      this.krbTokenSubject.registerVC(this.verifiableCredential, proofValue, {
        value: ethers.utils.parseEther("0.0001").toString(),
      })
    ).to.be.revertedWith(
      "KRBToken: Verifiable Credential hash already been issued"
    );
  });

  it("revokeVC from non issuer", async function () {
    await expect(
      this.krbToken.revokeVC(this.verifiableCredential, "Test Revokation")
    ).to.be.revertedWith("KRBToken: sender must be the issuer address");
  });

  it("revokeVC", async function () {
    let uuid = await this.krbToken.getUuid(this.verifiableCredential);
    //console.log("uuid:", uuid);
    await expect(
      this.krbTokenIssuer.revokeVC(this.verifiableCredential, "Test Revokation")
    )
      .to.emit(this.krbToken, "Revoked")
      .withArgs(uuid, "Test Revokation");
    expect(await this.krbToken.getVCStatus(this.verifiableCredential)).to.equal(
      "Revoked"
    );
    expect(
      (await this.krbToken.balanceOf(this.accounts[2])).toString()
    ).to.equal((0 * 10 ** 18).toString()); // 0 KRB
    expect(
      (await this.krbToken.balanceOf(this.accounts[1])).toString()
    ).to.equal((200 * 10 ** 18).toString()); // 200 KRB
    expect((await this.krbToken.stakeOf(this.accounts[1])).toString()).to.equal(
      (0 * 10 ** 18).toString()
    ); // 0 KRB
  });

  it("registerVC already revoked", async function () {
    let proofValue = await this.issuer._signTypedData(
      this.domain,
      vcTypes,
      this.verifiableCredential
    );

    await expect(
      this.krbTokenSubject.registerVC(this.verifiableCredential, proofValue, {
        value: ethers.utils.parseEther("0.0001").toString(),
      })
    ).to.be.revertedWith(
      "KRBToken: Verifiable Credential hash already been issued"
    );
  });

  it("updateMinPriceToIssue to 0 eth", async function () {
    await expect(
      this.krbToken.updateParameters(
        (2 * 10 ** 18).toString(),
        (2 * 10 ** 18).toString(),
        (2 * 10 ** 18).toString(),
        (20).toString(),
        ethers.utils.parseEther("0").toString(),
        ethers.utils.parseEther("0.0002").toString(),
        (3 * 10 ** 18).toString(),
        (100 * 10 ** 18).toString(),
        ethers.constants.AddressZero
      )
    ).to.emit(this.krbToken, "Updated");
    expect(await this.krbToken.minPriceToIssue()).to.equal(
      ethers.utils.parseEther("0").toString()
    );
  });

  it("suspendVC", async function () {
    // The data to sign
    let issuanceDate = Date.now();
    let expirationDate = new Date();
    expirationDate.setFullYear(expirationDate.getFullYear() + 3);

    let vc = {
      _context:
        "https://www.w3.org/2018/credentials/v1,https://raw.githubusercontent.com/w3c-ccg/ethereum-eip712-proofValue-2021-spec/main/contexts/v1/index.json",
      id: "ceramic://doc2",
      _type: "123456",
      issuer: {
        id: "did:issuer",
        ethereumAddress: this.accounts[1],
      },
      credentialSubject: {
        id: "did:user",
        ethereumAddress: this.accounts[2],
        _type: "fullName",
        typeSchema: "ceramic://def",
        value: "encrypted",
        encrypted:
          "0x0c94bf56745f8d3d9d49b77b345c780a0c11ea997229f925f39a1946d51856fb",
        trust: 50,
        stake: 6,
        price: 0,
        nbf: Math.floor(issuanceDate / 1000),
        exp: Math.floor(expirationDate.getTime() / 1000),
      },
      credentialSchema: {
        id: "https://krebit.id/schemas/v1",
        _type: "Eip712SchemaValidator2021",
      },
      issuanceDate: new Date(issuanceDate).toISOString(),
      expirationDate: new Date(expirationDate).toISOString(),
    };

    let proofValue = await this.issuer._signTypedData(this.domain, vcTypes, vc);

    //Issue
    await expect(this.krbTokenSubject.registerVC(vc, proofValue)).to.emit(
      this.krbToken,
      "Issued"
    );
    expect(await this.krbToken.getVCStatus(vc)).to.equal("Issued");
    expect(
      (await this.krbToken.balanceOf(this.accounts[2])).toString()
    ).to.equal((3 * 10 ** 18).toString()); // 3 KRB
    expect(
      (await this.krbToken.balanceOf(this.accounts[1])).toString()
    ).to.equal((197 * 10 ** 18).toString()); // 197 KRB
    expect((await this.krbToken.stakeOf(this.accounts[1])).toString()).to.equal(
      (6 * 10 ** 18).toString()
    ); // 6 KRB

    //Suspend
    let uuid = await this.krbToken.getUuid(vc);
    //console.log("uuid:", uuid);
    await expect(this.krbTokenIssuer.suspendVC(vc, "Test Suspension"))
      .to.emit(this.krbToken, "Suspended")
      .withArgs(uuid, "Test Suspension");
    expect(await this.krbToken.getVCStatus(vc)).to.equal("Suspended");
    expect(
      (await this.krbToken.balanceOf(this.accounts[2])).toString()
    ).to.equal((0 * 10 ** 18).toString()); // 0 KRB
    expect(
      (await this.krbToken.balanceOf(this.accounts[1])).toString()
    ).to.equal((203 * 10 ** 18).toString()); // 203 KRB
    expect((await this.krbToken.stakeOf(this.accounts[1])).toString()).to.equal(
      (0 * 10 ** 18).toString()
    ); // 0 KRB
  });

  it("deleteVC", async function () {
    // The data to sign
    let issuanceDate = Date.now();
    let expirationDate = new Date();
    expirationDate.setFullYear(expirationDate.getFullYear() + 3);

    let vc = {
      _context:
        "https://www.w3.org/2018/credentials/v1,https://raw.githubusercontent.com/w3c-ccg/ethereum-eip712-proofValue-2021-spec/main/contexts/v1/index.json",

      id: "ceramic://doc3",
      _type: "12345",
      issuer: {
        id: "did:issuer",
        ethereumAddress: this.accounts[1],
      },
      credentialSubject: {
        id: "did:user",
        ethereumAddress: this.accounts[2],
        _type: "fullName",
        typeSchema: "ceramic://def",
        value: "encrypted",
        encrypted:
          "0x0c94bf56745f8d3d9d49b77b345c780a0c11ea997229f925f39a1946d51856fb",
        trust: 50,
        stake: 6,
        price: 0,
        nbf: Math.floor(issuanceDate / 1000),
        exp: Math.floor(expirationDate.getTime() / 1000),
      },
      credentialSchema: {
        id: "https://krebit.id/schemas/v1",
        _type: "Eip712SchemaValidator2021",
      },
      issuanceDate: new Date(issuanceDate).toISOString(),
      expirationDate: new Date(expirationDate).toISOString(),
    };

    let proofValue = await this.issuer._signTypedData(this.domain, vcTypes, vc);

    //Issue
    await expect(this.krbTokenSubject.registerVC(vc, proofValue)).to.emit(
      this.krbToken,
      "Issued"
    );
    expect(await this.krbToken.getVCStatus(vc)).to.equal("Issued");
    expect(
      (await this.krbToken.balanceOf(this.accounts[2])).toString()
    ).to.equal((3 * 10 ** 18).toString()); // 3 KRB
    expect(
      (await this.krbToken.balanceOf(this.accounts[1])).toString()
    ).to.equal((200 * 10 ** 18).toString()); // 200 KRB
    expect((await this.krbToken.stakeOf(this.accounts[1])).toString()).to.equal(
      (6 * 10 ** 18).toString()
    ); // 6 KRB

    //Delete
    let uuid = await this.krbToken.getUuid(vc);
    await expect(this.krbTokenSubject.deleteVC(vc, "Test Deletion"))
      .to.emit(this.krbToken, "Deleted")
      .withArgs(uuid, "Test Deletion");
    expect(await this.krbToken.getVCStatus(vc)).to.equal("None");
    expect(
      (await this.krbToken.balanceOf(this.accounts[2])).toString()
    ).to.equal((0 * 10 ** 18).toString()); // 0 KRB
    expect(
      (await this.krbToken.balanceOf(this.accounts[1])).toString()
    ).to.equal((203 * 10 ** 18).toString()); // 203 KRB
    expect((await this.krbToken.stakeOf(this.accounts[1])).toString()).to.equal(
      (0 * 10 ** 18).toString()
    ); // 0 KRB
  });

  it("expiredVC", async function () {
    // The data to sign
    let issuanceDate = Date.now();
    let expirationDate = new Date();
    expirationDate.setFullYear(expirationDate.getFullYear() - 1);

    let vc = {
      _context:
        "https://www.w3.org/2018/credentials/v1,https://raw.githubusercontent.com/w3c-ccg/ethereum-eip712-proofValue-2021-spec/main/contexts/v1/index.json",

      id: "ceramic://doc4",
      _type: "12345",
      issuer: {
        id: "did:issuer",
        ethereumAddress: this.accounts[1],
      },
      credentialSubject: {
        id: "did:user",
        ethereumAddress: this.accounts[2],
        _type: "fullName",
        typeSchema: "ceramic://def",
        value: "encrypted",
        encrypted:
          "0x0c94bf56745f8d3d9d49b77b345c780a0c11ea997229f925f39a1946d51856fb",
        trust: 50,
        stake: 6,
        price: 0,
        nbf: Math.floor(issuanceDate / 1000),
        exp: Math.floor(expirationDate.getTime() / 1000),
      },
      credentialSchema: {
        id: "https://krebit.id/schemas/v1",
        _type: "Eip712SchemaValidator2021",
      },
      issuanceDate: new Date(issuanceDate).toISOString(),
      expirationDate: new Date(expirationDate).toISOString(),
    };

    let proofValue = await this.issuer._signTypedData(this.domain, vcTypes, vc);

    //Issue
    await expect(
      this.krbTokenSubject.registerVC(vc, proofValue)
    ).to.be.revertedWith("KRBToken: VC has already expired");
    expect(await this.krbToken.getVCStatus(vc)).to.equal("None");

    //Expired
    let uuid = await this.krbToken.getUuid(vc);
    await expect(this.krbTokenSubject.expiredVC(vc))
      .to.emit(this.krbToken, "Expired")
      .withArgs(uuid);
    expect(await this.krbToken.getVCStatus(vc)).to.equal("Expired");
    expect((await this.krbToken.stakeOf(this.accounts[1])).toString()).to.equal(
      (0 * 10 ** 18).toString()
    ); // 0 KRB
  });

  it("disputeVCByGovern", async function () {
    // The data to sign
    let issuanceDate = Date.now();
    let expirationDate = new Date();
    expirationDate.setFullYear(expirationDate.getFullYear() + 3);

    let vc = {
      _context:
        "https://www.w3.org/2018/credentials/v1,https://raw.githubusercontent.com/w3c-ccg/ethereum-eip712-proofValue-2021-spec/main/contexts/v1/index.json",

      id: "ceramic://doc5",
      _type: "12345",
      issuer: {
        id: "did:issuer",
        ethereumAddress: this.accounts[1],
      },
      credentialSubject: {
        id: "did:user",
        ethereumAddress: this.accounts[2],
        _type: "fullName",
        value: "encrypted",
        typeSchema: "ceramic://def",
        encrypted:
          "0x0c94bf56745f8d3d9d49b77b345c780a0c11ea997229f925f39a1946d51856fb",
        trust: 50,
        stake: 6,
        price: 0,
        nbf: Math.floor(issuanceDate / 1000),
        exp: Math.floor(expirationDate.getTime() / 1000),
      },
      credentialSchema: {
        id: "https://krebit.id/schemas/v1",
        _type: "Eip712SchemaValidator2021",
      },
      issuanceDate: new Date(issuanceDate).toISOString(),
      expirationDate: new Date(expirationDate).toISOString(),
    };

    let proofValue = await this.issuer._signTypedData(this.domain, vcTypes, vc);

    //Issue
    await expect(this.krbTokenSubject.registerVC(vc, proofValue)).to.emit(
      this.krbToken,
      "Issued"
    );
    expect(await this.krbToken.getVCStatus(vc)).to.equal("Issued");
    expect(
      (await this.krbToken.balanceOf(this.accounts[2])).toString()
    ).to.equal((3 * 10 ** 18).toString()); // 3 KRB
    expect(
      (await this.krbToken.balanceOf(this.accounts[1])).toString()
    ).to.equal((206 * 10 ** 18).toString()); // 206 KRB
    expect((await this.krbToken.stakeOf(this.accounts[1])).toString()).to.equal(
      (6 * 10 ** 18).toString()
    ); // 6 KRB

    let uuid = await this.krbToken.getUuid(vc);
    //console.log("uuid:", uuid);

    let disputeVC = {
      _context:
        "https://www.w3.org/2018/credentials/v1,https://raw.githubusercontent.com/w3c-ccg/ethereum-eip712-proofValue-2021-spec/main/contexts/v1/index.json",

      id: "ceramic://doc6",
      _type: JSON.stringify(["VerifiableCredential", "DisputeCredential"]),
      issuer: {
        id: "did:govern",
        ethereumAddress: this.accounts[0],
      },
      credentialSubject: {
        id: "ceramic://doc5",
        ethereumAddress: this.accounts[3],
        _type: "DisputeCredential",
        value: "encrypted",
        typeSchema: "ceramic://def",
        encrypted:
          "0x0c94bf56745f8d3d9d49b77b345c780a0c11ea997229f925f39a1946d51856fb",
        trust: 50,
        stake: 6,
        price: 0,
        nbf: Math.floor(issuanceDate / 1000),
        exp: Math.floor(expirationDate.getTime() / 1000),
      },
      credentialSchema: {
        id: "https://krebit.id/schemas/v1",
        _type: "Eip712SchemaValidator2021",
      },
      issuanceDate: new Date(issuanceDate).toISOString(),
      expirationDate: new Date(expirationDate).toISOString(),
    };

    //Dispute
    let disputeUuid = await this.krbToken.getUuid(disputeVC);
    await expect(this.krbToken.disputeVCByGovern(vc, disputeVC))
      .to.emit(this.krbToken, "Disputed")
      .withArgs(uuid, disputeUuid);
    expect(await this.krbToken.getVCStatus(vc)).to.equal("Disputed");
    expect(await this.krbToken.getVCStatus(disputeVC)).to.equal("Issued");
    expect(
      (await this.krbToken.balanceOf(this.accounts[2])).toString()
    ).to.equal((0 * 10 ** 18).toString()); // 0 KRB
    expect(
      (await this.krbToken.balanceOf(this.accounts[1])).toString()
    ).to.equal((203 * 10 ** 18).toString()); // 203 KRB
    expect((await this.krbToken.stakeOf(this.accounts[1])).toString()).to.equal(
      (0 * 10 ** 18).toString()
    ); // 0 KRB
    expect(
      (await this.krbToken.balanceOf(this.accounts[3])).toString()
    ).to.equal((3 * 10 ** 18).toString()); // 3 KRB
  });

  it("registerVC with eip712-vc", async function () {
    // The data to sign
    let issuanceDate = Date.now();
    let expirationDate = new Date();
    expirationDate.setFullYear(expirationDate.getFullYear() + 3);

    let credential = {
      "@context": [DEFAULT_CONTEXT, EIP712_CONTEXT],
      type: [DEFAULT_VC_TYPE],
      id: "https://example.org/person/1234",
      issuer: {
        id: "did:issuer",
        ethereumAddress: this.accounts[1],
      },
      credentialSubject: {
        id: "did:user",
        ethereumAddress: this.accounts[2],
        type: "fullName",
        value: "encrypted",
        typeSchema: "ceramic://def",
        encrypted:
          "0x0c94bf56745f8d3d9d49b77b345c780a0c11ea997229f925f39a1946d51856fb",
        trust: 50,
        stake: 6,
        price: 0,
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

    let eip712credential = getEIP712Credential(credential);
    //console.log("eip712credential:", eip712credential);

    let krebitTypes = getKrebitCredentialTypes();

    let eip712vc = new EIP712VC(this.domain);

    const vc = await eip712vc.createEIP712VerifiableCredential(
      eip712credential,
      krebitTypes,
      async (data) => {
        return await this.issuer._signTypedData(
          this.domain,
          krebitTypes,
          eip712credential
        );
      }
    );

    //console.log(vc);

    //Issue
    await expect(
      this.krbTokenSubject.registerVC(eip712credential, vc.proof.proofValue)
    ).to.emit(this.krbToken, "Issued");
    expect(await this.krbToken.getVCStatus(eip712credential)).to.equal(
      "Issued"
    );
    expect(
      (await this.krbToken.balanceOf(this.accounts[2])).toString()
    ).to.equal((3 * 10 ** 18).toString()); // 3 KRB
    expect(
      (await this.krbToken.balanceOf(this.accounts[1])).toString()
    ).to.equal((200 * 10 ** 18).toString()); // 200 KRB
    expect((await this.krbToken.stakeOf(this.accounts[1])).toString()).to.equal(
      (6 * 10 ** 18).toString()
    ); // 6 KRB
  });

  it("burn Stake", async function () {
    await expect(
      this.krbToken.burnStake(this.accounts[1], (3 * 10 ** 18).toString())
    )
      .to.emit(this.krbToken, "Staked")
      .withArgs(
        this.accounts[1],
        ethers.constants.AddressZero,
        (3 * 10 ** 18).toString() // 100  KRB
      );
    expect((await this.krbToken.stakeOf(this.accounts[1])).toString()).to.equal(
      (3 * 10 ** 18).toString()
    ); // 3 KRB
  });
});
