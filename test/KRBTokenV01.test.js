// test/krbToken.test.js

const { ethers, upgrades } = require("hardhat");
const { expect } = require("chai");

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
    { name: "value", type: "string" },
    { name: "encrypted", type: "string" },
    { name: "trust", type: "uint8" },
    { name: "stake", type: "uint256" },
    { name: "nbf", type: "uint256" },
    { name: "exp", type: "uint256" },
  ],
  Issuer: [
    { name: "id", type: "string" },
    { name: "ethereumAddress", type: "address" },
  ],
};

describe("KRBTokenV01", function () {
  before(async function () {
    this.accounts = await ethers.provider.listAccounts();

    this.KRBTokenV01 = await ethers.getContractFactory("KRBTokenV01");
    this.krbToken = await upgrades.deployProxy(this.KRBTokenV01, {
      kind: "uups",
    });
    await this.krbToken.deployed();

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
        value: "encrypted",
        encrypted:
          "0x0c94bf56745f8d3d9d49b77b345c780a0c11ea997229f925f39a1946d51856fb",
        trust: 50,
        stake: 6,
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

  it("minBalanceToTransfer", async function () {
    expect(await this.krbToken.minBalanceToTransfer()).to.equal(
      (100 * 10 ** 18).toString()
    );
  });

  it("updateMinBalanceToTransfer from non-Govern role", async function () {
    await expect(
      this.krbTokenIssuer.updateMinBalanceToTransfer((2 * 10 ** 18).toString())
    ).to.be.revertedWith(
      "KRBToken: must have govern role to change minBalance"
    );
    expect(await this.krbToken.minBalanceToTransfer()).to.equal(
      (100 * 10 ** 18).toString()
    );
  });

  it("updateMinBalanceToTransfer", async function () {
    await expect(
      this.krbToken.updateMinBalanceToTransfer((2 * 10 ** 18).toString())
    )
      .to.emit(this.krbToken, "Updated")
      .withArgs("minBalanceToTransfer");
    expect(await this.krbToken.minBalanceToTransfer()).to.equal(
      (2 * 10 ** 18).toString()
    );
  });

  it("minBalanceToReceive", async function () {
    expect(await this.krbToken.minBalanceToReceive()).to.equal(
      (100 * 10 ** 18).toString()
    );
  });

  it("updateMinBalanceToReceive", async function () {
    await expect(
      await this.krbToken.updateMinBalanceToReceive((2 * 10 ** 18).toString())
    )
      .to.emit(this.krbToken, "Updated")
      .withArgs("minBalanceToReceive");
    expect(await this.krbToken.minBalanceToReceive()).to.equal(
      (2 * 10 ** 18).toString()
    );
  });

  it("minBalanceToIssue", async function () {
    expect(await this.krbToken.minBalanceToIssue()).to.equal(
      (100 * 10 ** 18).toString()
    );
  });

  it("updateMinBalanceToIssue", async function () {
    await expect(
      await this.krbToken.updateMinBalanceToIssue((2 * 10 ** 18).toString())
    )
      .to.emit(this.krbToken, "Updated")
      .withArgs("minBalanceToIssue");
    expect(await this.krbToken.minBalanceToIssue()).to.equal(
      (2 * 10 ** 18).toString()
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

  it("updateStakeToIssue", async function () {
    await expect(
      await this.krbToken.updateStakeToIssue(
        (3 * 10 ** 18).toString(),
        (100 * 10 ** 18).toString()
      )
    )
      .to.emit(this.krbToken, "Updated")
      .withArgs("minStakeToIssue");

    expect(await this.krbToken.minStakeToIssue()).to.equal(
      (3 * 10 ** 18).toString()
    );
    expect(await this.krbToken.maxStakeToIssue()).to.equal(
      (100 * 10 ** 18).toString()
    );
  });

  it("updateStakeToIssue negative", async function () {
    await expect(
      this.krbToken.updateStakeToIssue(
        (10 * 10 ** 18).toString(),
        (1 * 10 ** 18).toString()
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
    const krbTokenV1 = await ethers.getContractFactory("KRBTokenV01", {
      libraries: {
        //VCTypesV01: this.VCTypesV01.address,
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
    let uuid = await this.krbToken.getUuid(this.verifiableCredential);
    await expect(
      await this.krbTokenSubject.registerVC(
        this.verifiableCredential,
        proofValue
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
    ).to.equal((203 * 10 ** 18).toString()); // 203 KRB
  });

  it("registerVC already issued", async function () {
    let proofValue = await this.issuer._signTypedData(
      this.domain,
      vcTypes,
      this.verifiableCredential
    );

    await expect(
      this.krbTokenSubject.registerVC(this.verifiableCredential, proofValue)
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
  });

  it("registerVC already revoked", async function () {
    let proofValue = await this.issuer._signTypedData(
      this.domain,
      vcTypes,
      this.verifiableCredential
    );

    await expect(
      this.krbTokenSubject.registerVC(this.verifiableCredential, proofValue)
    ).to.be.revertedWith(
      "KRBToken: Verifiable Credential hash already been issued"
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
        value: "encrypted",
        encrypted:
          "0x0c94bf56745f8d3d9d49b77b345c780a0c11ea997229f925f39a1946d51856fb",
        trust: 50,
        stake: 6,
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
    ).to.equal((203 * 10 ** 18).toString()); // 203 KRB

    //Suspend
    let uuid = await this.krbToken.getUuid(vc);
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
        value: "encrypted",
        encrypted:
          "0x0c94bf56745f8d3d9d49b77b345c780a0c11ea997229f925f39a1946d51856fb",
        trust: 50,
        stake: 6,
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

    //Suspend
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
        value: "encrypted",
        encrypted:
          "0x0c94bf56745f8d3d9d49b77b345c780a0c11ea997229f925f39a1946d51856fb",
        trust: 50,
        stake: 6,
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
        encrypted:
          "0x0c94bf56745f8d3d9d49b77b345c780a0c11ea997229f925f39a1946d51856fb",
        trust: 50,
        stake: 6,
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

    let uuid = await this.krbToken.getUuid(vc);

    let disputeVC = {
      _context:
        "https://www.w3.org/2018/credentials/v1,https://raw.githubusercontent.com/w3c-ccg/ethereum-eip712-proofValue-2021-spec/main/contexts/v1/index.json",

      id: "ceramic://doc6",
      _type: "DisputeCredential",
      issuer: {
        id: "did:govern",
        ethereumAddress: this.accounts[0],
      },
      credentialSubject: {
        id: "did:user",
        ethereumAddress: this.accounts[2],
        _type: "fullName",
        value: "encrypted",
        encrypted:
          "0x0c94bf56745f8d3d9d49b77b345c780a0c11ea997229f925f39a1946d51856fb",
        trust: 50,
        stake: 6,
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
    ).to.equal((197 * 10 ** 18).toString()); // 197 KRB
  });
});