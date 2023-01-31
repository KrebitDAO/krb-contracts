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

describe("KrebitEscrow", function () {
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

    this.KrebitEscrow = await ethers.getContractFactory("KrebitEscrow");
    console.log("Deploying KrebitEscrow...");
    this.krbEscrow = await this.KrebitEscrow.deploy(this.krbToken.address);
    await this.krbEscrow.deployed();
    console.log("KrebitEscrow deployed to:", this.krbEscrow.address);

    this.issuer = ethers.provider.getSigner(this.accounts[0]);

    //accounts[1] is the Escrow buyer
    this.buyer = ethers.provider.getSigner(this.accounts[1]);
    const EscrowBuyer = await ethers.getContractFactory(
      "KrebitEscrow",
      this.buyer
    );
    this.escrowBuyer = await EscrowBuyer.attach(this.krbEscrow.address);
    const KRBTokenBuyer = await ethers.getContractFactory(
      "KRBToken",
      this.buyer
    );
    this.krbTokenBuyer = await KRBTokenBuyer.attach(this.krbToken.address);

    //accounts[2] is the Escrow seller
    this.seller = ethers.provider.getSigner(this.accounts[2]);
    const EscrowSeller = await ethers.getContractFactory(
      "KrebitEscrow",
      this.seller
    );
    this.escrowSeller = await EscrowSeller.attach(this.krbEscrow.address);
    const KRBTokenSeller = await ethers.getContractFactory(
      "KRBToken",
      this.seller
    );
    this.krbTokenSeller = await KRBTokenSeller.attach(this.krbToken.address);

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

    let referral = {
      "@context": [DEFAULT_CONTEXT, EIP712_CONTEXT],
      type: [DEFAULT_VC_TYPE, "Referral"],
      id: "https://krebit.id/referral/id/1234",
      issuer: {
        id: "did:referrer",
        ethereumAddress: this.accounts[0],
      },
      credentialSubject: {
        id: "did:seller",
        ethereumAddress: this.accounts[2],
        type: "Referral",
        value:
          '{"issueTo":["0xd6eeF6A4ceB9270776d6b388cFaBA62f5Bc3357f"],"name":"Great builder","description":"developer and founder","proof":"","image":"","entity":"Personal","parentCredential":"ceramic://kjzl6cwe1jw145u5avj2g3izida1x1nwfmzlogbqqdiml5skbmibponc0xt5rwe","onBehalveOfIssuer":{"id":"did:pkh:eip155:1:0xd9d96fb150136798861363d8ad9fe4033cfc32b3","ethereumAddress":"0xD9D96fb150136798861363d8Ad9Fe4033cfC32b3"}}',
        typeSchema: "ceramic://def",
        encrypted: "null",
        trust: 50,
        stake: 6,
        price: ethers.utils.parseEther("0").toString(),
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

    this.referralCredential = getEIP712Credential(referral);

    let dealExpiration = new Date();
    dealExpiration.setSeconds(dealExpiration.getSeconds() + 30);
    let deal = {
      "@context": [DEFAULT_CONTEXT, EIP712_CONTEXT],
      type: [DEFAULT_VC_TYPE, "Deal"],
      id: "https://krebit.id/deals/id/1",
      issuer: {
        id: "did:seller",
        ethereumAddress: this.accounts[2],
      },
      credentialSubject: {
        id: "did:buyer",
        ethereumAddress: this.accounts[1],
        type: "Deal",
        value: '{"value":"Title","evidence":""}',
        typeSchema: "ceramic://def",
        encrypted: "null",
        trust: 100,
        stake: 0,
        price: ethers.utils.parseEther("0.1").toString(),
        nbf: Math.floor(issuanceDate / 1000),
        exp: Math.floor(dealExpiration.getTime() / 1000),
      },
      credentialSchema: {
        id: "https://krebit.id/schemas/v1",
        type: "Eip712SchemaValidator2021",
      },
      issuanceDate: new Date(issuanceDate).toISOString(),
      expirationDate: new Date(dealExpiration).toISOString(),
    };

    this.dealCredential = getEIP712Credential(deal);

    let canceledExpiration = new Date();
    canceledExpiration.setMilliseconds(
      canceledExpiration.getMilliseconds() + 10000
    );
    let canceled = {
      "@context": [DEFAULT_CONTEXT, EIP712_CONTEXT],
      type: [DEFAULT_VC_TYPE, "Deal"],
      id: "https://krebit.id/deals/id/2",
      issuer: {
        id: "did:seller",
        ethereumAddress: this.accounts[2],
      },
      credentialSubject: {
        id: "did:buyer",
        ethereumAddress: this.accounts[1],
        type: "Deal",
        value: '{"value":"Title","evidence":""}',
        typeSchema: "ceramic://def",
        encrypted: "null",
        trust: 100,
        stake: 0,
        price: ethers.utils.parseEther("0.1").toString(),
        nbf: Math.floor(issuanceDate / 1000),
        exp: Math.floor(canceledExpiration.getTime() / 1000),
      },
      credentialSchema: {
        id: "https://krebit.id/schemas/v1",
        type: "Eip712SchemaValidator2021",
      },
      issuanceDate: new Date(issuanceDate).toISOString(),
      expirationDate: new Date(canceledExpiration).toISOString(),
    };

    this.canceledDeal = getEIP712Credential(canceled);

    let sellerCancelExp = new Date();
    sellerCancelExp.setSeconds(sellerCancelExp.getSeconds() + 30);
    let sellerCancel = {
      "@context": [DEFAULT_CONTEXT, EIP712_CONTEXT],
      type: [DEFAULT_VC_TYPE, "Deal"],
      id: "https://krebit.id/deals/id/3",
      issuer: {
        id: "did:seller",
        ethereumAddress: this.accounts[2],
      },
      credentialSubject: {
        id: "did:buyer",
        ethereumAddress: this.accounts[1],
        type: "Deal",
        value: '{"value":"Title","evidence":""}',
        typeSchema: "ceramic://def",
        encrypted: "null",
        trust: 100,
        stake: 0,
        price: ethers.utils.parseEther("0.1").toString(),
        nbf: Math.floor(issuanceDate / 1000),
        exp: Math.floor(sellerCancelExp.getTime() / 1000),
      },
      credentialSchema: {
        id: "https://krebit.id/schemas/v1",
        type: "Eip712SchemaValidator2021",
      },
      issuanceDate: new Date(issuanceDate).toISOString(),
      expirationDate: new Date(sellerCancelExp).toISOString(),
    };

    this.sellerCancelCredential = getEIP712Credential(sellerCancel);

    let disputedExpiration = new Date();
    disputedExpiration.setSeconds(disputedExpiration.getSeconds() + 30);
    let disputed = {
      "@context": [DEFAULT_CONTEXT, EIP712_CONTEXT],
      type: [DEFAULT_VC_TYPE, "Deal"],
      id: "https://krebit.id/deals/id/4",
      issuer: {
        id: "did:seller",
        ethereumAddress: this.accounts[2],
      },
      credentialSubject: {
        id: "did:buyer",
        ethereumAddress: this.accounts[1],
        type: "Deal",
        value: '{"value":"Title","evidence":""}',
        typeSchema: "ceramic://def",
        encrypted: "null",
        trust: 100,
        stake: 0,
        price: ethers.utils.parseEther("0.1").toString(),
        nbf: Math.floor(issuanceDate / 1000),
        exp: Math.floor(disputedExpiration.getTime() / 1000),
      },
      credentialSchema: {
        id: "https://krebit.id/schemas/v1",
        type: "Eip712SchemaValidator2021",
      },
      issuanceDate: new Date(issuanceDate).toISOString(),
      expirationDate: new Date(disputedExpiration).toISOString(),
    };

    this.disputedCredential = getEIP712Credential(disputed);
  });
  it("mints KRB to issuer", async function () {
    await this.krbToken.mint(this.accounts[0], (200 * 10 ** 18).toString());
    expect(
      (await this.krbToken.balanceOf(this.accounts[0])).toString()
    ).to.equal(
      (200 * 10 ** 18).toString() // 2 KRB
    );
  });

  it("mints KRB to seller", async function () {
    await this.krbToken.mint(this.accounts[2], (200 * 10 ** 18).toString());
    expect((await this.krbToken.totalSupply()).toString()).to.equal(
      (400 * 10 ** 18).toString() // 2 KRB
    );
  });

  it("Referral credential", async function () {
    let krebitTypes = getKrebitCredentialTypes();

    let eip712vc = new EIP712VC(this.domain);

    const vc = await eip712vc.createEIP712VerifiableCredential(
      this.referralCredential,
      krebitTypes,
      async (data) => {
        return await this.issuer._signTypedData(
          this.domain,
          krebitTypes,
          this.referralCredential
        );
      }
    );

    //Issue
    await expect(
      this.krbTokenSeller.registerVC(
        this.referralCredential,
        vc.proof.proofValue,
        {
          value: ethers.utils.parseEther("0").toString(),
        }
      )
    ).to.emit(this.krbToken, "Issued");
    expect(await this.krbToken.getVCStatus(this.referralCredential)).to.equal(
      "Issued"
    );
    expect(
      (await this.krbToken.balanceOf(this.accounts[2])).toString()
    ).to.equal((203 * 10 ** 18).toString()); // 3 KRB
    expect(
      (await this.krbToken.balanceOf(this.accounts[0])).toString()
    ).to.equal((197 * 10 ** 18).toString()); // 197 KRB
    expect((await this.krbToken.stakeOf(this.accounts[0])).toString()).to.equal(
      (6 * 10 ** 18).toString()
    ); // 6 KRB
  });

  it("buyerCancel too soon", async function () {
    let krebitTypes = getKrebitCredentialTypes();

    let eip712vc = new EIP712VC(this.domain);

    const vc = await eip712vc.createEIP712VerifiableCredential(
      this.canceledDeal,
      krebitTypes,
      async (data) => {
        return await this.seller._signTypedData(
          this.domain,
          krebitTypes,
          this.canceledDeal
        );
      }
    );

    await expect(
      this.escrowBuyer.createEscrow(
        this.referralCredential,
        this.canceledDeal,
        vc.proof.proofValue,
        {
          value: this.canceledDeal.credentialSubject.price,
        }
      )
    ).to.emit(this.escrowBuyer, "Created");
    expect(await this.escrowBuyer.getDealStatus(this.canceledDeal)).to.equal(
      "Created"
    );
    await expect(
      this.escrowBuyer.buyerCancel(
        this.referralCredential,
        this.canceledDeal,
        this.accounts[0]
      )
    ).to.be.revertedWith("Deal can't be canceled yet");
  });

  it("feePercentage", async function () {
    expect(await this.krbEscrow.feePercentage()).to.equal((4).toString());
  });

  it("update feePercentage to 9", async function () {
    await expect(this.krbEscrow.setFeePercentage((9).toString())).to.emit(
      this.krbEscrow,
      "Updated"
    );
    expect(await this.krbEscrow.feePercentage()).to.equal((9).toString());
  });

  it("Deal not created yet", async function () {
    expect(await this.escrowBuyer.getDealStatus(this.dealCredential)).to.equal(
      "None"
    );
  });

  it("createEscrow", async function () {
    let krebitTypes = getKrebitCredentialTypes();

    let eip712vc = new EIP712VC(this.domain);

    const vc = await eip712vc.createEIP712VerifiableCredential(
      this.dealCredential,
      krebitTypes,
      async (data) => {
        return await this.seller._signTypedData(
          this.domain,
          krebitTypes,
          this.dealCredential
        );
      }
    );

    await expect(
      this.escrowBuyer.createEscrow(
        this.referralCredential,
        this.dealCredential,
        vc.proof.proofValue,
        {
          value: this.dealCredential.credentialSubject.price,
        }
      )
    ).to.emit(this.escrowBuyer, "Created");
    expect(await this.escrowBuyer.getDealStatus(this.dealCredential)).to.equal(
      "Created"
    );
  });

  it("Duplicate createEscrow", async function () {
    let krebitTypes = getKrebitCredentialTypes();

    let eip712vc = new EIP712VC(this.domain);

    const vc = await eip712vc.createEIP712VerifiableCredential(
      this.dealCredential,
      krebitTypes,
      async (data) => {
        return await this.seller._signTypedData(
          this.domain,
          krebitTypes,
          this.dealCredential
        );
      }
    );

    await expect(
      this.escrowBuyer.createEscrow(
        this.referralCredential,
        this.dealCredential,
        vc.proof.proofValue,
        {
          value: this.dealCredential.credentialSubject.price,
        }
      )
    ).to.be.revertedWith("Deal already exists");
  });

  it("Deal delivered by seller (disableBuyerCancel)", async function () {
    await expect(
      this.escrowSeller.disableBuyerCancel(this.dealCredential)
    ).to.emit(this.escrowSeller, "BuyerCancelDisabled");
    expect(await this.escrowSeller.getDealStatus(this.dealCredential)).to.equal(
      "Delivered"
    );
  });

  it("buyerCancel fails", async function () {
    await expect(
      this.escrowBuyer.buyerCancel(
        this.referralCredential,
        this.dealCredential,
        this.accounts[0]
      )
    ).to.be.revertedWith("Deal can't be canceled");
  });

  it("Release by buyer", async function () {
    await expect(
      this.escrowBuyer.release(
        this.referralCredential,
        this.dealCredential,
        "0xd9d96fb150136798861363d8ad9fe4033cfc32b3"
      )
    ).to.emit(this.escrowBuyer, "Released");
    expect(await this.escrowBuyer.getDealStatus(this.dealCredential)).to.equal(
      "Released"
    );
    //Buyer balance
    expect(
      (await this.escrowBuyer.payments(this.accounts[1])).toString()
    ).to.equal((0 * 10 ** 18).toString());
    //Seller balance
    expect(
      (await this.escrowBuyer.payments(this.accounts[2])).toString()
    ).to.equal((0.09 * 10 ** 18).toString());
    //Referrer balance
    expect(
      (
        await this.escrowBuyer.payments(
          "0xd9d96fb150136798861363d8ad9fe4033cfc32b3"
        )
      ).toString()
    ).to.equal((0.001 * 10 ** 18).toString());
    //Fees balance
    expect(
      (await this.escrowBuyer.feesAvailableForWithdraw()).toString()
    ).to.equal("9000000000000000"); // 0.009 * 10 ** 18
  });

  it("createEscrow already expired", async function () {
    let krebitTypes = getKrebitCredentialTypes();

    let eip712vc = new EIP712VC(this.domain);

    const vc = await eip712vc.createEIP712VerifiableCredential(
      this.canceledDeal,
      krebitTypes,
      async (data) => {
        return await this.seller._signTypedData(
          this.domain,
          krebitTypes,
          this.canceledDeal
        );
      }
    );

    await expect(
      this.escrowBuyer.createEscrow(
        this.referralCredential,
        this.canceledDeal,
        vc.proof.proofValue,
        {
          value: this.canceledDeal.credentialSubject.price,
        }
      )
    ).to.be.revertedWith("KRBToken: VC has already expired");
  });

  it("buyerCancel", async function () {
    await expect(
      this.escrowBuyer.buyerCancel(
        this.referralCredential,
        this.canceledDeal,
        this.accounts[0]
      )
    ).to.emit(this.escrowBuyer, "CancelledByBuyer");
    expect(await this.escrowBuyer.getDealStatus(this.canceledDeal)).to.equal(
      "BuyerCanceled"
    );
    //Buyer balance
    expect(
      (await this.escrowBuyer.payments(this.accounts[1])).toString()
    ).to.equal((0.09 * 10 ** 18).toString());
    //Seller balance
    expect(
      (await this.escrowBuyer.payments(this.accounts[2])).toString()
    ).to.equal((0.09 * 10 ** 18).toString());
    //Referrer balance
    expect(
      (await this.escrowBuyer.payments(this.accounts[0])).toString()
    ).to.equal((0.001 * 10 ** 18).toString());
    //Fees balance
    expect(
      (await this.escrowBuyer.feesAvailableForWithdraw()).toString()
    ).to.equal("18000000000000000"); // 0.018 * 10 ** 18
  });

  it("Release expired", async function () {
    await expect(
      this.escrowBuyer.release(
        this.referralCredential,
        this.canceledDeal,
        this.accounts[0]
      )
    ).to.be.revertedWith("Deal can't be released");
  });

  it("sellerCancel", async function () {
    let krebitTypes = getKrebitCredentialTypes();

    let eip712vc = new EIP712VC(this.domain);

    const vc = await eip712vc.createEIP712VerifiableCredential(
      this.sellerCancelCredential,
      krebitTypes,
      async (data) => {
        return await this.seller._signTypedData(
          this.domain,
          krebitTypes,
          this.sellerCancelCredential
        );
      }
    );

    await expect(
      this.escrowBuyer.createEscrow(
        this.referralCredential,
        this.sellerCancelCredential,
        vc.proof.proofValue,
        {
          value: this.sellerCancelCredential.credentialSubject.price,
        }
      )
    ).to.emit(this.escrowBuyer, "Created");

    await expect(
      this.escrowSeller.sellerCancel(
        this.referralCredential,
        this.sellerCancelCredential,
        this.accounts[0]
      )
    ).to.emit(this.escrowSeller, "CancelledBySeller");
    expect(
      await this.escrowBuyer.getDealStatus(this.sellerCancelCredential)
    ).to.equal("SellerCanceled");
    //Buyer balance
    expect(
      (await this.escrowSeller.payments(this.accounts[1])).toString()
    ).to.equal((0.18 * 10 ** 18).toString());
    //Seller balance
    expect(
      (await this.escrowSeller.payments(this.accounts[2])).toString()
    ).to.equal((0.09 * 10 ** 18).toString());
    //Referrer balance
    expect(
      (await this.escrowSeller.payments(this.accounts[0])).toString()
    ).to.equal((0.002 * 10 ** 18).toString());
    //Fees balance
    expect(
      (await this.escrowSeller.feesAvailableForWithdraw()).toString()
    ).to.equal("27000000000000000"); // 0.027 * 10 ** 18
  });

  it("Govern resolveDispute", async function () {
    let krebitTypes = getKrebitCredentialTypes();

    let eip712vc = new EIP712VC(this.domain);

    const vc = await eip712vc.createEIP712VerifiableCredential(
      this.disputedCredential,
      krebitTypes,
      async (data) => {
        return await this.seller._signTypedData(
          this.domain,
          krebitTypes,
          this.disputedCredential
        );
      }
    );

    await expect(
      this.escrowBuyer.createEscrow(
        this.referralCredential,
        this.disputedCredential,
        vc.proof.proofValue,
        {
          value: this.disputedCredential.credentialSubject.price,
        }
      )
    ).to.emit(this.escrowBuyer, "Created");

    await expect(
      this.escrowSeller.disableBuyerCancel(this.disputedCredential)
    ).to.emit(this.escrowSeller, "BuyerCancelDisabled");
    expect(
      await this.escrowSeller.getDealStatus(this.disputedCredential)
    ).to.equal("Delivered");

    await expect(
      this.krbEscrow.resolveDispute(this.disputedCredential, 50)
    ).to.emit(this.krbEscrow, "DisputeResolved");
    expect(
      await this.escrowBuyer.getDealStatus(this.disputedCredential)
    ).to.equal("DisputeResolved");
    //Buyer balance
    expect(
      (await this.krbEscrow.payments(this.accounts[1])).toString()
    ).to.equal((0.2255 * 10 ** 18).toString());
    //Seller balance
    expect(
      (await this.krbEscrow.payments(this.accounts[2])).toString()
    ).to.equal("135500000000000000"); // (0.1355 * 10 ** 18)
    //Referrer balance
    expect(
      (await this.krbEscrow.payments(this.accounts[0])).toString()
    ).to.equal((0.002 * 10 ** 18).toString());
    //Fees balance
    expect(
      (await this.krbEscrow.feesAvailableForWithdraw()).toString()
    ).to.equal("36000000000000000"); // 0.036 * 10 ** 18
  });

  it("withdrawFees", async function () {
    await this.krbEscrow.withdrawFees(
      this.accounts[0],
      (0.03 * 10 ** 18).toString()
    );
    //Referrer balance
    expect(
      (await this.krbEscrow.payments(this.accounts[0])).toString()
    ).to.equal((0.032 * 10 ** 18).toString());
    //Fees balance
    expect(
      (await this.krbEscrow.feesAvailableForWithdraw()).toString()
    ).to.equal("6000000000000000"); // 0.06 * 10 ** 18
  });
});
