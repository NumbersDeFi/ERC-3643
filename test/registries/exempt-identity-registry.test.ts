import { loadFixture } from '@nomicfoundation/hardhat-network-helpers';
import { expect } from 'chai';
import { ethers } from 'hardhat';

describe('ExemptIdentityRegistry', () => {
  async function deployStandInsFixture() {
    const [, eoa] = await ethers.getSigners();
    const Mock = await ethers.getContractFactory('MockContract');
    const vault = await Mock.deploy();
    await vault.deployed();
    const swap = await Mock.deploy();
    await swap.deployed();
    const Exempt = await ethers.getContractFactory('ExemptIdentityRegistry');
    return { eoa, vault, swap, Exempt };
  }

  it('wires two distinct deployed protocol contracts', async () => {
    const { vault, swap, Exempt } = await loadFixture(deployStandInsFixture);
    const registry = await Exempt.deploy(vault.address, swap.address);
    await registry.deployed();

    expect(await registry.systemVault()).to.equal(vault.address);
    expect(await registry.systemSwap()).to.equal(swap.address);
    expect(await registry.isVerified(vault.address)).to.equal(true);
    expect(await registry.isVerified(swap.address)).to.equal(true);
  });

  it('rejects zero addresses', async () => {
    const { vault, swap, Exempt } = await loadFixture(deployStandInsFixture);
    await expect(
      Exempt.deploy(ethers.constants.AddressZero, swap.address),
    ).to.be.revertedWithCustomError(Exempt, 'InvalidSystemExemption');
    await expect(
      Exempt.deploy(vault.address, ethers.constants.AddressZero),
    ).to.be.revertedWithCustomError(Exempt, 'InvalidSystemExemption');
  });

  it('rejects duplicate addresses', async () => {
    const { vault, Exempt } = await loadFixture(deployStandInsFixture);
    await expect(
      Exempt.deploy(vault.address, vault.address),
    ).to.be.revertedWithCustomError(Exempt, 'InvalidSystemExemption');
  });

  it('rejects addresses without deployed code', async () => {
    const { eoa, vault, swap, Exempt } = await loadFixture(deployStandInsFixture);
    await expect(
      Exempt.deploy(eoa.address, swap.address),
    ).to.be.revertedWithCustomError(Exempt, 'InvalidSystemExemption');
    await expect(
      Exempt.deploy(vault.address, eoa.address),
    ).to.be.revertedWithCustomError(Exempt, 'InvalidSystemExemption');
  });
});
