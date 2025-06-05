const { deployProxy } = require("@openzeppelin/truffle-upgrades");

const PoolFactory = artifacts.require("PoolFactory");
const AMMPool = artifacts.require("AMMPool");

module.exports = async function (deployer) {
  const poolFactory = await deployProxy(PoolFactory, [], { deployer, initializer: "initialize" });
  console.log("PoolFactory deployed at:", poolFactory.address);

  const ammPool = await deployProxy(AMMPool, [], { deployer, initializer: "initialize" });
  console.log("AMMPool deployed at:", ammPool.address);
};
