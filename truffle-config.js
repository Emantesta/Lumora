module.exports = {
  // Specify the Solidity compiler version
  networks: {
    development: {
      host: "127.0.0.1",
      port: 8545,
      network_id: "*",
    },
  },
  compilers: {
    solc: {
      version: "0.8.24", // Match PriceOracle.sol pragma
      settings: {
        optimizer: {
          enabled: true, // Enable optimizer for gas efficiency
          runs: 200 // Optimize for deployment
        },
        evmVersion: "paris" // Compatible with Solidity 0.8.24
      }
    }
  },
  // Network configurations (add your networks, e.g., development, mainnet)
  networks: {
    development: {
      host: "127.0.0.1",
      port: 8545,
      network_id: "*" // Match any network ID
    }
  },
  // Add remappings for imports
  plugins: ["truffle-plugin-verify"],
  // Optional: Mocha testing options
  mocha: {
    timeout: 100000
  }
};