require("@nomicfoundation/hardhat-toolbox");
require("@openzeppelin/hardhat-upgrades");
require("dotenv").config();

module.exports = {
    solidity: {
        compilers: [
            {
                version: "0.8.24",
                settings: {
                    optimizer: {
                        enabled: true,
                        runs: 200
                    }
                }
            },
            {
                version: "0.8.20",
                settings: {
                    optimizer: {
                        enabled: true,
                        runs: 200
                    }
                }
            },
            {
                version: "0.7.6" // For Uniswap v3-periphery
            }
        ]
    },
    paths: {
        sources: "./Contracts",
        tests: "./test",
        cache: "./cache",
        artifacts: "./artifacts"
    },
    networks: {
        hardhat: {
            forking: {
                url: process.env.SONIC_BLAZE_TESTNET_RPC_URL || "https://rpc.blaze.soniclabs.com"
            }
        },
        sonicBlaze: {
            url: process.env.SONIC_BLAZE_TESTNET_RPC_URL || "https://rpc.blaze.soniclabs.com",
            chainId: 57054,
            accounts: process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : []
        }
    },
    etherscan: {
        apiKey: {
            sonicBlaze: process.env.SONICSCAN_API_KEY || "your-sonicscan-api-key"
        },
        customChains: [
            {
                network: "sonicBlaze",
                chainId: 57054,
                urls: {
                    apiURL: "https://api-testnet.sonicscan.org/api",
                    browserURL: "https://testnet.sonicscan.org"
                }
            }
        ]
    }
};