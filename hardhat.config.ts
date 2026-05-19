import '@xyrusworx/hardhat-solidity-json';
import '@nomicfoundation/hardhat-toolbox';
import { HardhatUserConfig } from 'hardhat/config';
import '@openzeppelin/hardhat-upgrades';
import 'solidity-coverage';
import '@nomiclabs/hardhat-solhint';
import '@primitivefi/hardhat-dodoc';

const optimizerSettings = { optimizer: { enabled: true, runs: 200 } };

// Single compiler 0.8.18: pragmas were patched to ^0.8.17 in contracts/ and node_modules/@onchain-id (avoids HH501 download).
const config: HardhatUserConfig = {
  solidity: {
    version: '0.8.18',
    settings: optimizerSettings,
  },
  gasReporter: {
    enabled: true,
  },
  dodoc: {
    runOnCompile: false,
    debugMode: true,
    outputDir: "./docgen",
    freshOutput: true,
  },
};

export default config;
