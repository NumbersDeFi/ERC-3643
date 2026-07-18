import '@xyrusworx/hardhat-solidity-json';
import '@nomicfoundation/hardhat-toolbox';
import { HardhatUserConfig, subtask } from 'hardhat/config';
import { TASK_COMPILE_SOLIDITY_GET_SOLC_BUILD } from 'hardhat/builtin-tasks/task-names';
import '@openzeppelin/hardhat-upgrades';
import 'solidity-coverage';
import '@nomiclabs/hardhat-solhint';
import '@primitivefi/hardhat-dodoc';

const optimizerSettings = { optimizer: { enabled: true, runs: 200 } };

// ONCHAINID 2.2.1 pins `pragma solidity 0.8.17`. Hardhat's remote compiler
// download is not reliable in the production build environment, so resolve
// that exact compiler from the lockfile-pinned npm alias. ERC-3643's YF
// extensions compile with 0.8.18; imported ONCHAINID sources compile with the
// exact 0.8.17 toolchain they declare. No node_modules source patching is
// required or permitted.
subtask(TASK_COMPILE_SOLIDITY_GET_SOLC_BUILD).setAction(
  async ({ solcVersion }: { solcVersion: string }, _hre, runSuper) => {
    if (solcVersion === '0.8.17') {
      return {
        compilerPath: require.resolve('solc-0.8.17/soljson.js'),
        isSolcJs: true,
        version: '0.8.17',
        longVersion: '0.8.17+commit.8df45f5f',
      };
    }
    return runSuper();
  },
);

const config: HardhatUserConfig = {
  solidity: {
    compilers: [
      { version: '0.8.18', settings: optimizerSettings },
      { version: '0.8.17', settings: optimizerSettings },
    ],
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
