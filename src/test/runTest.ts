import * as cp from 'child_process';
import * as path from 'path';

import { downloadAndUnzipVSCode, resolveCliArgsFromVSCodeExecutablePath, runTests } from '@vscode/test-electron';

async function main() {
	try {
		// The folder containing the Extension Manifest package.json
		// Passed to `--extensionDevelopmentPath`
		const extensionDevelopmentPath = path.resolve(__dirname, '../../');

		// The path to test runner
		// Passed to --extensionTestsPath
		const extensionTestsPath = path.resolve(__dirname, './suite/index');

		const vscodeExecutablePath = await downloadAndUnzipVSCode();
		const [cliPath, ...args] = resolveCliArgsFromVSCodeExecutablePath(vscodeExecutablePath);

		// Use cp.spawn / cp.exec for custom setup
		console.info('Install dependencies:');
		console.info(`  ${cliPath} ${args}`);
		const result = cp.spawnSync(
			cliPath,
			[...args, '--install-extension', 'ms-vscode.cpptools'],
			{
				shell: true
			}
		);
		console.info(`  status: ${result.status}`);
		console.info(`  stdout: ${result.stdout}`);
		console.info(`  stderr: ${result.stderr}`);
		console.info(`  error:  ${result.error}`);

		// Download VS Code, unzip it and run the integration test
		await runTests({ extensionDevelopmentPath, extensionTestsPath });
	} catch (err) {
		console.error('Failed to run tests');
		process.exit(1);
	}
}

main();
