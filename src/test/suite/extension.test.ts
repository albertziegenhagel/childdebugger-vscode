import { assert } from 'chai';
import { EventEmitter } from 'events';
import * as path from 'path';

// You can import and use all API from the 'vscode' module
// as well as import your extension to test it
import * as vscode from 'vscode';
// import * as myExtension from '../../extension';

async function startDebuggingAndWait(configuration: vscode.DebugConfiguration) {

	let startedSessions: vscode.DebugSession[] = [];

	const eventEmitter = new EventEmitter();

	vscode.debug.onDidStartDebugSession((session) => {
		startedSessions.push(session);
		eventEmitter.emit('startSession', session);
	});
	vscode.debug.onDidTerminateDebugSession((session) => {
		eventEmitter.emit('terminateSession', session);
	});

	const parentSessionStart = new Promise<vscode.DebugSession>((resolve) => {
		eventEmitter.on('startSession', resolve);
	});

	// vscode.debug.registerDebugAdapterTrackerFactory('*', {
	// 	createDebugAdapterTracker(session: vscode.DebugSession) {
	// 		return {
	// 			onDidSendMessage: (m) => {
	// 				if (m.type !== "event" ||
	// 					m.event !== "output" ||
	// 					m.body.category !== "console") {
	// 					return;
	// 				}
	// 				console.log(m.body.output);
	// 			}
	// 		};
	// 	}
	// });

	await vscode.debug.startDebugging(undefined, configuration);

	const parentSession = await parentSessionStart;

	await new Promise<void>((resolve) => {
		eventEmitter.on('terminateSession', (session: vscode.DebugSession) => {
			if (session.name !== parentSession.name) {
				return;
			}
			resolve();
		});
	});

	return startedSessions;
}

suite('Auto attach', () => {
	vscode.window.showInformationMessage('Start all tests.');

	const testExeDir = path.join(__dirname, "..", "..", "..", "build", "tests", "bin");

	test('Attach once', async () => {

		const sessions = await startDebuggingAndWait({
			type: "cppvsdbg",
			name: "Parent Session",
			request: "launch",
			program: path.join(testExeDir, "caller.exe"),
			args: [
				"--init-time", "100",
				"--final-time", "100",
				"--wait",
				path.join(testExeDir, "callee.exe"),
				"-",
				"--sleep-time", "200"
			],
		});

		assert.strictEqual(sessions.length, 2);

		assert.strictEqual(sessions[0].name, "Parent Session");

		assert.isTrue(sessions[1].name.startsWith("callee.exe #"));

	}).timeout(100000);

	test('Attach recursive', async () => {

		const sessions = await startDebuggingAndWait({
			type: "cppvsdbg",
			name: "Parent Session",
			request: "launch",
			program: path.join(testExeDir, "caller.exe"),
			args: [
				"--init-time", "100",
				"--final-time", "100",
				"--wait",
				path.join(testExeDir, "caller.exe"),
				"-",
				"--init-time", "100",
				"--final-time", "100",
				"--wait",
				path.join(testExeDir, "callee.exe"),
				"-",
				"--sleep-time", "200"
			],
			"console": "integratedTerminal",
		});

		// console.log(JSON.stringify(sessions));

		assert.strictEqual(sessions.length, 3);

		assert.strictEqual(sessions[0].name, "Parent Session");

		assert.isTrue(sessions[1].name.startsWith("caller.exe #"));

		assert.isTrue(sessions[2].name.startsWith("callee.exe #"));

	}).timeout(100000);

	test('Attach suspended', async () => {

		const sessions = await startDebuggingAndWait({
			type: "cppvsdbg",
			name: "Parent Session",
			request: "launch",
			program: path.join(testExeDir, "caller.exe"),
			args: [
				"--init-time", "100",
				"--suspend-time", "0",
				"--final-time", "100",
				"--suspend",
				"--wait",
				path.join(testExeDir, "callee.exe"),
				"-",
				"--sleep-time", "200"
			],
		});

		assert.strictEqual(sessions.length, 2);

		assert.strictEqual(sessions[0].name, "Parent Session");

		assert.isTrue(sessions[1].name.startsWith("callee.exe #"));

	}).timeout(100000);

	test('Attach Only Command Line', async () => {

		const sessions = await startDebuggingAndWait({
			type: "cppvsdbg",
			name: "Parent Session",
			request: "launch",
			program: path.join(testExeDir, "caller.exe"),
			args: [
				"--init-time", "100",
				"--final-time", "100",
				"--no-app-name",
				"--wait",
				path.join(testExeDir, "callee.exe"),
				"-",
				"--sleep-time", "200"
			],
		});

		assert.strictEqual(sessions.length, 2);

		assert.strictEqual(sessions[0].name, "Parent Session");

		assert.isTrue(sessions[1].name.startsWith("callee.exe #"));

	}).timeout(100000);
});
