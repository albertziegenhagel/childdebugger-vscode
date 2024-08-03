import { assert } from 'chai';
import { EventEmitter } from 'events';
import * as path from 'path';

// You can import and use all API from the 'vscode' module
// as well as import your extension to test it
import * as vscode from 'vscode';
import { ChildDebuggerConfigurationExtension } from '../../extension';
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

	var output = "";

	vscode.debug.registerDebugAdapterTrackerFactory('*', {
		createDebugAdapterTracker(session: vscode.DebugSession) {
			return {
				onDidSendMessage: (m) => {
					if (m.type !== "event" ||
						m.event !== "output" ||
						m.body.category !== "stdout") {
						return;
					}
					output += m.body.output;
					// console.log(m.body.output);
				}
			};
		}
	});

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

	return { startedSessions, output };
}

function testArchitecture(callerPath: string, calleePath: string, arch: string) {

	test(`Attach once (${arch})`, async () => {
		vscode.window.showInformationMessage(`RUN Attach once (${arch}).`);

		const result = await startDebuggingAndWait({
			type: "cppvsdbg",
			name: "Parent Session",
			request: "launch",
			program: callerPath,
			args: [
				"--init-time", "0",
				"--final-time", "0",
				"--wait",
				calleePath,
				"-",
				"--sleep-time", "0"
			],
			"console": "internalConsole",
		});
		assert.strictEqual(result.startedSessions.length, 2);

		assert.strictEqual(result.startedSessions[0].name, "Parent Session");

		const childSession = result.startedSessions[1];
		assert.isTrue('childDebuggerExtension' in childSession.configuration);

		const debuggerConfigExtension: ChildDebuggerConfigurationExtension = childSession.configuration.childDebuggerExtension;

		assert.isTrue(debuggerConfigExtension.childSuspended);
		assert.isTrue(debuggerConfigExtension.parentSuspended);

		const cpid = debuggerConfigExtension.childProcessId;
		const ctid = debuggerConfigExtension.childThreadId;
		const ppid = debuggerConfigExtension.parentProcessId;

		assert.strictEqual(childSession.name, `callee.exe #${cpid}`);

		assert.strictEqual(result.output,
			`  CALLER (${ppid}): initialized\r\n` +
			`  CALLER (${ppid}): started process ${calleePath}; PID ${cpid}; TID ${ctid}\r\n` +
			`  CALLER (${ppid}): wait for child\r\n` +
			`  CALLEE (${cpid}): initialized\r\n` +
			`  CALLEE (${cpid}): terminating\r\n` +
			`  CALLER (${ppid}): terminating\r\n`
		);

	}).timeout(100000);

	test(`Attach non existent (${arch})`, async () => {
		vscode.window.showInformationMessage(`RUN non existent (${arch}).`);

		const result = await startDebuggingAndWait({
			type: "cppvsdbg",
			name: "Parent Session",
			request: "launch",
			program: callerPath,
			args: [
				"--init-time", "0",
				"--final-time", "0",
				"--wait",
				path.join(__dirname, "does-not-exist.exe"),
				"-",
				"--sleep-time", "0"
			],
			"console": "internalConsole",
		});

		assert.strictEqual(result.startedSessions.length, 1);

		assert.strictEqual(result.startedSessions[0].name, "Parent Session");

		assert.include(result.output, "failed to create child process");

	}).timeout(100000);

	test(`Attach recursive (${arch})`, async () => {
		vscode.window.showInformationMessage(`RUN Attach recursive (${arch}).`);

		const result = await startDebuggingAndWait({
			type: "cppvsdbg",
			name: "Parent Session",
			request: "launch",
			program: callerPath,
			args: [
				"--init-time", "0",
				"--final-time", "0",
				"--wait",
				callerPath,
				"-",
				"--init-time", "0",
				"--final-time", "0",
				"--wait",
				calleePath,
				"-",
				"--sleep-time", "0"
			],
			"console": "internalConsole",
			// "console": "integratedTerminal",
		});

		// console.log(JSON.stringify(sessions));

		assert.strictEqual(result.startedSessions.length, 3);

		assert.strictEqual(result.startedSessions[0].name, "Parent Session");

		const childSession1 = result.startedSessions[1];
		assert.isTrue('childDebuggerExtension' in childSession1.configuration);
		const childSession2 = result.startedSessions[2];
		assert.isTrue('childDebuggerExtension' in childSession2.configuration);

		const debuggerConfigExtension1: ChildDebuggerConfigurationExtension = childSession1.configuration.childDebuggerExtension;

		assert.isTrue(debuggerConfigExtension1.childSuspended);
		assert.isTrue(debuggerConfigExtension1.parentSuspended);

		const cpid1 = debuggerConfigExtension1.childProcessId;
		const ctid1 = debuggerConfigExtension1.childThreadId;
		const ppid1 = debuggerConfigExtension1.parentProcessId;

		assert.strictEqual(childSession1.name, `caller.exe #${cpid1}`);

		const debuggerConfigExtension2: ChildDebuggerConfigurationExtension = childSession2.configuration.childDebuggerExtension;

		assert.isTrue(debuggerConfigExtension2.childSuspended);
		assert.isTrue(debuggerConfigExtension2.parentSuspended);

		const cpid2 = debuggerConfigExtension2.childProcessId;
		const ctid2 = debuggerConfigExtension2.childThreadId;
		const ppid2 = debuggerConfigExtension2.parentProcessId;
		const ptid2 = debuggerConfigExtension2.parentProcessId;

		assert.strictEqual(childSession2.name, `callee.exe #${cpid2}`);

		assert.strictEqual(ppid2, cpid1);
		// assert.strictEqual(ptid2, ctid1); // We can probably not assume that the main thread starts the child process?

		assert.strictEqual(result.output,
			`  CALLER (${ppid1}): initialized\r\n` +
			`  CALLER (${ppid1}): started process ${callerPath}; PID ${cpid1}; TID ${ctid1}\r\n` +
			`  CALLER (${ppid1}): wait for child\r\n` +
			`  CALLER (${cpid1}): initialized\r\n` +
			`  CALLER (${cpid1}): started process ${calleePath}; PID ${cpid2}; TID ${ctid2}\r\n` +
			`  CALLER (${cpid1}): wait for child\r\n` +
			`  CALLEE (${cpid2}): initialized\r\n` +
			`  CALLEE (${cpid2}): terminating\r\n` +
			`  CALLER (${cpid1}): terminating\r\n` +
			`  CALLER (${ppid1}): terminating\r\n`
		);

	}).timeout(100000);

	test(`Attach suspended (${arch})`, async () => {
		vscode.window.showInformationMessage(`RUN Attach suspended (${arch}).`);

		const result = await startDebuggingAndWait({
			type: "cppvsdbg",
			name: "Parent Session",
			request: "launch",
			program: callerPath,
			args: [
				"--init-time", "0",
				"--suspend-time", "0",
				"--final-time", "0",
				"--suspend",
				"--wait",
				calleePath,
				"-",
				"--sleep-time", "0"
			],
			"console": "internalConsole",
		});

		assert.strictEqual(result.startedSessions.length, 2);

		assert.strictEqual(result.startedSessions[0].name, "Parent Session");

		const childSession = result.startedSessions[1];
		assert.isTrue('childDebuggerExtension' in childSession.configuration);

		const debuggerConfigExtension: ChildDebuggerConfigurationExtension = childSession.configuration.childDebuggerExtension;

		assert.isFalse(debuggerConfigExtension.childSuspended);
		assert.isTrue(debuggerConfigExtension.parentSuspended);

		const cpid = debuggerConfigExtension.childProcessId;
		const ctid = debuggerConfigExtension.childThreadId;
		const ppid = debuggerConfigExtension.parentProcessId;

		assert.isTrue(childSession.name.startsWith(`callee.exe #${cpid}`));

		assert.strictEqual(result.output,
			`  CALLER (${ppid}): initialized\r\n` +
			`  CALLER (${ppid}): started process ${calleePath}; PID ${cpid}; TID ${ctid}\r\n` +
			`  CALLER (${ppid}): resumed child\r\n` +
			`  CALLER (${ppid}): wait for child\r\n` +
			`  CALLEE (${cpid}): initialized\r\n` +
			`  CALLEE (${cpid}): terminating\r\n` +
			`  CALLER (${ppid}): terminating\r\n`
		);

	}).timeout(100000);

	test(`Attach only command line (${arch})`, async () => {
		vscode.window.showInformationMessage(`RUN Attach Only Command Line (${arch}).`);

		const result = await startDebuggingAndWait({
			type: "cppvsdbg",
			name: "Parent Session",
			request: "launch",
			program: callerPath,
			args: [
				"--init-time", "0",
				"--final-time", "0",
				"--no-app-name",
				"--wait",
				calleePath,
				"-",
				"--sleep-time", "0"
			],
			"console": "internalConsole",
		});

		assert.strictEqual(result.startedSessions.length, 2);

		assert.strictEqual(result.startedSessions[0].name, "Parent Session");

		const childSession = result.startedSessions[1];
		assert.isTrue('childDebuggerExtension' in childSession.configuration);

		const debuggerConfigExtension: ChildDebuggerConfigurationExtension = childSession.configuration.childDebuggerExtension;

		assert.isTrue(debuggerConfigExtension.childSuspended);
		assert.isTrue(debuggerConfigExtension.parentSuspended);

		const cpid = debuggerConfigExtension.childProcessId;
		const ctid = debuggerConfigExtension.childThreadId;
		const ppid = debuggerConfigExtension.parentProcessId;

		assert.strictEqual(childSession.name, `callee.exe #${cpid}`);

		assert.strictEqual(result.output,
			`  CALLER (${ppid}): initialized\r\n` +
			`  CALLER (${ppid}): started process ${calleePath}; PID ${cpid}; TID ${ctid}\r\n` +
			`  CALLER (${ppid}): wait for child\r\n` +
			`  CALLEE (${cpid}): initialized\r\n` +
			`  CALLEE (${cpid}): terminating\r\n` +
			`  CALLER (${ppid}): terminating\r\n`
		);

	}).timeout(100000);

	test(`Attach once ANSI (${arch})`, async () => {
		vscode.window.showInformationMessage(`RUN Attach ANSI (${arch}).`);

		const result = await startDebuggingAndWait({
			type: "cppvsdbg",
			name: "Parent Session",
			request: "launch",
			program: callerPath,
			args: [
				"--init-time", "0",
				"--final-time", "0",
				"--ansi",
				"--wait",
				calleePath,
				"-",
				"--sleep-time", "0"
			],
			"console": "internalConsole",
		});

		assert.strictEqual(result.startedSessions.length, 2);

		assert.strictEqual(result.startedSessions[0].name, "Parent Session");

		const childSession = result.startedSessions[1];
		assert.isTrue('childDebuggerExtension' in childSession.configuration);

		const debuggerConfigExtension: ChildDebuggerConfigurationExtension = childSession.configuration.childDebuggerExtension;

		assert.isTrue(debuggerConfigExtension.childSuspended);
		assert.isTrue(debuggerConfigExtension.parentSuspended);

		const cpid = debuggerConfigExtension.childProcessId;
		const ctid = debuggerConfigExtension.childThreadId;
		const ppid = debuggerConfigExtension.parentProcessId;

		assert.strictEqual(childSession.name, `callee.exe #${cpid}`);

		assert.strictEqual(result.output,
			`  CALLER (${ppid}): initialized\r\n` +
			`  CALLER (${ppid}): started process ${calleePath}; PID ${cpid}; TID ${ctid}\r\n` +
			`  CALLER (${ppid}): wait for child\r\n` +
			`  CALLEE (${cpid}): initialized\r\n` +
			`  CALLEE (${cpid}): terminating\r\n` +
			`  CALLER (${ppid}): terminating\r\n`
		);

	}).timeout(100000);

	test(`Attach only command line ANSI (${arch})`, async () => {
		vscode.window.showInformationMessage(`RUN Attach Only Command Line ANSI (${arch}).`);

		const result = await startDebuggingAndWait({
			type: "cppvsdbg",
			name: "Parent Session",
			request: "launch",
			program: callerPath,
			args: [
				"--init-time", "0",
				"--final-time", "0",
				"--no-app-name",
				"--ansi",
				"--wait",
				calleePath,
				"-",
				"--sleep-time", "0"
			],
			"console": "internalConsole",
		});

		assert.strictEqual(result.startedSessions.length, 2);

		assert.strictEqual(result.startedSessions[0].name, "Parent Session");

		const childSession = result.startedSessions[1];
		assert.isTrue('childDebuggerExtension' in childSession.configuration);

		const debuggerConfigExtension: ChildDebuggerConfigurationExtension = childSession.configuration.childDebuggerExtension;

		assert.isTrue(debuggerConfigExtension.childSuspended);
		assert.isTrue(debuggerConfigExtension.parentSuspended);

		const cpid = debuggerConfigExtension.childProcessId;
		const ctid = debuggerConfigExtension.childThreadId;
		const ppid = debuggerConfigExtension.parentProcessId;

		assert.strictEqual(childSession.name, `callee.exe #${cpid}`);

		assert.strictEqual(result.output,
			`  CALLER (${ppid}): initialized\r\n` +
			`  CALLER (${ppid}): started process ${calleePath}; PID ${cpid}; TID ${ctid}\r\n` +
			`  CALLER (${ppid}): wait for child\r\n` +
			`  CALLEE (${cpid}): initialized\r\n` +
			`  CALLEE (${cpid}): terminating\r\n` +
			`  CALLER (${ppid}): terminating\r\n`
		);

	}).timeout(100000);

	test(`Attach once User (${arch})`, async () => {
		vscode.window.showInformationMessage(`RUN Attach user (${arch}).`);

		const result = await startDebuggingAndWait({
			type: "cppvsdbg",
			name: "Parent Session",
			request: "launch",
			program: callerPath,
			args: [
				"--init-time", "0",
				"--final-time", "0",
				"--method", "user",
				"--wait",
				calleePath,
				"-",
				"--sleep-time", "0"
			],
			"console": "internalConsole",
		});

		assert.strictEqual(result.startedSessions.length, 2);

		assert.strictEqual(result.startedSessions[0].name, "Parent Session");

		const childSession = result.startedSessions[1];
		assert.isTrue('childDebuggerExtension' in childSession.configuration);

		const debuggerConfigExtension: ChildDebuggerConfigurationExtension = childSession.configuration.childDebuggerExtension;

		assert.isTrue(debuggerConfigExtension.childSuspended);
		assert.isTrue(debuggerConfigExtension.parentSuspended);

		const cpid = debuggerConfigExtension.childProcessId;
		const ctid = debuggerConfigExtension.childThreadId;
		const ppid = debuggerConfigExtension.parentProcessId;

		assert.strictEqual(childSession.name, `callee.exe #${cpid}`);

		assert.strictEqual(result.output,
			`  CALLER (${ppid}): initialized\r\n` +
			`  CALLER (${ppid}): started process ${calleePath}; PID ${cpid}; TID ${ctid}\r\n` +
			`  CALLER (${ppid}): wait for child\r\n` +
			`  CALLEE (${cpid}): initialized\r\n` +
			`  CALLEE (${cpid}): terminating\r\n` +
			`  CALLER (${ppid}): terminating\r\n`
		);

	}).timeout(100000);

	test(`Attach once User ANSI (${arch})`, async () => {
		vscode.window.showInformationMessage(`RUN Attach user ANSI (${arch}).`);

		const result = await startDebuggingAndWait({
			type: "cppvsdbg",
			name: "Parent Session",
			request: "launch",
			program: callerPath,
			args: [
				"--init-time", "0",
				"--final-time", "0",
				"--method", "user",
				"--ansi",
				"--wait",
				calleePath,
				"-",
				"--sleep-time", "0"
			],
			"console": "internalConsole",
		});

		assert.strictEqual(result.startedSessions.length, 2);

		assert.strictEqual(result.startedSessions[0].name, "Parent Session");

		const childSession = result.startedSessions[1];
		assert.isTrue('childDebuggerExtension' in childSession.configuration);

		const debuggerConfigExtension: ChildDebuggerConfigurationExtension = childSession.configuration.childDebuggerExtension;

		assert.isTrue(debuggerConfigExtension.childSuspended);
		assert.isTrue(debuggerConfigExtension.parentSuspended);

		const cpid = debuggerConfigExtension.childProcessId;
		const ctid = debuggerConfigExtension.childThreadId;
		const ppid = debuggerConfigExtension.parentProcessId;

		assert.strictEqual(childSession.name, `callee.exe #${cpid}`);

		assert.strictEqual(result.output,
			`  CALLER (${ppid}): initialized\r\n` +
			`  CALLER (${ppid}): started process ${calleePath}; PID ${cpid}; TID ${ctid}\r\n` +
			`  CALLER (${ppid}): wait for child\r\n` +
			`  CALLEE (${cpid}): initialized\r\n` +
			`  CALLEE (${cpid}): terminating\r\n` +
			`  CALLER (${ppid}): terminating\r\n`
		);

	}).timeout(100000);

	// test(`Attach once Token (${arch})`, async () => {
	// 	vscode.window.showInformationMessage(`RUN Attach Token (${arch}).`);

	// 	const result = await startDebuggingAndWait({
	// 		type: "cppvsdbg",
	// 		name: "Parent Session",
	// 		request: "launch",
	// 		program: callerPath,
	// 		args: [
	// 			"--init-time", "0",
	// 			"--final-time", "0",
	// 			"--method", "token",
	// 			"--wait",
	// 			calleePath,
	// 			"-",
	// 			"--sleep-time", "0"
	// 		],
	// 		"console": "internalConsole",
	// 	});

	// 	assert.strictEqual(result.startedSessions.length, 2);

	// 	assert.strictEqual(result.startedSessions[0].name, "Parent Session");

	// 	const childSession = result.startedSessions[1];
	// 	assert.isTrue('childDebuggerExtension' in childSession.configuration);

	// 	const debuggerConfigExtension: ChildDebuggerConfigurationExtension = childSession.configuration.childDebuggerExtension;

	// 	assert.isTrue(debuggerConfigExtension.childSuspended);
	// 	assert.isTrue(debuggerConfigExtension.parentSuspended);

	// 	const cpid = debuggerConfigExtension.childProcessId;
	// 	const ctid = debuggerConfigExtension.childThreadId;
	// 	const ppid = debuggerConfigExtension.parentProcessId;

	// 	assert.strictEqual(childSession.name, `callee.exe #${cpid}`);

	// 	assert.strictEqual(result.output,
	// 		`  CALLER (${ppid}): initialized\r\n` +
	// 		`  CALLER (${ppid}): started process ${calleePath}; PID ${cpid}; TID ${ctid}\r\n` +
	// 		`  CALLER (${ppid}): wait for child\r\n` +
	// 		`  CALLEE (${cpid}): initialized\r\n` +
	// 		`  CALLEE (${cpid}): terminating\r\n` +
	// 		`  CALLER (${ppid}): terminating\r\n`
	// 	);

	// }).timeout(100000);

}

suite('Auto attach x64', () => {
	const testExeDirX64 = path.join(__dirname, "..", "..", "..", "build-x64", "tests", "bin");

	const callerPathX64 = path.join(testExeDirX64, "caller.exe");
	const calleePathX64 = path.join(testExeDirX64, "callee.exe");

	testArchitecture(callerPathX64, calleePathX64, "x64");
});

suite('Auto attach x86', () => {
	const testExeDirX86 = path.join(__dirname, "..", "..", "..", "build-x86", "tests", "bin");

	const callerPathX86 = path.join(testExeDirX86, "caller.exe");
	const calleePathX86 = path.join(testExeDirX86, "callee.exe");

	testArchitecture(callerPathX86, calleePathX86, "x86");
});
