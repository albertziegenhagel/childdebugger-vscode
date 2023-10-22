import * as vscode from 'vscode';
// import * as ntsuspend from 'ntsuspend';

var outputChannel = vscode.window.createOutputChannel("ChildDebugger");

export function activate(context: vscode.ExtensionContext) {

	vscode.debug.onDidStartDebugSession((session : vscode.DebugSession) => {
		if(session.type !== "cppvsdbg") {
			return;
		}
		if('suspended' in session.configuration && session.configuration.suspended) {
			const processId : number = session.configuration.processId;
			const threadId : number = session.configuration.threadId;
			outputChannel.appendLine(`Continue suspended child process ${processId}:`);
			const args = {
				threadId: threadId,
				singleThread: false
			};
			session.customRequest("continue", args).then((response)=> {
				outputChannel.appendLine(`  continue: succeeded: ${response}`);
			}, (reason) => {
				outputChannel.appendLine(`  continue: failed: "${reason}"`);
			});
		}
	});

	vscode.debug.registerDebugAdapterTrackerFactory('*', {
		createDebugAdapterTracker(session: vscode.DebugSession) {
		  return {
			onDidSendMessage: (m) => {
				if (m.type !== "event" ||
					m.event !== "output" ||
					m.body.category !== "console") {
					return;
				}
				const startDebugInitText : string = "ChildDebugger: attach to child ";
				const output : string = m.body.output;
				if (!output.startsWith(startDebugInitText)) {
					return;
				}
				const suspended = output.indexOf(" SUSPENDED", startDebugInitText.length);

				const pidRegex = /PID (\d+)/g;
				const tidRegex = /TID (\d+)/g;
				const nameRegex = /NAME '([^"]*)'/g;
				const pidMatch = output.matchAll(pidRegex);
				const tidMatch = output.matchAll(tidRegex);
				const nameMatch = output.matchAll(nameRegex);
				const pidStr: string|undefined|null = pidMatch.next().value[1];
				const tidStr: string|undefined|null = tidMatch.next().value[1];
				let name: string|undefined|null = nameMatch.next().value[1];

				if(!pidStr || !tidStr) {
					return;
				}

				if(!name || name.length === 0) {
					name = "Child";
				}

				const processId = parseInt(pidStr);
				const threadId = parseInt(tidStr);

				const configuration : vscode.DebugConfiguration = {
					type : "cppvsdbg",
					name : `${name} (${processId})`,
					request : "attach",
					processId : processId,
					threadId : threadId,
					suspended : suspended !== -1
				};
				const options : vscode.DebugSessionOptions = {
					parentSession: session,
					compact: true,
					lifecycleManagedByParent: true,
					consoleMode: vscode.DebugConsoleMode.MergeWithParent,
					// noDebug: true,
					// suppressDebugToolbar : true,
					// suppressDebugStatusbar : true,
					// suppressDebugView : true
				};
				outputChannel.appendLine(`Attempting attach to child ${processId}`);
				vscode.debug.startDebugging(undefined, configuration, options).then(()=> {
					outputChannel.appendLine(`  attach: succeeded`);
				}, (reason) => {
					outputChannel.appendLine(`  attach: failed: "${reason}"`);
				});
			}
		  };
		}
	  });
}

export function deactivate() {}
