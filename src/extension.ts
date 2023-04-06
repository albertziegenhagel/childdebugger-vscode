import * as vscode from 'vscode';
// import * as ntsuspend from 'ntsuspend';

export function activate(context: vscode.ExtensionContext) {

	vscode.debug.onDidStartDebugSession((session : vscode.DebugSession) => {
		if(session.type !== "cppvsdbg") {
			return;
		}
		console.log("SEND CUSTOM MESSAGE");
		session.customRequest("custom_message", "some other text").then(()=> {
			console.log("ACCEPTED");
		}, (reason) => {
			console.log("Rejected!");
			console.log(reason);
		});
		if('suspended' in session.configuration && session.configuration.suspended) {
			console.log("SEND SUSPENDED CUSTOM MESSAGE");
			session.customRequest("custom_message", "some other text").then(()=> {
				console.log("ACCEPTED");
			}, (reason) => {
				console.log("Rejected!");
				console.log(reason);
			});

			if (process.platform === 'win32') {
				// const ntsuspend = require('ntsuspend');
				// ntsuspend.resume(session.configuration.processId);
			}
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
				const startDebugInitText : string = "ChildDebugger: attach to child PID ";
				const output : string = m.body.output;
				if (!output.startsWith(startDebugInitText)) {
					return;
				}
				const suspended = output.indexOf(" SUSPENDED", startDebugInitText.length);
				const running = output.indexOf(" RUNNING",  startDebugInitText.length);

				const end = suspended === -1 ? running : suspended;
				const processId = parseInt(output.substring(startDebugInitText.length, end));
				const configuration : vscode.DebugConfiguration = {
					type : "cppvsdbg",
					name : `Child PID ${processId}`,
					request : "attach",
					processId : processId,
					suspended : suspended !== -1
				};
				vscode.debug.startDebugging(undefined, configuration, undefined);
			}
		  };
		}
	  });
}

export function deactivate() {}
