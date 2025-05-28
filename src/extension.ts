import * as vscode from 'vscode';
import { installVsDbgEngineExtensionIntegration, uninstallVsDbgEngineExtensionIntegration } from './integration';

const outputChannelName = "Child Debugger";

var outputChannel = vscode.window.createOutputChannel(outputChannelName);

interface EngineProcessConfig {
	applicationName: string | undefined,
	commandLine: string | undefined,
	attach: boolean,
}
interface EngineSettings {
	logLevel: string, //"off" | "error" | "info" | "debug" | "trace",

	suspendChildren: boolean,
	suspendParents: boolean,
	skipInitialBreakpoint: boolean,

	attachAny: boolean,

	processConfigs: EngineProcessConfig[],
	attachOthers: boolean
}

export interface ChildDebuggerConfigurationExtension {
	parentProcessId: number;
	parentThreadId: number;
	parentSuspended: boolean;

	childProcessId: number;
	childThreadId: number;
	childSuspended: boolean;
}

enum CustomMessageType {
	settings = 1,
	resumeChild = 2,
	resumeParent = 3,
	informChild = 4,
}

const childDebuggerSourceId = "{0BB89D05-9EAD-4295-9A74-A241583DE420}";

export function activate(context: vscode.ExtensionContext) {

	installVsDbgEngineExtensionIntegration(context.extensionPath).catch().then((value) => {
		outputChannel.appendLine("Successfully installed VS Debug Engine integration.");
	}, (reason) => {
		vscode.window.showErrorMessage(`Failed to install VS Debug Engine integration.\nSee "${outputChannelName}" output channel for more information.`);
		outputChannel.appendLine("Failed to install VS Debug Engine integration:");
		outputChannel.appendLine(`  ${reason}`);
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
					// Check whether this is some log message send from the child debugger
					// vs debug engine extension and skip otherwise
					const startDebugInitText: string = "ChildDebugger: attach to child ";
					const output: string = m.body.output;
					if (!output.startsWith(startDebugInitText)) {
						return;
					}

					// Parse the message for the necessary information about the involved
					// processes/threads.
					const parentSuspended = output.indexOf(" PSUSPENDED", startDebugInitText.length);
					const childSuspended = output.indexOf(" CSUSPENDED", startDebugInitText.length);
					const parentPidRegex = /PPID (\d+)/g;
					const parentTidRegex = /PTID (\d+)/g;
					const childPidRegex = /CPID (\d+)/g;
					const childTidRegex = /CTID (\d+)/g;
					const nameRegex = /NAME '([^"]*)'/g;
					const parentPidMatch = output.matchAll(parentPidRegex);
					const parentTidMatch = output.matchAll(parentTidRegex);
					const childPidMatch = output.matchAll(childPidRegex);
					const childTidMatch = output.matchAll(childTidRegex);
					const nameMatch = output.matchAll(nameRegex);
					const parentPidStr: string | undefined | null = parentPidMatch.next().value[1];
					const parentTidStr: string | undefined | null = parentTidMatch.next().value[1];
					const childPidStr: string | undefined | null = childPidMatch.next().value[1];
					const childTidStr: string | undefined | null = childTidMatch.next().value[1];
					let name: string | undefined | null = nameMatch.next().value[1];

					if (!parentPidStr || !parentTidStr || !childPidStr || !childTidStr) {
						return;
					}

					if (!name || name.length === 0) {
						name = "Child"; // default name
					}

					const parentProcessId = parseInt(parentPidStr);
					const parentThreadId = parseInt(parentTidStr);
					const childProcessId = parseInt(childPidStr);
					const childThreadId = parseInt(childTidStr);

					// Create the debug configuration for the child process debugging session.
					// We simply add some extended configuration options that should be ignored
					// by the debug adapter, but we will later use to inform the debug engine
					// extension that attaching the debugger finished and we can resume the
					// parent and child processes.
					const configurationExtension: ChildDebuggerConfigurationExtension = {
						parentProcessId: parentProcessId,
						parentThreadId: parentThreadId,
						parentSuspended: parentSuspended !== -1,
						childProcessId: childProcessId,
						childThreadId: childThreadId,
						childSuspended: childSuspended !== -1,
					};
					const configuration: vscode.DebugConfiguration = {
						type: "cppvsdbg",
						name: `${name} #${childProcessId}`,
						request: "attach",
						processId: childProcessId,
						// NOTE: we exploit the fact that we can attach any additional configuration
						//       to the debug session. This additional information carries data about the
						//       child and parent processes and is used to identify child process session
						//       in the `onDidStartDebugSession` handler.
						//       This is more of a HACK, since the additional configuration is actually
						//       transferred to the debug adapter, but so far the `cppvsdbg` adapter seems
						//       to simply ignore it and everything works fine.
						_childDebuggerExtension: configurationExtension,
						// always attach to children of children
						autoAttachChildProcess: true,
						visualizerFile: session.configuration.visualizerFile,
						// TODO: should we copy other configuration properties (like `symbolOptions`)
						//       from the parent to the child?,
					};
					const options: vscode.DebugSessionOptions = {
						parentSession: session,
						compact: true,
						lifecycleManagedByParent: true,
						consoleMode: vscode.DebugConsoleMode.MergeWithParent,
					};

					// Now, start attaching to the child process.
					outputChannel.appendLine(`Attempting attach to child process ${childProcessId}`);
					vscode.debug.startDebugging(session.workspaceFolder, configuration, options).then(() => {
						// outputChannel.appendLine(`  attach: succeeded`);
					}, (reason) => {
						outputChannel.appendLine(`  attach to ${childProcessId}: failed: "${reason}"`);
					});
				}
			};
		}
	});

	vscode.debug.onDidStartDebugSession(async (session: vscode.DebugSession) => {
		const globalConfiguration = vscode.workspace.getConfiguration("childDebugger");
		if (globalConfiguration === null || globalConfiguration === undefined) {
			return;
		}

		if (!globalConfiguration.get<boolean>("enabled", true)) {
			return;
		}

		if (session.type !== "cppvsdbg") {
			return;
		}

		// Build settings to be send to the new debug session.
		var processConfigs: EngineProcessConfig[] = [];
		for (const entry of globalConfiguration.get<any[]>("filter.childProcesses", [])) {
			processConfigs.push({
				applicationName: entry['applicationName'],
				commandLine: entry['commandLine'],
				attach: entry['attach'],
			});
		}

		const engineSettings: EngineSettings = {
			logLevel: globalConfiguration.get<string>("general.logLevel", "error"),

			suspendChildren: globalConfiguration.get<boolean>("general.suspendChildren", true),
			suspendParents: globalConfiguration.get<boolean>("general.suspendParents", true),

			skipInitialBreakpoint: globalConfiguration.get<boolean>("general.skipInitialBreakpoint", true),

			attachAny: session.configuration.autoAttachChildProcess === true,

			processConfigs: processConfigs,
			attachOthers: globalConfiguration.get<boolean>("filter.attachOtherChildren", true),
		};

		// Send the settings to the debug engine extension in the new session.
		try {
			// wait for this message to arrive before continuing to make sure
			// the debug session will not be terminated (when we resume the child/parent)
			// before we had a chance to deliver this message.
			await session.customRequest("vsCustomMessage", {
				message: {
					sourceId: childDebuggerSourceId,
					messageCode: CustomMessageType.settings.valueOf(),
					parameter1: JSON.stringify(engineSettings),
				}
			});
		}
		catch (reason) {
			outputChannel.appendLine(`  Sending child debugger settings failed: "${reason}"`);
		}

		// If this is not a debug session that we started for a child process,
		// there is nothing else we need to do.
		if (!('_childDebuggerExtension' in session.configuration)) {
			return;
		}
		const debuggerConfigExtension: ChildDebuggerConfigurationExtension = session.configuration._childDebuggerExtension;

		// If the child was suspended, send a request to resume it.
		// If it was not suspended by us, but we still want to skip over the initial breakpoint,
		// we will send a message anyways.
		// Only if we neither suspended the child process, nor do we want to skip the
		// initial breakpoint, we can skip sending a message.
		if (debuggerConfigExtension.childSuspended || engineSettings.skipInitialBreakpoint) {
			outputChannel.appendLine(`Resume child process ${debuggerConfigExtension.childProcessId}`);
			try {
				// Wait for this message to arrive before resuming the parent process.
				// Otherwise, the parent could resume the child process before we had a chance to
				// deliver this message, which could either make the child being already
				// stuck in the initial breakpoint, or it might even have terminated already.
				await session.customRequest("vsCustomMessage", {
					message: {
						sourceId: childDebuggerSourceId,
						messageCode: debuggerConfigExtension.childSuspended ? CustomMessageType.resumeChild.valueOf() : CustomMessageType.informChild.valueOf(),
						parameter1: debuggerConfigExtension.childProcessId,
						parameter2: debuggerConfigExtension.childThreadId
					}
				});
			}
			catch (reason) {
				outputChannel.appendLine(`  Resume child message failed: "${reason}"`);
			};
		}

		// If the parent was suspended, send a request to resume it.
		if (debuggerConfigExtension.parentSuspended &&
			session.parentSession !== undefined) {
			outputChannel.appendLine(`Resume parent process for ${debuggerConfigExtension.childProcessId}`);
			session.parentSession.customRequest("vsCustomMessage", {
				message: {
					sourceId: childDebuggerSourceId,
					messageCode: CustomMessageType.resumeParent.valueOf(),
					parameter1: debuggerConfigExtension.parentProcessId,
					parameter2: debuggerConfigExtension.parentThreadId,
				}
			}).then((response) => {
				// outputChannel.appendLine(`  vsCustomMessage resume parent: succeeded: ${response}`);
			}, (reason) => {
				outputChannel.appendLine(`  Resume parent message failed: "${reason}"`);
			});
		}
	});
}

export function deactivate() {
	// uninstallVsDbgEngineExtensionIntegration();
}
