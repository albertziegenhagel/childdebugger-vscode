# Child Process Debugger for VS Code

A VS Code extension to support (Windows) child process debugging in Visual Studio Code via the `cppvsdbg` Debug Adapter. If installed, adding `"autoAttachChildProcess": true` to your debug launch configuration will make VS Code automatically attach a debugger to all child processes spawned by any process that is currently being debugged.

It is intended to be the VS Code equivalent of the [Microsoft Child Process Debugging Power Tool](https://marketplace.visualstudio.com/items?itemName=vsdbgplat.MicrosoftChildProcessDebuggingPowerTool2022).

## Features

- Automatically attaches to child processes of any native application currently being debugged.
- Supports the `cppvsdbg` Debug Adapter on Windows provided by [`ms-vscode.cpptools`](https://marketplace.visualstudio.com/items?itemName=ms-vscode.cpptools).
- Detects child process creation by the following Win32 API functions:
  - [`CreateProcessA`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa)/[`CreateProcessW`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw)
  - [`CreateProcessAsUserA`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasusera)/[`CreateProcessAsUserW`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw).
  - [`CreateProcessWithTokenW`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw).
  - [`CreateProcessWithLogonW`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithlogonw).
- Suspends the child process while we are waiting for the debugger to attach, so that:
  - it is guaranteed that you can debug the child process right from the first user instruction.
  - even very short lived child processes can be debugged (especially useful for "proxy" processes that just launch another child process).
- Suspends the parent process while we are waiting for the debugger to attach, so that:
  - it does not proceed and generates some unexpected behavior (e.g. a parent process that original creates a suspended child process could resume it before we had a change to attach the debugger).
- Recursively attaches to child processes of child processes.
- Filtering of processes to attach to by the executable name or the command line they are invoked with.

## Limitations

- Only supports the `cppvsdbg` Debug Adapter on Windows. Other platforms or debug adapters are not supported.

## Installation

> NOTE: pre-build binaries are currently available for Windows x86-64 only.

This extension has been published to the [VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=albertziegenhagel.childdebugger).

It is suggested to install the latest release via VS Code's extension manager.

When installed in VS Code, the extension will automatically install an integration into the VS Debug Engine when it is activated. You can confirm that this integration was installed successfully by checking that you see something similar to 

```
-------------------------------------------------------------------
You may only use the C/C++ Extension for Visual Studio Code
with Visual Studio Code, Visual Studio or Visual Studio for Mac
software to help you develop and test your applications.
-------------------------------------------------------------------
Loading extensions from 'C:\Users\[User]\.vscode\extensions\albertziegenhagel-childdebugger-X.X.X\vsdbg-engine-extension\bin'.
```

in the beginning of the `DEBUG CONSOLE` output view when debugging any native application through the C++ `cppvsdbg` debugger.

If you want to try out the very latest features, you can can download the latest pre-release `*.vsix` package from the "Rolling release" at

https://github.com/albertziegenhagel/childdebugger-vscode/releases/tag/head

and [install it in VS Code manually](https://code.visualstudio.com/docs/editor/extension-marketplace#_install-from-a-vsix).

## Usage

By default, child processes debugging is disabled to make the impact of this extension on the usual debugging experience as small as possible. To enable it, you have to add `"autoAttachChildProcess": true` to the debug configuration in your `launch.json`. E.g. this could look like this:

```json
{
    "name": "Debug With Child Processes",
    "type": "cppvsdbg",
    "request": "launch",
    "program": "C:\\Path\\To\\My\\Executable.exe",
    "cwd": "${workspaceRoot}",
    "autoAttachChildProcess": true,
},
```

## Dependencies

- [`ms-vscode.cpptools`](https://marketplace.visualstudio.com/items?itemName=ms-vscode.cpptools) >= 1.4.0.

## Implementation Details

This extension works by integrating a [VS Debug Engine extension](https://github.com/microsoft/ConcordExtensibilitySamples) that can be found [here](vsdbg-engine-extension/README.md).

While a process is being debugged it will:

  - Automatically establish internal breakpoints on calls to the Win32 API functions [`CreateProcessA`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa), [`CreateProcessW`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw), [`CreateProcessAsUserA`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasusera), [`CreateProcessAsUserW`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw), [`CreateProcessWithTokenW`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw) and [`CreateProcessWithLogonW`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithlogonw) when `kernel32.dll` or `advapi32.dll` are loaded into the process.
  - When such a breakpoint is hit, it will:
    - Read the `lpApplicationName` and `lpCommandLine` arguments passed to the function call and filter based on the settings whether we want to attach to the new child process or not. If we do not want to attach, we stop here.
    - Read the `dwCreationFlags` and see whether [`CREATE_SUSPENDED`](learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags#:~:text=CREATE_SUSPENDED) is set. If it is not set, we will overwrite the internal process memory and set it to make sure that the child will be created in suspended state (can be disabled in the settings).
    - Determine the return instruction address of the function call and add a new internal breakpoint there.
  - When the breakpoint at the function return address is hit, it will:
    - Read the return value of the function call and abort if the create process call failed.
    - Read the resulting `lpProcessInformation` structure to determine the process ID and main thread ID of the new child process.
    - Suspend the parent process (can be disabled in the settings).
    - Send a message to VS Code that it should attach to the new child process.
  - When VS Code receives that message, it will start a new debug session to attach to the child process.
  - When VS Code finished attaching to the new child process, it will:
    - Send a message to the newly created debug session for the child process so that it can:
      - Resume the child process if it was suspended by the extension.
      - Inform it that it should skip over the ["initial breakpoint"](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/initial-breakpoint) for this process (can be disabled in the settings).
    - Send a message to the parents debug session so that it can:
      - Resume the parent process if it was suspended by the extension.
