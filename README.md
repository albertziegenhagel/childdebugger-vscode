# Child Debugger - VS Code extension

Prototype code for a VS Code extension to support (Windows) child process debugging in VS Code.

This extension is supposed to work in combination with the "Concord" VS Debug Engine extension to be found at https://github.com/albertziegenhagel/childdebugger-concord

## Getting Started

> NOTE: pre-build binaries are currently only available for Windows x86-64.

1. Download the pre-build package of this VS Code extension from

   https://github.com/albertziegenhagel/childdebugger-vscode/releases/download/head/childdebugger-win32-x64.vsix

   and install it in VS Code (see https://code.visualstudio.com/docs/editor/extension-marketplace#_install-from-a-vsix).


2. Download the latest pre-build binary package of the "Concord" VS Debug Engine from

   https://github.com/albertziegenhagel/childdebugger-concord/releases/download/head/childdebugger-concord-x86_64-windows.zip

   and extract the archive to an arbitrary directory (in the following assumed to be `C:\dev\childdebugger-concord\`).

   Create a file `$HOME\.cppvsdbg\extensions\ChildDebugger.link`, which's only content is a single line with the path to the `bin` subfolder of the directory we just extracted. E.g.:

   ```
   C:\dev\childdebugger-concord\bin
   ```

3. Start debugging any native program through the C++ `cppvsdbg` debugger. You should now see something similar to 

   ```
   -------------------------------------------------------------------
   You may only use the C/C++ Extension for Visual Studio Code
   with Visual Studio Code, Visual Studio or Visual Studio for Mac
   software to help you develop and test your applications.
   -------------------------------------------------------------------
   Loading extensions from 'C:\dev\childdebugger-concord\bin'.
   ```

   in the beginning of the `DEBUG CONSOLE` output view.

   If the program starts any child process via the Win32 API functions [`CreateProcessA`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa) or [`CreateProcessW`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw), VS Code should automatically attach to the child process.
