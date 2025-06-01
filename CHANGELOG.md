# Change Log

## [Unreleased]

## 1.2.0

- Fixed an issue where the debugger got confused when multiple threads of a parent process started child processes at nearly the same time. This could manifest itself in the process picker launching is VS Code ([#30](https://github.com/albertziegenhagel/childdebugger-vscode/pull/30)).

## 1.1.0

- Fix possible crashes of debugger that was attached to the child processes ([#27](https://github.com/albertziegenhagel/childdebugger-vscode/pull/27)).
- Fix missing line breaks in log messages ([#28](https://github.com/albertziegenhagel/childdebugger-vscode/pull/28)).

## 1.0.0

- Make child debugging opt-in instead of on-by-default ([#25](https://github.com/albertziegenhagel/childdebugger-vscode/pull/25)).
  It is now required to set `"autoAttachChildProcess": true` in the `launch.json` config to enable child process debugging.

## 0.1.0

- Initial pre-release
