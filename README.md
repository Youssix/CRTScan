# CRTScan

CRTScan is a defensive user-mode prototype for detecting suspicious DLLs through
C Runtime fingerprinting, PE structure analysis, and return-address inspection.

The research idea is simple: injected or manually mapped payloads often differ
from normal application DLLs in their signing state, import table shape, unwind
metadata, security-cookie setup, and CRT initialization behavior. CRTScan turns
those differences into a small scoring engine that can be studied and extended
in an authorized lab.

## What is implemented

- loaded-module enumeration with `CreateToolhelp32Snapshot`
- Authenticode signature checks through `WinVerifyTrust`
- PE header parsing for x64 modules
- `.pdata` / exception directory detection
- load-config inspection for security-cookie metadata
- import table counting and CRT import detection
- basic suspicion scoring for anomalous modules
- IAT hook prototypes for selected CRT initialization-related APIs
- stack capture and return-address validation against signed modules

## Detection model

CRTScan combines several weak signals rather than relying on one indicator:

- unsigned module loaded into a signed process
- missing x64 unwind metadata
- missing security-cookie metadata
- very small or sparse import table
- absence of normal CRT linkage in a module that performs real work
- calls into common initialization APIs from unsigned or unknown modules

The result is a research score, not a final verdict. The project is meant to
show how these signals can be correlated, tuned, and validated.

## Build

Requirements:

- Visual Studio 2022
- x64 Native Tools Command Prompt

Build the prototype:

```bat
cl /W4 /O2 /DWIN32_LEAN_AND_MEAN src\main.c src\scanner.c src\hooks.c /Fe:crtscan.exe /link advapi32.lib wintrust.lib imagehlp.lib dbghelp.lib
```

Run against the current process:

```bat
crtscan.exe
```

Run with a target PID:

```bat
crtscan.exe 1234
```

## Current status

CRTScan is a work-in-progress research tool. The scoring heuristic needs tuning
against larger benign and malicious datasets. The IAT hook engine currently
covers a small set of APIs and is designed for local experimentation, not
enterprise deployment.

## Responsible use

This project is for defensive analysis, malware triage labs, and detection
engineering research. It does not include injection, exploitation, persistence,
or evasion functionality.

## Related writeup

- [CRT vs NoCRT Detection](https://youssix.github.io/2026/05/10/crt-nocrt-detection/)

## License

MIT
