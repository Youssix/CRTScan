# CRTScan

User-mode DLL injection detection via CRT fingerprinting.

Scans loaded modules in a process and flags ones that look manually mapped or injected. The idea is simple: legitimately loaded DLLs link against the CRT, have exception data (.pdata), security cookies, and valid signatures. Injected ones usually don't.

Also hooks a handful of common API functions and checks whether the return address belongs to a known signed module.

## What it checks

For each loaded module:
- Digital signature status
- Presence of `.pdata` section (structured exception handling)
- `__security_cookie` in `.data`
- Import count (low count = suspicious)
- CRT linkage (vcruntime140.dll, ucrtbase.dll)

Each check contributes to a suspicion score. High score = probably injected.

## Hook engine

Patches IAT entries for:
- `GetSystemTimeAsFileTime`
- `QueryPerformanceCounter`
- `GetCurrentProcessId`
- `GetCurrentThreadId`

In each hook, captures the return address and walks the stack to see if the caller lives inside a legitimate module. Logs anything suspicious.

## Building

Visual Studio 2022, x64, Release. Open a Developer Command Prompt:

```
cl /W4 /O2 /DWIN32_LEAN_AND_MEAN src/main.c src/scanner.c src/hooks.c /Fe:crtscan.exe /link advapi32.lib wintrust.lib imagehlp.lib dbghelp.lib
```

Or just make a VS project, add the source files, set platform to x64. Nothing fancy.

## Status

Work in progress. The scoring heuristic needs tuning and the hook engine only covers a few functions right now. Stack walking is basic.

## License

None yet.
