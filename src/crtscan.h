#ifndef CRTSCAN_H
#define CRTSCAN_H

#include <windows.h>

#define MAX_MODULE_NAME 260
#define MAX_MODULES 512
#define SCORE_THRESHOLD 60

// TODO: make these configurable
#define SCAN_INTERVAL_MS 5000
#define MAX_STACK_FRAMES 32

typedef struct _MODULE_SCAN_RESULT {
    PVOID       base_address;
    SIZE_T      size;
    CHAR        module_name[MAX_MODULE_NAME];
    BOOL        is_signed;
    BOOL        has_security_cookie;
    BOOL        has_pdata;
    DWORD       import_count;
    BOOL        crt_linked;
    int         score;          // 0-100, higher = more suspicious
} MODULE_SCAN_RESULT, *PMODULE_SCAN_RESULT;

typedef struct _SCAN_CONTEXT {
    MODULE_SCAN_RESULT  results[MAX_MODULES];
    DWORD               module_count;
    DWORD               target_pid;
    HANDLE              target_process;
    BOOL                hooks_installed;
} SCAN_CONTEXT, *PSCAN_CONTEXT;

typedef struct _HOOK_ENTRY {
    LPCSTR      function_name;
    LPCSTR      module_name;
    PVOID       original_func;
    PVOID       hook_func;
    PVOID       iat_entry;      // pointer to the IAT slot we patched
} HOOK_ENTRY, *PHOOK_ENTRY;

typedef struct _SUSPICIOUS_CALLER {
    PVOID       return_address;
    PVOID       module_base;
    CHAR        module_name[MAX_MODULE_NAME];
    CHAR        hooked_function[64];
    DWORD       thread_id;
} SUSPICIOUS_CALLER, *PSUSPICIOUS_CALLER;

//
// scanner.c
//
BOOL ScanLoadedModules(PSCAN_CONTEXT ctx);
BOOL CheckModuleSignature(LPCSTR module_path, PBOOL is_signed);
BOOL ParsePEHeaders(PVOID base, PMODULE_SCAN_RESULT result);
int  ComputeSuspicionScore(PMODULE_SCAN_RESULT result);
void PrintScanResults(PSCAN_CONTEXT ctx);

//
// hooks.c
//
BOOL InstallIATHooks(void);
BOOL RemoveIATHooks(void);
BOOL IsAddressInSignedModule(PVOID address);
void LogSuspiciousCaller(PVOID ret_addr, LPCSTR function_name);

#endif // CRTSCAN_H
