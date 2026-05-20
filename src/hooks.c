#include "crtscan.h"
#include <stdio.h>
#include <intrin.h>
#include <dbghelp.h>

#pragma comment(lib, "dbghelp.lib")

#pragma intrinsic(_ReturnAddress)

// ---------------------------------------------------------------
// Original function pointers
// ---------------------------------------------------------------

typedef void (WINAPI *pfnGetSystemTimeAsFileTime)(LPFILETIME);
typedef BOOL (WINAPI *pfnQueryPerformanceCounter)(LARGE_INTEGER *);
typedef DWORD (WINAPI *pfnGetCurrentProcessId)(void);
typedef DWORD (WINAPI *pfnGetCurrentThreadId)(void);

static pfnGetSystemTimeAsFileTime  g_orig_GetSystemTimeAsFileTime  = NULL;
static pfnQueryPerformanceCounter  g_orig_QueryPerformanceCounter  = NULL;
static pfnGetCurrentProcessId      g_orig_GetCurrentProcessId      = NULL;
static pfnGetCurrentThreadId       g_orig_GetCurrentThreadId       = NULL;

#define MAX_HOOK_ENTRIES 4
static HOOK_ENTRY g_hooks[MAX_HOOK_ENTRIES];
static DWORD g_hook_count = 0;

// Simple log buffer for suspicious callers
// TODO: make this thread-safe, use a lock or lockfree queue
#define MAX_SUSPICIOUS_LOG 256
static SUSPICIOUS_CALLER g_suspicious_log[MAX_SUSPICIOUS_LOG];
static volatile LONG g_suspicious_count = 0;

// ---------------------------------------------------------------
// Return address validation
// ---------------------------------------------------------------

BOOL
IsAddressInSignedModule(PVOID address)
{
    HMODULE hmod = NULL;
    CHAR path[MAX_PATH];
    BOOL is_signed = FALSE;

    // figure out which module this address belongs to
    if (!GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            (LPCSTR)address,
            &hmod)) {
        return FALSE; // address doesn't belong to any module - very suspicious
    }

    if (GetModuleFileNameA(hmod, path, MAX_PATH) == 0)
        return FALSE;

    CheckModuleSignature(path, &is_signed);
    return is_signed;
}

static void
WalkCallStack(LPCSTR hooked_func)
{
    void *stack[MAX_STACK_FRAMES];
    USHORT frames;

    frames = CaptureStackBackTrace(2, MAX_STACK_FRAMES, stack, NULL);

    for (USHORT i = 0; i < frames; i++) {
        if (!IsAddressInSignedModule(stack[i])) {
            // found a frame that's not in a signed module
            HMODULE hmod = NULL;
            GetModuleHandleExA(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                (LPCSTR)stack[i],
                &hmod);

            LONG idx = InterlockedIncrement(&g_suspicious_count) - 1;
            if (idx < MAX_SUSPICIOUS_LOG) {
                PSUSPICIOUS_CALLER entry = &g_suspicious_log[idx];
                entry->return_address = stack[i];
                entry->module_base = hmod;
                entry->thread_id = GetCurrentThreadId();
                strncpy_s(entry->hooked_function, 64, hooked_func, _TRUNCATE);

                if (hmod) {
                    GetModuleFileNameA(hmod, entry->module_name, MAX_MODULE_NAME);
                } else {
                    strncpy_s(entry->module_name, MAX_MODULE_NAME, "<unknown>", _TRUNCATE);
                }
            }
            break; // log the first suspicious frame only
        }
    }
}

void
LogSuspiciousCaller(PVOID ret_addr, LPCSTR function_name)
{
    if (!IsAddressInSignedModule(ret_addr)) {
        printf("[!] Suspicious call to %s from 0x%p (unsigned module)\n",
               function_name, ret_addr);
    }
}

// ---------------------------------------------------------------
// Hook implementations
// ---------------------------------------------------------------

static void WINAPI
Hook_GetSystemTimeAsFileTime(LPFILETIME ft)
{
    PVOID ret = _ReturnAddress();
    LogSuspiciousCaller(ret, "GetSystemTimeAsFileTime");
    WalkCallStack("GetSystemTimeAsFileTime");

    if (g_orig_GetSystemTimeAsFileTime)
        g_orig_GetSystemTimeAsFileTime(ft);
}

static BOOL WINAPI
Hook_QueryPerformanceCounter(LARGE_INTEGER *counter)
{
    PVOID ret = _ReturnAddress();
    LogSuspiciousCaller(ret, "QueryPerformanceCounter");
    WalkCallStack("QueryPerformanceCounter");

    if (g_orig_QueryPerformanceCounter)
        return g_orig_QueryPerformanceCounter(counter);
    return FALSE;
}

static DWORD WINAPI
Hook_GetCurrentProcessId(void)
{
    PVOID ret = _ReturnAddress();
    LogSuspiciousCaller(ret, "GetCurrentProcessId");
    WalkCallStack("GetCurrentProcessId");

    if (g_orig_GetCurrentProcessId)
        return g_orig_GetCurrentProcessId();
    return 0;
}

static DWORD WINAPI
Hook_GetCurrentThreadId(void)
{
    PVOID ret = _ReturnAddress();
    LogSuspiciousCaller(ret, "GetCurrentThreadId");
    WalkCallStack("GetCurrentThreadId");

    if (g_orig_GetCurrentThreadId)
        return g_orig_GetCurrentThreadId();
    return 0;
}

// ---------------------------------------------------------------
// IAT patching
// ---------------------------------------------------------------

static PVOID *
FindIATEntry(HMODULE hmod, LPCSTR target_module, LPCSTR target_function)
{
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS64 nt;
    PIMAGE_IMPORT_DESCRIPTOR import_desc;
    DWORD import_rva;

    dos = (PIMAGE_DOS_HEADER)hmod;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    nt = (PIMAGE_NT_HEADERS64)((BYTE *)hmod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    import_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (import_rva == 0)
        return NULL;

    import_desc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE *)hmod + import_rva);

    while (import_desc->Name != 0) {
        const char *dll_name = (const char *)((BYTE *)hmod + import_desc->Name);

        if (_stricmp(dll_name, target_module) == 0) {
            PIMAGE_THUNK_DATA64 orig_thunk = (PIMAGE_THUNK_DATA64)(
                (BYTE *)hmod + import_desc->OriginalFirstThunk);
            PIMAGE_THUNK_DATA64 iat_thunk = (PIMAGE_THUNK_DATA64)(
                (BYTE *)hmod + import_desc->FirstThunk);

            while (orig_thunk->u1.AddressOfData != 0) {
                if (!(orig_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)) {
                    PIMAGE_IMPORT_BY_NAME import_name = (PIMAGE_IMPORT_BY_NAME)(
                        (BYTE *)hmod + orig_thunk->u1.AddressOfData);

                    if (strcmp(import_name->Name, target_function) == 0) {
                        return (PVOID *)&iat_thunk->u1.Function;
                    }
                }
                orig_thunk++;
                iat_thunk++;
            }
        }
        import_desc++;
    }

    return NULL;
}

static BOOL
PatchIATEntry(PVOID *iat_slot, PVOID new_func, PVOID *old_func)
{
    DWORD old_protect;

    *old_func = *iat_slot;

    if (!VirtualProtect(iat_slot, sizeof(PVOID), PAGE_READWRITE, &old_protect)) {
        printf("[!] VirtualProtect failed on IAT slot: %lu\n", GetLastError());
        return FALSE;
    }

    *iat_slot = new_func;

    VirtualProtect(iat_slot, sizeof(PVOID), old_protect, &old_protect);
    return TRUE;
}

static BOOL
RegisterHook(LPCSTR module, LPCSTR function, PVOID hook, PVOID *original)
{
    HMODULE exe = GetModuleHandleA(NULL);
    PVOID *iat_slot;

    iat_slot = FindIATEntry(exe, module, function);
    if (!iat_slot) {
        // TODO: scan all loaded modules, not just the exe
        printf("[!] Could not find IAT entry for %s!%s\n", module, function);
        return FALSE;
    }

    if (!PatchIATEntry(iat_slot, hook, original)) {
        return FALSE;
    }

    if (g_hook_count < MAX_HOOK_ENTRIES) {
        PHOOK_ENTRY entry = &g_hooks[g_hook_count++];
        entry->function_name = function;
        entry->module_name = module;
        entry->original_func = *original;
        entry->hook_func = hook;
        entry->iat_entry = iat_slot;
    }

    printf("[+] Hooked %s!%s\n", module, function);
    return TRUE;
}

// ---------------------------------------------------------------
// Public API
// ---------------------------------------------------------------

BOOL
InstallIATHooks(void)
{
    BOOL ok = TRUE;

    ok &= RegisterHook("kernel32.dll", "GetSystemTimeAsFileTime",
                        Hook_GetSystemTimeAsFileTime,
                        (PVOID *)&g_orig_GetSystemTimeAsFileTime);

    ok &= RegisterHook("kernel32.dll", "QueryPerformanceCounter",
                        Hook_QueryPerformanceCounter,
                        (PVOID *)&g_orig_QueryPerformanceCounter);

    ok &= RegisterHook("kernel32.dll", "GetCurrentProcessId",
                        Hook_GetCurrentProcessId,
                        (PVOID *)&g_orig_GetCurrentProcessId);

    ok &= RegisterHook("kernel32.dll", "GetCurrentThreadId",
                        Hook_GetCurrentThreadId,
                        (PVOID *)&g_orig_GetCurrentThreadId);

    if (!ok)
        printf("[!] Some hooks failed to install\n");

    return ok;
}

BOOL
RemoveIATHooks(void)
{
    DWORD old_protect;

    for (DWORD i = 0; i < g_hook_count; i++) {
        PHOOK_ENTRY entry = &g_hooks[i];
        PVOID *slot = (PVOID *)entry->iat_entry;

        if (VirtualProtect(slot, sizeof(PVOID), PAGE_READWRITE, &old_protect)) {
            *slot = entry->original_func;
            VirtualProtect(slot, sizeof(PVOID), old_protect, &old_protect);
            printf("[-] Unhooked %s!%s\n", entry->module_name, entry->function_name);
        }
    }

    g_hook_count = 0;
    return TRUE;
}
