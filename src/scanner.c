#include "crtscan.h"
#include <tlhelp32.h>
#include <wintrust.h>
#include <softpub.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "imagehlp.lib")

// CRT dlls we expect legitimate modules to link against
static const char *g_crt_dlls[] = {
    "vcruntime140.dll",
    "vcruntime140d.dll",
    "ucrtbase.dll",
    "ucrtbased.dll",
    "msvcrt.dll",
    "msvcp140.dll",
    NULL
};

static BOOL
IsCrtDll(const char *name)
{
    for (int i = 0; g_crt_dlls[i] != NULL; i++) {
        if (_stricmp(name, g_crt_dlls[i]) == 0)
            return TRUE;
    }
    return FALSE;
}

BOOL
CheckModuleSignature(LPCSTR module_path, PBOOL is_signed)
{
    WCHAR wide_path[MAX_PATH];
    WINTRUST_FILE_INFO file_info = { 0 };
    WINTRUST_DATA wt_data = { 0 };
    GUID policy_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status;

    *is_signed = FALSE;

    if (MultiByteToWideChar(CP_ACP, 0, module_path, -1, wide_path, MAX_PATH) == 0)
        return FALSE;

    file_info.cbStruct = sizeof(WINTRUST_FILE_INFO);
    file_info.pcwszFilePath = wide_path;
    file_info.hFile = NULL;
    file_info.pgKnownSubject = NULL;

    wt_data.cbStruct = sizeof(WINTRUST_DATA);
    wt_data.pPolicyCallbackData = NULL;
    wt_data.pSIPClientData = NULL;
    wt_data.dwUIChoice = WTD_UI_NONE;
    wt_data.fdwRevocationChecks = WTD_REVOKE_NONE;
    wt_data.dwUnionChoice = WTD_CHOICE_FILE;
    wt_data.dwStateAction = WTD_STATEACTION_VERIFY;
    wt_data.hWVTStateData = NULL;
    wt_data.pwszURLReference = NULL;
    wt_data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
    wt_data.pFile = &file_info;

    status = WinVerifyTrust(INVALID_HANDLE_VALUE, &policy_guid, &wt_data);

    *is_signed = (status == ERROR_SUCCESS);

    // close the state handle
    wt_data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(INVALID_HANDLE_VALUE, &policy_guid, &wt_data);

    return TRUE;
}

BOOL
ParsePEHeaders(PVOID base, PMODULE_SCAN_RESULT result)
{
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS64 nt;
    PIMAGE_SECTION_HEADER section;
    PIMAGE_IMPORT_DESCRIPTOR import_desc;
    DWORD import_rva;
    DWORD import_size;

    dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    nt = (PIMAGE_NT_HEADERS64)((BYTE *)base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    // TODO: handle 32-bit modules too
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
        return FALSE;

    result->has_pdata = FALSE;
    result->has_security_cookie = FALSE;
    result->import_count = 0;
    result->crt_linked = FALSE;

    //
    // Check for .pdata section (exception directory)
    //
    if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress != 0 &&
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size != 0) {
        result->has_pdata = TRUE;
    }

    //
    // Check load config for security cookie
    // The load config directory tells us if __security_cookie is present
    //
    if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress != 0) {
        PIMAGE_LOAD_CONFIG_DIRECTORY64 load_cfg = (PIMAGE_LOAD_CONFIG_DIRECTORY64)(
            (BYTE *)base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress
        );
        // SecurityCookie field is at a known offset; if nonzero the module uses /GS
        if (load_cfg->SecurityCookie != 0) {
            result->has_security_cookie = TRUE;
        }
    }

    //
    // Walk import directory
    //
    import_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    import_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;

    if (import_rva != 0 && import_size != 0) {
        import_desc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE *)base + import_rva);

        while (import_desc->Name != 0) {
            const char *dll_name = (const char *)((BYTE *)base + import_desc->Name);

            result->import_count++;

            if (IsCrtDll(dll_name)) {
                result->crt_linked = TRUE;
            }

            import_desc++;
        }
    }

    return TRUE;
}

int
ComputeSuspicionScore(PMODULE_SCAN_RESULT result)
{
    int score = 0;

    // Not signed: +30
    if (!result->is_signed)
        score += 30;

    // No exception data: +20
    if (!result->has_pdata)
        score += 20;

    // No security cookie (/GS): +15
    if (!result->has_security_cookie)
        score += 15;

    // No CRT linkage: +25
    if (!result->crt_linked)
        score += 25;

    // Very few imports (manual mapped DLLs often have minimal imports): +10
    if (result->import_count < 3)
        score += 10;

    // TODO: check for TLS callbacks, unusual entry point locations,
    // suspicious section names (.text0, .code, etc)

    return score;
}

BOOL
ScanLoadedModules(PSCAN_CONTEXT ctx)
{
    HANDLE snap;
    MODULEENTRY32 me32;
    DWORD pid;
    DWORD idx = 0;

    pid = ctx->target_pid;
    if (pid == 0)
        pid = GetCurrentProcessId();

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) {
        printf("[!] CreateToolhelp32Snapshot failed: %lu\n", GetLastError());
        return FALSE;
    }

    me32.dwSize = sizeof(MODULEENTRY32);

    if (!Module32First(snap, &me32)) {
        CloseHandle(snap);
        return FALSE;
    }

    do {
        if (idx >= MAX_MODULES)
            break;

        PMODULE_SCAN_RESULT res = &ctx->results[idx];
        ZeroMemory(res, sizeof(MODULE_SCAN_RESULT));

        res->base_address = me32.modBaseAddr;
        res->size = me32.modBaseSize;
        strncpy_s(res->module_name, MAX_MODULE_NAME, me32.szModule, _TRUNCATE);

        // skip the CRT dlls themselves, not interesting
        if (IsCrtDll(me32.szModule))
            goto next;

        // check signature
        // TODO: this is slow, maybe cache results or do async
        CheckModuleSignature(me32.szExePath, &res->is_signed);

        // parse PE to check pdata, imports, security cookie
        if (!ParsePEHeaders(me32.modBaseAddr, res)) {
            // couldn't parse PE, that's suspicious by itself
            res->score = 70;
            idx++;
            goto next;
        }

        res->score = ComputeSuspicionScore(res);
        idx++;

next:
        me32.dwSize = sizeof(MODULEENTRY32);
    } while (Module32Next(snap, &me32));

    ctx->module_count = idx;
    CloseHandle(snap);
    return TRUE;
}

void
PrintScanResults(PSCAN_CONTEXT ctx)
{
    printf("\n=== Module Scan Results (%lu modules) ===\n\n", ctx->module_count);
    printf("%-40s %-18s %-6s %-6s %-6s %-5s %-4s %-6s\n",
           "Module", "Base", "Signed", "Pdata", "GS", "Imps", "CRT", "Score");
    printf("%-40s %-18s %-6s %-6s %-6s %-5s %-4s %-6s\n",
           "------", "----", "------", "-----", "--", "----", "---", "-----");

    for (DWORD i = 0; i < ctx->module_count; i++) {
        PMODULE_SCAN_RESULT r = &ctx->results[i];

        const char *flag = "";
        if (r->score >= SCORE_THRESHOLD)
            flag = " <<<";

        printf("%-40s 0x%016llX %-6s %-6s %-6s %-5lu %-4s %3d%s\n",
               r->module_name,
               (ULONGLONG)r->base_address,
               r->is_signed ? "yes" : "NO",
               r->has_pdata ? "yes" : "NO",
               r->has_security_cookie ? "yes" : "NO",
               r->import_count,
               r->crt_linked ? "yes" : "NO",
               r->score,
               flag);
    }

    printf("\nModules with score >= %d are flagged.\n", SCORE_THRESHOLD);
}
