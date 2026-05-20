#include "crtscan.h"
#include <stdio.h>

static volatile BOOL g_running = TRUE;

static BOOL WINAPI
ConsoleCtrlHandler(DWORD ctrl_type)
{
    if (ctrl_type == CTRL_C_EVENT || ctrl_type == CTRL_BREAK_EVENT) {
        printf("\n[*] Shutting down...\n");
        g_running = FALSE;
        return TRUE;
    }
    return FALSE;
}

int main(int argc, char **argv)
{
    SCAN_CONTEXT ctx = { 0 };

    printf("CRTScan - DLL Injection Detection via CRT Fingerprinting\n");
    printf("=========================================================\n\n");

    // TODO: add command line args for target PID, scan interval, etc
    if (argc > 1) {
        ctx.target_pid = (DWORD)atoi(argv[1]);
        printf("[*] Target PID: %lu\n", ctx.target_pid);
    } else {
        ctx.target_pid = 0; // scan self
        printf("[*] Scanning own process (PID %lu)\n", GetCurrentProcessId());
    }

    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);

    // install hooks on our own process
    printf("[*] Installing IAT hooks...\n");
    if (InstallIATHooks()) {
        ctx.hooks_installed = TRUE;
        printf("[+] Hooks installed\n\n");
    } else {
        printf("[!] Hook installation partially failed, continuing anyway\n\n");
    }

    // main scan loop
    printf("[*] Starting scan loop (interval: %dms, Ctrl+C to stop)\n", SCAN_INTERVAL_MS);

    while (g_running) {
        ZeroMemory(ctx.results, sizeof(ctx.results));
        ctx.module_count = 0;

        if (ScanLoadedModules(&ctx)) {
            PrintScanResults(&ctx);

            // count flagged modules
            DWORD flagged = 0;
            for (DWORD i = 0; i < ctx.module_count; i++) {
                if (ctx.results[i].score >= SCORE_THRESHOLD)
                    flagged++;
            }

            if (flagged > 0) {
                printf("\n[!] WARNING: %lu module(s) flagged as potentially injected\n", flagged);
            } else {
                printf("\n[*] No suspicious modules detected\n");
            }
        } else {
            printf("[!] Module scan failed\n");
        }

        // TODO: also dump the suspicious caller log here
        // right now it just prints inline from the hooks which is messy

        Sleep(SCAN_INTERVAL_MS);
    }

    // cleanup
    if (ctx.hooks_installed) {
        printf("[*] Removing hooks...\n");
        RemoveIATHooks();
    }

    printf("[*] Done\n");
    return 0;
}
