#include "stdio.h"
#include "Windows.h"
#include "tlhelp32.h"
#include "tchar.h"
#include "wchar.h"

HANDLE findProcess(WCHAR *processName);
BOOL loadRemoteDLL(HANDLE hProcess, const char *dllPath);

int wmain(int argc, wchar_t *argv[])
{
    if (argc != 3)
    {
        wprintf(L"Usage: %ls <process name> <dll path>\n", argv[0]);
        return 1;
    }

    WCHAR *processName = argv[1];
    char dllPath[MAX_PATH];

    wcstombs(dllPath, argv[2], MAX_PATH);

    wprintf(L"Executable name %s.\n", processName);
    printf("DLL path %s.\n", dllPath);

    HANDLE hProcess = findProcess(argv[1]);
    if (hProcess != NULL)
    {
        BOOL injectSuccessful = loadRemoteDLL(hProcess, dllPath);
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

HANDLE findProcess(WCHAR *processName)
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

        if (wcscmp(pe32.szExeFile, processName) == 0)
        {
            wprintf(L"[+] The process %s was found in memory.\n", pe32.szExeFile);

            hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
            if (hProcess != NULL)
            {
                return hProcess;
            }
            else
            {
                wprintf(L"[---] Failed to open process %s.\n", pe32.szExeFile);
                return NULL;
            }
        }

    } while (Process32NextW(hProcessSnap, &pe32));

    wprintf(L"[---] %s has not been loaded into memory, aborting.\n", processName);
    return NULL;
}

BOOL loadRemoteDLL(HANDLE hProcess, const char *dllPath)
{
    printf("Enter any key to attempt DLL injection.");
    getchar();

    // Allocate memory for DLL's path name to remote process
    LPVOID dllPathAddressInRemoteMemory = VirtualAllocEx(hProcess, NULL, strlen(dllPath), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (dllPathAddressInRemoteMemory == NULL)
    {
        printf("[---] VirtualAllocEx unsuccessful.\n");
        getchar();
        return FALSE;
    }

    // Write DLL's path name to remote process
    BOOL succeededWriting = WriteProcessMemory(hProcess, dllPathAddressInRemoteMemory, dllPath, strlen(dllPath), NULL);

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