DLL_Injector.exe <Executable_Name> <Path_To_DLL>
DLL_Injector.exe Receiver.exe C:\Windows\System32\cryptext.dll

mingw32-make 

wchar_t *get_process_command_line(DWORD pid)
{
    typedef LONG NTSTATUS;

    typedef struct {
        PVOID Reserved1;
        PVOID PebBaseAddress;
        PVOID Reserved2[2];
        ULONG_PTR UniqueProcessId;
        PVOID Reserved3;
    } PROCESS_BASIC_INFORMATION;

    typedef NTSTATUS (NTAPI *NtQueryInformationProcessFn)(
        HANDLE, ULONG, PVOID, ULONG, PULONG
    );

    NtQueryInformationProcessFn NtQueryInformationProcess =
        (NtQueryInformationProcessFn)GetProcAddress(
            GetModuleHandleW(L"ntdll.dll"),
            "NtQueryInformationProcess"
        );

    if (!NtQueryInformationProcess)
        return NULL;

    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE,
        pid
    );

    if (!hProcess)
        return NULL;

    PROCESS_BASIC_INFORMATION pbi;
    ULONG len;

    if (NtQueryInformationProcess(
            hProcess, 0, &pbi, sizeof(pbi), &len) < 0)
    {
        CloseHandle(hProcess);
        return NULL;
    }

    // PEB -> ProcessParameters
    PVOID processParameters;

    if (!ReadProcessMemory(
            hProcess,
            (BYTE *)pbi.PebBaseAddress + 0x20,
            &processParameters,
            sizeof(processParameters),
            NULL))
    {
        CloseHandle(hProcess);
        return NULL;
    }

    // ProcessParameters -> CommandLine
    UNICODE_STRING commandLine;

    if (!ReadProcessMemory(
            hProcess,
            (BYTE *)processParameters + 0x70,
            &commandLine,
            sizeof(commandLine),
            NULL))
    {
        CloseHandle(hProcess);
        return NULL;
    }

    if (!commandLine.Buffer || !commandLine.Length)
    {
        CloseHandle(hProcess);
        return NULL;
    }

    size_t count = commandLine.Length / sizeof(wchar_t);

    wchar_t *result = malloc((count + 1) * sizeof(wchar_t));

    if (!result)
    {
        CloseHandle(hProcess);
        return NULL;
    }

    if (!ReadProcessMemory(
            hProcess,
            commandLine.Buffer,
            result,
            commandLine.Length,
            NULL))
    {
        free(result);
        CloseHandle(hProcess);
        return NULL;
    }

    result[count] = L'\0';

    CloseHandle(hProcess);

    return result;
}