#include <windows.h>
#include <stdio.h>

BOOL WINAPI DllMain(
    HINSTANCE instance,
    DWORD reason,
    LPVOID reserved)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        MessageBoxA(
            NULL,
            "La DLL ha sido cargada",
            "Mi DLL",
            MB_OK);
    }

    return TRUE;
}