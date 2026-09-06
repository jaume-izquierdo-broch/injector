#define _WIN32_DCOM

#include <windows.h>
#include <wbemidl.h>
#include <stdio.h>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

WCHAR *get_process_command_line(DWORD pid)
{
    HRESULT hr;
    IWbemLocator *locator = NULL;
    IWbemServices *services = NULL;
    IEnumWbemClassObject *enumerator = NULL;
    IWbemClassObject *object = NULL;
    VARIANT value;
    WCHAR query[128];
    WCHAR *result = NULL;

    CoInitializeEx(NULL, COINIT_MULTITHREADED);
    CoInitializeSecurity(NULL, -1, NULL, NULL,
                         RPC_C_AUTHN_LEVEL_DEFAULT,
                         RPC_C_IMP_LEVEL_IMPERSONATE,
                         NULL, EOAC_NONE, NULL);

    hr = CoCreateInstance(&CLSID_WbemLocator, NULL,
                          CLSCTX_INPROC_SERVER,
                          &IID_IWbemLocator,
                          (void **)&locator);
    if (FAILED(hr))
        goto cleanup;

    hr = locator->lpVtbl->ConnectServer(
        locator, L"ROOT\\CIMV2", NULL, NULL, NULL, 0, NULL, NULL, &services);
    if (FAILED(hr))
        goto cleanup;

    swprintf(query, 128,
             L"SELECT CommandLine FROM Win32_Process WHERE ProcessId=%lu",
             pid);

    hr = services->lpVtbl->ExecQuery(
        services, L"WQL", query,
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL, &enumerator);
    if (FAILED(hr))
        goto cleanup;

    ULONG returned;
    hr = enumerator->lpVtbl->Next(enumerator, WBEM_INFINITE,
                                  1, &object, &returned);

    if (SUCCEEDED(hr) && returned)
    {
        VariantInit(&value);

        if (SUCCEEDED(object->lpVtbl->Get(
                object, L"CommandLine", 0, &value, NULL, NULL)))
        {
            if (value.vt == VT_BSTR)
                result = _wcsdup(value.bstrVal);
        }

        VariantClear(&value);
    }

cleanup:
    if (object)
        object->lpVtbl->Release(object);
    if (enumerator)
        enumerator->lpVtbl->Release(enumerator);
    if (services)
        services->lpVtbl->Release(services);
    if (locator)
        locator->lpVtbl->Release(locator);

    CoUninitialize();

    return result;
}

BOOL is_chrome_process(DWORD pid)
{
    WCHAR *cmd = get_process_command_line(pid);

    if (cmd == NULL)
        return FALSE;

    BOOL result =
        wcsstr(cmd, L"chrome.exe") != NULL &&
        wcsstr(cmd, L"--type=") == NULL;

    free(cmd);

    return result;
}