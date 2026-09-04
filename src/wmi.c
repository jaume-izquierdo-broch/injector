#define _WIN32_DCOM

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <string.h>

#include <wbemidl.h>

#include "wmi.h"


static void print_hr(const char *where, HRESULT hr)
{
    fprintf(
        stderr,
        "[-] %s failed: HRESULT=0x%08lX\n",
        where,
        (unsigned long)hr
    );
}


static int get_command_line(DWORD pid, WCHAR **result)
{
    HRESULT hr;

    IWbemLocator *locator = NULL;
    IWbemServices *services = NULL;
    IEnumWbemClassObject *enumerator = NULL;
    IWbemClassObject *object = NULL;

    BSTR namespace = NULL;
    BSTR language = NULL;
    BSTR query = NULL;

    VARIANT value;

    ULONG returned = 0;

    *result = NULL;

    /*
     * ---------------------------------------------------------
     * COM
     * ---------------------------------------------------------
     */

    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);

    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE)
    {
        print_hr("CoInitializeEx", hr);
        return 0;
    }

    /*
     * Si RPC_E_CHANGED_MODE, COM ya estaba inicializado
     * en otro modelo. Para este código podemos continuar
     * porque WMI se puede utilizar mediante el proxy COM.
     *
     * Solo hacemos CoUninitialize si nuestra llamada
     * realmente inicializó COM.
     */
    int com_initialized = (hr == S_OK || hr == S_FALSE);

    /*
     * ---------------------------------------------------------
     * Seguridad COM
     * ---------------------------------------------------------
     */

    hr = CoInitializeSecurity(
        NULL,
        -1,
        NULL,
        NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE,
        NULL
    );

    if (FAILED(hr) && hr != RPC_E_TOO_LATE)
    {
        print_hr("CoInitializeSecurity", hr);

        if (com_initialized)
            CoUninitialize();

        return 0;
    }

    /*
     * ---------------------------------------------------------
     * IWbemLocator
     * ---------------------------------------------------------
     */

    hr = CoCreateInstance(
        &CLSID_WbemLocator,
        NULL,
        CLSCTX_INPROC_SERVER,
        &IID_IWbemLocator,
        (void **)&locator
    );

    if (FAILED(hr))
    {
        print_hr("CoCreateInstance(IWbemLocator)", hr);

        if (com_initialized)
            CoUninitialize();

        return 0;
    }

    /*
     * ---------------------------------------------------------
     * ROOT\CIMV2
     * ---------------------------------------------------------
     */

    namespace = SysAllocString(L"ROOT\\CIMV2");

    if (namespace == NULL)
    {
        fprintf(stderr, "[-] SysAllocString(namespace) failed\n");

        locator->lpVtbl->Release(locator);

        if (com_initialized)
            CoUninitialize();

        return 0;
    }

    /*
     * ---------------------------------------------------------
     * Conectar a WMI
     * ---------------------------------------------------------
     */

    hr = locator->lpVtbl->ConnectServer(
        locator,
        namespace,
        NULL,
        NULL,
        NULL,
        0,
        NULL,
        NULL,
        &services
    );

    SysFreeString(namespace);
    namespace = NULL;

    if (FAILED(hr))
    {
        print_hr("IWbemLocator::ConnectServer", hr);

        locator->lpVtbl->Release(locator);

        if (com_initialized)
            CoUninitialize();

        return 0;
    }

    /*
     * ---------------------------------------------------------
     * Configurar proxy WMI
     * ---------------------------------------------------------
     */

    hr = CoSetProxyBlanket(
        (IUnknown *)services,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE
    );

    if (FAILED(hr))
    {
        print_hr("CoSetProxyBlanket", hr);

        services->lpVtbl->Release(services);
        locator->lpVtbl->Release(locator);

        if (com_initialized)
            CoUninitialize();

        return 0;
    }

    /*
     * ---------------------------------------------------------
     * Construir consulta
     * ---------------------------------------------------------
     */

    WCHAR query_text[256];

    swprintf(
        query_text,
        sizeof(query_text) / sizeof(query_text[0]),
        L"SELECT CommandLine FROM Win32_Process WHERE ProcessId = %lu",
        (unsigned long)pid
    );

    language = SysAllocString(L"WQL");
    query = SysAllocString(query_text);

    if (language == NULL || query == NULL)
    {
        fprintf(stderr, "[-] Failed to allocate WMI query\n");

        if (language)
            SysFreeString(language);

        if (query)
            SysFreeString(query);

        services->lpVtbl->Release(services);
        locator->lpVtbl->Release(locator);

        if (com_initialized)
            CoUninitialize();

        return 0;
    }

    /*
     * ---------------------------------------------------------
     * Ejecutar consulta
     * ---------------------------------------------------------
     */

    hr = services->lpVtbl->ExecQuery(
        services,
        language,
        query,
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &enumerator
    );

    SysFreeString(language);
    SysFreeString(query);

    language = NULL;
    query = NULL;

    if (FAILED(hr))
    {
        print_hr("IWbemServices::ExecQuery", hr);

        services->lpVtbl->Release(services);
        locator->lpVtbl->Release(locator);

        if (com_initialized)
            CoUninitialize();

        return 0;
    }

    /*
     * ---------------------------------------------------------
     * Obtener primer resultado
     * ---------------------------------------------------------
     */

    hr = enumerator->lpVtbl->Next(
        enumerator,
        WBEM_INFINITE,
        1,
        &object,
        &returned
    );

    if (FAILED(hr))
    {
        print_hr("IEnumWbemClassObject::Next", hr);

        enumerator->lpVtbl->Release(enumerator);
        services->lpVtbl->Release(services);
        locator->lpVtbl->Release(locator);

        if (com_initialized)
            CoUninitialize();

        return 0;
    }

    if (returned == 0 || object == NULL)
    {
        fprintf(
            stderr,
            "[-] WMI returned no process for PID %lu\n",
            (unsigned long)pid
        );

        enumerator->lpVtbl->Release(enumerator);
        services->lpVtbl->Release(services);
        locator->lpVtbl->Release(locator);

        if (com_initialized)
            CoUninitialize();

        return 0;
    }

    /*
     * ---------------------------------------------------------
     * Obtener CommandLine
     * ---------------------------------------------------------
     */

    VariantInit(&value);

    hr = object->lpVtbl->Get(
        object,
        L"CommandLine",
        0,
        &value,
        NULL,
        NULL
    );

    if (FAILED(hr))
    {
        print_hr("IWbemClassObject::Get(CommandLine)", hr);

        VariantClear(&value);

        object->lpVtbl->Release(object);
        enumerator->lpVtbl->Release(enumerator);
        services->lpVtbl->Release(services);
        locator->lpVtbl->Release(locator);

        if (com_initialized)
            CoUninitialize();

        return 0;
    }

    /*
     * ---------------------------------------------------------
     * Comprobar CommandLine
     * ---------------------------------------------------------
     */

    if (value.vt != VT_BSTR || value.bstrVal == NULL)
    {
        fprintf(
            stderr,
            "[-] CommandLine is NULL or has unexpected VARIANT type\n"
        );

        VariantClear(&value);

        object->lpVtbl->Release(object);
        enumerator->lpVtbl->Release(enumerator);
        services->lpVtbl->Release(services);
        locator->lpVtbl->Release(locator);

        if (com_initialized)
            CoUninitialize();

        return 0;
    }

    /*
     * ---------------------------------------------------------
     * Copiar CommandLine
     * ---------------------------------------------------------
     */

    UINT len = SysStringLen(value.bstrVal);

    WCHAR *buffer = malloc(
        ((size_t)len + 1) * sizeof(WCHAR)
    );

    if (buffer == NULL)
    {
        fprintf(stderr, "[-] malloc failed\n");

        VariantClear(&value);

        object->lpVtbl->Release(object);
        enumerator->lpVtbl->Release(enumerator);
        services->lpVtbl->Release(services);
        locator->lpVtbl->Release(locator);

        if (com_initialized)
            CoUninitialize();

        return 0;
    }

    memcpy(
        buffer,
        value.bstrVal,
        (size_t)len * sizeof(WCHAR)
    );

    buffer[len] = L'\0';

    *result = buffer;

    /*
     * ---------------------------------------------------------
     * Cleanup
     * ---------------------------------------------------------
     */

    VariantClear(&value);

    object->lpVtbl->Release(object);
    enumerator->lpVtbl->Release(enumerator);
    services->lpVtbl->Release(services);
    locator->lpVtbl->Release(locator);

    if (com_initialized)
        CoUninitialize();

    return 1;
}


/*
 * Devuelve:
 *
 *     1 -> PID corresponde al Browser de Chrome
 *     0 -> no es el Browser o hubo un error
 */
int wmi(DWORD pid)
{
    WCHAR *command_line = NULL;

    if (!get_command_line(pid, &command_line))
    {
        fprintf(
            stderr,
            "[-] Could not obtain command line for PID %lu\n",
            (unsigned long)pid
        );

        return 0;
    }

    wprintf(
        L"[*] PID %lu\n"
        L"[*] CommandLine: %ls\n",
        (unsigned long)pid,
        command_line
    );

    /*
     * Los procesos secundarios de Chromium llevan
     * normalmente --type=...
     *
     * Browser:
     *
     *     chrome.exe
     *
     * Renderer:
     *
     *     chrome.exe --type=renderer ...
     *
     * GPU:
     *
     *     chrome.exe --type=gpu-process ...
     *
     * Utility:
     *
     *     chrome.exe --type=utility ...
     */

    int is_browser =
        (wcsstr(command_line, L"--type=") == NULL);

    free(command_line);

    if (is_browser)
        wprintf(L"[+] This is the Chrome Browser process.\n");
    else
        wprintf(L"[-] This is a Chrome child process.\n");

    return is_browser;
}