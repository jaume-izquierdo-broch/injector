#ifndef CHROME_H
#define CHROME_H

#include <windows.h>

WCHAR *get_process_command_line(DWORD pid);
BOOL is_chrome_process(DWORD pid);

#endif