//
// Created by Brock on 08/03/2022.
// Sets SeDebugPrivilege
//
#include <Windows.h>
#include <minwindef.h>
#include <stdio.h>

#include "setPrivilege.h"


TOKEN_PRIVILEGES tp;
LUID luid;
LPCTSTR lpszPrivilege = "SeDebugPrivilege";
HANDLE hProc;
HANDLE hToken;
BOOL bEnablePrivilege = TRUE;
int result;

BOOL setPrivilege(){
    DWORD pid = GetCurrentProcessId();

    hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if ((hProc == NULL ) || (hProc == INVALID_HANDLE_VALUE )) {
        (void)printf("OpenProcess() failed with error code %ld\n", GetLastError());
        return FALSE;
    }
    //Get the Access token corresponding to our process
    result = OpenProcessToken(hProc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
    if (result == 0) {
        printf("OpenProcessToken() failed with error code %lu\n", GetLastError());
        return FALSE;
    }

    // Retrieves the locally unique identifier (LUID) used on a specified
    // system to locally represent the specified privilege name.
    if (!LookupPrivilegeValue(
            NULL,            // lookup privilege on local system
            lpszPrivilege,   // privilege to lookup -> L"SeDebugPrivilege"
            &luid))          // receives LUID of privilege
    {
        printf("LookupPrivilegeValue error: %lu\n", GetLastError());
        return FALSE;
    }
    // The TOKEN_PRIVILEGES structure contains information about a set of privileges for an access token.
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; //#define SE_PRIVILEGE_ENABLED 0x2L
    else
        tp.Privileges[0].Attributes = 0;

    // Enable the privilege using the AdjustTokenPrivileges() function.

    if (!AdjustTokenPrivileges(
            hToken,
            FALSE,
            &tp, // Info on what priv to enable/disbale stored here in form of luid.
            sizeof(TOKEN_PRIVILEGES),
            (PTOKEN_PRIVILEGES)NULL,
            (PDWORD)NULL))
    {
        printf("AdjustTokenPrivileges error: %lu\n", GetLastError());
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
    {
        printf("The token does not have the specified privilege. \n");
        return FALSE;
    }

    return TRUE;
}