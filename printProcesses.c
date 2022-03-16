//
// Created by Brock on 10/03/2022.
//

#include <Windows.h>
#include <Psapi.h>
#include <stdio.h>

#include "printProcesses.h"
#include "setPrivilege.h"

int printProcesses(){
    // Enable SeDebugPrivilege
    DWORD result = setPrivilege();


    if (result == FALSE){
        return -1;
    }

    // We're going to ask for a list of PIDs.  Obviously we need somewhere to put them, so we're
    // going to allocate an array on the stack.  This may not be big enough...

    DWORD pidList[2000];
    DWORD bytesRequired = 0;

    // First psapi function used! Writing each of the PID's to the pidList.
    result = EnumProcesses(pidList, sizeof(pidList), &bytesRequired);
    DWORD numberOfProcesses = bytesRequired / sizeof(DWORD);

    // Looping through the processes
    for (unsigned int i = 0; i < numberOfProcesses; i++){

        if (0 != pidList[i]){
            // Buffer to which we will write the process name.
            TCHAR processName[MAX_PATH] = TEXT("<Unknown>");

            // Open the process with pid == pidList[i]
            // MUST be opened with PROCESS_QUERY_INFORMATION
            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                       FALSE,
                                       pidList[i]);

            if (hProc != NULL){
                HMODULE hMod; // #define HANDLE HMODULE (simply a handle to a module, contains pointer to array of mods)
                DWORD bytesNeeded = 0;
                result = EnumProcessModules(hProc, &hMod, sizeof(hMod), &bytesNeeded);

                if (!result){
                    result = GetLastError();
                    (void)printf("EnumProcessModules() returns %ld\n", result); // 299 - Only part of a Read/WriteProcessMemory
                    // request was completed
                    // 998 - Error No Access
                    if (ERROR_PARTIAL_COPY == result){
                        (void)printf("You probably forgot to ask for ReadProcessMemory or WriteProcessMemory\n");
                    }
                }
                if (result){
                    // Write the basename of the module to "processName"
                    GetModuleBaseName(hProc, hMod, processName, sizeof(processName) / sizeof(TCHAR));
                }
            }
            // Print out the PID and processName!
            (void)printf("Process %08ld - %s\t\n", pidList[i], processName);
        }
    }
    return 0;
}