#include <process.h>
#include <stdio.h>

#include "printProcesses.h"

int main(){
    int pid = getpid();
    printf("PID: %i \n",pid);

//    printProcesses();

    system("logman query providers");

    return 0;
}