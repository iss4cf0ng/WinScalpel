// WinScalpel.cpp

#ifndef NOMINMAX
#define NOMINMAX
#endif

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif

#include <iostream>
#include <vector>
#include <string>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <algorithm>

#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>

#ifdef _WIN64
#include "hde64.h"
#else
#include "hde32.h"
#endif

std::string fnBytesToHex(const uint8_t* data, size_t len)
{
    std::string hexStr = "";
    char buf[8];
    for (size_t i = 0; i < len; i++)
    {
        sprintf(buf, "%02X ", data[i]);
        hexStr += buf;
    }
    return hexStr;
}

bool fnMatchPattern(const char* pattern, const char* str)
{
    while (*pattern && *str)
    {
        if (*pattern == '*')
        {
            while (*pattern == '*')
                pattern++;

            if (!*pattern)
                return true;

            while (*str)
            {
                if (fnMatchPattern(pattern, str))
                    return true;

                str++;
            }

            return false;
        }
        else if (*pattern == '?' || *pattern == *str)
        {
            pattern++;
            str++;
        }
        else
        {
            return false;
        }
    }

    while (*pattern == '*')
        pattern++;

    return !*pattern && !*str;
}

std::string fnGetModuleFileVersion(const std::wstring& szFilePath)
{
    
}

std::string fnFindApiNameByAddress(HMODULE hModule, uintptr_t targetAddr)
{
    if (!hModule)
        return "";

    uint8_t* basePtr = (uint8_t*)hModule;
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)basePtr;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return "";

    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(basePtr + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
        return "";

    DWORD exportDirRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exportDirRva == 0)
        return "";

    IMAGE_EXPORT_DIRECTORY* exportDir = (IMAGE_EXPORT_DIRECTORY*)(basePtr + exportDirRva);
    DWORD* functions = (DWORD*)(basePtr + exportDir->AddressOfFunctions);
    DWORD* names = (DWORD*)(basePtr + exportDir->AddressOfNames);
    WORD* ordinals = (WORD*)(basePtr + exportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++)
    {
        const char* funcName = (const char*)(basePtr + names[i]);
        WORD ordinalIdx = ordinals[i];
        DWORD funcRva = functions[ordinalIdx];
        uintptr_t funcActualAddr = (uintptr_t)(basePtr + funcRva);

        if (funcActualAddr == targetAddr)
            return std::string(funcName);
    }

    return "";
}

struct SymbolRecord
{
    std::string addrStr;
    std::string symbolStr;
};

void fnDoSymbolSearch(const std::string& query, size_t max_line = 100)
{
    size_t splitPos = query.find('!');
    std::string moduleName = "kernel32.dll";
    std::string pattern = "*";

    if (splitPos != std::string::npos)
    {
        moduleName = query.substr(0, splitPos) + ".dll";
        pattern = query.substr(splitPos + 1);
    }
    else
    {
        pattern = query;
    }

    std::string fullPath = moduleName;
    if (moduleName.find(':') == std::string::npos)
    {
        fullPath = "C:\\Windows\\System32\\" + moduleName;
    }

    HMODULE hModule = LoadLibraryA(fullPath.c_str());
    if (!hModule)
    {
        std::cerr << "[-] Error: Failed to load module for symbol search: " << fullPath << std::endl;
        return;
    }

    uint8_t* basePtr = (uint8_t*)hModule;
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)basePtr;
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(basePtr + dosHeader->e_lfanew);
    DWORD exportDirRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    if (exportDirRva == 0)
    {
        std::cerr << "[-] Error: No export table found in " << moduleName << std::endl;
        FreeLibrary(hModule);
        return;
    }

    IMAGE_EXPORT_DIRECTORY* exportDir = (IMAGE_EXPORT_DIRECTORY*)(basePtr + exportDirRva);
    DWORD* functions = (DWORD*)(basePtr + exportDir->AddressOfFunctions);
    DWORD* names = (DWORD*)(basePtr + exportDir->AddressOfNames);
    WORD* ordinals = (WORD*)(basePtr + exportDir->AddressOfNameOrdinals);

    std::vector<SymbolRecord> records;
    size_t maxAddrLen = std::string("Address").length();
    size_t maxSymbolLen = std::string("Symbol Name").length();

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++)
    {
        const char* funcName = (const char*)(basePtr + names[i]);
        if (fnMatchPattern(pattern.c_str(), funcName))
        {
            WORD ordinalIdx = ordinals[i];
            DWORD funcRva = functions[ordinalIdx];
            uintptr_t funcActualAddr = (uintptr_t)(basePtr + funcRva);

            char bufAddr[32];
#ifdef _WIN64
            sprintf(bufAddr, "0x%016llX", (unsigned long long)funcActualAddr);
#else
            sprintf(bufAddr, "0x%08X", (unsigned int)funcActualAddr);
#endif
            std::string fullSym = moduleName + "!" + funcName;

            SymbolRecord rec;
            rec.addrStr = bufAddr;
            rec.symbolStr = fullSym;

            maxAddrLen = (std::max)(maxAddrLen, rec.addrStr.length());
            maxSymbolLen = (std::max)(maxSymbolLen, rec.symbolStr.length());

            records.push_back(rec);
            if (records.size() >= max_line)
            {
                std::cout << "Results are truncated to 100 records." << std::endl;
                break;
            }
        }
    }

    std::cout << "[*] Symbol search results for pattern: " << query << " (Total matched: " << records.size() << ")\n";
    size_t totalWidth = maxAddrLen + maxSymbolLen + 3;
    std::string separator(totalWidth, '-');

    std::cout << separator << "\n";
    std::cout << std::left << std::setw(maxAddrLen) << "Address" << " | " << std::setw(maxSymbolLen) << "Symbol Name" << "\n";
    std::cout << separator << "\n";

    for (const auto& rec : records)
    {
        std::cout << std::left << std::setw(maxAddrLen) << rec.addrStr << " | " << std::setw(maxSymbolLen) << rec.symbolStr << "\n";
    }
    std::cout << separator << "\n";

    FreeLibrary(hModule);
}

void fnDoProcessMemoryDump(DWORD pid, uintptr_t address, size_t lineCount)
{
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess)
    {
        std::cerr << "[-] Error: Failed to open process ID " << pid << " (Error code: " << GetLastError() << ")\n";
        return;
    }

    size_t totalBytes = lineCount * 16;
    std::vector<uint8_t> buffer(totalBytes, 0);
    SIZE_T bytesRead = 0;

    BOOL success = ReadProcessMemory(hProcess, (LPCVOID)address, buffer.data(), totalBytes, &bytesRead);
    if (!success)
    {
        std::cerr << "[-] Error: ReadProcessMemory failed at address 0x" << std::hex << address << std::dec << " (Error: " << GetLastError() << ")\n";
        CloseHandle(hProcess);
        return;
    }

#ifdef _WIN64
    size_t addrColLen = std::string("0x0000000000000000").length();
#else
    size_t addrColLen = std::string("0x00000000").length();
#endif
    size_t hexColLen = 48; 
    size_t asciiColLen = 16; 

    size_t totalWidth = addrColLen + hexColLen + asciiColLen + 6;
    std::string separator(totalWidth, '-');

    std::cout << "[+] Memory Dump for PID " << pid << " at 0x" << std::hex << address << std::dec << " (" << lineCount << " lines / " << bytesRead << " bytes read):\n";
    std::cout << separator << "\n";
    std::cout << std::left 
              << std::setw(addrColLen) << "Address" << " | "
              << std::setw(hexColLen) << "Hex Bytes (16 bytes per row)" << " | "
              << std::setw(asciiColLen) << "ASCII Preview" << "\n";
    std::cout << separator << "\n";

    for (size_t i = 0; i < bytesRead; i += 16)
    {
        char addrBuf[32];
#ifdef _WIN64
        sprintf(addrBuf, "0x%016llX", (unsigned long long)(address + i));
#else
        sprintf(addrBuf, "0x%08X", (unsigned int)(address + i));
#endif

        std::string hexStr = "";
        for (size_t j = 0; j < 16; j++)
        {
            if (i + j < bytesRead)
            {
                char bBuf[8];
                sprintf(bBuf, "%02X ", buffer[i + j]);
                hexStr += bBuf;
            }
            else
            {
                hexStr += "   ";
            }

            if (j == 7)
                hexStr += " ";
        }

        std::string asciiStr = "";
        for (size_t j = 0; j < 16; j++)
        {
            if (i + j < bytesRead)
            {
                uint8_t c = buffer[i + j];
                if (c >= 32 && c <= 126)
                    asciiStr += (char)c;
                else
                    asciiStr += '.';
            }
        }

        std::cout << std::left 
                  << std::setw(addrColLen) << addrBuf << " | "
                  << std::setw(hexColLen) << hexStr << " | "
                  << std::setw(asciiColLen) << asciiStr << "\n";
    }
    std::cout << separator << "\n";

    CloseHandle(hProcess);
}

void fnDoStackDump(DWORD pid, size_t lineCount)
{
    DWORD targetTid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap != INVALID_HANDLE_VALUE)
    {
        THREADENTRY32 te;
        te.dwSize = sizeof(THREADENTRY32);
        if (Thread32First(hSnap, &te))
        {
            do
            {
                if (te.th32OwnerProcessID == pid)
                {
                    targetTid = te.th32ThreadID;
                    break;
                }
            }
            while (Thread32Next(hSnap, &te));
        }
        CloseHandle(hSnap);
    }

    if (targetTid == 0)
    {
        std::cerr << "[-] Error: Could not find any active thread for PID " << pid << "\n";
        return;
    }

    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, FALSE, targetTid);
    if (!hThread)
    {
        std::cerr << "[-] Error: Failed to open thread ID " << targetTid << "\n";
        return;
    }

    SuspendThread(hThread);
    CONTEXT ctx;
    memset(&ctx, 0, sizeof(CONTEXT));
    ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    GetThreadContext(hThread, &ctx);
    ResumeThread(hThread);
    CloseHandle(hThread);

#ifdef _WIN64
    uintptr_t stackPtr = ctx.Rsp;
    uintptr_t basePtr = ctx.Rbp;
    size_t addrColLen = std::string("0x0000000000000000").length();
    size_t valColLen = std::string("0x0000000000000000").length();
    size_t asciiColLen = 8;
#else
    uintptr_t stackPtr = ctx.Esp;
    uintptr_t basePtr = ctx.Ebp;
    size_t addrColLen = std::string("0x00000000").length();
    size_t valColLen = std::string("0x00000000").length();
    size_t asciiColLen = 4;
#endif

    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess)
        return;

    size_t wordSize = (sizeof(void*) == 8) ? 8 : 4;
    size_t totalBytes = lineCount * wordSize;
    std::vector<uint8_t> buffer(totalBytes, 0);
    SIZE_T bytesRead = 0;

    ReadProcessMemory(hProcess, (LPCVOID)stackPtr, buffer.data(), totalBytes, &bytesRead);

    size_t totalWidth = addrColLen + valColLen + asciiColLen + std::string("Remarks / Markers").length() + 9;
    std::string separator(totalWidth, '-');

    std::cout << "[+] Stack Dump for PID " << pid << " (Thread ID: " << targetTid << ")\n";
    std::cout << separator << "\n";
    std::cout << std::left 
              << std::setw(addrColLen) << "Stack Address" << " | "
              << std::setw(valColLen) << "Value (Data)" << " | "
              << std::setw(asciiColLen) << "ASCII" << " | "
              << "Remarks / Markers\n";
    std::cout << separator << "\n";

    for (size_t i = 0; i < bytesRead; i += wordSize)
    {
        uintptr_t currentAddr = stackPtr + i;
        uint64_t val = (wordSize == 8) ? *(uint64_t*)&buffer[i] : *(uint32_t*)&buffer[i];

        char addrBuf[32];
        char valBuf[32];
#ifdef _WIN64
        sprintf(addrBuf, "0x%016llX", (unsigned long long)currentAddr);
        sprintf(valBuf, "0x%016llX", (unsigned long long)val);
#else
        sprintf(addrBuf, "0x%08X", (unsigned int)currentAddr);
        sprintf(valBuf, "0x%08X", (unsigned int)val);
#endif

        std::string asciiStr = "";
        for (size_t j = 0; j < wordSize; j++)
        {
            if (i + j < bytesRead)
            {
                uint8_t b = buffer[i + j];
                if (b >= 32 && b <= 126) asciiStr += (char)b;
                else asciiStr += '.';
            }
        }

        std::string marker = "";
        if (currentAddr == stackPtr)
            marker += "<- RSP/ESP (Stack Top)";
        if (currentAddr == basePtr)
            marker += "<- RBP/EBP (Frame Pointer)";

        std::cout << std::left 
                  << std::setw(addrColLen) << addrBuf << " | "
                  << std::setw(valColLen) << valBuf << " | "
                  << std::setw(asciiColLen) << asciiStr << " | "
                  << marker << "\n";
    }
    std::cout << separator << "\n";

    CloseHandle(hProcess);
}

void fnDoProcessInfo(DWORD pid)
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess)
    {
        std::cerr << "[-] Error: Failed to open process ID " << pid << " (Error code: " << GetLastError() << ")\n";
        return;
    }

    std::cout << "[+] Process Information for PID: " << pid << "\n";
    std::cout << "--------------------------------------------------------\n";

    DWORD ppid = 0;
    std::string processName = "Unknown";
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(PROCESSENTRY32W);
        if (Process32FirstW(hSnap, &pe))
        {
            do
            {
                if (pe.th32ProcessID == pid)
                {
                    ppid = pe.th32ParentProcessID;
                    char szName[MAX_PATH];
                    WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, szName, MAX_PATH, NULL, NULL);
                    processName = szName;

                    break;
                }
            }
            while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }
    std::cout << " Process Name  : " << processName << "\n";
    std::cout << " Parent PID    : " << ppid << "\n";

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    typedef BOOL(WINAPI* PFN_QueryFullProcessImageNameW)(HANDLE, DWORD, LPWSTR, PDWORD);
    auto pQueryFullProcessImageNameW = reinterpret_cast<PFN_QueryFullProcessImageNameW>(GetProcAddress(hKernel32, "QueryFullProcessImageNameW"));

    WCHAR szImagePath[MAX_PATH * 2] = { 0 };
    DWORD dwSize = MAX_PATH * 2;
    bool pathFound = false;

    if (pQueryFullProcessImageNameW && pQueryFullProcessImageNameW(hProcess, 0, szImagePath, &dwSize))
        pathFound = true;

    if (!pathFound)
    {
        HMODULE hPsapi = LoadLibraryA("psapi.dll");
        if (hPsapi)
        {
            typedef DWORD(WINAPI* PFN_GetModuleFileNameExW)(HANDLE, HMODULE, LPWSTR, DWORD);
            auto pGetModuleFileNameExW = reinterpret_cast<PFN_GetModuleFileNameExW>(GetProcAddress(hPsapi, "GetModuleFileNameExW"));
            if (pGetModuleFileNameExW && pGetModuleFileNameExW(hProcess, NULL, szImagePath, MAX_PATH * 2) > 0)
                pathFound = true;

            FreeLibrary(hPsapi);
        }
    }

    if (pathFound)
    {
        char szPathA[MAX_PATH * 2];
        WideCharToMultiByte(CP_ACP, 0, szImagePath, -1, szPathA, sizeof(szPathA), NULL, NULL);
        std::cout << " Image Path    : " << szPathA << "\n";
    }
    else
    {
        std::cout << " Image Path    : (Restricted or Access Denied)\n";
    }

    typedef BOOL(WINAPI* PFN_IsWow64Process)(HANDLE, PBOOL);
    auto pIsWow64Process = reinterpret_cast<PFN_IsWow64Process>(GetProcAddress(hKernel32, "IsWow64Process"));
    BOOL isWow64 = FALSE;
    if (pIsWow64Process && pIsWow64Process(hProcess, &isWow64))
    {
        SYSTEM_INFO sysInfo;
        GetNativeSystemInfo(&sysInfo);
        if (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
        {
            std::cout << " Architecture  : x86 (32-bit System)\n";
        }
        else
        {
            std::cout << " Architecture  : " << (isWow64 ? "x86 (32-bit Process under WOW64)" : "x64 (64-bit Native Process)") << "\n";
        }
    }
    else
    {
        std::cout << " Architecture  : x86 (Windows XP 32-bit)\n";
    }

    typedef BOOL(WINAPI* PFN_ProcessIdToSessionId)(DWORD, DWORD*);
    auto pProcessIdToSessionId = reinterpret_cast<PFN_ProcessIdToSessionId>(GetProcAddress(hKernel32, "ProcessIdToSessionId"));
    DWORD sessionId = 0;
    if (pProcessIdToSessionId && pProcessIdToSessionId(pid, &sessionId))
    {
        std::cout << " Session ID    : Session " << sessionId << (sessionId == 0 ? " (Services / System)" : " (User)") << "\n";
    }

    typedef BOOL(WINAPI* PFN_IsProcessCritical)(HANDLE, PBOOL);
    auto pIsProcessCritical = reinterpret_cast<PFN_IsProcessCritical>(GetProcAddress(hKernel32, "IsProcessCritical"));
    if (pIsProcessCritical)
    {
        BOOL isCritical = FALSE;
        if (pIsProcessCritical(hProcess, &isCritical))
        {
            std::cout << " Critical      : " << (isCritical ? "YES (Protected System Process)" : "No") << "\n";
        }
    }

    HANDLE hToken = NULL;
    if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
    {
        DWORD cbTokenUser = 0;
        GetTokenInformation(hToken, TokenUser, NULL, 0, &cbTokenUser);
        if (cbTokenUser > 0)
        {
            PTOKEN_USER pTokenUser = (PTOKEN_USER)LocalAlloc(LPTR, cbTokenUser);
            if (pTokenUser && GetTokenInformation(hToken, TokenUser, pTokenUser, cbTokenUser, &cbTokenUser))
            {
                WCHAR szUser[256] = { 0 };
                WCHAR szDomain[256] = { 0 };
                DWORD cchUser = 256, cchDomain = 256;
                SID_NAME_USE sidUse;
                if (LookupAccountSidW(NULL, pTokenUser->User.Sid, szUser, &cchUser, szDomain, &cchDomain, &sidUse))
                {
                    char szUserA[256], szDomainA[256];
                    WideCharToMultiByte(CP_ACP, 0, szUser, -1, szUserA, sizeof(szUserA), NULL, NULL);
                    WideCharToMultiByte(CP_ACP, 0, szDomain, -1, szDomainA, sizeof(szDomainA), NULL, NULL);
                    std::cout << " User Account  : " << szDomainA << "\\" << szUserA << "\n";
                }
            }

            if (pTokenUser)
                LocalFree(pTokenUser);
        }
        CloseHandle(hToken);
    }

    std::cout << "--------------------------------------------------------\n";

    CloseHandle(hProcess);
}

struct ModuleInfoRecord {
    std::string addrStr;
    std::string sizeStr;
    std::string name;
    std::string path;
};

void fnDoProcessModules(DWORD pid)
{
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnap == INVALID_HANDLE_VALUE)
    {
        std::cerr << "[-] Error: Failed to create module snapshot for PID " << pid << " (Error: " << GetLastError() << ")\n";
        return;
    }

    MODULEENTRY32W me;
    me.dwSize = sizeof(MODULEENTRY32W);

    std::vector<ModuleInfoRecord> records;
    size_t maxAddrLen = std::string("Base Address").length();
    size_t maxSizeLen = std::string("Size").length();
    size_t maxNameLen = std::string("Module Name").length();

    if (Module32FirstW(hSnap, &me))
    {
        do
        {
            char szModuleName[MAX_PATH];
            char szModulePath[MAX_PATH];
            WideCharToMultiByte(CP_ACP, 0, me.szModule, -1, szModuleName, MAX_PATH, NULL, NULL);
            WideCharToMultiByte(CP_ACP, 0, me.szExePath, -1, szModulePath, MAX_PATH, NULL, NULL);

            char bufAddr[32];
            char bufSize[32];

#ifdef _WIN64
            sprintf(bufAddr, "0x%016llX", (unsigned long long)me.modBaseAddr);
#else
            sprintf(bufAddr, "0x%08X", (unsigned int)(uintptr_t)me.modBaseAddr);
#endif
            sprintf(bufSize, "0x%08X", (unsigned int)me.modBaseSize);

            ModuleInfoRecord rec;
            rec.addrStr = bufAddr;
            rec.sizeStr = bufSize;
            rec.name = szModuleName;
            rec.path = szModulePath;

            maxAddrLen = (std::max)(maxAddrLen, rec.addrStr.length());
            maxSizeLen = (std::max)(maxSizeLen, rec.sizeStr.length());
            maxNameLen = (std::max)(maxNameLen, rec.name.length());

            records.push_back(rec);
        }
        while (Module32NextW(hSnap, &me));
    }

    CloseHandle(hSnap);

    std::cout << "[+] Loaded Modules for PID: " << pid << " (Total: " << records.size() << ")\n";
    size_t totalLineWidth = maxAddrLen + maxSizeLen + maxNameLen + 9;
    std::string separator(totalLineWidth, '-');

    std::cout << separator << "\n";
    std::cout << std::left 
              << std::setw(maxAddrLen) << "Base Address" << " | "
              << std::setw(maxSizeLen) << "Size" << " | "
              << std::setw(maxNameLen) << "Module Name" << " | "
              << "Path\n";
    std::cout << separator << "\n";

    for (const auto& rec : records)
    {
        std::cout << std::left
                  << std::setw(maxAddrLen) << rec.addrStr << " | "
                  << std::setw(maxSizeLen) << rec.sizeStr << " | "
                  << std::setw(maxNameLen) << rec.name << " | "
                  << rec.path << "\n";
    }

    std::cout << separator << "\n";
}

void fnDoDepTest(int method)
{
    std::cout << "[*] Running DEP Test Method " << method << " on [" << (sizeof(void*) == 8 ? "x64" : "x86") << "] architecture...\n";

    size_t const test_size = 64;
    void *code_space = VirtualAlloc(NULL, test_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!code_space)
        return;

    *(unsigned char*)code_space = 0xC3; 

    bool success = false;
    switch(method)
    {
    case 1:
        {
            typedef NTSTATUS (WINAPI *pNtSetInformationProcess)(HANDLE, ULONG, PVOID, ULONG);
            auto NtSetInformationProcess = (pNtSetInformationProcess)(void*)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationProcess");
            if (NtSetInformationProcess)
            {
                ULONG executeFlags = 2;
                NtSetInformationProcess((HANDLE)-1, 0x22, &executeFlags, sizeof(executeFlags));
                success = true;
            }
        }
        break;
    case 2:
        {
            typedef BOOL (WINAPI *pSetProcessDEPPolicy)(DWORD);
            auto fnSetDEP = (pSetProcessDEPPolicy)(void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "SetProcessDEPPolicy");
            if (fnSetDEP)
            {
                fnSetDEP(0);
                success = true;
            }
        }
        break;
    case 3:
        {
            DWORD oldProtect;
            if (VirtualProtect(code_space, test_size, PAGE_EXECUTE_READWRITE, &oldProtect)) success = true;
        }
        break;
    case 4:
        {
            unsigned char stub = 0xC3;
            if (WriteProcessMemory((HANDLE)-1, code_space, &stub, 1, 0)) success = true;
        }
        break;
    case 5:
        {
            VirtualFree(code_space, 0, MEM_RELEASE);
            code_space = VirtualAlloc(NULL, test_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (code_space) success = true;
        }
        break;
    case 6:
        {
            HANDLE heap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, test_size, 0);
            if (heap && HeapAlloc(heap, 0, test_size)) success = true;
        }
        break;
    }

    if (success)
        std::cout << "[+] SUCCESS: DEP Test Method " << method << " verified successfully!\n";
    else
        std::cout << "[-] FAILED: DEP Test Method " << method << " blocked.\n";

    if (code_space) VirtualFree(code_space, 0, MEM_RELEASE);
}

bool fnEnableDebugPrivilege()
{
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;

    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &luid))
    {
        CloseHandle(hToken);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
    CloseHandle(hToken);

    return result;
}

void fnPrintUsage(const char* programName)
{
    std::string prog(programName);
    size_t lastSlash = prog.find_last_of("\\/");
    if (lastSlash != std::string::npos)
    {
        prog = prog.substr(lastSlash + 1);
    }

    std::cout << std::endl;
    std::cout << "WinScalpel - Lightweight Offline Disassembler & Analysis Tool (XP Compatible)\n\n";
    std::cout << "Usage Modes:\n";
    std::cout << "  0. Coffee:                " << prog << " --coffee\n";
    std::cout << "  1. Disassembly:           " << prog << " --da [ModulePath] [ApiName] [LineCount]\n";
    std::cout << "  2. Symbol Search:         " << prog << " --search [Module!Pattern] [--line [LineCount]]\n";
    std::cout << "  3. Process Memory Dump:   " << prog << " --dump [Address] --pid [PID] [--line [LineCount]]\n";
    std::cout << "  4. Process Stack Dump:    " << prog << " --stack --pid [PID] [--line [LineCount]]\n";
    std::cout << "  5. Process Info:          " << prog << " --info --pid [PID]\n";
    std::cout << "  6. Process Modules:       " << prog << " --modules --pid [PID]\n";
    std::cout << "  7. DEP Bypass/Test (1-6)  " << prog << " --dep [1-6]\n";
    std::cout << std::endl;
}

void fnPrintCoffee()
{
    printf("\n");
    printf("      ( )  (   )  )\n");
    printf("      ) (   )  (  (\n");
    printf("      ( )  (    ) )\n");
    printf("      _____________\n");
    printf("     <_____________> ___\n");
    printf("     |             |/ _ \\\n");
    printf("     |               | | |\n");
    printf("     |               |_| |\n");
    printf("  __|              |\\___/\n");
    printf(" /    \\___________/    \\\n");
    printf(" \\_____________________/\n");
    printf("\n");
    printf("  Author : ISSAC/iss4cf0ng\n");
    printf("  GitHub : https://github.com/iss4cf0ng\n");
    printf("  Blog   : https://iss4cf0ng.github.io\n");
    printf("\n");
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        fnPrintUsage(argv[0]);
        return 1;
    }

    if (!fnEnableDebugPrivilege())
    {
        std::cout << "[!] Failed to enable debug privilege." << std::endl;
    }

    std::string arg1 = argv[1];
    
    if (arg1 == "--coffee")
    {
        fnPrintCoffee();
        return 0;
    }
    else if (arg1 == "--help" || arg1 == "-h")
    {
        fnPrintUsage(argv[0]);
        return 0;
    }
    else if (arg1 == "--dep")
    {
        if (argc >= 3)
        {
            try
            {
                fnDoDepTest(std::stoi(argv[2]));
            }
            catch (...)
            {
                std::cerr << "[-] Invalid DEP test argument.\n";
                return 1;
            }
            return 0;
        }
        else
        {
            std::cout << "\n 1. ZwSetInformationProcess\n"
                      << " 2. SetProcessDEPPolicy\n"
                      << " 3. VirtualProtect\n"
                      << " 4. WriteProcessMemory\n"
                      << " 5. VirtualAlloc + memcpy\n"
                      << " 6. HeapCreate + HeapAlloc + memcpy\n\n";
            return 0;
        }
    }

    DWORD pid = 0;
    size_t lineCount = 0;
    uintptr_t dumpAddr = 0;
    int max_line = 100;

    for (int i = 2; i < argc; i++)
    {
        std::string arg = argv[i];

        if (arg == "--pid" && i + 1 < argc)
        {
            try
            {
                pid = std::stoul(argv[++i], nullptr, 0);
            }
            catch (...)
            {
                std::cerr << "Error: Invalid --pid value.\n";
                return 1;
            }
        }
        else if (arg == "--line" && i + 1 < argc)
        {
            try
            {
                lineCount = std::stoi(argv[++i]);
            }
            catch (...)
            {
                std::cerr << "Error: Invalid --line value.\n";
                return 1;
            }
        }
    }

    if (arg1 == "--search")
    {
        if (argc < 3)
        {
            std::cerr << "Error: --search requires a search term.\n";
            return 1;
        }

        if (lineCount > 0)
        {
            max_line = static_cast<int>(lineCount);
        }

        try
        {
            fnDoSymbolSearch(argv[2], max_line);
            return 0;
        }
        catch (const std::exception& e)
        {
            std::cerr << "[-] Error: " << e.what() << std::endl;
            return 1;
        }
        catch (...)
        {
            std::cerr << "[-] Unknown error occurred during search.\n";
            return 1;
        }
    }
    else if (arg1 == "--info")
    {
        if (pid == 0)
        {
            std::cerr << "Error: --info requires a valid --pid N\n";
            return 1;
        }

        fnDoProcessInfo(pid);
        return 0;
    }
    else if (arg1 == "--modules")
    {
        if (pid == 0)
        {
            std::cerr << "Error: --modules requires a valid --pid N\n";
            return 1;
        }

        fnDoProcessModules(pid);
        return 0;
    }
    else if (arg1 == "--dump")
    {
        if (argc < 3)
        {
            std::cerr << "Error: --dump requires a target address.\n";
            return 1;
        }

        try
        {
            dumpAddr = (uintptr_t)std::stoull(argv[2], nullptr, 0);
        }
        catch (...)
        {
            std::cerr << "Error: Invalid dump address format.\n";
            return 1;
        }

        if (pid == 0)
        {
            std::cerr << "Error: --dump requires --pid N\n";
            return 1;
        }

        if (lineCount == 0) lineCount = 8;

        fnDoProcessMemoryDump(pid, dumpAddr, lineCount);
        return 0;
    }
    else if (arg1 == "--stack")
    {
        if (pid == 0)
        {
            std::cerr << "Error: --stack requires --pid N\n";
            return 1;
        }

        if (lineCount == 0) lineCount = 12;

        fnDoStackDump(pid, lineCount);
        return 0;
    }
    else if (arg1 == "--da")
    {
        std::string szTargetDll = (argc >= 3 && argv[2][0] != '-') ? argv[2] : "C:\\Windows\\System32\\user32.dll";
        std::string targetApi = (argc >= 4 && argv[3][0] != '-') ? argv[3] : "MessageBoxA";
        
        int maxLines = (lineCount > 0) ? static_cast<int>(lineCount) : 30;

        std::cout << "[*] Target Module  : " << szTargetDll << "\n";
        std::cout << "[*] Target Function: " << targetApi << "\n";
        std::cout << "[*] Disasm Lines   : " << maxLines << "\n\n";

        HMODULE hModule = LoadLibraryA(szTargetDll.c_str());
        if (!hModule)
        {
            std::cerr << "[-] Error: Failed to load DLL: " << szTargetDll << std::endl;
            return 1;
        }

        FARPROC pFunc = GetProcAddress(hModule, targetApi.c_str());
        if (!pFunc)
        {
            std::cerr << "[-] Error: Cannot find the API inside the module." << std::endl;
            FreeLibrary(hModule);
            return 1;
        }

        const uint8_t* codePtr = (const uint8_t*)pFunc;
        uintptr_t uRuntimeAddr = (uintptr_t)pFunc;

#ifdef _WIN64
        std::cout << "[+] Successfully located API! Address: 0x" << std::hex << uRuntimeAddr << std::dec << "\n\n";
        std::cout << "----------------------------------------------------------------------------------------------------\n";
        std::cout << " Address          | Length | Machine code       | Disassembly\n";
        std::cout << "----------------------------------------------------------------------------------------------------\n";
#else
        std::cout << "[+] Successfully located API! Address: 0x" << std::hex << uRuntimeAddr << std::dec << "\n\n";
        std::cout << "----------------------------------------------------------------------------------------\n";
        std::cout << " Address     | Length | Machine code       | Disassembly\n";
        std::cout << "----------------------------------------------------------------------------------------\n";
#endif

        size_t offset = 0;
        for (int i = 0; i < maxLines; i++)
        {
#ifdef _WIN64
            hde64s hs;
            hde64_disasm((void*)(codePtr + offset), &hs);
#else
            hde32s hs;
            hde32_disasm((void*)(codePtr + offset), &hs);
#endif

            if (hs.flags & F_ERROR)
            {
                std::cout << "[-] Read invalid instruction or to the end. Stopped\n";
                break;
            }

            uintptr_t currentAddr = uRuntimeAddr + offset;
            std::string bytesStr = fnBytesToHex(codePtr + offset, hs.len);

#ifdef _WIN64
            printf(" 0x%016llX  | %-4d | %-20s | ", (unsigned long long)currentAddr, hs.len, bytesStr.c_str());
#else
            printf(" 0x%08X     | %-4d | %-20s | ", (unsigned int)currentAddr, hs.len, bytesStr.c_str());
#endif

            uint8_t op = codePtr[offset];
            uint8_t op2 = (hs.len > 1) ? codePtr[offset + 1] : 0;

            if (op == 0x55)
            {
                std::cout << "push ebp\n";
            } 
            else if (op == 0x8B && op2 == 0xEC)
            {
                std::cout << "mov ebp, esp\n";
            } 
            else if (op == 0x8B && op2 == 0xFF)
            {
                std::cout << "mov edi, edi  ; (Hotpatch stub)\n";
            } 
            else if (op == 0xC3)
            {
                std::cout << "ret\n";
                offset += hs.len;
                break; 
            } 
            else if (op == 0xC2)
            {
                uint16_t imm16 = *(uint16_t*)(codePtr + offset + 1);
                printf("ret  0x%04X (%d bytes)\n", imm16, imm16);
            }
            else if (op == 0x64)
            {
                std::cout << "fs: ...       ; (Thread Information Block access)\n";
            }
            else if ((op & 0xF8) == 0x50)
            {
                int regIdx = op & 0x07;
                const char* regs[] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"};
                printf("push %s\n", regs[regIdx]);
            } 
            else if ((op & 0xF8) == 0x58)
            {
                int regIdx = op & 0x07;
                const char* regs[] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"};
                printf("pop %s\n", regs[regIdx]);
            }
            else if (op == 0x6A)
            {
                int8_t imm8 = *(int8_t*)(codePtr + offset + 1);
                printf("push 0x%02X (%d)\n", (unsigned char)imm8, imm8);
            } 
            else if (op == 0x68)
            {
                uint32_t imm32 = *(uint32_t*)(codePtr + offset + 1);
                printf("push 0x%08X\n", imm32);
            }
            else if (op == 0xE8)
            {
                int32_t relAddr = *(int32_t*)(codePtr + offset + 1);
                uintptr_t targetFunc = currentAddr + hs.len + relAddr;
                
                std::string resolvedName = fnFindApiNameByAddress(hModule, targetFunc);
                if (!resolvedName.empty())
                {
#ifdef _WIN64
                    printf("call 0x%016llX  ; <_> %s\n", (unsigned long long)targetFunc, resolvedName.c_str());
#else
                    printf("call 0x%08X  ; <_> %s\n", (unsigned int)targetFunc, resolvedName.c_str());
#endif
                }
                else
                {
#ifdef _WIN64
                    printf("call 0x%016llX  ; Call internal function\n", (unsigned long long)targetFunc);
#else
                    printf("call 0x%08X  ; Call internal function\n", (unsigned int)targetFunc);
#endif
                }
            }
            else if (op == 0xE9)
            {
                int32_t relJmp = *(int32_t*)(codePtr + offset + 1);
                uintptr_t targetJmp = currentAddr + hs.len + relJmp;
#ifdef _WIN64
                printf("jmp  0x%016llX\n", (unsigned long long)targetJmp);
#else
                printf("jmp  0x%08X\n", (unsigned int)targetJmp);
#endif
            }
            else if (op == 0x74 || op == 0x75)
            {
                int8_t rel8 = *(int8_t*)(codePtr + offset + 1);
                uintptr_t targetJcc = currentAddr + hs.len + rel8;
#ifdef _WIN64
                printf("%-4s 0x%016llX\n", (op == 0x74 ? "je" : "jne"), (unsigned long long)targetJcc);
#else
                printf("%-4s 0x%08X\n", (op == 0x74 ? "je" : "jne"), (unsigned int)targetJcc);
#endif
            }
            else if (op == 0x83)
            {
                uint8_t modrm = op2;
                int regField = (modrm >> 3) & 0x07;
                if (regField == 5)
                {
                    printf("sub esp, 0x%02X\n", codePtr[offset + 2]);
                } else {
                    printf("sub/add/cmp [imm8]\n");
                }
            }
            else if (op == 0xFF)
            {
                std::cout << "call/push dword ptr [Indirect/Memory operand]\n";
            }
            else if (op == 0xCC)
            {
                std::cout << "int 3         ; (Debug breakpoint)\n";
            }
            else {
                printf("db   0x%02X ...     ; [raw opcode]\n", op);
            }

            offset += hs.len;
        }

#ifdef _WIN64
        std::cout << "----------------------------------------------------------------------------------------------------\n";
#else
        std::cout << "----------------------------------------------------------------------------------------\n";
#endif
        std::cout << "[*] Disassembly finished\n";

        FreeLibrary(hModule);
        return 0;
    }

    fnPrintUsage(argv[0]);
    return 1;
}