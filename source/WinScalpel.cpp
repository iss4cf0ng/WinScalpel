// WinScalpel.cpp

#ifndef NOMINMAX
#define NOMINMAX
#endif

#ifndef WINVER
#define WINVER 0x0501
#endif

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif

#include <windows.h>

#include <psapi.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <dbghelp.h>

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <algorithm>
#include <sstream>

#ifdef _WIN64
#include "hde64.h"
#else
#include "hde32.h"
#endif

typedef BOOL (WINAPI *PFN_GetProcessMitigationPolicy)(
    HANDLE ProcessHandle,
    int MitigationPolicy,
    PVOID lpBuffer,
    SIZE_T Length
);

typedef BOOL(WINAPI* LPFN_MINIDUMPWRITEDUMP)(
    HANDLE hProcess,
    DWORD ProcessId,
    HANDLE hFile,
    MINIDUMP_TYPE DumpType,
    PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
    PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
    PMINIDUMP_CALLBACK_INFORMATION CallbackParam
);

struct MFT_FILE_RECORD_HEADER {
    DWORD Magic;            // "FILE" (0x454C4946)
    WORD  UpdateSequenceOffset;
    WORD  UpdateSequenceSize;
    ULONGLONG LogFileSequenceNumber;
    WORD  SequenceNumber;
    WORD  HardLinkCount;
    WORD  FirstAttributeOffset;
    WORD  Flags;            // 0x01 = In Use, 0x02 = Directory
    DWORD RealSize;
    DWORD AllocatedSize;
    ULONGLONG BaseFileRecord;
    WORD  NextAttributeId;
} __attribute__((packed));

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

ULONG fnHexDump(PUCHAR pData, ULONG nSize, int nMaxLine = -1)
{
    ULONG nResult = 0;
    int nLine = 0;

    for (ULONG i = 0; i < nSize; i += 16)
    {
        nLine++;

        if (nMaxLine != -1 && nLine > nMaxLine)
            break;

        printf("%08lX |", i);
        
        nResult += 16;
        for (ULONG j = 0; j < 16; j++)
        {
            if (i + j < nSize)
            {
                nResult += printf(" %02X", pData[i + j]);
            }
            else
            {
                nResult += printf(" 00");
            }
        }

        nResult += printf(" | ");
        for (ULONG j = 0; j < 16; j++)
        {
            if (i + j < nSize)
            {
                UCHAR k = pData[i + j];
                char c = (k < 32 || k > 127) ? '.' : (char)k; 

                nResult += printf("%c", c);
            }
            else
            {
                nResult += printf(" ");
            }
        }

        nResult += printf("\n");
    }

    return nResult;
}

BOOL fnReadBuffer(LPCTSTR lpFilename, PUCHAR *pBuffer, PULONG pcbResult)
{
    HANDLE hFile;
    LARGE_INTEGER nFileSize;
    DWORD nBytesRead = 0;
    BOOL bResult = FALSE;

    *pBuffer = NULL;
    if (INVALID_HANDLE_VALUE == (hFile = CreateFile(lpFilename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)))
    {
        std::cerr << "CreateFile() failed: " << GetLastError() << std::endl;
        return FALSE;
    }

    if (!GetFileSizeEx(hFile, &nFileSize))
    {
        std::cerr << "GetFileSizeEx() failed: " << GetLastError() << std::endl;
        goto Error_Exit;
    }

    *pBuffer = new UCHAR[(ULONG)nFileSize.QuadPart];
    if (NULL == *pBuffer)
    {
        std::cerr << "Failed to allocate memory: " << GetLastError() << std::endl;
        goto Error_Exit;
    }

    if (!ReadFile(hFile, *pBuffer, (DWORD)nFileSize.QuadPart, &nBytesRead, NULL))
    {
        std::cerr << "ReadFile() failed: " << GetLastError() << std::endl;
        delete[] *pBuffer;
        *pBuffer = NULL;

        goto Error_Exit;
    }

    *pcbResult = nBytesRead;
    bResult = TRUE;

Error_Exit:
    CloseHandle(hFile);
    return bResult;
}

bool fnShowMftRecordInfo(const std::string& volumePath, ULONGLONG recordIndex)
{
    std::cout << "[*] Opening volume " << volumePath << " for MFT inspection..." << std::endl;

    HANDLE hVolume = CreateFileA(
        volumePath.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (hVolume == INVALID_HANDLE_VALUE)
    {
        std::cerr << "[-] Failed to open volume. Error code: " << GetLastError() << std::endl;
        return false;
    }

    NTFS_VOLUME_DATA_BUFFER volData = {};
    DWORD bytesReturned = 0;
    if (!DeviceIoControl(
        hVolume,
        FSCTL_GET_NTFS_VOLUME_DATA,
        NULL, 0,
        &volData, sizeof(volData),
        &bytesReturned,
        NULL))
    {
        std::cerr << "[-] DeviceIoControl FSCTL_GET_NTFS_VOLUME_DATA failed. Error code: " << GetLastError() << std::endl;
        CloseHandle(hVolume);
        return false;
    }

    DWORD bytesPerSector = volData.BytesPerSector;
    DWORD bytesPerCluster = volData.BytesPerCluster;
    ULONGLONG mftStartCluster = volData.MftStartLcn.QuadPart;
    DWORD mftRecordSize = volData.BytesPerFileRecordSegment;

    // Calculate absolute byte offset for the target MFT record
    ULONGLONG mftByteOffset = (mftStartCluster * bytesPerCluster) + (recordIndex * mftRecordSize);

    std::cout << "[+] NTFS Volume Metadata Retrieved Successfully:" << std::endl;
    std::cout << "    - Bytes Per Sector: " << bytesPerSector << std::endl;
    std::cout << "    - Bytes Per Cluster: " << bytesPerCluster << std::endl;
    std::cout << "    - $MFT Start Cluster: 0x" << std::hex << mftStartCluster << std::dec << std::endl;
    std::cout << "    - MFT Record Size: " << mftRecordSize << " bytes" << std::endl;
    std::cout << "    - Target Record #" << recordIndex << " Byte Offset: 0x" << std::hex << mftByteOffset << std::dec << std::endl;

    // Seek to the target MFT Record
    LARGE_INTEGER offset;
    offset.QuadPart = (LONGLONG)mftByteOffset;
    if (!SetFilePointerEx(hVolume, offset, NULL, FILE_BEGIN))
    {
        std::cerr << "[-] Failed to seek to MFT record position. Error code: " << GetLastError() << std::endl;
        CloseHandle(hVolume);
        return false;
    }

    std::vector<char> recordBuffer(mftRecordSize);
    DWORD bytesRead = 0;
    if (!ReadFile(hVolume, recordBuffer.data(), mftRecordSize, &bytesRead, NULL) || bytesRead != mftRecordSize)
    {
        std::cerr << "[-] Failed to read MFT record data. Error code: " << GetLastError() << std::endl;
        CloseHandle(hVolume);
        return false;
    }

    CloseHandle(hVolume);

    // Parse MFT Header Info
    MFT_FILE_RECORD_HEADER* pHeader = reinterpret_cast<MFT_FILE_RECORD_HEADER*>(recordBuffer.data());

    std::cout << "\n==================== MFT RECORD INFO ====================" << std::endl;
    std::cout << "Magic Signature   : " << std::string((char*)&pHeader->Magic, 4) << (pHeader->Magic == 0x454C4946 ? " [VALID]" : " [INVALID]") << std::endl;
    std::cout << "Sequence Number   : " << pHeader->SequenceNumber << std::endl;
    std::cout << "Hard Link Count   : " << pHeader->HardLinkCount << std::endl;
    std::cout << "Flags             : 0x" << std::hex << pHeader->Flags << std::dec 
              << ((pHeader->Flags & 0x01) ? " (Allocated / In-Use)" : " (Free / Deleted)") 
              << ((pHeader->Flags & 0x02) ? " [Directory]" : " [File]") << std::endl;
    std::cout << "Real Size         : " << pHeader->RealSize << " bytes" << std::endl;
    std::cout << "Allocated Size    : " << pHeader->AllocatedSize << " bytes" << std::endl;
    std::cout << "Base File Record  : " << pHeader->BaseFileRecord << std::endl;
    std::cout << "First Attr Offset : 0x" << std::hex << pHeader->FirstAttributeOffset << std::dec << std::endl;

    // Print Raw Data (Hex Dump of the first 256 bytes)
    std::cout << "\n===================== MFT RECORD DATA (Hex) =====================" << std::endl;
    DWORD dumpLen = mftRecordSize < 256 ? mftRecordSize : 256;
    for (DWORD i = 0; i < dumpLen; i++)
    {
        if (i % 16 == 0)
        {
            std::cout << std::hex << std::setw(4) << std::setfill('0') << i << "  ";
        }

        std::cout << std::hex << std::setw(2) << std::setfill('0') << (unsigned int)(unsigned char)recordBuffer[i] << " ";
        if ((i + 1) % 16 == 0)
        {
            std::cout << " | ";
            for (DWORD j = i - 15; j <= i; j++)
            {
                char c = recordBuffer[j];
                std::cout << (c >= 32 && c <= 126 ? c : '.');
            }

            std::cout << std::endl;
        }
    }

    std::cout << std::dec << "-----------------------------------------------------------------" << std::endl;

    return true;
}

void fnProcessMiniDump(DWORD nProcId, const std::string& szOutputPath)
{
    std::cout << "[*] Opening target process (PID: " << nProcId << ")..." << std::endl;
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, nProcId);
    if (NULL == hProcess || INVALID_HANDLE_VALUE == hProcess)
    {
        std::cerr << "[-] Failed to open target process. Error code: " << GetLastError() << std::endl;
        return;
    }

    HANDLE hFile = CreateFileA(
        szOutputPath.c_str(),
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (INVALID_HANDLE_VALUE == hFile || NULL == hFile)
    {
        std::cerr << "[-] Failed to create output dump file. Error code: " << GetLastError() << std::endl;
        CloseHandle(hProcess);

        return;
    }

    HMODULE hDbgHelp = LoadLibraryA("dbghelp.dll");
    if (!hDbgHelp)
    {
        std::cerr << "[-] Failed to load dbghelp.dll. Error code: " << GetLastError() << std::endl;
        CloseHandle(hFile);
        CloseHandle(hProcess);

        return;
    }

    LPFN_MINIDUMPWRITEDUMP pMiniDumpWriteDump = (LPFN_MINIDUMPWRITEDUMP)(void*)GetProcAddress(hDbgHelp, "MiniDumpWriteDump");
    if (!pMiniDumpWriteDump)
    {
        std::cerr << "[-] Failed to locate MiniDumpWriteDump entry point." << std::endl;
        FreeLibrary(hDbgHelp);
        CloseHandle(hFile);
        CloseHandle(hProcess);

        return;
    }

    std::cout << "[*] Generating mini-dump..." << std::endl;

    MINIDUMP_TYPE dumpType = static_cast<MINIDUMP_TYPE>(
        MiniDumpWithFullMemory | 
        MiniDumpWithHandleData | 
        MiniDumpWithUnloadedModules
    );

    BOOL bSuccess = pMiniDumpWriteDump(
        hProcess,
        nProcId,
        hFile,
        dumpType,
        NULL,
        NULL,
        NULL
    );

    if (bSuccess)
    {
        std::cout << "[+] Process dump successfully created at: " << szOutputPath << std::endl;
    }
    else
    {
        std::cerr << "[-] MiniDumpWriteDump failed. Error code: " << GetLastError() << std::endl;
    }

    FreeLibrary(hDbgHelp);
    CloseHandle(hFile);
    CloseHandle(hProcess);
}

void fnDoModuleExports(const std::string& dllPath)
{
    HMODULE hModule = LoadLibraryExA(dllPath.c_str(), NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!hModule)
    {
        std::cerr << "[-] Error: Failed to load library for export inspection: " << dllPath << "\n";
        return;
    }

    uintptr_t baseAddr = (uintptr_t)hModule;
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)baseAddr;
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(baseAddr + dosHeader->e_lfanew);

    DWORD exportDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exportDirRVA == 0)
    {
        std::cout << "[-] Module has no export table.\n";
        FreeLibrary(hModule);
        return;
    }

    IMAGE_EXPORT_DIRECTORY* exportDir = (IMAGE_EXPORT_DIRECTORY*)(baseAddr + exportDirRVA);
    DWORD* functions = (DWORD*)(baseAddr + exportDir->AddressOfFunctions);
    DWORD* names = (DWORD*)(baseAddr + exportDir->AddressOfNames);
    WORD* ordinals = (WORD*)(baseAddr + exportDir->AddressOfNameOrdinals);

    std::cout << "================================================================================\n";
    std::cout << " Exports for: " << dllPath << " (Total: " << exportDir->NumberOfNames << " named functions)\n";
    std::cout << "================================================================================\n";
    std::cout << " Ordinal | RVA        | Function Name\n";
    std::cout << "--------------------------------------------------------------------------------\n";

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++)
    {
        const char* funcName = (const char*)(baseAddr + names[i]);
        WORD ordinal = ordinals[i] + exportDir->Base;
        DWORD funcRVA = functions[ordinals[i]];

        printf(" %-7d | 0x%08X | %s\n", (int)ordinal, (unsigned int)funcRVA, funcName);
    }

    std::cout << "--------------------------------------------------------------------------------\n\n";

    FreeLibrary(hModule);
}

void fnDoProcessMitigations(DWORD pid)
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess)
    {
        std::cerr << "[-] Error: Failed to open process (PID: " << pid << ").\n";
        return;
    }

    std::cout << "==================================================\n";
    std::cout << " Process Mitigation Policies (PID: " << pid << ")\n";
    std::cout << "==================================================\n";

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    auto pGetProcessMitigationPolicy = reinterpret_cast<PFN_GetProcessMitigationPolicy>(
        GetProcAddress(hKernel32, "GetProcessMitigationPolicy")
    );

    if (!pGetProcessMitigationPolicy)
    {
        std::cout << " [!] Mitigation policy API is not available on this Windows version (Requires Win 8+).\n";
    }
    else
    {
        // 0 = ProcessDEPPolicy, 1 = ProcessASLRPolicy
        PROCESS_MITIGATION_DEP_POLICY depPolicy;
        std::memset(&depPolicy, 0, sizeof(depPolicy));
        if (pGetProcessMitigationPolicy(hProcess, 0, &depPolicy, sizeof(depPolicy)))
        {
            std::cout << " - DEP Enabled    : " << ((depPolicy.Flags & 1) ? "Yes" : "No") << "\n";
            std::cout << " - DEP Permanent  : " << ((depPolicy.Flags & 2) ? "Yes" : "No") << "\n";
        }
        else
        {
            std::cout << " - DEP Policy     : <Not Enforced / Unavailable>\n";
        }

        PROCESS_MITIGATION_ASLR_POLICY aslrPolicy;
        std::memset(&aslrPolicy, 0, sizeof(aslrPolicy));
        if (pGetProcessMitigationPolicy(hProcess, 1, &aslrPolicy, sizeof(aslrPolicy)))
        {
            std::cout << " - ASLR Randomization : " << ((aslrPolicy.Flags & 1) ? "Yes" : "No") << "\n";
            std::cout << " - High Entropy VA    : " << ((aslrPolicy.Flags & 2) ? "Yes" : "No") << "\n";
        }
        else
        {
            std::cout << " - ASLR Policy        : <Not Enforced / Unavailable>\n";
        }
    }

    std::cout << "--------------------------------------------------\n\n";

    CloseHandle(hProcess);
}

void fnDoLoadDllTest(const std::string& dllPath)
{
    std::cout << "[*] Attempting to load DLL for analysis: " << dllPath << "\n";
    HMODULE hModule = LoadLibraryA(dllPath.c_str());
    if (!hModule)
    {
        std::cerr << "[-] Error: Failed to load DLL. Error code: " << GetLastError() << "\n";
        return;
    }

    std::cout << "[+] Successfully loaded DLL at base address: 0x" << std::hex << (uintptr_t)hModule << std::dec << "\n";
    std::cout << "[*] Press ENTER to unload DLL and exit...";
    std::cin.get();

    FreeLibrary(hModule);

    std::cout << "[*] DLL unloaded successfully.\n";
}

void fnDoDllInjection(DWORD pid, const std::string& dllPath)
{
    char fullPath[MAX_PATH];
    if (!GetFullPathNameA(dllPath.c_str(), MAX_PATH, fullPath, NULL))
    {
        std::cerr << "[-] Error: Invalid DLL path.\n";
        return;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess)
    {
        std::cerr << "[-] Error: Failed to open target process PID: " << pid << " (Admin rights required?)\n";
        return;
    }

    size_t pathLen = strlen(fullPath) + 1;
    LPVOID pRemoteBuf = VirtualAllocEx(hProcess, NULL, pathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteBuf)
    {
        std::cerr << "[-] Error: Failed to allocate memory in target process.\n";
        CloseHandle(hProcess);
        return;
    }

    if (!WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)fullPath, pathLen, NULL))
    {
        std::cerr << "[-] Error: Failed to write DLL path to target process memory.\n";
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    LPTHREAD_START_ROUTINE pLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryA");
    if (!pLoadLibrary)
    {
        std::cerr << "[-] Error: Failed to resolve LoadLibraryA address.\n";
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pLoadLibrary, pRemoteBuf, 0, NULL);
    if (!hThread)
    {
        std::cerr << "[-] Error: Failed to create remote thread. Injection failed.\n";
    }
    else
    {
        std::cout << "[+] Success! DLL injected into PID " << pid << ".\n";
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }

    VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
    CloseHandle(hProcess);
}

void fnDoBinToShellcode(const std::string& filePath, const std::string& format)
{
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file.is_open())
    {
        std::cerr << "[-] Error: Failed to open file: " << filePath << std::endl;
        return;
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<unsigned char> buffer(static_cast<size_t>(size));
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size))
    {
        std::cerr << "[-] Error: Failed to read file: " << filePath << std::endl;
        return;
    }
    file.close();

    std::cout << "[*] Converting file: " << filePath << " (" << size << " bytes) -> Format: " << format << "\n\n";

    if (format == "python" || format == "py")
    {
        std::cout << "shellcode = b\"\"\n";
        for (size_t i = 0; i < buffer.size(); i++)
        {
            if (i % 16 == 0)
            {
                if (i > 0) std::cout << "\"\n";
                std::cout << "shellcode += b\"";
            }
            std::printf("\\x%02X", buffer[i]);
        }
        if (!buffer.empty()) std::cout << "\"\n";
    }
    else if (format == "c" || format == "cpp")
    {
        std::cout << "unsigned char shellcode[] = {\n    ";
        for (size_t i = 0; i < buffer.size(); i++)
        {
            std::printf("0x%02X", buffer[i]);
            if (i != buffer.size() - 1)
            {
                std::cout << ", ";
            }
            if ((i + 1) % 12 == 0)
            {
                std::cout << "\n    ";
            }
        }
        std::cout << "\n};\n";
        std::cout << "unsigned int shellcode_len = " << buffer.size() << ";\n";
    }
    else 
    {
        std::cout << "\"";
        for (size_t i = 0; i < buffer.size(); i++)
        {
            std::printf("\\x%02X", buffer[i]);
        }
        std::cout << "\"\n";
    }
    std::cout << "\n";
}

void fnDoModuleSectionsInspect(DWORD pid, const std::string& targetModule)
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess)
    {
        std::cerr << "[-] Error: Failed to open process (PID: " << pid << "). Need Admin rights?\n";
        return;
    }

    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
    {
        std::cerr << "[-] Error: Failed to enumerate modules.\n";
        CloseHandle(hProcess);
        return;
    }

    int moduleCount = cbNeeded / sizeof(HMODULE);
    bool found = false;

    for (int i = 0; i < moduleCount; i++)
    {
        wchar_t szModName[MAX_PATH];
        if (GetModuleFileNameExW(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(wchar_t)))
        {
            std::wstring ws(szModName);
            std::string modPath(ws.begin(), ws.end());
            
            size_t lastSlash = modPath.find_last_of("\\/");
            std::string fileName = (lastSlash != std::string::npos) ? modPath.substr(lastSlash + 1) : modPath;

            if (_stricmp(fileName.c_str(), targetModule.c_str()) == 0)
            {
                found = true;
                MODULEINFO modInfo;
                if (!GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(MODULEINFO)))
                    continue;

                uintptr_t baseAddr = (uintptr_t)modInfo.lpBaseOfDll;

                IMAGE_DOS_HEADER dosHeader;
                IMAGE_NT_HEADERS ntHeaders;
                SIZE_T bytesRead = 0;

                if (!ReadProcessMemory(hProcess, (LPCVOID)baseAddr, &dosHeader, sizeof(dosHeader), &bytesRead) ||
                    dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
                {
                    std::cerr << "[-] Error: Invalid DOS header.\n";
                    break;
                }

                if (!ReadProcessMemory(hProcess, (LPCVOID)(baseAddr + dosHeader.e_lfanew), &ntHeaders, sizeof(ntHeaders), &bytesRead))
                {
                    std::cerr << "[-] Error: Invalid NT headers.\n";
                    break;
                }

                WORD numSections = ntHeaders.FileHeader.NumberOfSections;
                uintptr_t sectionHeadersAddr = baseAddr + dosHeader.e_lfanew + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) + ntHeaders.FileHeader.SizeOfOptionalHeader;

                std::vector<IMAGE_SECTION_HEADER> sections(numSections);
                if (!ReadProcessMemory(hProcess, (LPCVOID)sectionHeadersAddr, sections.data(), numSections * sizeof(IMAGE_SECTION_HEADER), &bytesRead))
                {
                    std::cerr << "[-] Error: Failed to read section headers.\n";
                    break;
                }

                std::cout << "================================================================================\n";
                std::cout << " PE Sections for: " << fileName << " (Base: 0x" << std::hex << baseAddr << std::dec << ")\n";
                std::cout << "================================================================================\n";
                std::cout << " Name     | Virtual Addr     | Virt Size  | Raw Size   | Perms | Characteristics\n";
                std::cout << "--------------------------------------------------------------------------------\n";

                for (int s = 0; s < numSections; s++)
                {
                    char name[9] = {0};
                    memcpy(name, sections[s].Name, 8);

                    uintptr_t virtAddr = baseAddr + sections[s].VirtualAddress;
                    DWORD virtSize = sections[s].Misc.VirtualSize;
                    DWORD rawSize = sections[s].SizeOfRawData;
                    DWORD chars = sections[s].Characteristics;

                    char perms[5] = "----";
                    if (chars & IMAGE_SCN_MEM_READ)    perms[0] = 'R';
                    if (chars & IMAGE_SCN_MEM_WRITE)   perms[1] = 'W';
                    if (chars & IMAGE_SCN_MEM_EXECUTE) perms[2] = 'X';
                    perms[3] = '\0';

#ifdef _WIN64
                    printf(" %-8s | 0x%016llX | 0x%08X | 0x%08X | %-5s | 0x%08X\n",
                        name, (unsigned long long)virtAddr, (unsigned int)virtSize, (unsigned int)rawSize, perms, (unsigned int)chars);
#else
                    printf(" %-8s | 0x%08X         | 0x%08X | 0x%08X | %-5s | 0x%08X\n",
                        name, (unsigned int)virtAddr, (unsigned int)virtSize, (unsigned int)rawSize, perms, (unsigned int)chars);
#endif
                }

                std::cout << "--------------------------------------------------------------------------------\n\n";
                break;
            }
        }
    }

    if (!found)
    {
        std::cerr << "[-] Module '" << targetModule << "' not found in PID " << pid << ".\n";
    }

    CloseHandle(hProcess);
}

std::string fnGetModuleFileVersion(const std::wstring& filePath)
{
    DWORD dummy = 0;
    DWORD infoSize = GetFileVersionInfoSizeW(filePath.c_str(), &dummy);
    if (infoSize == 0) return "Unknown";

    std::vector<BYTE> verData(infoSize);
    if (!GetFileVersionInfoW(filePath.c_str(), 0, infoSize, verData.data()))
        return "Unknown";

    VS_FIXEDFILEINFO* fileInfo = nullptr;
    UINT len = 0;
    if (VerQueryValueW(verData.data(), L"\\", (LPVOID*)&fileInfo, &len) && fileInfo)
    {
        DWORD ms = fileInfo->dwFileVersionMS;
        DWORD ls = fileInfo->dwFileVersionLS;
        char buf[64];
        sprintf_s(buf, "%d.%d.%d.%d", 
            (ms >> 16) & 0xFFFF, ms & 0xFFFF, 
            (ls >> 16) & 0xFFFF, ls & 0xFFFF);
        return std::string(buf);
    }
    return "Unknown";
}

void fnDoModuleSecurityInspect(DWORD pid, const std::string& targetModulesArg)
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess)
    {
        std::cerr << "[-] Error: Failed to open process (PID: " << pid << "). Need Admin rights?\n";
        return;
    }

    std::vector<std::string> targetList;
    bool inspectAll = true;

    if (!targetModulesArg.empty() && targetModulesArg != "all")
    {
        inspectAll = false;
        std::stringstream ss(targetModulesArg);
        std::string item;
        while (std::getline(ss, item, ','))
        {
            size_t start = item.find_first_not_of(" \t");
            size_t end = item.find_last_not_of(" \t");
            if (start != std::string::npos && end != std::string::npos)
            {
                targetList.push_back(item.substr(start, end - start + 1));
            }
        }
    }

    HMODULE hMods[1024];
    DWORD cbNeeded;
    bool enumSuccess = false;

    HMODULE hPsapi = LoadLibraryA("psapi.dll");
    if (hPsapi)
    {
        typedef BOOL (WINAPI *PFN_EnumProcessModulesEx)(HANDLE, HMODULE*, DWORD, LPDWORD, DWORD);
        auto pEnumProcessModulesEx = (PFN_EnumProcessModulesEx)GetProcAddress(hPsapi, "EnumProcessModulesEx");

        if (pEnumProcessModulesEx)
        {
            enumSuccess = pEnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL);
        }
        else
        {
            enumSuccess = EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded);
        }
        FreeLibrary(hPsapi);
    }
    else
    {
        enumSuccess = EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded);
    }

    if (!enumSuccess)
    {
        std::cerr << "[-] Error: Failed to enumerate modules.\n";
        CloseHandle(hProcess);
        return;
    }

    int moduleCount = cbNeeded / sizeof(HMODULE);
    int printedCount = 0;

    for (int i = 0; i < moduleCount; i++)
    {
        wchar_t szModName[MAX_PATH];
        if (GetModuleFileNameExW(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(wchar_t)))
        {
            std::wstring ws(szModName);
            std::string modPath(ws.begin(), ws.end());
            
            size_t lastSlash = modPath.find_last_of("\\/");
            std::string fileName = (lastSlash != std::string::npos) ? modPath.substr(lastSlash + 1) : modPath;

            bool match = inspectAll;
            if (!match)
            {
                for (const auto& t : targetList)
                {
                    if (_stricmp(fileName.c_str(), t.c_str()) == 0)
                    {
                        match = true;
                        break;
                    }
                }
            }

            if (match)
            {
                printedCount++;
                MODULEINFO modInfo;
                if (!GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(MODULEINFO)))
                    continue;

                uintptr_t baseAddr = (uintptr_t)modInfo.lpBaseOfDll;
                DWORD size = modInfo.SizeOfImage;
                uintptr_t topAddr = baseAddr + size;

                IMAGE_DOS_HEADER dosHeader;
                IMAGE_NT_HEADERS ntHeaders;
                SIZE_T bytesRead = 0;

                if (!ReadProcessMemory(hProcess, (LPCVOID)baseAddr, &dosHeader, sizeof(dosHeader), &bytesRead) ||
                    dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
                {
                    std::cout << "[!] Could not read DOS header for " << fileName << "\n";
                    continue;
                }

                if (!ReadProcessMemory(hProcess, (LPCVOID)(baseAddr + dosHeader.e_lfanew), &ntHeaders, sizeof(ntHeaders), &bytesRead))
                {
                    std::cout << "[!] Could not read NT headers for " << fileName << "\n";
                    continue;
                }

                WORD dllChars = ntHeaders.OptionalHeader.DllCharacteristics;
                
                bool hasASLR = (dllChars & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0;
                bool hasNX = (dllChars & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0;
                bool canRebase = (ntHeaders.FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) == 0;
                
                bool hasSafeSEH = false;
                #ifndef _WIN64
                bool noSEH = (dllChars & IMAGE_DLLCHARACTERISTICS_NO_SEH) != 0;
                if (!noSEH && ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size > 0)
                {
                    hasSafeSEH = true; 
                }
                #else
                hasSafeSEH = true;
                #endif

                bool isOSDll = (modPath.find("System32") != std::string::npos || 
                                modPath.find("SysWOW64") != std::string::npos ||
                                modPath.find("winsxs") != std::string::npos);

                std::string version = fnGetModuleFileVersion(szModName);

                std::cout << "==================================================\n";
                std::cout << " Module Name : " << fileName << "\n";
                std::cout << " Path        : " << modPath << "\n";
                std::cout << "==================================================\n";
#ifdef _WIN64
                std::cout << " Base Address: 0x" << std::hex << std::setw(16) << std::setfill('0') << baseAddr << "\n";
                std::cout << " Top Address : 0x" << std::hex << std::setw(16) << std::setfill('0') << topAddr << "\n";
#else
                std::cout << " Base Address: 0x" << std::hex << std::setw(8) << std::setfill('0') << baseAddr << "\n";
                std::cout << " Top Address : 0x" << std::hex << std::setw(8) << std::setfill('0') << topAddr << "\n";
#endif
                std::cout << std::dec;
                std::cout << " Size        : " << size << " bytes (" << (size / 1024) << " KB)\n";
                std::cout << "--------------------------------------------------\n";
                std::cout << " [Mitigations & Properties]\n";
                std::cout << "  - ASLR     : " << (hasASLR ? "[+] Enabled" : "[-] Disabled") << "\n";
                std::cout << "  - NXCompat : " << (hasNX ? "[+] Enabled" : "[-] Disabled") << "\n";
                std::cout << "  - Rebase   : " << (canRebase ? "[+] Yes (Relocatable)" : "[-] No (Fixed Base)") << "\n";
                std::cout << "  - SafeSEH  : " << (hasSafeSEH ? "[+] Enabled/N/A" : "[-] Disabled/Vulnerable") << "\n";
                std::cout << "  - OS DLL   : " << (isOSDll ? "Yes (System DLL)" : "No (Third-party/App)") << "\n";
                std::cout << "  - Version  : " << version << "\n";
                std::cout << "--------------------------------------------------\n\n";
            }
        }
    }

    if (!inspectAll && printedCount == 0)
    {
        std::cout << "[-] None of the specified modules were found in PID " << pid << ".\n";
    }

    CloseHandle(hProcess);
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

    HMODULE hNtDll = GetModuleHandleA("ntdll.dll");
    if (hNtDll)
    {
        typedef NTSTATUS (WINAPI *pNtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        auto NtQueryQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");
        
        if (NtQueryQueryInformationProcess)
        {
            ULONG breakOnTermination = 0;
            NTSTATUS status = NtQueryQueryInformationProcess(
                hProcess, 
                29, // ProcessBreakOnTermination
                &breakOnTermination, 
                sizeof(ULONG), 
                NULL
            );
            
            if (status == 0) // STATUS_SUCCESS
            {
                std::cout << " Critical      : " << (breakOnTermination != 0 ? "YES (Protected / Critical)" : "No") << "\n";
            }
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

void fnDoSetCriticalStatus(DWORD nCriticalStatus, DWORD pid)
{
    typedef NTSTATUS (WINAPI *pNtSetInformationProcess)(HANDLE, ULONG, PVOID, ULONG);
    HMODULE hNtDll = GetModuleHandleA("ntdll.dll");

    if (!hNtDll)
    {
        std::cerr << "[-] Invalid handle value of hNtDll." << std::endl;
        return;
    }

    auto NtSetInformationProcess = (pNtSetInformationProcess)(void*)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationProcess");
    if (!NtSetInformationProcess)
    {
        std::cout << "[-] Failed to get API address. Error: " << GetLastError() << std::endl;
        return;
    }

    ULONG executeFlags = 2;
    NtSetInformationProcess((HANDLE)-1, 0x22, &executeFlags, sizeof(executeFlags));

    HANDLE hProcess = OpenProcess(PROCESS_SET_INFORMATION, FALSE, pid);
    if (!hProcess)
    {
        std::cout << "[-] Failed to open process. Error: " << GetLastError() << std::endl;
        return;
    }

    ULONG nIsCritical = nCriticalStatus;
    ULONG nProcInfoClass = 29;

    NTSTATUS status = NtSetInformationProcess(hProcess, nProcInfoClass, &nIsCritical, sizeof(ULONG));
    if (0 == status)
        printf("[+] Success! Process %lu is now %s\n", pid, nIsCritical == 1 ? "CRITICAL" : "NORMAL");
    else
        printf("[-] Failed. NTSTATUS: 0x%lX (Check if running as Admin)\n", status);

    CloseHandle(hProcess);
    CloseHandle(hNtDll);
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
    
    if (result && GetLastError() == ERROR_NOT_ALL_ASSIGNED)
    {
        result = FALSE;
    }

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

    std::cout << "  0. Coffee - Easter egg\n";
    std::cout << "     Usage: " << prog << " --coffee\n\n";

    std::cout << "  1. Disassembly - Disassemble machine code from a module API\n";
    std::cout << "     Usage: " << prog << " --da [ModulePath] [ApiName] [LineCount]\n\n";

    std::cout << "  2. Symbol Search - Search symbols or patterns in a module\n";
    std::cout << "     Usage: " << prog << " --search [Module!Pattern] [--line [LineCount]]\n\n";

    std::cout << "  3. Process Memory Dump - Dump process memory at specified address\n";
    std::cout << "     Usage: " << prog << " --dump [Address] --pid [PID] [--line [LineCount]]\n\n";

    std::cout << "  4. Process Stack Dump - Dump process stack contents\n";
    std::cout << "     Usage: " << prog << " --stack --pid [PID] [--line [LineCount]]\n\n";

    std::cout << "  5. Process Info - Show detailed process information\n";
    std::cout << "     Usage: " << prog << " --info --pid [PID]\n\n";

    std::cout << "  6. Process Modules - List all loaded modules in a process\n";
    std::cout << "     Usage: " << prog << " --modules --pid [PID]\n\n";

    std::cout << "  7. DEP Bypass/Test - Test different DEP bypass techniques (1-6)\n";
    std::cout << "     Usage: " << prog << " --dep [1-6]\n\n";

    std::cout << "  8. Module Security Inspect - Check ASLR, DEP, SafeSEH, Rebase, Version\n";
    std::cout << "     Usage: " << prog << " --mod-info [module1.dll,module2.dll] --pid [PID]\n\n";

    std::cout << "  9. PE Sections Inspect - Inspect PE section perms (RX/RWX/RO)\n";
    std::cout << "     Usage: " << prog << " --sections [Module] --pid [PID]\n\n";

    std::cout << " 10. Bin to Shellcode - Convert binary files into Python/C/Raw formats\n";
    std::cout << "     Usage: " << prog << " --bin2sc [FilePath] [--format python|c|raw]\n\n";

    std::cout << " 11. Module Exports - Inspect EAT of a DLL file\n";
    std::cout << "     Usage: " << prog << " --exports [DllPath]\n\n";

    std::cout << " 12. Process Mitigations - Check process-level security policies\n";
    std::cout << "     Usage: " << prog << " --mitigations --pid [PID]\n\n";

    std::cout << " 13. Load DLL Test - Manually load a DLL for malware/API testing\n";
    std::cout << "     Usage: " << prog << " --load-dll [DllPath]\n\n";

    std::cout << " 14. DLL Injection - Inject a DLL into a target process for patching\n";
    std::cout << "     Usage: " << prog << " --inject [DllPath] --pid [PID]\n\n";

    std::cout << " 15. Critical Process - Set critical process status\n";
    std::cout << "     Usage: " << prog << " --set-critical [0|1] --pid [PID]\n\n";

    std::cout << " 16. Dump Process - Set critical process status\n";
    std::cout << "     Usage: " << prog << " --dump-proc --pid [PID] --output-path [Path]\n\n";

    std::cout << " 17. Display MFT - Set critical process status\n";
    std::cout << "     Usage: " << prog << " --mft-read \\\\.\\C: --mft-index [Index]\n\n";

    std::cout << " 18. Hexdump - Display file hexdump\n";
    std::cout << "     Usage: " << prog << " --hexdump [File]\n";

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
    ULONGLONG mft_index = 0;
    std::string outputFormat = "raw";
    DWORD critical_status = 0;

    std::string inputFile = "";
    std::string outputFile = "";

    for (int i = 1; i < argc; i++)
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
        else if (arg == "--format" && i + 1 < argc)
        {
            outputFormat = argv[++i];
        }
        else if (arg == "--set-critical" && i + 1 < argc)
        {
            try
            {
                critical_status = std::stoi(argv[++i]);
            }
            catch (...)
            {
                std::cerr << "Error: Invalid --set-critical value.\n";
                return 1;
            }
        }
        else if (arg == "--output-file" && i + 1 < argc)
        {
            outputFile = argv[++i];
        }
        else if (arg == "--mft-read" && i + 1 < argc)
        {
            inputFile = argv[++i];
        }
        else if (arg == "--mft-index" && i + 1 < argc)
        {
            mft_index = (ULONGLONG)std::stoi(argv[++i]);
        }
        else if (arg == "--hexdump" && i + 1 < argc)
        {
            inputFile = argv[++i];
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
    else if (arg1 == "--mod-info")
    {
        if (pid == 0)
        {
            std::cerr << "Error: --mod-info requires --pid N\n";
            return 1;
        }

        std::string targetMods = "all";
        if (argc >= 3 && argv[2][0] != '-')
        {
            targetMods = argv[2];
        }

        fnDoModuleSecurityInspect(pid, targetMods);
        return 0;
    }
    else if (arg1 == "--sections")
    {
        if (argc < 3 || pid == 0)
        {
            std::cerr << "Error: --sections requires [ModulePath] and --pid N\n";
            return 1;
        }

        fnDoModuleSectionsInspect(pid, argv[2]);

        return 0;
    }
    else if (arg1 == "--bin2sc")
    {
        if (argc < 3)
        {
            std::cerr << "Error: --bin2sc requires a target file path.\n";
            return 1;
        }

        fnDoBinToShellcode(argv[2], outputFormat);
        return 0;
    }
    else if (arg1 == "--exports")
    {
        if (argc < 3)
        {
            std::cerr << "Error: --exports requires a DLL path.\n";
            return 1;
        }
        fnDoModuleExports(argv[2]);
        return 0;
    }
    else if (arg1 == "--mitigations")
    {
        if (pid == 0)
        {
            std::cerr << "Error: --mitigations requires --pid N\n";
            return 1;
        }
        fnDoProcessMitigations(pid);
        return 0;
    }
    else if (arg1 == "--load-dll")
    {
        if (argc < 3)
        {
            std::cerr << "Error: --load-dll requires a DLL path.\n";
            return 1;
        }
        fnDoLoadDllTest(argv[2]);
        return 0;
    }
    else if (arg1 == "--inject")
    {
        if (argc < 3 || pid == 0)
        {
            std::cerr << "Error: --inject requires [DllPath] and --pid N\n";
            return 1;
        }
        
        fnDoDllInjection(pid, argv[2]);
        return 0;
    }
    else if (arg1 == "--set-critical")
    {
        if (argc < 4 || pid == 0)
        {
            std::cerr << "[-] Usage: " << argv[0] << " --set-critical [0|1] --pid [PID]" << std::endl;
            return 1;
        }

        fnDoSetCriticalStatus(critical_status, pid);
        return 0;
    }
    else if (arg1 == "--dump-proc")
    {
        if (argc < 6 || pid == 0)
        {
            std::cerr << "[-] Usage: " << argv[0] << " --dump-proc --pid N --output-file <Path>" << std::endl;
            return 1;
        }

        fnProcessMiniDump(pid, outputFile);
        return 0;
    }
    else if (arg1 == "--mft-read")
    {
        if (argc < 4)
        {
            std::cerr << "[-] Usage: " << argv[0] << " --mft-read \\\\.\\C: --mft-index 0" << std::endl;
            return 1;
        }

        fnShowMftRecordInfo(inputFile, mft_index);
        return 0;
    }
    else if (arg1 == "--hexdump")
    {
        if (argc < 4)
        {

        }

        LPCTSTR lpFilename = inputFile.c_str();
        PUCHAR pBuffer = NULL;
        ULONG nRead = 0;

        if (fnReadBuffer(lpFilename, &pBuffer, &nRead))
        {
            std::cout << "Read " << nRead << " bytes from file: " << inputFile << std::endl;
            
            if (lineCount == 0)
                max_line = -1;
            else
                max_line = lineCount;

            fnHexDump(pBuffer, nRead, max_line);
            
            return 0;
        }
        else
        {
            std::cerr << "Failed to read file: " << inputFile << std::endl;
            return 1;
        }
    }

    fnPrintUsage(argv[0]);
    return 1;
}