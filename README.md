# WinScalpel

Lightweight Offline Disassembler & Analysis Tool (XP Compatible)

The idea for this tool came to me while I was developing a ROP script. It allows you to search for specific APIs without having to use WinDbg or other heavy tools.

I also integrated several features into it that can be helpful when analyzing malware or Windows APIs.

# Usage

Winscalpel currently contains the features below:

## Disassembly — Simply disassemble machine code from a module API

```
WinScalpel.exe --da [ModulePath] [ApiName] [LineCount]
```

## Symbol Search — Search symbols or patterns in a module

```
WinScalpel.exe --search [Module!Pattern] [--line [LineCount]]
```

## Process Memory Dump — Dump process memory at specified address

```
WinScalpel.exe --dump [Address] --pid [PID] [--line [LineCount]]
```

## Process Stack Dump — Dump process stack contents

```
WinScalpel.exe --stack --pid [PID] [--line [LineCount]]
```

## Process Info — Show detailed process information

```
WinScalpel.exe --info --pid [PID]
```

## Process Modules — List all loaded modules in a process

```
WinScalpel.exe --modules --pid [PID]
```

## DEP Bypass/Test — Test different DEP bypass techniques (1-6)

1. `NtSetInformationprocess`
2. `SetProcessDEPPolicy`
3. `VirtualProtect`
4. `WriteProcessMemory`
5. `VirtualAlloc` + `memcpy`
6. `HeapCreate` + `HeapAlloc` + `memcpy`

```
WinScalpel.exe --dep [1-6]
```

## Module Security Inspect — Check ASLR, DEP, SafeSEH, Rebase, Version

```
WinScalpel.exe --mod-info [module1.dll,module2.dll] --pid [PID]
```

## PE Sections Inspect - Inspect PE section perms (RX/RWX/RO)

```
WinScalpel.exe --sections [Module] --pid [PID]
```

## Bin to Shellcode - Convert binary files into Python/C/Raw formats

```
WinScalpel.exe --bin2sc [FilePath] [--format python|c|raw]
```

## Module Exports - Inspect EAT of a DLL file

```
WinScalpel.exe --exports [DllPath]
```

## Process Mitigations - Check process-level security policies

```
WinScalpel.exe --mitigations --pid [PID]
```

## Load DLL Test - Manually load a DLL for malware/API testing

```
WinScalpel.exe --load-dll [DllPath]
```

## DLL Injection - Inject a DLL into a target process for patching

```
WinScalpel.exe --inject [DllPath] --pid [PID]
```

## Critical Process - Set critical process status

```
WinScalpel.exe --set-critical [0|1] --pid [PID]
```

## Dump Process - Dump process from memory and save it into a file

```
WinScalpel.exe --dump-proc --pid [PID] --output-path [Path]
```

## Display MFT - Display MFT information with a specified index

```
WinScalpel.exe --mft-read \\.\C: --mft-index [Index]
```

## Hexdump - Display file hexdump

```
WinScalpel.exe --hexdump [File]
```


