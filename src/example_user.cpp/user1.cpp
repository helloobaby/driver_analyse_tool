/*++

其他的文件不用动,只把自己的代码放到user_main函数里就行,DriverEntry中会调用

--*/

#include<ntifs.h>
#include<ntddk.h>
#include<wdm.h>
#include<fltKernel.h>
#include<intrin.h>

#include"utils.h"
#include"module.h"
#include"pe.h"
#include"exclusivity.h"

#include"dependencies/kernel-hook/khook/khook/hk.h"

extern "C" {
    NTSYSAPI 
        PVOID RtlPcToFileHeader(
        PVOID PcValue,
        PVOID* BaseOfImage
    );
}

//
bool FltReadBusy;
using FltReadFileType = decltype(&FltReadFile);     
FltReadFileType OriFltReadFile;                     //
FltReadFileType FltReadFileAddress;                 //待hook的函数地址
NTSTATUS
DetourFltReadFile(
    _In_ PFLT_INSTANCE InitiatingInstance,
    _In_ PFILE_OBJECT FileObject,
    _In_opt_ PLARGE_INTEGER ByteOffset,
    _In_ ULONG Length,
    _Out_writes_bytes_to_(Length, *BytesRead) PVOID Buffer,
    _In_ FLT_IO_OPERATION_FLAGS Flags,
    _Out_opt_ PULONG BytesRead,
    _In_opt_ PFLT_COMPLETED_ASYNC_IO_CALLBACK CallbackRoutine,
    _In_opt_ PVOID CallbackContext
);
//


//
bool NtReadBusy;
using NtReadFileType = decltype(&NtReadFile);
NtReadFileType OriNtReadFile;
NtReadFileType NtReadFileAddress;
NTSTATUS
DetourNtReadFile(
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _Out_writes_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _In_opt_ PLARGE_INTEGER ByteOffset,
    _In_opt_ PULONG Key
);
//

PVOID isCsAgentModule(PLIST_ENTRY ListEntry) {

    static UNICODE_STRING CsAgent = RTL_CONSTANT_STRING(L"csagent.sys");
    PKLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(ListEntry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

    if (!RtlCompareUnicodeString(&CsAgent, &pEntry->BaseDllName, true)) {
        return pEntry->DllBase;
    }

    return false;
}

PVOID isFlgMgrModule(PLIST_ENTRY ListEntry) {
    static UNICODE_STRING FltMgr = RTL_CONSTANT_STRING(L"fltmgr.sys");
    PKLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(ListEntry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

    if (!RtlCompareUnicodeString(&FltMgr, &pEntry->BaseDllName, true)) {
        return pEntry->DllBase;
    }

    return false;
}

static PVOID CsAgentBase;
static PVOID FltMgrBase;
static PVOID NtBase;
void user_main(PDRIVER_OBJECT drv, PUNICODE_STRING reg) {

    NTSTATUS Status;

    //获得需要的模块基址

    CsAgentBase = kmodule::get_module<PVOID>(isCsAgentModule);
    FltMgrBase = kmodule::get_module<PVOID>(isFlgMgrModule);
    RtlPcToFileHeader(NtReadFile, &NtBase);
    
    if (!((ULONG64)CsAgentBase & (ULONG64)FltMgrBase & (ULONG64)NtBase))
        return;

    //获得需要hook的函数地址

    FltReadFileAddress = (FltReadFileType)GetDriverExportRoutine(FltMgrBase, "FltReadFile");
    if (!FltReadFileAddress)
        return;

    NtReadFileAddress = (NtReadFileType)GetDriverExportRoutine(NtBase, "NtReadFile");
    if (!NtReadFileAddress)
        return;

    print("[+]CsAgentBase : %p\n", CsAgentBase);
    print("[+]FltMgrBase : %p\n", FltMgrBase);
    print("[+]FltReadFile : %p\n", FltReadFileAddress);
    print("[+]NtReadFile : %p\n", NtReadFileAddress);

    //hook

    Status = HkDetourFunction(FltReadFileAddress, DetourFltReadFile, (PVOID*)&OriFltReadFile);
    if (!NT_SUCCESS(Status)) {
        print("[-]hook FltReadFile failed\n");
        return;
    }
    Status = HkDetourFunction(NtReadFileAddress, DetourNtReadFile, (PVOID*)&OriNtReadFile);
    if (!NT_SUCCESS(Status)) {
        HkRestoreFunction(FltReadFileAddress, OriFltReadFile);
        print("[-]hook NtReadFile failed\n");
        return;
    }
    


    pe64 CsAgentPe(CsAgentBase);
    CsAgentPe.print_dos_headers();
    CsAgentPe.print_nt_headers();
    CsAgentPe.print_sections();














    return;
}

void unload(PDRIVER_OBJECT drv) {

    NTSTATUS Status;
    void* Ex = ExclGainExclusivity();

    if (FltReadBusy || NtReadBusy) {
        print("[-]FltReadBusy is busy,probably bugcheck!\n");
    }

    if (OriFltReadFile) {
        Status = HkRestoreFunction(FltReadFileAddress, OriFltReadFile);
        print("[+]unhook FltReadFile... Status : %x\n",Status);
    }
    if (OriNtReadFile) {
        Status = HkRestoreFunction(NtReadFileAddress, OriNtReadFile);
        print("[+]unhook NtReadFile... Status : %x\n", Status);
    }

    ExclReleaseExclusivity(Ex);




    print("[+]driver unload...\n");
}


NTSTATUS
DetourFltReadFile(
    _In_ PFLT_INSTANCE InitiatingInstance,
    _In_ PFILE_OBJECT FileObject,
    _In_opt_ PLARGE_INTEGER ByteOffset,
    _In_ ULONG Length,
    _Out_writes_bytes_to_(Length, *BytesRead) PVOID Buffer,
    _In_ FLT_IO_OPERATION_FLAGS Flags,
    _Out_opt_ PULONG BytesRead,
    _In_opt_ PFLT_COMPLETED_ASYNC_IO_CALLBACK CallbackRoutine,
    _In_opt_ PVOID CallbackContext
) {
    FltReadBusy = true;

    PVOID ReturnAddress = _ReturnAddress();
    PVOID BaseImage;
    NTSTATUS Status;

    RtlPcToFileHeader(ReturnAddress, &BaseImage);
    if (BaseImage == CsAgentBase) {
        //print("[+]CrowdStrike FltReadFile Read File : %wZ  ReturnAddress : %p\n", FileObject->FileName,ReturnAddress);
    }




   Status = OriFltReadFile(InitiatingInstance, FileObject, ByteOffset, Length, Buffer, Flags, BytesRead, CallbackRoutine, CallbackContext);
   FltReadBusy = false;
   return Status;
}

NTSTATUS
DetourNtReadFile(
    _In_ HANDLE FileHandle,
    _In_opt_ HANDLE Event,
    _In_opt_ PIO_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcContext,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _Out_writes_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _In_opt_ PLARGE_INTEGER ByteOffset,
    _In_opt_ PULONG Key
) {
    NTSTATUS Status;
    NtReadBusy = true;
    FILE_OBJECT* FileObject;
    PVOID ReturnAddress = _ReturnAddress();
    PVOID BaseImage;

    Status = ObReferenceObjectByHandle(FileHandle, GENERIC_READ, *IoFileObjectType, KernelMode, (PVOID*)&FileObject, NULL);
    if (NT_SUCCESS(Status)) {
        RtlPcToFileHeader(ReturnAddress, &BaseImage);
        if (BaseImage == CsAgentBase) {
            print("[+]CrowdStrike NtReadFile Read File : %wZ  ReturnAddress : %p\n", FileObject->FileName,ReturnAddress);
        }
    }
    else {
        print("[-]ObReferenceObjectByHandle failed with %x\n", Status);
    }





    Status = OriNtReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
    NtReadBusy = false;
    return Status;
}