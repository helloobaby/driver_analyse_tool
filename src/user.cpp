/*++

其他的文件不用动,只把自己的代码放到user_main函数里就行,DriverEntry中会调用

--*/

#include<ntifs.h>
#include<ntddk.h>
#include<wdm.h>
#include<strsafe.h>
#include<ntstrsafe.h>
#include<intrin.h>

#include"utils.h"
#include "module.h"
#include "pe.h"
#include "dependencies/wdmlib/cm/cmregutil.h"

#include "special_system/wrap_call.h"
#include "special_system/special_system.h"
#include "special_system/ntkrnl_symbol.h"
#include "special_system/fltmgr_symbol.h"
#include "special_system/ci_symbol.h"

EXTERN_C NTSTATUS RtlFormatCurrentUserKeyPath(OUT PUNICODE_STRING  RegistryPath);

typedef struct _IMAGE_IMPORT_BY_NAME2 {
    USHORT  Hint;
    CHAR   Name[46];
} IMAGE_IMPORT_BY_NAME2, * PIMAGE_IMPORT_BY_NAME2;

typedef struct _HARDWARE_PTE           // 16 elements, 0x8 bytes (sizeof) 
{
    /*0x000*/     UINT64       Valid : 1;            // 0 BitPosition                   
    /*0x000*/     UINT64       Write : 1;            // 1 BitPosition                   
    /*0x000*/     UINT64       Owner : 1;            // 2 BitPosition                   
    /*0x000*/     UINT64       WriteThrough : 1;     // 3 BitPosition                   
    /*0x000*/     UINT64       CacheDisable : 1;     // 4 BitPosition                   
    /*0x000*/     UINT64       Accessed : 1;         // 5 BitPosition                   
    /*0x000*/     UINT64       Dirty : 1;            // 6 BitPosition                   
    /*0x000*/     UINT64       LargePage : 1;        // 7 BitPosition                   
    /*0x000*/     UINT64       Global : 1;           // 8 BitPosition                   
    /*0x000*/     UINT64       CopyOnWrite : 1;      // 9 BitPosition                   
    /*0x000*/     UINT64       Prototype : 1;        // 10 BitPosition                  
    /*0x000*/     UINT64       reserved0 : 1;        // 11 BitPosition                  
    /*0x000*/     UINT64       PageFrameNumber : 36; // 12 BitPosition                  
    /*0x000*/     UINT64       reserved1 : 4;        // 48 BitPosition                  
    /*0x000*/     UINT64       SoftwareWsIndex : 11; // 52 BitPosition                  
    /*0x000*/     UINT64       NoExecute : 1;        // 63 BitPosition                  
}HARDWARE_PTE, * PHARDWARE_PTE;

typedef struct _aEPROCESS {
    union 
    {
        struct
        {
            make_offset(0x2E8);
            struct _LIST_ENTRY ActiveProcessLinks;
        };
    };
}aEPROCESS, *aPEPROCESS;

KIRQL WPOFF()
{
    KIRQL OldIrql = KeRaiseIrqlToDpcLevel();

    ULONG_PTR cr0 = __readcr0();
#ifdef _X86_
    cr0 &= 0xfffeffff;
#else
    cr0 &= 0xfffffffffffeffff;
#endif
    _disable();	
    __writecr0(cr0);			

    return OldIrql;
}


VOID WPON(KIRQL irql)
{

    ULONG_PTR cr0 = __readcr0();
    cr0 |= 0x10000;
    __writecr0(cr0);	
    _enable();	

    KeLowerIrql(irql);
}


void unload(PDRIVER_OBJECT drv) {
    UNREFERENCED_PARAMETER(drv);
    print("[+]driver unload...\n");
    return;
}

static PVOID CsAgentBase;
static PVOID HalBase = (PVOID)0xfffff80012e08000;
static PVOID CiBase = (PVOID)0xfffff80015310000;
static PVOID FltBase = (PVOID)0xfffff800ede30000;
PVOID NtBase;
PVOID MmPteBase;

PVOID isCsAgentModule(PLIST_ENTRY ListEntry) {

    static UNICODE_STRING CsAgent = RTL_CONSTANT_STRING(L"csagent.sys");
    PKLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(ListEntry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

    if (!RtlCompareUnicodeString(&CsAgent, &pEntry->BaseDllName, true)) {
        return pEntry->DllBase;
    }

    return false;
}

PEPROCESS get_explorer_eprocess(PLIST_ENTRY ListEntry) {
    PEPROCESS EPROCESS = (PEPROCESS)CONTAINING_RECORD(ListEntry, _aEPROCESS, ActiveProcessLinks);
    if (!strcmp("explorer.exe", (const char*)PsGetProcessImageFileName(EPROCESS))) {
        return EPROCESS;
    }
    return 0;
}

void fix_sections(IMAGE_SECTION_HEADER* sec) {
    sec->PointerToRawData = sec->VirtualAddress;
}

void user_main(PDRIVER_OBJECT drv, PUNICODE_STRING reg) {
    UNREFERENCED_PARAMETER(drv);
    UNREFERENCED_PARAMETER(reg);

    NTSTATUS Status;
    ULONG64* ptes[4]{};

    CsAgentBase = kmodule::get_module<PVOID>(isCsAgentModule);
    RtlPcToFileHeader(NtReadFile, &NtBase);
    if (!NtBase) {
        print("[-]cant find ntbase\n");
        return;
    }
    if (!CsAgentBase)
    {
        print("[-]cant find CsAgent");
        return;
    }
    print("[*]CsAgentBase 0x%llx\n", CsAgentBase);
    

    wrap_call<PVOID, PVOID, ULONG64**> MiFillPteHierarchy((PVOID)((ULONG64)NtBase + Offset_MiFillPteHierarchy));

    PVOID assume_text_seg = (PVOID)((ULONG64)CsAgentBase + 0x1000);
    
    MmPteBase = MiFillPteHierarchy(assume_text_seg,ptes);
    if (!MmPteBase) {
        print("[-]cant find MmPteBase\n");
        return;
    }
    print("[*]MmPteBase 0x%llx\n", MmPteBase);

    PHARDWARE_PTE pte_content = (PHARDWARE_PTE)ptes[0];

    print("[*]csagent+0x1000 pte content 0x%llx\n",*pte_content);

    if (pte_content->NoExecute) {
        print("[-] assume text segment cant execute\n");
        return;
    }

    PVOID assume_text_seg_end = NULL; 

    for (;;) {
        static ULONG64 p = (ULONG64)assume_text_seg;
        MiFillPteHierarchy((PVOID)(p), ptes);
        PHARDWARE_PTE pte_content_2 = (PHARDWARE_PTE)ptes[0];
        if (pte_content_2->NoExecute) {  //遇到了数据段
            print("[+]assume text segment end %llx\n", p);
            assume_text_seg_end = (PVOID)p;
            break;
        }
        p = p + 0x1000;
    }

    ULONG64 text_seg_size = (ULONG64)assume_text_seg_end - (ULONG64)assume_text_seg;
    print("[+]test seg size %llx\n", text_seg_size);
    
    HANDLE KeyHandle;
    Status = CmRegUtilOpenExistingWstrKey(NULL, CM_REGISTRY_MACHINE("SYSTEM\\CurrentControlSet\\Services\\CsAgent"), KEY_ALL_ACCESS, &KeyHandle);
    if (!NT_SUCCESS(Status))
    {
        print("[-]CmRegUtilOpenExistingWstrKey failed with %x\n", Status);
        return;
    }


    UNICODE_STRING ValueName = RTL_CONSTANT_STRING(L"ImagePath");
    PKEY_VALUE_FULL_INFORMATION Info{};
    Status = CmRegUtilUcValueGetFullBuffer(KeyHandle, &ValueName, 0, 0, &Info);

    if (!NT_SUCCESS(Status))
    {
        print("[-]CmRegUtilUcValueGetFullBuffer failed with %x\n", Status);
        return;
    }

    //从KEY_VALUE_FULL_INFORMATION中取键值的正确写法
    print("[+]csagent disk path %ws\n", Info->Name+Info->NameLength/2+1);

    WCHAR* sys_path = Info->Name + Info->NameLength / 2 + 1;
    
    HANDLE hFile;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING usSysPath;
    IO_STATUS_BLOCK IoStatus;
    RtlInitUnicodeString(&usSysPath, sys_path);
    InitializeObjectAttributes(&oa, &usSysPath, NULL, NULL, NULL);

    //https://blog.csdn.net/iteye_17686/article/details/82357881
    //同步打开,不然ZwReadFile大概率返回pending
    Status = IoCreateFileSpecifyDeviceObjectHint(&hFile, SYNCHRONIZE |GENERIC_READ, &oa, &IoStatus, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_VALID_FLAGS, FILE_OPEN, FILE_NON_DIRECTORY_FILE| FILE_SYNCHRONOUS_IO_NONALERT, NULL, NULL, CreateFileTypeNone, NULL, IO_IGNORE_SHARE_ACCESS_CHECK,NULL);
    if (!NT_SUCCESS(Status)) {
        print("[-]IoCreateFileSpecifyDeviceObjectHint failed with status %x\n", Status);
        ExFreePool(Info);
        return;
    }

    
    //获得桌面地址

    UNICODE_STRING usCurrentUserKey = { 0 };
    
    //挂靠到explorer.exe
    PEPROCESS CurrentEP = IoGetCurrentProcess();
    PEPROCESS explorerEP = travelsee_list(&((aEPROCESS*)CurrentEP)->ActiveProcessLinks, get_explorer_eprocess);
    
    if (!explorerEP)
        return;

    print("[+]explorer eprocess : %p\n", explorerEP);

    KAPC_STATE apcState;
    KeStackAttachProcess(explorerEP,&apcState);

    Status = RtlFormatCurrentUserKeyPath(&usCurrentUserKey);
    if (!NT_SUCCESS(Status))
    {
        print("[-]RtlFormatCurrentUserKeyPath failed with %x\n",Status);
        ExFreePool(Info);
        return;
    }
    print("[+]current user %wZ\n", usCurrentUserKey);

    KeUnstackDetachProcess(&apcState);

#if 0
    WCHAR MaxPath[256]{};
    memcpy(MaxPath, usCurrentUserKey.Buffer, usCurrentUserKey.MaximumLength);
    StringCchCatW(MaxPath, 256, L"\\Volatile Environment");

    print("[+]%ws\n", MaxPath);

    Status = CmRegUtilOpenExistingWstrKey(NULL, MaxPath, KEY_ALL_ACCESS, &KeyHandle);
    if (!NT_SUCCESS(Status))
    {
        print("[-]CmRegUtilOpenExistingWstrKey failed with %x\n", Status);
        return;
    }
    UNICODE_STRING v = RTL_CONSTANT_STRING(L"USERPROFILE");
    CmRegUtilUcValueGetFullBuffer(KeyHandle, &v, 0, 0, &Info);
#endif

    decltype(auto) FileInformation = (FILE_STANDARD_INFORMATION*)ExAllocatePoolWithTag(NonPagedPool, 0x1000, 'aaaa');

    Status = ZwQueryInformationFile(hFile, &IoStatus, FileInformation, 0x1000, FileStandardInformation);
    if (!NT_SUCCESS(Status)) {
        print("[-]ZwQueryInformationFile failed with status %x\n", Status);
        ExFreePool(Info);
        ExFreePool(FileInformation);
        return;
    }

    ULONG64 FileSize = 0;
    FileSize = FileInformation->AllocationSize.QuadPart;
    ExFreePool(FileInformation);
    print("[+]FileSize %llx\n", FileSize);

    char* FileBuffer = (char*)ExAllocatePool(NonPagedPool, FileSize);
    if (!FileBuffer) {
        print("[-]ExAllocatePool failed\n");
        ExFreePool(Info);
        return;
    }

    LARGE_INTEGER ByteOffset{};
    Status = ZwReadFile(hFile, NULL, NULL, NULL, &IoStatus, FileBuffer, (ULONG32)FileSize, &ByteOffset, 0);
    if (!NT_SUCCESS(Status))
    {
        print("[-]ZwReadFile failed with status %x\n", Status);
        ExFreePool(Info);
        return;
    }

    //print("%c%c", FileBuffer[0], FileBuffer[1]);              //-> 'MZ'
    pe64 RawCsAgent(FileBuffer, false);
    pe64 MemoryCsAgent(CsAgentBase, true);
    LARGE_INTEGER SizeOfImage{ MemoryCsAgent.get_nt_headers()->OptionalHeader.SizeOfImage };
    LARGE_INTEGER SizeOfImage2{ MemoryCsAgent.get_nt_headers()->OptionalHeader.SizeOfImage+0x200000 };
    
    print("[-]size image : %x\n", SizeOfImage.QuadPart);

    ULONG sizeBeforeTextSeg = RawCsAgent.get_dos_headers()->e_lfanew
        + 4  //Signature
        + sizeof(IMAGE_FILE_HEADER)
        + RawCsAgent.get_nt_headers()->FileHeader.SizeOfOptionalHeader  //0x1f4+4 = 0x1f8  
        + (RawCsAgent.get_nt_headers()->FileHeader.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER);       
    print("[+]sizeBeforeTextSeg : 0x%x\n", sizeBeforeTextSeg);

    if (sizeBeforeTextSeg > 0x1000) {
        print("[-] not common pe file\n");
        ExFreePool(Info);
        return;
    }

    HANDLE hdump;
    UNICODE_STRING dump_path = RTL_CONSTANT_STRING(L"\\??\\C:\\Users\\user\\Desktop\\dumpxxx.sys");
    InitializeObjectAttributes(&oa, &dump_path, NULL, NULL, NULL);
    Status = ZwCreateFile(&hdump, SYNCHRONIZE | FILE_WRITE_ACCESS, &oa, &IoStatus, &SizeOfImage2, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT,0,0);
    if (!NT_SUCCESS(Status)) {
        print("[-]ZwCreateFile failed with %x\n", Status);
        return;
    }

    //先搞一下入口点,直接是text段起始地址就可以了,不需要去搞真正的入口点在哪
    RawCsAgent.get_nt_headers()->OptionalHeader.AddressOfEntryPoint = 0x1000;
    
    //一个页一个页拷贝,因为有些节区是INIT的
    char* zero = (char*)ExAllocatePool(NonPagedPool, 0x1000);
    RtlZeroMemory(zero, 0x1000);

    //将VirutalAddress和PointerToRawData相同
    auto irql = WPOFF();
    MemoryCsAgent.processing_sections(fix_sections);
    IMAGE_SECTION_HEADER* p = MemoryCsAgent.get_section("INIT");
    p->SizeOfRawData += 0x200000;       //需要把后面的内容搞到节区内  不然什么pebear cff ida他都不会识别这部分(而且不能加到.reloc上,ida不会解析这一节)
    p->Misc.VirtualSize += 0x200000;
    WPON(irql);

    //修复导入表 crowdstrike的导入表是在INIT字段的,加载完就卸载了
    IMAGE_DATA_DIRECTORY* idd_import = MemoryCsAgent.get_data_dir(IMAGE_DIRECTORY_ENTRY_IMPORT);
    print("[+]Import Directory Address : 0x%x  , Size : 0x%x\n", idd_import->VirtualAddress, idd_import->Size);
    print("[+]IID count %d\n", idd_import->Size / sizeof(IMAGE_IMPORT_DESCRIPTOR)); //最后一个为空

    //分配iid结构需要的内存(只需要关键的ntoskrnl\Hal\Fltmgr\Ci\)   别的模块不关键
    IMAGE_IMPORT_DESCRIPTOR* rebuild_iid = (IMAGE_IMPORT_DESCRIPTOR*)ExAllocatePool(NonPagedPool, 0x200000);
    memset(rebuild_iid, 0, 0x200000);
    if (!rebuild_iid)
        print("[-]rebuild iid alloc failed\n");
    memset(rebuild_iid, 0, 0x1000);


    char* ntoskrnl_name = "ntoskrnl.exe";
    char* haldll_name = "HAL.dll";
    char* fltmgr_name = "FLTMGR.SYS";
    char* Ci_name = "ci.dll";

    /*
INIT:000000000029E1C0 50 E9 29 00       __IMPORT_DESCRIPTOR_ntoskrnl_exe dd rva off_29E950 ; 一般来说导入表信息是在idata的，他这直接搞到init区段里了。
INIT:000000000029E1C4 00 00 00 00                       dd 0                    ; Time stamp
INIT:000000000029E1C8 00 00 00 00                       dd 0                    ; Forwarder Chain
INIT:000000000029E1CC 68 F6 29 00                       dd rva aNtoskrnlExe     ; DLL Name
INIT:000000000029E1D0 A0 A6 17 00                       dd rva IoGetAttachedDeviceReference ; Import Address Table
    */
    rebuild_iid->TimeDateStamp = 0x11111111;
    rebuild_iid->Name = 0x2d4000+100;
    rebuild_iid->OriginalFirstThunk = 0x2d4000 + 500;   //4085个函数，每个占8字节，大概32680字节  下一个位置应该是0x3559c
    rebuild_iid->FirstThunk = 0x187000;
    memcpy((char*)rebuild_iid+100, ntoskrnl_name, 13);
    
    ULONG64* OriginalFirstThunk = (ULONG64*)((char*)rebuild_iid + 500); //这里是一堆rva，每个rva都是一个image_import_by_name    偏移500处构造rva
    IMAGE_IMPORT_BY_NAME2* Oriiibn = (IMAGE_IMPORT_BY_NAME2*)((char*)rebuild_iid + 0x40000);  //在这构造每个iidb    函数名字给50个字节就行 偏移0x40000构造
    for (int i = 0; i < 4085; i++) {
        OriginalFirstThunk[i] = i * sizeof(IMAGE_IMPORT_BY_NAME2) + 0x2d4000 + 0x40000;
    }

    rebuild_iid[1].TimeDateStamp = 0x22222222;
    rebuild_iid[1].Name = 0x2d4000 + 200;
    memcpy((char*)rebuild_iid + 200, haldll_name, 8);

    rebuild_iid[2].TimeDateStamp = 0x33333333;
    rebuild_iid[2].Name = 0x2d4000 + 300;
    memcpy((char*)rebuild_iid + 300, fltmgr_name, 11);

    rebuild_iid[3].TimeDateStamp = 0x44444444;
    rebuild_iid[3].Name = 0x2d4000 + 400;
    memcpy((char*)rebuild_iid + 400, Ci_name, 7);

    irql = WPOFF();

    idd_import->VirtualAddress = 0x2d4000;      //调整新的iid结构的指针
    idd_import->Size = 5 * sizeof(IMAGE_IMPORT_DESCRIPTOR);
    MemoryCsAgent.get_nt_headers()->OptionalHeader.SizeOfImage += 0x20000;
    WPON(irql);

    //需要构造OriginalFirstThunk和FirstThunk
    

    
    //pe64 ntpe(NtBase);
    //pe64 halpe(HalBase);
    //pe64 fltmgrpe(FltBase);
    //pe64 Cipe(CiBase);
    

    //




    int count = 0;
    //char*和unsigned char*  用char作比较的时候要用unsigned char*
    for (ULONG64* start = (ULONG64*)0xFFFFF80016277000; start <= (ULONG64*)0xfffff80016278400; start++) {
        //搜0x48 0xff 0x15   导入表调用

        //if (!MmIsAddressValid(start))
            //continue;

        //if ((start[0] == 0x48) && (start[1] == 0xff) && (start[2] == 0x15)) //找到导入表调用         自己这样搜还一堆重复的，不好搞
        {
            bool find = false;

            ULONG64 IAT_ADDRESS = (ULONG64)start;

            if (MmIsAddressValid((PVOID)IAT_ADDRESS)) {
                ULONG64 TargetFunction = *(ULONG64*)IAT_ADDRESS;
                print("[+]import call pc : %p IAT ADDRESS : %p TargetAddress : %p", start,IAT_ADDRESS, TargetFunction);

                //现在就需要知道这个目标函数地址是哪个模块的,并且叫什么名字
                
                for (auto &addr : nt_symbol) {
                    if (TargetFunction == addr.absAddress) {
                        print(" TargetFunctionName : %s", addr.symbol_name);
                        Oriiibn[count].Hint = 0;
                        memcpy(Oriiibn[count].Name, addr.symbol_name,strlen(addr.symbol_name));
                        
                        find = true;        //是否找到对应模块
                    }
                }


                //
                if (!find)   //没有找到
                {

                    for (auto &addr : fltmgr_symbol) {
                        if (TargetFunction == addr.absAddress) {
                            print(" TargetFunctionName : %s", addr.symbol_name);
                            Oriiibn[count].Hint = 0;
                            memcpy(Oriiibn[count].Name, addr.symbol_name, strlen(addr.symbol_name));

                            find = true;        //是否找到对应模块
                        }
                    }
                }

                if (!find) {
                    for (auto& addr : ci_symbol) {
                        if (TargetFunction == addr.absAddress) {
                            print(" TargetFunctionName : %s", addr.symbol_name);
                            Oriiibn[count].Hint = 0;
                            memcpy(Oriiibn[count].Name, addr.symbol_name, strlen(addr.symbol_name));

                            find = true;        //是否找到对应模块
                        }
                    }
                }

                if (!find) {

                }

                count++;












                print("\n");
            }


        }
    }
    print("nt kernel import function count : %d\n",count);


    //ZwWriteFile(hdump, NULL, NULL, NULL, &IoStatus, RawCsAgent.get_dos_headers(), 0x1000, NULL, NULL);
    for (char* start = (char*)MemoryCsAgent.get_dos_headers(); start <= ((char*)MemoryCsAgent.get_dos_headers() + SizeOfImage.QuadPart); start += 0x1000) {
        if (MmIsAddressValid(start))
            ZwWriteFile(hdump, NULL, NULL, NULL, &IoStatus, start, 0x1000, NULL, NULL);
        else
            ZwWriteFile(hdump, NULL, NULL, NULL, &IoStatus, zero, 0x1000, NULL, NULL);  //invalid用0填充
    }

    LARGE_INTEGER offset{ 0x2d4000 };
    Status = ZwWriteFile(hdump, NULL, NULL, NULL, &IoStatus, rebuild_iid, 0x200000, &offset, NULL);  //文件最后写入IID结构
    if (!NT_SUCCESS(Status))
        print("[-]ZwWriteFile failed with %x\n", Status);


    //修复完之后直接创建文件  append data









    ZwClose(hdump);
    ZwClose(hFile);
    RtlFreeUnicodeString(&usCurrentUserKey);
    ExFreePool(FileBuffer);
    ExFreePool(Info);
    return;
}