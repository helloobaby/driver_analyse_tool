/*++
其他的文件不用动,只把自己的代码放到user_main函数里就行,DriverEntry中会调用
--*/

#include<ntifs.h>
#include<ntddk.h>
#include<wdm.h>

#include"utils.h"
#include "module.h"


void unload(PDRIVER_OBJECT drv) {
    UNREFERENCED_PARAMETER(drv);
    print("[+]driver unload...\n");
    return;
}

PVOID isCsAgentModule(PLIST_ENTRY ListEntry) {

    static UNICODE_STRING CsAgent = RTL_CONSTANT_STRING(L"csagent.sys");
    PKLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(ListEntry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

    if (!RtlCompareUnicodeString(&CsAgent, &pEntry->BaseDllName, true)) {
        return pEntry->DllBase;
    }

    return false;
}


void user_main(PDRIVER_OBJECT drv, PUNICODE_STRING reg) {
    UNREFERENCED_PARAMETER(drv);
    UNREFERENCED_PARAMETER(reg);

    static PVOID CsAgentBase = kmodule::get_module<PVOID>(isCsAgentModule);

    print("[+]CsAgentBase : %p\n",CsAgentBase);





}