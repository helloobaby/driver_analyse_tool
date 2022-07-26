#ifdef _X86_
#error not support x86
#endif

#include<ntifs.h>
#include<ntddk.h>
#include<wdm.h>

#include"utils.h"

void user_main(PDRIVER_OBJECT drv, PUNICODE_STRING reg);

void unload(PDRIVER_OBJECT drv) {
	print("[+]driver unload...\n");
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING reg) {

	print("[+]driver load...\n");
	drv->DriverUnload = unload;
	user_main(drv,reg);
	return STATUS_SUCCESS;
}