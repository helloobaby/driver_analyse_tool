#ifdef _X86_
#error not support x86
#endif

#include<ntifs.h>
#include<ntddk.h>
#include<wdm.h>

#include"utils.h"

void user_main(PDRIVER_OBJECT drv, PUNICODE_STRING reg);
extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING reg) {



	user_main(drv,reg);




	print("[+]driver load...\n");
	return STATUS_SUCCESS;
}