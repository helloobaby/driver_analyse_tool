/*++
    dependencies : no
    
--*/

#pragma once

#include<ntifs.h>
#include<ntddk.h>
#include<wdm.h>

#define INTERNAL		//��Ҫ�Լ��������ֺ���
#define HARDCODE_OFFSET	//ϵͳ��ص�ƫ��(Ӳ����)

extern "C" {
    void* RtlFindExportedRoutineByName(void*, const char*);         //win10֮����еĵ�������
}



template<typename... types>
__inline void print(types... args)
{
	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, args...);
}

template <typename T>
using travelFuncType = T (*)(PLIST_ENTRY ListEntry);

template <typename T>
T travelsee_list(PLIST_ENTRY ListHead, travelFuncType<T> Function) {
    for (PLIST_ENTRY pListEntry = ListHead->Flink; pListEntry != ListHead; pListEntry = pListEntry->Flink)
    {
        T result = Function(pListEntry);

        if(result != 0)
            return result;
    }
}



inline PVOID GetDriverExportRoutine(void* DriverBase,const char* FunctionName) {
    return RtlFindExportedRoutineByName(DriverBase, FunctionName);
}