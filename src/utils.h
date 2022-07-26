#pragma once

#include<ntifs.h>
#include<ntddk.h>
#include<wdm.h>

template<typename... types>
__inline void print(types... args)
{
	DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, args...);
}
