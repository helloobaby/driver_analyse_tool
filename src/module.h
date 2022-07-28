/*++
	dependencies : slist.h
				   utils.h
				   util_stru.hh

--*/

#pragma once
#pragma warning (disable : 4201)
#include<ntifs.h>
#include<ntddk.h>
#include<wdm.h>

#include "slist.h"
#include "utils.h"
#include "util_stru.hh"

#define INTERNAL		//��Ҫ�Լ��������ֺ���
#define HARDCODE_OFFSET	//ϵͳ��ص�ƫ��(Ӳ����)

extern "C" {
	extern LIST_ENTRY PsLoadedModuleList;
	extern ERESOURCE PsLoadedModuleResource;
}

typedef struct _KLDR_DATA_TABLE_ENTRY
{
	union {
		struct _LIST_ENTRY InLoadOrderLinks;	HARDCODE_OFFSET
		struct {
			make_offset(0x30);
			void* DllBase;
		};
		struct
		{
			make_offset(0x58);
			struct _UNICODE_STRING BaseDllName; HARDCODE_OFFSET
		};
	};
}KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;


template <typename T>
using travelFuncType = T(*)(PLIST_ENTRY ListEntry);

class kmodule {
public:

	//
	//ͨ������PsLoadedModuleList����ں�ģ��Ļ���ַ
	//
	template<typename T>
	static T get_module(travelFuncType<T> Function);








private:




};