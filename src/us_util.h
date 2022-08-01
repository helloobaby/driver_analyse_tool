/*++

	unicode string utility
	
	dependencies : no

--*/

#pragma once
#include<ntifs.h>
#include<ntddk.h>
#include<wdm.h>


inline void RtlDowncaseUnicodeArray(WCHAR* p)
{
	if (!p)
		return;

	int i = 0;
	while (p[i]) {
		p[i] = RtlDowncaseUnicodeChar(p[i]);
		i++;
	}

	return;
}

//
// @sub�ַ��������Կ��ַ���β
// @src�����ǺϷ���unicodestring
// @�����Ӵ��Ļ�����true
//
bool RtlFindSubUnicodeString(const WCHAR* sub, PCUNICODE_STRING src);
bool RtlFindSubUnicodeStringWithNoCase(const WCHAR* sub, const PCUNICODE_STRING src);