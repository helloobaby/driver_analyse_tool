/*++
	dependencies : utils.h

--*/

#pragma once
#include<ntifs.h>
#include<ntddk.h>
#include<wdm.h>
#include<ntimage.h>

#include "utils.h"

extern "C" __declspec(dllimport)
PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(
	PVOID Base);

class pe64
{
public:
	pe64(PVOID ImageBase);

	bool check_image();

	IMAGE_DOS_HEADER* get_dos_headers();
	void print_dos_headers();

	IMAGE_NT_HEADERS* get_nt_headers();
	void print_nt_headers();

	IMAGE_SECTION_HEADER* get_section(const char* section_name);
	void print_sections();

	//根据PE头中存储的内容dump把驱动dump下来,内存中的PE头很多时候都是不可靠的。
	//就算定位磁盘中的PE头,如果原来驱动有壳,磁盘中的PE头也不可靠。
	bool dump_driver_relay_pe_header();

	bool dump_driver_relay_page_attibute();








private:
	PVOID _image_base;
};
