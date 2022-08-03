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

	//����PEͷ�д洢������dump������dump����,�ڴ��е�PEͷ�ܶ�ʱ���ǲ��ɿ��ġ�
	//���㶨λ�����е�PEͷ,���ԭ�������п�,�����е�PEͷҲ���ɿ���
	bool dump_driver_relay_pe_header();

	bool dump_driver_relay_page_attibute();








private:
	PVOID _image_base;
};
