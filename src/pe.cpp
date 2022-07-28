#include "pe.h"

pe64::pe64(PVOID ImageBase) {
	this->_image_base = ImageBase;
}

bool pe64::check_image() {
	return MmIsAddressValid(this->_image_base);
}

IMAGE_NT_HEADERS* pe64::get_nt_headers()
{
	return RtlImageNtHeader(this->_image_base);
}

IMAGE_DOS_HEADER* pe64::get_dos_headers() {
	
	return (IMAGE_DOS_HEADER*)this->_image_base;
}

IMAGE_SECTION_HEADER* pe64::get_section(const char* section_name) {

	USHORT section_count = get_nt_headers()->FileHeader.NumberOfSections;
	IMAGE_SECTION_HEADER* section_header = IMAGE_FIRST_SECTION(get_nt_headers());
	for (int i = 0; i < section_count; i++) {
		if (!section_name) {
			print("[+]Name : %s\n", section_header[i].Name);
			print("[+]VirtualSize : 0x%x\n", section_header[i].Misc.VirtualSize);
			print("[+]VirtualAddress : 0x%x\n", section_header[i].VirtualAddress);
			print("[+]PointerToRawData : 0x%x\n", section_header[i].PointerToRawData);
			print("[+]SizeOfRawData : 0x%x\n", section_header[i].SizeOfRawData);
			print("[+]Characteristics : 0x%x\n", section_header[i].Characteristics);
		}
		else {
			if (!strcmp(section_name, (const char*)section_header[i].Name)) {
				return section_header;
			}
		}
	}
	return nullptr;
}

void pe64::print_dos_headers() {
	auto dos = get_dos_headers();
	print("[+]e_magic : 0x%x\n", dos->e_magic);
	print("[+]e_lfanew : %u\n", dos->e_lfanew);
	print("[+]dos header end...\n");
}

void pe64::print_nt_headers() {
	auto nt = get_nt_headers();
	print("[+]Signature : 0x%x\n", nt->Signature);
	print("[+]NumberOfSections : %d\n", nt->FileHeader.NumberOfSections);
	print("[+]SizeOfOptionalHeader : %d\n", nt->FileHeader.SizeOfOptionalHeader);
	print("[+]Magic : 0x%x\n", nt->OptionalHeader.Magic);
	print("[+]AddressOfEntryPoint : 0x%x\n", nt->OptionalHeader.AddressOfEntryPoint);
	print("[+]ImageBase : 0x%x\n", nt->OptionalHeader.ImageBase);
	print("[+]SectionAlignment : 0x%x\n", nt->OptionalHeader.SectionAlignment);
	print("[+]FileAlignment : 0x%x\n", nt->OptionalHeader.FileAlignment);
	print("[+]SizeOfImage : 0x%x\n", nt->OptionalHeader.SizeOfImage);
	print("[+]SizeOfHeaders : 0x%x\n", nt->OptionalHeader.SizeOfHeaders);
	print("[+]CheckSum : 0x%x\n", nt->OptionalHeader.CheckSum);
	print("[+]nt header end...\n");
}

void pe64::print_sections() {
	get_section(nullptr);
}