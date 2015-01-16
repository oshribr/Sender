#include "PEModifier.h"
#include <iostream>
using namespace std;

PEModifier::PEModifier(void)
{
}


PEModifier::~PEModifier(void)
{
}

inline unsigned int PEModifier::align_to_boundary(unsigned int address, unsigned int boundary) {
	return (((address + boundary - 1) / boundary) * boundary);
}

//map a PE file to a file_info
//append mode - this file is being modified. and added stub_size bytes
bool PEModifier::map_file(const wchar_t *file_name, unsigned int stub_size, bool append_mode, pfile_info mapped_file_info) {
	//try to open file_name to read and write, 0 prevents other proccesses to read , write or delete while opened,
	//NUll - the handle returned by CreateFile cannot be inherited by any child processes the application may create
	//and the file or device associated with the returned handle gets a default security descriptor.
	//OPEN_EXISTING - Opens a file or device, only if it exists.
	//FILE_ATTRIBUTE_NORMAL - The file does not have other attributes set.
	//NULL - When opening an existing file, function ignores this
	//returns handle to file on succsess.
	void *file_handle = CreateFileW(file_name, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file_handle == INVALID_HANDLE_VALUE) {
		wprintf(L"Could not open %s", file_name);
		return false;
	}
	unsigned int file_size = GetFileSize(file_handle, NULL);  //get file size 
	if (file_size == INVALID_FILE_SIZE) {  //function fails
		wprintf(L"Could not get file size for %s", file_name);
		return false;
	}
	//would like to modify file.
	if (append_mode == true) {
		file_size += (stub_size + sizeof(DWORD_PTR));
	}
	//If this function succeeds, the return value is a handle to the newly created file mapping object
	//NULL - the handle cannot be inherited.
	//PAGE_READWRITE - Allows views to be mapped for read-only, copy-on-write, or read/write access.
	//NULL - the file mapping object is created without a name.
	void *file_map_handle = CreateFileMapping(file_handle, NULL, PAGE_READWRITE, 0,
		file_size, NULL);
	if (file_map_handle == NULL) {
		wprintf(L"File map could not be opened");
		CloseHandle(file_handle);
		return false;
	}
	//Maps a view of a file mapping into the address space of a calling process.
	void *file_mem_buffer = MapViewOfFile(file_map_handle, FILE_MAP_WRITE | FILE_MAP_READ, 0, 0, file_size);
	if (file_mem_buffer == NULL) {
		wprintf(L"Could not map view of file");
		CloseHandle(file_map_handle);
		CloseHandle(file_handle);
		return false;
	}
	//insert fileds into our struct.
	mapped_file_info->file_handle = file_handle;
	mapped_file_info->file_map_handle = file_map_handle;
	mapped_file_info->file_mem_buffer = (unsigned char*)file_mem_buffer;
	return true;
}

//Reference: http://www.codeproject.com/KB/system/inject2exe.aspx
//Add a section to the PE file, receive new section name, size and the file PIMAGE_DOS_HEADER.
PIMAGE_SECTION_HEADER PEModifier::add_section(const char *section_name, unsigned int section_size, void *image_addr)
{
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)image_addr;
	if (dos_header->e_magic != 0x5A4D) {           //check if this is a Dos Header
		wprintf(L"Could not retrieve DOS header from %p", image_addr);
		return NULL;
	}
	PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)((DWORD_PTR)dos_header + dos_header->e_lfanew);
	if (nt_header->OptionalHeader.Magic != 0x010B) {  //try to retrieve the NT Header (PE header)
		wprintf(L"Could not retrieve NT header from %p", dos_header);
		return NULL;
	}
	const int name_max_length = 8;  //not to overflow
	PIMAGE_SECTION_HEADER last_section = IMAGE_FIRST_SECTION(nt_header) + (nt_header->FileHeader.NumberOfSections - 1);  //Gets a pointer to the last section
	PIMAGE_SECTION_HEADER new_section = IMAGE_FIRST_SECTION(nt_header) + (nt_header->FileHeader.NumberOfSections);  //gets a pointe to the place of the new section
	memset(new_section, 0, sizeof(IMAGE_SECTION_HEADER));  //sets all of new structure to zeros
	new_section->Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_WRITE; //section is readable,exectable and contains code
	memcpy(new_section->Name, section_name, name_max_length);  //copy section name.
	new_section->Misc.VirtualSize = section_size;  //copy section size
	//get the proper peremeteres
	new_section->PointerToRawData = align_to_boundary(last_section->PointerToRawData + last_section->SizeOfRawData,
		nt_header->OptionalHeader.FileAlignment);
	new_section->SizeOfRawData = align_to_boundary(section_size, nt_header->OptionalHeader.SectionAlignment);
	new_section->VirtualAddress = align_to_boundary(last_section->VirtualAddress + last_section->Misc.VirtualSize,
		nt_header->OptionalHeader.SectionAlignment);
	nt_header->OptionalHeader.SizeOfImage = new_section->VirtualAddress + new_section->Misc.VirtualSize;
	nt_header->FileHeader.NumberOfSections++;
	return new_section;
}

void PEModifier::set_section(PIMAGE_SECTION_HEADER section, void *image_addr, void *mySection) {
	int counter = 4;
	SECTION * mySec = (SECTION *)mySection;
	memcpy(((unsigned char *)image_addr + section->PointerToRawData), mySec, 4);  //amount of sections
	for (int i = 0; i <mySec->amount_of_signed_sections; i++)
	{
		memcpy(((unsigned char *)image_addr + section->PointerToRawData + counter), &(mySec->my_section_data[i].section_number), 4);
		counter += 4;
		memcpy(((unsigned char *)image_addr + section->PointerToRawData + counter), &(mySec->my_section_data[i].size), 4);
		counter += 4;
		memcpy(((unsigned char *)image_addr + section->PointerToRawData + counter), (mySec->my_section_data[i].RSA), mySec->my_section_data->size);
		counter += mySec->my_section_data->size;
	}

}

SECTION * PEModifier::get_last_section(void * image_addr)
{
	SECTION * sec = new SECTION;
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)image_addr;
	PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)((DWORD_PTR)image_addr + dos_header->e_lfanew);
	PIMAGE_SECTION_HEADER mySection = IMAGE_FIRST_SECTION(nt_header) + (nt_header->FileHeader.NumberOfSections - 1);
	int ptr = (int)image_addr + mySection->PointerToRawData;
	int * ptr2 = (int *)ptr;
	sec->amount_of_signed_sections = *ptr2;
	sec->my_section_data = new section_data[sec->amount_of_signed_sections];
	ptr2++;
	for (int i = 0; i < sec->amount_of_signed_sections; i++)
	{
		sec->my_section_data[i].section_number = *ptr2;
		ptr2++;
		sec->my_section_data[i].size = *ptr2;
		ptr2++;
		sec->my_section_data[i].RSA = new char[sec->my_section_data[i].size];
		memcpy(sec->my_section_data[i].RSA, (char*)ptr2, sec->my_section_data[i].size);
		ptr = (int)ptr2;
		ptr += sec->my_section_data[i].size;
		ptr2 = (int *)ptr;
	}

	return sec;

}

char * PEModifier::get_section(int section_number, void *image_addr)
{
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)image_addr;
	PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)((DWORD_PTR)image_addr + dos_header->e_lfanew);
	PIMAGE_SECTION_HEADER mySection = IMAGE_FIRST_SECTION(nt_header) + (section_number);
	if (section_number == 0)
	{
		PIMAGE_SECTION_HEADER mySection1 = IMAGE_FIRST_SECTION(nt_header) + (1);
		mySection->SizeOfRawData = mySection1->PointerToRawData;
	}
	char * sec = new char[mySection->SizeOfRawData];
	int temp = (int)image_addr + mySection->PointerToRawData;
	int * temp2 = (int *)temp;
	memcpy(sec, (char *)temp2, mySection->SizeOfRawData);
	return sec;

}

void PEModifier::change_file_oep(PIMAGE_NT_HEADERS nt_headers, PIMAGE_SECTION_HEADER section) {
	unsigned int file_address = section->PointerToRawData;
	PIMAGE_SECTION_HEADER current_section = IMAGE_FIRST_SECTION(nt_headers);
	for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i)
	{
		if (file_address >= current_section->PointerToRawData && file_address < (current_section->PointerToRawData + current_section->SizeOfRawData))
		{
			file_address -= current_section->PointerToRawData;
			file_address += (nt_headers->OptionalHeader.ImageBase +
				current_section->VirtualAddress);
			break;
		}
		++current_section;
	}
	nt_headers->OptionalHeader.AddressOfEntryPoint = file_address - nt_headers->OptionalHeader.ImageBase;
}

bool PEModifier::delete_last_section(void *image_addr)
{
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)image_addr;
	if (dos_header->e_magic != 0x5A4D) {
		wprintf(L"Could not retrieve DOS header from %p", image_addr);
		return false;
	}
	PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((DWORD_PTR)dos_header + dos_header->e_lfanew);
	if (nt_headers->OptionalHeader.Magic != 0x010B) {
		wprintf(L"Could not retrieve NT header from %p", dos_header);
		return false;
	}
	PIMAGE_SECTION_HEADER last_section = IMAGE_FIRST_SECTION(nt_headers) + (nt_headers->FileHeader.NumberOfSections - 1);
	nt_headers->OptionalHeader.SizeOfImage -= last_section->Misc.VirtualSize;
	//	memset(last_section, 0, sizeof(IMAGE_SECTION_HEADER));
	nt_headers->FileHeader.NumberOfSections--;
	return true;
}