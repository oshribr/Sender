#pragma once
#include <iostream>
#include <fstream>
#ifndef __wtypes_h__
#include <wtypes.h>
#endif
#ifndef __WINDEF_
#include <windef.h>
#endif


typedef struct {
	int section_number;
	int size;
	char* RSA;
} section_data;

typedef struct {
	int amount_of_signed_sections;
	section_data * my_section_data;
} SECTION;

//file_info repesents a file
typedef struct {
	void *file_handle;
	void *file_map_handle;
	unsigned char *file_mem_buffer;
} file_info, *pfile_info;

class PEModifier
{
public:



	PEModifier(void);
	~PEModifier(void);
	inline unsigned int align_to_boundary(unsigned int address, unsigned int boundary);
	bool map_file(const wchar_t *file_name, unsigned int stub_size, bool append_mode, pfile_info mapped_file_info);
	PIMAGE_SECTION_HEADER add_section(const char *section_name, unsigned int section_size, void *image_addr);
	void set_section(PIMAGE_SECTION_HEADER section, void *image_addr, void *mySection);
	SECTION * get_last_section(void* dos_header);
	void change_file_oep(PIMAGE_NT_HEADERS nt_headers, PIMAGE_SECTION_HEADER section);
	bool delete_last_section(void *image_addr);
	char * get_section(int section_number, void *image_addr);


};
