#include "Crypto.h"	
#include "PEModifier.h"
#include "Cmd.h"
using namespace std; 

int main(int argc, char* argv[])
{
	Cmd* cmd = new Cmd(argc,argv); 
	char section_name[] = "RSA"; //name of new section

	PEModifier* myPE = new PEModifier();
	pfile_info file = new file_info(); //create a new pointer to file_info
	bool map = myPE->map_file(cmd->get_file_pe_path(), 4096, true, file);  //map the pe file. This will put into the pfile_info the file information
	if (!map)
	{
		printf_s("Can't mapping the exe file\n"); 
		return 1; 
	}
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)file->file_mem_buffer;  //first section is a PIMAGE_DOS_HEADER
	PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)((DWORD_PTR)dos_header + dos_header->e_lfanew); //The last field in PIMAGE_NT_HEADERS is an offset to the PIMAGE_NT_HEADERS
	SECTION *mySection = new SECTION;
	mySection->amount_of_signed_sections = cmd->get_number_section();
	mySection->my_section_data = new section_data[cmd->get_number_section()];

	PIMAGE_SECTION_HEADER mySec;

	for (int i = 0; i < cmd->get_number_section(); i++)
	{
		int section_number_to_handle = cmd->get_number_section_by_index(i); 
		mySection->my_section_data[i].section_number = section_number_to_handle;
		mySection->my_section_data[i].size = MES_LEN;
		mySec = IMAGE_FIRST_SECTION(nt_header) + (section_number_to_handle);
		long section_size = mySec->SizeOfRawData;
		char* sign = sing((unsigned char *)myPE->get_section(section_number_to_handle, dos_header), section_size,cmd->get_key_path());
		mySection->my_section_data[i].RSA = new char[mySection->my_section_data[i].size];
		memcpy(mySection->my_section_data[i].RSA, sign, mySection->my_section_data[i].size);
	}
	printf("Number of section: %d\n", nt_header->FileHeader.NumberOfSections);
	PIMAGE_SECTION_HEADER new_section = myPE->add_section(section_name, nt_header->OptionalHeader.SectionAlignment, dos_header);
	printf("Number of section: %d\n", nt_header->FileHeader.NumberOfSections);
	myPE->set_section(new_section, dos_header, mySection);
	system("pause"); 
}