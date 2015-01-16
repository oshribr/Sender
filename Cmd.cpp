#include "Cmd.h"
#include "Crypto.h"
using namespace std; 

Cmd::Cmd(int argc, char* argv[])
{
	if ((4 > argc) || ((strcmp(argv[1], "-help") == 0)))
		help(); 
	this->file_pe_path = new wchar_t[strlen(argv[1]) + 1]; 
	mbstowcs(this->file_pe_path, argv[1], strlen(argv[1]) + 1); 
	if (strcmp(argv[2], "newKey")) // the strcmp function return 0 if the string equal
		this->key_path = argv[2]; 
	else
	{
		gen_key(); 
		this->key_path = "our-key.pem"; 
	}

	this->number_section = argc - 3; 
	this->numbers_sections = new int[this->number_section]; 
	int a = 3; 
	for (int n = 0; n < this->number_section; n++, a++)
	{
		try{ 
			this->numbers_sections[n] = stoi(argv[a]); 
		}
		catch (exception e)
		{
			printf("Error %s\n", e.what()); 
			help(); 
		}
	}
}


Cmd::~Cmd()
{
}

int Cmd::get_number_section()
{
	return this->number_section; 
}

int Cmd::get_number_section_by_index(int index)
{
	return this->numbers_sections[index]; 
}

wchar_t* Cmd::get_file_pe_path()
{
	return this->file_pe_path; 
}

char* Cmd::get_key_path()
{
	return this->key_path; 
}
void Cmd::help()
{
	printf_s("\n%s\n%s\n%s\n%s\n",
		"To help -- -help", 
		"The 1st arg must be exe file", 
		"The 2nd arg is the key path to new key write newKey", 
		"From the 3th arg numbers of section to encryptoin");
	system("pause"); 
	exit(1); 
}
