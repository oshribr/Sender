#pragma once
#include <stdio.h>
#include <string.h>
#include <string>
#include <iostream>

class Cmd
{
private:
	int number_section; 
	int* numbers_sections;
	wchar_t* file_pe_path;
	char* key_path; 
public:
	Cmd(int argc, char* argv[]);
	~Cmd();
	int get_number_section(); 
	int get_number_section_by_index(int index); 
	wchar_t* get_file_pe_path();
	char* get_key_path(); 
	static void help(); 
};

