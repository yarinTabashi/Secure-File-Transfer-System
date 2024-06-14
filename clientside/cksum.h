#include <iostream>
#include <fstream>
#include <ostream>
#include <cstdio>
#include <vector>
#include <iterator>
#include <filesystem>
#include <string>

class CKsum
{
public:
	static unsigned long get_crc(std::filesystem::path);
};