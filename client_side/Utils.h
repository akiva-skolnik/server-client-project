#pragma once
#include <string>
#include <vector>


class Utils {
public:
	static std::vector<uint8_t> pad(std::string byte_string, int block_size);
	static std::string bytes_to_hex(const std::string& bytes);
	static std::string hex_to_bytes(const std::string& hex);
};

