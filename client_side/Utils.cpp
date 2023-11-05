#include "Utils.h"


std::vector<uint8_t> Utils::pad(std::string byte_string, int block_size) {
	std::vector<uint8_t> byte_vector(byte_string.begin(), byte_string.end());
	byte_vector.resize(block_size, '\0');
	return byte_vector;
}

std::string Utils::bytes_to_hex(const std::string& bytes) {
	std::string hex;
	for (char byte : bytes) {
		hex += "0123456789ABCDEF"[((byte & 0xF0) >> 4)];
		hex += "0123456789ABCDEF"[((byte & 0x0F) >> 0)];
	}
	return hex;
}

std::string Utils::hex_to_bytes(const std::string& hex) {
	std::string bytes;
	for (unsigned int i = 0; i < hex.length(); i += 2) {
		std::string byteString = hex.substr(i, 2);
		char byte = (char)strtol(byteString.c_str(), NULL, 16);
		bytes += byte;
	}
	return bytes;
}
