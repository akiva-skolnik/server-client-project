#include <fstream>
#include <iostream>
#include <array>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <filesystem>
#include <string>
#include <vector>

#include <boost/asio.hpp>

#include "AESWrapper.h"
#include "Base64Wrapper.h"
#include "RSAWrapper.h"
#include "crc32.h"
#include "Utils.h"


// Constants and Enums
const uint8_t CLIENT_VERSION = 3;
const std::string ME_INFO_FILE = "me.info";
const std::string TRANSFER_INFO_FILE = "transfer.info";
const std::string KEY_FILE = "key.priv";
const int MAX_RETRIES = 3;

enum FieldSize : uint8_t {  // in bytes 
	CLIENT_ID = 16,
	CLIENT_NAME = 255,
	FILE_NAME = 255,
	PATH_NAME = 255,
	VERSION = 1,
	CODE = 2,
	PAYLOAD = 4,
	FILE_SIZE = 4,
	AES_KEY = 16,
	PUBLIC_KEY = 160,
	CRC = 4
};

enum RequestCode : uint16_t {
	REGISTER = 1025,
	PUBLIC_KEY_REQUEST = 1026,
	LOGIN = 1027,
	RECEIVE_FILE = 1028,
	CRC_VALID = 1029,
	CRC_RETRY = 1030,
	CRC_FAILURE = 1031
};

enum ResponseCode : uint16_t {
	REGISTRATION_SUCCESS = 2100,
	REGISTRATION_FAILURE = 2101,
	AES_KEY_SENT = 2102,
	FILE_RECEIVED = 2103,
	MESSAGE_RECEIVED = 2104,
	LOGIN_SUCCESS = 2105,
	LOGIN_FAILURE = 2106,
	GENERAL_ERROR = 2107
};

// Client class
class Client {
private:
	// Data members
	std::string client_name;
	std::string client_id;
	std::string file_to_send;
	boost::asio::io_service io_service;
	boost::asio::ip::tcp::socket socket;
	boost::asio::ip::tcp::endpoint server_endpoint;
	std::vector<uint8_t> encrypted_aes_key;  // encrypted for security reasons

	// Methods

	void register_client() {
		/* Send request code 1025 (register) with padded client name as payload.
		* After registration, send request code 1026 (public key request).
		* The server should send in respond the client id + AES key encrypted with the public key.
		* The client should decrypt the AES key with its private key and save it.
		*/
		std::cout << "Registering client..." << std::endl;

		if (client_name.empty()) {
			throw std::runtime_error("Client name not found.");
		}
		std::vector<uint8_t> register_payload = Utils::pad(client_name, FieldSize::CLIENT_NAME);
		send_request(RequestCode::REGISTER, register_payload);
		int response_code;
		std::vector<uint8_t> payload;
		std::tie(response_code, payload) = receive_response();
		if (response_code == ResponseCode::REGISTRATION_SUCCESS) {
			if (payload.size() != FieldSize::CLIENT_ID) {
				throw std::runtime_error("Client ID size mismatch.");
			}
			client_id.assign(payload.begin(), payload.end());
			std::cout << "Registration successful." << std::endl << std::endl;

			// Generate RSA key pair and save the private key
			std::cout << "Generating RSA key pair and requesting AES key..." << std::endl;
			std::string public_key = generate_rsa_pair();
			save_me_info();
			send_aes_key_request(client_name, public_key);
			receive_and_save_aes_key();
		}
		else if (response_code == ResponseCode::REGISTRATION_FAILURE) {
			throw std::runtime_error("Registration failed.");
		}
		else {
			throw std::runtime_error("Unexpected response code.");
		}

	}

	void login() {
		load_me_info();
		std::cout << "Logging in..." << std::endl;
		std::vector<uint8_t> payload = Utils::pad(client_name, FieldSize::CLIENT_NAME);
		send_request(RequestCode::LOGIN, payload);
		int response_code;
		std::vector<uint8_t> response_payload;
		std::tie(response_code, response_payload) = receive_response();
		if (response_code == ResponseCode::LOGIN_SUCCESS) {
			client_id.assign(response_payload.begin(), response_payload.begin() + FieldSize::CLIENT_ID);
			encrypted_aes_key.assign(response_payload.begin() + FieldSize::CLIENT_ID, response_payload.end());

			verify_client_id(client_id);
			std::cout << "Login successful." << std::endl << std::endl;
		}
		else if (response_code == ResponseCode::LOGIN_FAILURE) {
			std::cout << "Login failed, registering..." << std::endl << std::endl;
			register_client();
		}
		else {
			throw std::runtime_error("Unexpected response code.");
		}
	}

	void send_aes_key_request(const std::string& client_name, const std::string& public_key) {
		/* send PUBLIC_KEY_REQUEST with padded client name(255 bytes) and public key(160 bytes) as payload */
		std::cout << "Sending AES key request..." << std::endl;
		std::vector<uint8_t> public_key_payload = Utils::pad(client_name, FieldSize::CLIENT_NAME);
		std::vector<uint8_t> padded_public_key = Utils::pad(public_key, FieldSize::PUBLIC_KEY);
		public_key_payload.insert(public_key_payload.end(), padded_public_key.begin(), padded_public_key.end());
		send_request(RequestCode::PUBLIC_KEY_REQUEST, public_key_payload);
		std::cout << "Done sending AES key request." << std::endl << std::endl;
	}

	void receive_and_save_aes_key() {
		/* Handle response code 2102 (AES key sent).
		* Payload format: CLIENT_ID(16 bytes) + AES_KEY(the rest)
		* Save the decrypted AES key.
		*/
		std::cout << "Receiving AES key..." << std::endl;
		int response_code;
		std::vector<uint8_t> payload;
		std::tie(response_code, payload) = receive_response();
		if (response_code == ResponseCode::AES_KEY_SENT) {
			try {
				std::string received_client_id(payload.begin(), payload.begin() + FieldSize::CLIENT_ID);
				verify_client_id(received_client_id);
				encrypted_aes_key.assign(payload.begin() + FieldSize::CLIENT_ID, payload.end());
				std::cout << "Done receiving AES key." << std::endl << std::endl;
			}
			catch (...) {
				throw std::runtime_error("Error reading AES key.");
			}
		}
		else if (response_code == ResponseCode::LOGIN_FAILURE) {
			std::cout << "Cannot get AES key because the server doesn't recognize this client, registering..." << std::endl << std::endl;
			register_client(); // it won't try to receive the AES key again, to prevent infinit loop
		}
		else {
			throw std::runtime_error("Unexpected response code.");
		}
	}

	std::vector<uint8_t> decrypt_aes_key(const std::vector<uint8_t>& encrypted_key) {
		// Decrypt the AES key with the private key.
		std::cout << "Starting decrypting AES key..." << std::endl;
		std::string private_key = get_private_key();
		RSAPrivateWrapper rsaPrivateWrapper(private_key.data(), static_cast<unsigned int>(private_key.size()));
		std::string decrypted_key_str = rsaPrivateWrapper.decrypt(
			reinterpret_cast<const char*>(encrypted_key.data()), static_cast<unsigned int>(encrypted_key.size()));
		std::cout << "Done decrypting AES key." << std::endl;
		return std::vector<uint8_t>(decrypted_key_str.begin(), decrypted_key_str.end());
	}

	void send_request(int code, const std::vector<uint8_t>& payload) {
		// Each request consists of: CLIENT_ID(16 bytes) + VERSION(1 byte) + CODE(2 bytes) + PAYLOAD_SIZE(4 bytes) + PAYLOAD
		std::vector<uint8_t> data;

		// Add the client ID (16 bytes)
		data = Utils::pad(client_id, FieldSize::CLIENT_ID);

		// Add the version (1 byte)
		data.push_back(CLIENT_VERSION);

		// Add the request code (2 bytes)
		auto code_bytes = static_cast<uint16_t>(code);
		data.insert(data.end(), reinterpret_cast<uint8_t*>(&code_bytes),
			reinterpret_cast<uint8_t*>(&code_bytes) + FieldSize::CODE);

		// Add the payload size (4 bytes), and the payload
		auto payload_size = static_cast<uint32_t>(payload.size());
		data.insert(data.end(), reinterpret_cast<uint8_t*>(&payload_size),
			reinterpret_cast<uint8_t*>(&payload_size) + FieldSize::PAYLOAD);
		data.insert(data.end(), payload.begin(), payload.end());

		// Send header + payload
		boost::system::error_code error;
		boost::asio::write(socket, boost::asio::buffer(data), error);
		if (error) {
			throw std::runtime_error("Write error: " + error.message());
		}
		std::cout << "Sent request code " << code_bytes << " with header size " << (data.size() - payload_size) << " and payload size " << payload_size << std::endl;
	}

	std::pair<int, std::vector<uint8_t>> receive_response() {
		/* Each response consists of: VERSION(1 byte) + CODE(2 bytes) + PAYLOAD_SIZE(4 bytes) + PAYLOAD */
		std::cout << "Receiving response..." << std::endl;
		boost::system::error_code error;

		// Read the header
		std::array<uint8_t, FieldSize::VERSION + FieldSize::CODE + FieldSize::PAYLOAD> header;
		std::size_t bytes_read = boost::asio::read(socket, boost::asio::buffer(header), error);

		if (error) {
			throw std::runtime_error("Error while reading header " + error.message());
		}
		if (bytes_read != header.size()) {  // should never happen
			throw std::runtime_error("Unexpected header size.");
		}

		// Parse the header
		uint8_t version;
		memcpy(&version, header.data(), sizeof(version));
		uint16_t response_code;
		memcpy(&response_code, header.data() + FieldSize::VERSION, sizeof(response_code));
		uint32_t payload_size;
		memcpy(&payload_size, header.data() + FieldSize::VERSION + FieldSize::CODE, sizeof(payload_size));

		// Read the payload
		std::vector<uint8_t> payload(payload_size);
		bytes_read = boost::asio::read(socket, boost::asio::buffer(payload), error);
		if (error) {
			throw std::runtime_error("Error while reading payload " + error.message());
		}
		if (bytes_read != payload_size) {  // should never happen
			throw std::runtime_error("Unexpected payload size.");
		}

		std::cout << "Received response: " << response_code << ". Payload size: " << payload_size << ", header size: " << header.size() << std::endl;
		if (version != CLIENT_VERSION) {
			throw std::runtime_error("Version mismatch, expected " + std::to_string(CLIENT_VERSION) + ", got " + std::to_string(version));
		}
		if (response_code == ResponseCode::GENERAL_ERROR) {
			throw std::runtime_error("Server responded with an error.");
		}
		return { response_code, payload };
	}


	void initiate_transfer_info() {
		/* File format:
		* IP:PORT
		* CLIENT_NAME
		* FILE_TO_SEND
		*/
		std::cout << "Reading transfer info..." << std::endl;
		std::ifstream file(TRANSFER_INFO_FILE);
		if (!file.is_open()) {
			throw std::runtime_error(TRANSFER_INFO_FILE + " file not found.");
		}
		std::string ip_address, port_str;
		try {
			std::getline(file, ip_address, ':');
			std::getline(file, port_str);
			server_endpoint = boost::asio::ip::tcp::endpoint(
				boost::asio::ip::address::from_string(ip_address), static_cast<unsigned short>(std::stoi(port_str)));
			std::getline(file, client_name);
			std::getline(file, file_to_send);
		}
		catch (...) {
			file.close();
			throw std::runtime_error("Error reading " + TRANSFER_INFO_FILE + " file.");
		}
		file.close();
		std::cout << "Done reading transfer info." << std::endl << std::endl;
	}

	void save_me_info() {
		/* Save client name, client id and private key to me.info file */
		std::ofstream file(ME_INFO_FILE);
		file << client_name << '\n'
			<< Utils::bytes_to_hex(client_id) << '\n'
			<< Base64Wrapper::encode(get_private_key()) << '\n';
		file.close();
	}

	void load_me_info() {
		/* Initiate client name, client id and private key from me.info file
		* File format:
		*   CLIENT_NAME
		*   CLIENT_ID (hex)
		*   PRIVATE_KEY (base64)  // we don't need it.
		*/
		std::ifstream file(ME_INFO_FILE);
		if (!file.is_open()) {
			throw std::runtime_error(ME_INFO_FILE + " file not found.");
		}
		std::string client_id_hex;
		try {
			std::getline(file, client_name);

			// Read the client ID in hex format and convert it to bytes
			std::getline(file, client_id_hex);
			client_id = Utils::hex_to_bytes(client_id_hex);

			// we don't need the private key
		}
		catch (...) {
			file.close();
			throw std::runtime_error("Error reading " + ME_INFO_FILE + " file.");
		}
		file.close();

		// print:
		std::cout << "Loaded client info" << std::endl;
		std::cout << "Client name: " << client_name << std::endl;
		std::cout << "Client ID: " << client_id_hex << std::endl << std::endl;
	}

	static std::string get_private_key() { // Returns DER format 
		std::cout << "WARNING: loading private key from " << KEY_FILE << ", is this you?" << std::endl;
		std::ifstream file(KEY_FILE, std::ios::binary);
		if (!file.is_open()) {
			throw std::runtime_error(KEY_FILE + " file not found.");
		}
		std::string private_key((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
		file.close();
		return private_key;
	}

	static std::string generate_rsa_pair() {
		/* Generate RSA key pair, save the private key to key.priv file and return the public key.*/
		RSAPrivateWrapper rsaPrivateWrapper;
		std::string private_key = rsaPrivateWrapper.getPrivateKey();
		std::string public_key = rsaPrivateWrapper.getPublicKey();
		std::ofstream file(KEY_FILE, std::ios::binary);
		file.write(private_key.data(), private_key.size());
		file.close();
		return public_key;
	}

	void verify_client_id(const std::string& received_client_id) {
		// Make sure the received client ID matches the one we have
		if (client_id != received_client_id) {
			throw std::runtime_error("Client ID mismatch.");
		}
	}


public:
	Client() : socket(io_service) {
		initiate_transfer_info();  // initiate server_endpoint(IP,port), client name and the file to send
		if (server_endpoint.address().is_unspecified()) {
			throw std::runtime_error("Server address not found.");
		}
		std::cout << "Connecting to " << server_endpoint.address().to_string() << ":" << server_endpoint.port() << "..." << std::endl << std::endl;
		socket.connect(server_endpoint);
	}

	~Client() {
		std::cout << "Closing connection..." << std::endl;

		boost::system::error_code ec;
		socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
		if (ec) {
			std::cerr << "Shutdown Error: " << ec.message() << std::endl;
		}
		socket.close(ec);
		if (ec) {
			std::cerr << "Close Error: " << ec.message() << std::endl;
		}

		// Stop the io_service
		if (!io_service.stopped()) {
			io_service.stop();
		}
		std::cout << "Connection closed." << std::endl << std::endl;
	}

	void authorize() {
		// Check if me.info exists. If it does, login, if not, register
		if (std::filesystem::exists(ME_INFO_FILE)) {
			login();
		}
		else {
			register_client();
		}
	}

	void send_encrypted_file() {
		if (encrypted_aes_key.empty()) {
			throw std::runtime_error("AES key not found. Authorize first.");
		}
		if (client_id.empty()) {
			throw std::runtime_error("Client ID not found.");
		}
		if (!std::filesystem::exists(file_to_send)) {
			throw std::runtime_error("File " + file_to_send + " not found.");
		}
		std::cout << "Sending file " << file_to_send << "..." << std::endl;

		// Read the file content
		std::ifstream file(file_to_send, std::ios::binary);
		std::vector<uint8_t> content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

		// Decrypt the AES key
		std::vector<uint8_t> decrypted_aes_key = decrypt_aes_key(encrypted_aes_key);

		// Encrypt the file content with the AES key
		AESWrapper aesWrapper(decrypted_aes_key.data(), static_cast<int>(decrypted_aes_key.size()));
		std::string encrypted_content = aesWrapper.encrypt(
			reinterpret_cast<const char*>(content.data()), static_cast<int>(content.size()));

		// Construct the payload (content_size(4) + file_name(255) + encrypted_content)
		std::vector<uint8_t> padded_file_name = Utils::pad(file_to_send, FieldSize::FILE_NAME);
		std::vector<uint8_t> send_payload;
		auto content_size = static_cast<uint32_t>(encrypted_content.size());
		send_payload.insert(send_payload.end(), reinterpret_cast<uint8_t*>(&content_size),
			reinterpret_cast<uint8_t*>(&content_size) + FieldSize::FILE_SIZE);
		send_payload.insert(send_payload.end(), padded_file_name.begin(), padded_file_name.end());
		send_payload.insert(send_payload.end(), encrypted_content.begin(), encrypted_content.end());

		// Calculate the CRC
		uint32_t crc = memcrc(reinterpret_cast<char*>(content.data()), content.size());

		int response_code;
		std::vector<uint8_t> receive_payload;
		for (int i = 0; i < MAX_RETRIES; ++i) {  // try to send the file up to 3 times
			send_request(RequestCode::RECEIVE_FILE, send_payload);

			std::tie(response_code, receive_payload) = receive_response();
			if (response_code == ResponseCode::LOGIN_FAILURE) {
				std::cout << "Cannot send file because the server doesn't recognize this client, registering..." << std::endl << std::endl;
				register_client();
				continue; // it have 2 more chances to send the file
			}
			else if (response_code != ResponseCode::FILE_RECEIVED) {
				throw std::runtime_error("Unexpected response code.");
			}
			if (receive_payload.size() != FieldSize::CLIENT_ID + FieldSize::FILE_SIZE + FieldSize::FILE_NAME + FieldSize::CRC) {
				throw std::runtime_error("Invalid payload size.");
			}
			// Read the received payload: client_id(16) + content_size(4) + file_name(255) + crc(4)
			std::string received_client_id(receive_payload.begin(), receive_payload.begin() + FieldSize::CLIENT_ID);
			verify_client_id(received_client_id);
			uint32_t received_content_size;
			std::copy(receive_payload.begin() + FieldSize::CLIENT_ID,
				receive_payload.begin() + FieldSize::CLIENT_ID + FieldSize::FILE_SIZE,
				reinterpret_cast<uint8_t*>(&received_content_size));
			std::string received_file_name(receive_payload.begin() + FieldSize::CLIENT_ID + FieldSize::FILE_SIZE,
				receive_payload.begin() + FieldSize::CLIENT_ID + FieldSize::FILE_SIZE + FieldSize::FILE_NAME);
			uint32_t received_crc;
			std::copy(receive_payload.end() - FieldSize::CRC, receive_payload.end(), reinterpret_cast<uint8_t*>(&received_crc));
			
			if (received_content_size != encrypted_content.size()) {
				std::cout << "File size mismatch (received: " << received_content_size << ", original: " << encrypted_content.size() << "), retrying..." << std::endl;
			}
			else if (strcmp(received_file_name.c_str(), file_to_send.c_str()) != 0) {
				std::cout << "File name mismatch (received: " << received_file_name << ", original: " << file_to_send << "), retrying..." << std::endl;
			}
			else if (received_crc != crc) {
				std::cout << "CRC mismatch (received: " << received_crc << ", original: " << crc << "), retrying..." << std::endl;
			}
			else {
				std::cout << "File sent successfully." << std::endl;
				send_request(RequestCode::CRC_VALID, padded_file_name);
				return;
			}

			// If the received payload is invalid, retry up to 3 times
			send_request(RequestCode::CRC_RETRY, padded_file_name);
			std::tie(response_code, receive_payload) = receive_response();
			if (response_code != ResponseCode::MESSAGE_RECEIVED) {
				throw std::runtime_error("Unexpected response code.");
			}
			verify_client_id(std::string(receive_payload.begin(), receive_payload.end()));
		}

		// If the file was not sent after 3 tries, send CRC_FAILURE
		std::cout << "Failed to send file " << file_to_send << std::endl;
		send_request(RequestCode::CRC_FAILURE, padded_file_name);
		std::tie(response_code, receive_payload) = receive_response();
		if (response_code != ResponseCode::MESSAGE_RECEIVED) {
			throw std::runtime_error("Unexpected response code.");
		}
		verify_client_id(std::string(receive_payload.begin(), receive_payload.end()));
	}
};

int main() {
	Client client;
	try {
		client.authorize();
		client.send_encrypted_file();
	}
	catch (const std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
		return 1;
	}
	catch (...) {
		std::cerr << "Unknown error." << std::endl;
		return 1;
	}

	std::cout << "Done." << std::endl;
	return 0;
}
