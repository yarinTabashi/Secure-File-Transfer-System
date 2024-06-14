#pragma once
#include <stdint.h>
#include <string>
#include <filesystem>
#include <fstream>
#include <eccrypto.h>
#include <osrng.h>
#include "protocol.h"
#include <rsa.h>
#include <modes.h>
#include <files.h>
#include <filters.h>
#include <base64.h>

#define RSA_SIZE (1024)
#define AES_KEY_SIZE (256)

class Encryption
{
	static const CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];
private:
	CryptoPP::AutoSeededRandomPool pool;
	CryptoPP::RSA::PrivateKey rsa_private_key;
	CryptoPP::RSA::PublicKey rsa_public_key;
	std::string aes_symteric_key;
	
public:
	Encryption();
	void copyStringToCharArray(const std::string& str, unsigned char* arr, size_t arrSize);

	/**
	* @brief Sets the RSA keys from the provided private key string.
	* @param private_key_st The private key string.
	*/
	void set_rsa_keys(std::string);
	bool set_rsa_keys_mock();

	/**
	* @brief Generates a pair of RSA key strings (public and private keys).
	* @return A pair of strings containing the generated RSA keys: <public,private>.
	*/
	std::pair<std::string, std::string> generate_rsa_pair();

	/**
	* @brief Decrypts the provided AES key using RSA encryption and sets it as the symmetric key.
	* @param encrypted_aes_key The encrypted AES key to decrypt.
	*/
	//void decrypt_and_set_aes_key(std::string encrypted_aes_key);
	void decrypt_and_set_aes_key(const std::string& encrypted_aes_key);

	/**
	* @brief Encrypts the contents of the file specified by the given file path using AES encryption.
	* @param file_path The path to the file to be encrypted.
	* @return The encrypted contents of the file as a string.
	*/
	std::string encrypt_file(std::filesystem::path); // Returns the encrypted file as a string, in order the server to be able to send it over the network.

	static std::string parse_key_from_base_64(const std::string& content);
	static std::string parse_key_to_base_64(const std::string& content);
	std::string get_aes_key(const std::string&);
};