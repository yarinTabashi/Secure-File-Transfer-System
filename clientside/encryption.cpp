#include "encryption.h"
#include <iostream>
#include <string>
#include <boost/asio/write.hpp>

Encryption::Encryption() : pool() {};
const CryptoPP::byte Encryption::iv[CryptoPP::AES::BLOCKSIZE] = { 0 };

void Encryption::set_rsa_keys(std::string private_key_base64)
{
    std::string key = this->parse_key_from_base_64(private_key_base64);
    CryptoPP::StringSource ss(key, true);
    this->rsa_private_key.Load(ss);
}

bool Encryption::set_rsa_keys_mock()
{
    generate_rsa_pair();
    return true;
}

std::pair<std::string,std::string> Encryption::generate_rsa_pair()
{
    this->rsa_private_key.Initialize(this->pool, RSA_SIZE);
    this->rsa_public_key = CryptoPP::RSA::PublicKey(this->rsa_private_key);

    // Return the private key as a string
    std::string rsa_public_key_st;
    CryptoPP::StringSink sink_pr(rsa_public_key_st);
    this->rsa_public_key.DEREncode(sink_pr);

    std::string rsa_private_key_st;
    CryptoPP::StringSink sink_pb(rsa_private_key_st);
    this->rsa_private_key.DEREncode(sink_pb);

    return std::make_pair(rsa_public_key_st, rsa_private_key_st);
}

void Encryption::decrypt_and_set_aes_key(const std::string& encrypted_aes_key)
{
    CryptoPP::RSAES_OAEP_SHA_Decryptor d(this->rsa_private_key);
    CryptoPP::StringSource ss_cipher(encrypted_aes_key, true, new CryptoPP::PK_DecryptorFilter(this->pool, d, new CryptoPP::StringSink(this->aes_symteric_key)));
}

std::string Encryption::encrypt_file(std::filesystem::path file_path)
{
    std::ifstream to_send(file_path, std::ios::binary);
    
    unsigned char key_temp[AES_KEY_LENGTH];
    copyStringToCharArray(this->aes_symteric_key, key_temp, 16);
    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption e;
    e.SetKeyWithIV(key_temp, sizeof(key_temp), iv);
    std::string cipher;
    CryptoPP::FileSource fs(to_send, true, new CryptoPP::StreamTransformationFilter(e, new CryptoPP::StringSink(cipher)));
    return cipher;
}

void Encryption::copyStringToCharArray(const std::string& str, unsigned char* arr, size_t arrSize) {
    size_t length = str.length();
    size_t copyLength = (length < arrSize) ? length : arrSize;

    for (size_t i = 0; i < copyLength; ++i) {
        arr[i] = static_cast<unsigned char>(str[i]);
    }
}

// Parseer from and to base 64
std::string Encryption::parse_key_to_base_64(const std::string& content)
{
    std::string parsed_content;
    CryptoPP::StringSource source(content, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(parsed_content), false));
    return parsed_content;
}

std::string Encryption::parse_key_from_base_64(const std::string& content)
{
    std::string parsed_content;
    CryptoPP::StringSource source(content, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(parsed_content)));
    return parsed_content;
}