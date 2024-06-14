#pragma once
#include <string>
#include <boost/asio.hpp>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <filesystem>

using boost::asio::ip::tcp;

#define INFO_FILE_PATH "me.info"
#define PRIV_FILE_PATH "priv.key"
#define TRANSFER_FILE_PATH "transfer.info"
#define CLIENT_ID_LENGTH (16)

class FilesHandler 
{
private:
    static inline uint8_t parse_hex(char digit);
    static void parse(const std::string& input, unsigned char* destination);
    static void write(std::ostream& out_s, unsigned char* source, size_t len);
public:
    static std::pair<std::string, int> fetch_server_config(const std::string& filename);
    static bool save_clientId_in_info_file(u_char client_id[16]);
    static void save_private_key_in_priv_file(std::string private_key);
    static bool get_name_from_info(std::string&);
    static bool get_name_from_transfer(std::string&);
    static bool get_uuid_from_info(unsigned char* destination);
    static std::string read_private_key();
    static std::filesystem::path get_required_file_path();
};