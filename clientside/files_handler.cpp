#include "files_handler.h"
#include "encryption.h"

std::pair<std::string, int> FilesHandler::fetch_server_config(const std::string& transfer_file_path)
{
    std::ifstream file(transfer_file_path);
    std::string line, address, port_str;
    int port;

    if (!file.is_open())
    {
        throw std::runtime_error("Failed to open transfer file");
    }

    // Read the single line containing IP:PORT
    if (!std::getline(file, line))
    {
        throw std::runtime_error("Failed to read from transfer file");
    }

    file.close();

    // Find the position of the colon separating address and port
    size_t colon_pos = line.find(':');
    if (colon_pos == std::string::npos) 
    {
        throw std::runtime_error("Invalid format in file: ");
    }

    // Extract the address and port as substrings
    address = line.substr(0, colon_pos);
    port_str = line.substr(colon_pos + 1);

    try 
    {
        port = std::stoi(port_str);
    }
    catch (const std::invalid_argument& e) 
    {
        throw std::runtime_error("Invalid port format in file: ");
    }
    catch (const std::out_of_range& e) 
    {
        throw std::runtime_error("Port out of range in file: ");
    }

    return std::make_pair(address, port);
}

bool FilesHandler::save_clientId_in_info_file(u_char client_id[16])
{
    std::ifstream infoFileRead(INFO_FILE_PATH);
    std::string first_line;

    if (!infoFileRead.is_open())
    {
        return false;
    }

    std::getline(infoFileRead, first_line);
    infoFileRead.close();

    std::ofstream infoFileWrite(INFO_FILE_PATH);

    if (!infoFileWrite.is_open())
    {
        return false;
    }

    infoFileWrite << first_line << std::endl;
    write(infoFileWrite, client_id, 16);
    infoFileWrite.close();
    return true;
}


void FilesHandler::save_private_key_in_priv_file(std::string private_key)
{
    std::ofstream privFile(PRIV_FILE_PATH);

    if (privFile.is_open())
    {
        privFile << private_key << '\n';
        privFile.close();
    }
}

bool FilesHandler::get_name_from_info(std::string& name)
{
    std::ifstream infoFile(INFO_FILE_PATH);
    if (!infoFile.is_open())
    {
        return false;
    }

    if (std::getline(infoFile, name))
    {
        return true;
    }

    return false;
}

bool FilesHandler::get_name_from_transfer(std::string& name)
{
    std::ifstream transFile(TRANSFER_FILE_PATH);
    bool flag = false;

    if (!transFile.is_open())
    {
        return flag;
    }

    if (std::getline(transFile, name))
    {
        if (std::getline(transFile, name))
        {
            flag = true;
        }
    }

    transFile.close();
    return flag;
}

std::string FilesHandler::read_private_key()
{
    std::ifstream privFile(PRIV_FILE_PATH);
    std::string key = "";

    if (!privFile.is_open())
    {
        return key;
    }

    std::getline(privFile, key);
    privFile.close();
    return key;
}



inline uint8_t FilesHandler::parse_hex(char digit)
{
    if ('0' <= digit && digit <= '9') 
    {
        return digit - '0';
    }

    digit = ('a' <= digit && digit <= 'f') ? digit : digit + ('a' - 'A');

    if ('a' <= digit && digit <= 'f') 
    {
        return digit - 'a' + 10;
    }
    else 
    {
        throw std::domain_error("Char is not hexadecimal!");
    }
}

void FilesHandler::parse(const std::string& input, unsigned char* destination)
{
    if (input.length() != CLIENT_ID_LENGTH * 2)
    {
        throw std::invalid_argument("Input string is not in the correct length.");
    }

    for (int i = 0; i < CLIENT_ID_LENGTH; ++i) 
    {
        uint8_t first = input[2 * i];
        uint8_t second = input[2 * i + 1];
        destination[i] = (parse_hex(first) << 4) + parse_hex(second);
    }
}

bool FilesHandler::get_uuid_from_info(unsigned char* destination)
{
    std::ifstream file(INFO_FILE_PATH);
    std::string client_id;

    if (!file.is_open())
    {
        return false;
    }

    std::getline(file, client_id);
    std::getline(file, client_id);
    file.close();

    if (!client_id.empty())
    {
        parse(client_id, destination);
        return true;
    }

    return false;
}

void FilesHandler::write(std::ostream& out_s, unsigned char* source, size_t len) 
{
    for (size_t i = 0; i < len; ++i)
    {
        out_s << std::hex << std::setw(2) << std::setfill('0') << (int) static_cast <unsigned char>(source[i]);
    }
}

// Returns the third line from 'transfer.info' file as a file path.
std::filesystem::path FilesHandler::get_required_file_path()
{
    std::ifstream file(TRANSFER_FILE_PATH);
    std::string line;

    if (file.is_open())
    {
        for (int i = 0; i < 3; ++i)
        {
            if (!std::getline(file, line))
            {
                file.close();
                throw std::runtime_error("File has fewer than three lines. ");
            }
        }
    }
    else
    {
        throw std::runtime_error("Unable to open 'transfer' file, in order to read the path file. ");
    }

    file.close();
    std::filesystem::path third_line_path = line;
    return third_line_path;
}
