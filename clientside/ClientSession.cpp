#include "ClientSession.h"
#include <rsa.cpp>

ClientSession::ClientSession(const std::string& transfer_file_path) : socket(io_context), encryption_obj()
{
    std::pair<std::string, int> server_config;

    // Establish a connection
    try
    {
        server_config = FilesHandler::fetch_server_config(transfer_file_path);
    }
    catch (const std::exception& e)
    {
        server_config.first = DEFAULT_ADDRESS;
        server_config.second = 1234;
    }

    tcp::resolver resolver(io_context);
    auto endpoints = resolver.resolve(server_config.first, std::to_string(server_config.second));

    try
    {
        boost::asio::connect(socket, endpoints);
    }
    catch (const boost::system::system_error& e) // Catch boost::system::system_error
    {
        std::cerr << "Error connecting to the server: " << e.what() << std::endl;
        throw;
    }

    // Try to load the client properties from the files.
    if (this->initialize_user())
    {
        this->login();
    }
    else
    {
        if (this->name.empty() || this->name.length() > MAX_NAME_LENGTH) // Cannot pereform registeration.
        {
            throw Exception("Cannot read valid client name from both files in order to login or register. ");
        }
        else
        {
            this->is_initialized = false; // One of the properties missing, so need to register again.
        }
    }

    if (!this->is_initialized)
    {
        this->is_initialized = this->reg();
        if (!this->is_initialized) // Registeration failed
        {
            throw Exception("Registeration failed. ");
        }
        else
        {
            this->send_public_key(); // Perform keys exchange
        }
    }

    this->send_file(FilesHandler::get_required_file_path());
}

// Initialize the user and then return true if the 'info' file exists and valid. Else - false.
// If 'me.info' exists and valid --> read uuid, and then login.
bool ClientSession::initialize_user()
{
    std::string temp_st;
    bool is_exists = FilesHandler::get_name_from_info(temp_st);

    if (!(is_exists && !temp_st.empty() && temp_st.length() < MAX_NAME_LENGTH))
    {
        // Try read name from transfer file
        is_exists = FilesHandler::get_name_from_transfer(temp_st);
        if (is_exists && !temp_st.empty() && temp_st.length() < MAX_NAME_LENGTH)
        {
            this->name = temp_st;
            return true;
        }
        return false; // Cannot read the name from both files
    }

    this->name = temp_st;

    std::string priv_key_base64 = FilesHandler::read_private_key(); // Try read the private key from file
    try
    {
        this->encryption_obj.set_rsa_keys(priv_key_base64);
    }
    catch (const std::exception& ex)
    {
        std::cerr << "Error while trying to read the private key from the file and parse it to object. \n ";
        return false;
    }

    is_exists = FilesHandler::get_uuid_from_info(this->uuid);

    if (is_exists) // Loading of the registered user is complete
    {
        this->is_initialized = true;
        return true;
    }

    return false;
}

bool ClientSession::reg()
{
    // Get a request to send
    RegisterReqPayload payload = ProtocolHandle::generate_request<RegisterReqPayload>(RequestId::REGISTER, this->uuid);
    strcpy_s(payload.name, sizeof(payload.name), this->name.c_str());
    ProtocolHandle::send_request(&payload, this->socket);

    // Waiting to the response and read it.
    ResponseHeader res_header;
    ProtocolHandle::recieve_response(&res_header, this->socket, sizeof(ResponseHeader));

    if (res_header.response_id == REGISTRATION_SUCCESSFUL)
    {
        RegistrationSuccessfulPayload response_payload;
        ProtocolHandle::recieve_response(&response_payload, this->socket, sizeof(response_payload.client_id));
        
        // Save the client ID in the information file and set the class member.
        memcpy_s(this->uuid, sizeof(this->uuid), response_payload.client_id, sizeof(response_payload.client_id));
        
        FilesHandler::save_clientId_in_info_file(this->uuid);
        this->is_initialized = true;
        return true;
    }
    else if (res_header.response_id == REGISTRATION_FAILED)
    {
        return false;
    }
}

bool ClientSession::login()
{
    // Get a request to send
    LoginPayload login_request = ProtocolHandle::generate_request<LoginPayload>(RequestId::LOGIN, this->uuid);
    strcpy_s(login_request.name, sizeof(login_request.name), this->name.c_str());
    ProtocolHandle::send_request(&login_request, this->socket);

    // Receive the response. If has not accepted, perform re-register.
    ResponseHeader res_header;
    ProtocolHandle::recieve_response(&res_header, this->socket, sizeof(ResponseHeader));

    if (res_header.response_id == ResponseId::SUCCESSFUL_LOGIN)
    {
        ReceivedPublicKeySendingAesPayload response_payload;
        ProtocolHandle::recieve_response(&response_payload, this->socket, sizeof(response_payload));
        this->read_symetric_key(res_header.response_id, res_header.payload_size);
        return true;
    }
    else if (res_header.response_id == ResponseId::LOGIN_REJECTED)
    {
        ReconnectRequestRejectedPayload response_payload;
        ProtocolHandle::recieve_response(&response_payload, this->socket, sizeof(response_payload));
    }

    this->is_initialized = false;
    return false;
}

// Keys exchange will occur only if the registeration have been made in the current session.
bool ClientSession::send_public_key()
{
    if (this->is_initialized)
    {
        // Build and send the request
        SendPublicKeyPayload request = ProtocolHandle::generate_request<SendPublicKeyPayload>(RequestId::SEND_PUBLIC_KEY, this->uuid);
        std::pair<std::string, std::string> rsa_keys = encryption_obj.generate_rsa_pair();
        std::string public_key = rsa_keys.first;
        std::string priv_key_base64 = encryption_obj.parse_key_to_base_64(rsa_keys.second);
        FilesHandler::save_private_key_in_priv_file(priv_key_base64);

        memcpy_s(request.public_key, sizeof(request.public_key), public_key.c_str(), public_key.length());
        strcpy_s(request.name, sizeof(request.name), this->name.c_str());
        ProtocolHandle::send_request(&request, this->socket);

        // Waiting the response and read it.
        ResponseHeader response_header;
        ProtocolHandle::recieve_response(&response_header, this->socket, sizeof(ResponseHeader));
        
        if (response_header.response_id == ResponseId::RECEIVED_PUBLIC_KEY_AND_SENDING_AES)
        {
            ReceivedPublicKeySendingAesPayload response_payload;
            ProtocolHandle::recieve_response(&response_payload, this->socket, sizeof(response_payload));
            this->read_symetric_key(response_header.response_id, response_header.payload_size);
        }
        else
        {
            throw new Exception("Unexcpected response.");
        }
    }
    else
    {
        throw Exception("Client must register before perform this keys exchange.");
    }
}

bool ClientSession::read_symetric_key(ResponseId res_id, unsigned int payload_size)
{
    auto key_exp_size = payload_size - sizeof(ReceivedPublicKeySendingAesPayload);
    char* encrypted_key_ptr = new char[key_exp_size];
    ProtocolHandle::recieve_additional(encrypted_key_ptr, socket, key_exp_size);

    std::string encrypted_key(encrypted_key_ptr, key_exp_size);
    delete[] encrypted_key_ptr; // Free the dynamically allocated memory
    this->encryption_obj.decrypt_and_set_aes_key(encrypted_key);
    return true;
}

void ClientSession::send_file(std::filesystem::path file_path)
{
     std::string file_name = file_path.filename().string();

    // Validations
    if ((std::filesystem::is_regular_file(file_path) == false) || (file_name.length() >= MAX_FILE_NAME_LENGTH))
    {
        throw std::runtime_error("File doesn't exists, or name length is too long. ");
    }

    // Calculate the local crc
    unsigned long local_cksum = CKsum::get_crc(file_path);

    // Sending the file
    retries_handle(file_path, local_cksum);
}

bool ClientSession::retries_handle(std::filesystem::path file_path, unsigned long local_cksum)
{
    std::string encrypted_file = encryption_obj.encrypt_file(file_path);
    unsigned long server_cksum;

    for (int i = 0; i < attemptsNo; i++)
    {
        server_cksum = send_once_process(file_path, encrypted_file);
        if (local_cksum == server_cksum) // Success
        {
            notifyServerCRCStatus(file_path, RequestId::VALID_CRC);
            return true;
        }
        else if (i == attemptsNo) // Sending abort
        {
            notifyServerCRCStatus(file_path, RequestId::INVALID_CRC_ABORT);
            return false;
        }
        else // Should retransmit on the next iteration.
        {
            notifyServerCRCStatus(file_path, RequestId::INVALID_CRC);
        }
    }
    return false; // All attempts failed
}

void ClientSession::notifyServerCRCStatus(std::filesystem::path file, RequestId req_id)
{
    ResponseHeader confirm_header;

    CrcPayload crc_payload = ProtocolHandle::generate_request<CrcPayload>(req_id, this->uuid);
    strcpy_s(crc_payload.file_name, sizeof(crc_payload.file_name), file.filename().string().c_str());
    ProtocolHandle::send_request(&crc_payload, this->socket);

    // Wait for a response only in case of Abort/Success
    if (req_id == RequestId::INVALID_CRC_ABORT || req_id == RequestId::VALID_CRC)
    {
        ProtocolHandle::recieve_response(&confirm_header, this->socket, sizeof(ResponseHeader));
        if (confirm_header.response_id != ResponseId::CONFIRMING_RECEIPT_MESSAGE)
        {
            throw Exception("Unexpected response. ");
        }
    }
}

unsigned long ClientSession::send_once_process(std::filesystem::path file, const std::string& encrypted_file)
{
    // Build the request header and sending file (1028)
    SendFilePayload sending_req = ProtocolHandle::generate_request<SendFilePayload>(RequestId::SEND_FILE, this->uuid);
    sending_req.content_size = encrypted_file.size();
    sending_req.orig_file_size = std::filesystem::file_size(file);
    strcpy_s(sending_req.file_name, sizeof(sending_req.file_name), file.filename().string().c_str());
    send_file_in_chunks(encrypted_file, sending_req);

    // Recieve the response and comparing the checksums
    ResponseHeader response_header;
    ProtocolHandle::recieve_response(&response_header, this->socket, sizeof(ResponseHeader));

    if (response_header.response_id != ResponseId::FILE_RECEIVED_OK)
    {
        throw Exception("Invalid response (excpected to 'file recieved'). ");
    }

    FileReceivedOkWithCrcPayload response_payload;
    ProtocolHandle::recieve_response(&response_payload, this->socket, sizeof(response_header.payload_size));
    
    return response_payload.cksum;
}

void ClientSession::send_file_in_chunks(std::string encrypted_content, SendFilePayload sending_req)
{
    size_t total_chunks = encrypted_content.length() / CHUNK_SIZE;
    if (encrypted_content.length() % CHUNK_SIZE != 0)
        total_chunks++;

    size_t current_chunk = 0, content_position = 0;

    sending_req.total_packets = total_chunks;
    sending_req.current_packet = 1;

    while (current_chunk < total_chunks)
    {
        // Extract the chunk from the encrypted content
        std::string current_content = encrypted_content.substr(content_position, CHUNK_SIZE);
        std::fill(sending_req.content, sending_req.content + CHUNK_SIZE, '\0');
        std::memcpy(sending_req.content, current_content.c_str(), std::min<size_t>(CHUNK_SIZE, current_content.size()));

        ProtocolHandle::send_request(&sending_req, socket);
        
        current_chunk++;
        content_position += CHUNK_SIZE;
        sending_req.current_packet += 1;
    }
}
