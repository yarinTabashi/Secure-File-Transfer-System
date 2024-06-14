#pragma once
#include <cstdint>
#include <string>

#define CLIENT_ID_LENGTH (16)
#define MAX_NAME_LENGTH (255)
#define MAX_PUBLIC_KEY_SIZE (160)
#define CONTENT_SIZE_LENGTH (4)
#define MAX_FILE_NAME_LENGTH (255)
#define MAX_CHECK_SUM_LENGTH (16)
#define CHUNK_SIZE (1024)
#define RSA_KEYS_LENGTH (1024)
#define AES_KEY_LENGTH (16)

//                       ### Client's Request ###         //

enum RequestId : uint16_t
{
    REGISTER = 1025,
    SEND_PUBLIC_KEY = 1026,
    LOGIN = 1027,
    SEND_FILE = 1028,
    VALID_CRC = 1029,
    INVALID_CRC = 1030,
    INVALID_CRC_ABORT = 1030,
    YARIN_REQUEST = 1035
};

enum ResponseId : uint16_t
{
    REGISTRATION_SUCCESSFUL = 1600,
    REGISTRATION_FAILED = 1601,
    RECEIVED_PUBLIC_KEY_AND_SENDING_AES = 1602,
    FILE_RECEIVED_OK = 1603,
    CONFIRMING_RECEIPT_MESSAGE = 1604,
    SUCCESSFUL_LOGIN = 1605,
    LOGIN_REJECTED = 1606,
    GENERAL_ERROR = 1607,
};

#pragma pack(push, 1)

struct RequestHeader
{
    unsigned char user_id[CLIENT_ID_LENGTH];
    unsigned char version;
    RequestId req_id;
    unsigned int payload_size;
};

struct YarinRequest
{
    RequestId req_id;
};

struct RegisterReqPayload : RequestHeader
{
    char name[MAX_NAME_LENGTH];
};

struct LoginPayload : RequestHeader
{
    char name[MAX_NAME_LENGTH];
};

struct SendPublicKeyPayload : RequestHeader
{
    char name[MAX_NAME_LENGTH];
    char public_key[MAX_PUBLIC_KEY_SIZE];
};

struct SendFilePayload : RequestHeader
{
    unsigned int content_size;
    unsigned int orig_file_size;
    unsigned short current_packet;
    unsigned short total_packets;
    char file_name[MAX_FILE_NAME_LENGTH];
    char content[CHUNK_SIZE];
};

struct CrcPayload : RequestHeader
{
    char file_name[MAX_FILE_NAME_LENGTH];
};


//                       ### Server's Response ###         //


struct ResponseHeader
{
    unsigned char version;
    ResponseId response_id;
    int payload_size;
};


struct RegistrationSuccessfulPayload
{
    unsigned char client_id[CLIENT_ID_LENGTH];
};

struct ReceivedPublicKeySendingAesPayload
{
    unsigned char client_id[CLIENT_ID_LENGTH];
};

struct FileReceivedOkWithCrcPayload
{
    unsigned char client_id[CLIENT_ID_LENGTH];
    unsigned int content_size[CONTENT_SIZE_LENGTH];
    char file_name[MAX_FILE_NAME_LENGTH];
    unsigned int cksum;
};

struct ConfirmingReceiptOfMessagePayload
{
    unsigned char client_id[CLIENT_ID_LENGTH];
};

struct ReconnectRequestRejectedPayload
{
    unsigned char client_id[CLIENT_ID_LENGTH];
};

#pragma pack(pop)