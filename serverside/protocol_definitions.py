from dataclasses import dataclass
from dataclasses import fields
from enum import Enum
from typing import Type, Dict
from uuid import UUID

MAX_UID_LENGTH = 16
MAX_NAME_LENGTH = 255
MAX_FILE_NAME_LENGTH = 255
MAX_PUBLIC_KEY_SIZE = 160
CONTENT_SIZE_LENGTH = 4
CHUNK_SIZE = 1024


#                       ### Client's Request ###         #
class RequestId(Enum):
    REGISTER = 1025
    SEND_PUBLIC_KEY = 1026
    LOGIN = 1027
    SEND_FILE = 1028
    VALID_CRC = 1029
    INVALID_CRC = 1030
    INVALID_CRC_ABORT = 1030


class BaseParser:
    def __post_init__(self):
        for field in fields(self):
            value = getattr(self, field.name)

            if field.type is str and type(value) is bytes:
                value = value.decode('charmap')
                value = value.split('\0', 1)[0]

            elif issubclass(field.type, Enum):  # Parsing to Enum
                value = field.type(value)

            elif field.type is UUID and type(value) is bytes:  # Parsing to uuid object
                value = UUID(bytes=value)

            else:
                continue
            setattr(self, field.name, value)


@dataclass
class RequestHeader(BaseParser):
    client_id: UUID
    version: int
    code: RequestId
    payload_size: int


# Payload's data structures
@dataclass
class SendPublicKeyPayload(BaseParser):
    name: str
    public_key: bytes


@dataclass
class RegisterReqPayload(BaseParser):
    name: str


@dataclass
class LoginPayload(BaseParser):
    name: str


@dataclass
class SendFilePayload(BaseParser):
    content_size: int
    orig_file_size: int
    packetNo: int
    totalNo: int
    file_name: str
    message_content: bytes


@dataclass
class CrcPayload(BaseParser):
    file_name: str


RequestCodesMap = {
    RequestId.LOGIN: LoginPayload,
    RequestId.REGISTER: RegisterReqPayload,
    RequestId.SEND_PUBLIC_KEY: SendPublicKeyPayload,
    RequestId.SEND_FILE: SendFilePayload,
    RequestId.VALID_CRC: CrcPayload,
    RequestId.INVALID_CRC: CrcPayload,
    RequestId.INVALID_CRC_ABORT: CrcPayload
}

RequestContentMap: Dict[Type,str] = {
    RequestHeader: f"<{MAX_UID_LENGTH}sBHL",
    RegisterReqPayload: f"<{MAX_NAME_LENGTH}s",
    LoginPayload: f"<{MAX_NAME_LENGTH}s",
    SendPublicKeyPayload: f"<{MAX_NAME_LENGTH}s{MAX_PUBLIC_KEY_SIZE}s",
    SendFilePayload: f"LLHH{MAX_FILE_NAME_LENGTH}s{CHUNK_SIZE}s",
    CrcPayload: f"<{MAX_UID_LENGTH}s{MAX_FILE_NAME_LENGTH}s",
}


#                       ### Server's Response ###         #
class ResponseId(Enum):
    REGISTRATION_SUCCESSFUL = 1600
    REGISTRATION_FAILED = 1601
    RECEIVED_PUBLIC_KEY_AND_SENDING_AES = 1602
    FILE_RECEIVED_OK = 1603
    CONFIRMING_RECEIPT_MESSAGE = 1604
    SUCCESSFUL_LOGIN = 1605
    LOGIN_REJECTED = 1606
    GENERAL_ERROR = 1607


@dataclass
class ResponseHeader:
    version: int
    code: ResponseId
    payload_size: int


# Payload's data structures
@dataclass
class RegistrationSuccessfulPayload:
    client_id: bytes


@dataclass
class ReceivedPublicKeySendingAesPayload:
    client_id: bytes
    encrypted_symmetric_key: bytes


@dataclass
class FileReceivedOkWithCrcPayload:
    client_id: bytes
    content_size: int
    file_name: str
    cksum: bytes


@dataclass
class ConfirmingReceiptOfMessagePayload:
    client_id: bytes


@dataclass
class ReconnectRequestRejectedPayload:
    client_id: bytes


CodeResponseMapping = {
    ResponseId.REGISTRATION_SUCCESSFUL: RegistrationSuccessfulPayload,
    ResponseId.RECEIVED_PUBLIC_KEY_AND_SENDING_AES: ReceivedPublicKeySendingAesPayload,
    ResponseId.FILE_RECEIVED_OK: FileReceivedOkWithCrcPayload,
    ResponseId.CONFIRMING_RECEIPT_MESSAGE: ConfirmingReceiptOfMessagePayload,
    ResponseId.SUCCESSFUL_LOGIN: ReceivedPublicKeySendingAesPayload,
    ResponseId.LOGIN_REJECTED: ReconnectRequestRejectedPayload
}

ResponseEncode: Dict[Type, str] = {
    ResponseHeader: "<BHL",
    RegistrationSuccessfulPayload: f"<{MAX_UID_LENGTH}s",
    ReceivedPublicKeySendingAesPayload: f"<{MAX_UID_LENGTH}s{{0}}s",
    FileReceivedOkWithCrcPayload: f"<{MAX_UID_LENGTH}sL{MAX_FILE_NAME_LENGTH}sL{MAX_FILE_NAME_LENGTH}s",
    ConfirmingReceiptOfMessagePayload: f"<{MAX_UID_LENGTH}s",
    ReconnectRequestRejectedPayload: f"<{MAX_UID_LENGTH}s",
}
