import os
import threading
from uuid import uuid4
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA
import protocol_handle
from protocol_handle import *
from protocol_definitions import *
from metadata import *
import checksum

BASE_FILES_DIRECTORY = 'clients files'

logger = logging.getLogger(__name__)


class Session(threading.Thread):
    def __init__(self, client_socket : socket, meta_db: MetaDB):
        super().__init__(daemon=True)
        self.client_socket = client_socket
        self.meta_db = meta_db

    def start(self):
        try:
            while True:
                self.handle_request()
        except Exception as e:
            logger.error(f"An error occurred in session: {e}")

        try: # When error occurred:
            self.client_socket.close()
        except IOError:
            pass

    def handle_request(self):
        req_header: RequestHeader = protocol_handle.get_request(self.client_socket, RequestHeader)
        req_content = protocol_handle.get_request(self.client_socket, RequestCodesMap[req_header.code])

        if req_header.code == RequestId.REGISTER:  # 1025
            return self.register(req_header, req_content)
        elif req_header.code == RequestId.LOGIN:  # 1027
            return self.login(req_header, req_content)

        # Permission validation
        if not self.meta_db.is_exist(client_uuid=req_header.client_id):
            logger.info("This request necessitates permissions. The client must be registered to perform it.")
            self.client_socket.send(generate_response(response_code=ResponseId.GENERAL_ERROR))
            return

        if req_header.code == RequestId.SEND_PUBLIC_KEY:  # 1026
            return self.receive_public_key(req_header, req_content)
        elif req_header.code == RequestId.SEND_FILE:  # 1028
            return self.receive_file(req_header, req_content)
        elif req_header.code == RequestId.VALID_CRC or req_header.code == RequestId.INVALID_CRC \
                or req_header.code == RequestId.INVALID_CRC_ABORT:
            return self.crc_handle(req_header, req_content)
        else:
            logger.info("Received unknown request. ")
            self.client_socket.send(generate_response(response_code=ResponseId.GENERAL_ERROR))  # 1607

    def register(self, req_header: RequestHeader, req_content: RegisterReqPayload):
        is_exists = self.meta_db.is_exist(client_uuid=req_header.client_id)
        if is_exists:  # If client already exists and request to register - send 1601 response
            self.client_socket.send(generate_response(response_code=ResponseId.REGISTRATION_FAILED))

        client_uuid = self.generate_uuid()
        self.meta_db.register(ClientMetadata(client_uuid, req_content.name))
        payload = RegistrationSuccessfulPayload(client_uuid.bytes)
        self.client_socket.send(generate_response(payload=payload, response_code=ResponseId.REGISTRATION_SUCCESSFUL))

    def login(self, request_header: RequestHeader, request_payload: LoginPayload):
        client = self.meta_db.login(request_payload.name, request_header.client_id)
        if client is not None:  # It means isn't registered.
            payload = ReceivedPublicKeySendingAesPayload(request_header.client_id.bytes, client.get_private_key())
            self.client_socket.send(generate_response(payload=payload, response_code=ResponseId.SUCCESSFUL_LOGIN))
        else:
            payload = ReconnectRequestRejectedPayload(request_header.client_id.bytes)
            self.client_socket.send(generate_response(payload=payload, response_code=ResponseId.LOGIN_REJECTED))

    def receive_public_key(self, request_header: RequestHeader, request_payload: SendPublicKeyPayload):
        # Save the public key (public of rsa) in db
        if self.meta_db.is_exist(request_payload.name):
            self.meta_db.save_public_key(request_header.client_id, request_payload.public_key)

        # Creating an aes (symmetric) key and encrypting it by the public key.
        aes_key = self.generate_aes_key()

        loaded_key = RSA.import_key(request_payload.public_key)
        encrypted_aes = PKCS1_OAEP.new(loaded_key).encrypt(aes_key)

        self.meta_db.save_aes_key(request_header.client_id, aes_key)
        payload = ReceivedPublicKeySendingAesPayload(request_header.client_id.bytes, encrypted_aes)
        aes_size = len(encrypted_aes)
        self.client_socket.send(generate_response(aes_size, payload=payload, response_code=ResponseId.RECEIVED_PUBLIC_KEY_AND_SENDING_AES))

    def receive_file(self, request_header: RequestHeader, request_payload: SendFilePayload):
        encrypted_content = self.get_content_by_chunks(request_payload)  # Whole chained chunks
        client_aes = self.meta_db.get_aes_key(request_header.client_id)

        # Decrypt the file and save it in the disk.
        cipher = AES.new(key=client_aes, mode=AES.MODE_CBC, iv=(b'\0' * 16))

        decrypted = cipher.decrypt(encrypted_content)
        with open(request_payload.file_name, 'wb') as f:
            f.write(decrypted)

        # Calculate the crc on the whole file (not on every chunk)
        crc = checksum.readfile(request_payload.file_name)

        # Send the response
        payload = FileReceivedOkWithCrcPayload(request_header.client_id.bytes, request_payload.content_size, request_payload.file_name, crc)
        self.client_socket.send(generate_response(payload=payload, response_code=ResponseId.FILE_RECEIVED_OK))

    # Handle one of the three CRC requests.
    def crc_handle(self, request_header: RequestHeader, request_payload: CrcPayload):
        req_id = request_header.code

        # No need to response about 'invalid crc'
        if req_id == RequestId.VALID_CRC:
            self.meta_db.add_file(request_header.client_id, request_payload.file_name)

        if req_id == RequestId.VALID_CRC or req_id == RequestId.INVALID_CRC_ABORT:
            payload = ConfirmingReceiptOfMessagePayload(request_header.client_id.bytes)
            self.client_socket.send(generate_response(payload=payload, response_code=ResponseId.CONFIRMING_RECEIPT_MESSAGE))

    @staticmethod
    def generate_aes_key():
        return os.urandom(32)

    @staticmethod
    def generate_uuid() -> UUID:
        return uuid4()

    @staticmethod
    def ensure_directory_exists(directory_path):
        if not os.path.exists(directory_path):
            os.makedirs(directory_path)

    def get_content_by_chunks(self, first_chunk_payload : SendFilePayload):
        chained_chunks = bytes(0)
        chained_chunks += first_chunk_payload.message_content

        expected_cur_no = 1

        # Initialize parameters according to the first chunk
        total_packets = first_chunk_payload.totalNo
        expected_name = first_chunk_payload.file_name

        while expected_cur_no < total_packets:
            # Validations
            cur_packet_header: RequestHeader = protocol_handle.get_request(self.client_socket, RequestHeader)
            if cur_packet_header.code is not RequestId.SEND_FILE:
                return

            cur_packet_payload : SendFilePayload = protocol_handle.get_request(self.client_socket, RequestCodesMap[cur_packet_header.code])
            if cur_packet_payload.packetNo is not expected_cur_no or cur_packet_payload.file_name is not expected_name:
                return

            chained_chunks += cur_packet_payload.message_content
            expected_cur_no += 1

        return chained_chunks
