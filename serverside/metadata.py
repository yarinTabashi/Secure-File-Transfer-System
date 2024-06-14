import logging
from typing import List
from protocol_definitions import UUID
from typing import Dict

logger = logging.getLogger(__name__)


#  This module includes several classes for managing client metadata and file information
class FilesMetadata:
    def __init__(self, file_name):
        self.file_name = file_name


class ClientMetadata:
    def __init__(self, client_id: UUID, name, public_key=None, private_key=None, aes_key=None):
        self.client_id = client_id
        self.name = name
        self.public_key: bytes = public_key  # The RSA pair (public and private)
        self.private_key: bytes = private_key
        self.aes_key: bytes = aes_key  # The decrypted AES symmetric key
        self.files: List[FilesMetadata] = []

    def get_private_key(self):
        return self.private_key

    def set_public_key(self, public_key):
        self.public_key = public_key


class MetaDB:
    def __init__(self):
        self.name_to_uuid_dict: Dict[str, UUID] = {}  # Get the UUID of a specific user by his name
        self.uuid_to_meta_dict: Dict[UUID, ClientMetadata] = {}  # Get metadata object of a specific user by his UUID

    def is_exist(self, client_name: str = None, client_uuid: UUID = None) -> bool:
        if client_name in self.name_to_uuid_dict or client_uuid in self.uuid_to_meta_dict:
            return True
        return False

    def register(self, client: ClientMetadata):
        if not self.is_exist(client.name):
            self.name_to_uuid_dict[client.name] = client.client_id
            self.uuid_to_meta_dict[client.client_id] = client
            return True

        raise Exception("This client name already exists.")

    def login(self, client_name: str, client_id: UUID):
        if self.is_exist(client_name):
            return self.uuid_to_meta_dict[client_id]
        else:
            return None

    def save_public_key(self, client_id: UUID, public_key):
        self.uuid_to_meta_dict[client_id].set_public_key(public_key)

    def save_aes_key(self, uuid, aes_key):
        self.uuid_to_meta_dict[uuid].aes_key = aes_key

    def get_aes_key(self, uuid) -> bytes:
        return self.uuid_to_meta_dict[uuid].aes_key

    def add_file(self, uuid, name):
        self.uuid_to_meta_dict[uuid].files.append(FilesMetadata(name))