from protocol_definitions import *
from dataclasses import dataclass, fields
from enum import Enum
from socket import socket
import struct
from typing import Any, Type
import logging

logger = logging.getLogger(__name__)


#                       ### Requests handling (Parse a request to their dataclass) ###         #
def get_request(client: socket, request_type: Type) -> Any:
    # Find the type of the request in map, in order to get its format. Then, Calculate the size.
    request_format = RequestContentMap[request_type]
    bytes_content = client.recv(struct.calcsize(request_format))
    x = len(bytes_content)

    if bytes_content == b'':
        raise Exception("Client Disconnected")

    # Parse it into the relevant data class and returns it.
    paras = struct.unpack(request_format, bytes_content)
    return request_type(*paras)


#                       ### Responses handling (Create a response dataclass and parse it to a string) ###         #
def get_packed_response(data_class, *lens) -> bytes:
    res_format = ResponseEncode[type(data_class)]
    res_format = res_format.format(*lens)

    vals = []
    for field in fields(data_class):
        val = getattr(data_class, field.name)
        if issubclass(type(val), Enum):
            val = val.value
        elif isinstance(val, str):
            val = bytes(val, 'charmap')
        vals.append(val)

    return struct.pack(res_format, *vals)


def generate_response(*lens, payload=None, response_code: ResponseId) -> bytes:
    payload_b = None  # The payload in bytes

    if payload is None:
        payload_b = bytes(0)
    else:
        payload_b = get_packed_response(payload, *lens)
    header = ResponseHeader(version=3, code=response_code, payload_size=len(payload_b))
    payload_header = get_packed_response(header)
    sum = payload_header + payload_b
    return sum