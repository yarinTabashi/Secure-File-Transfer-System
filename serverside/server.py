import socket
import server_session
import os
from metadata import *
import threading
import logging

PORT_FILE_PATH = "port.info"
DEFAULT_PORT_NUM = 1234
DEFAULT_HOST = ''
MAX_QUEUE_SIZE = 5

logger = logging.getLogger(__name__)


def initialize_log():
    # Create logger
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%H:%M:%S')

    # Create console handler and set level to INFO
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(formatter)
    logger.addHandler(ch)


# Reading his port from a file, named 'port.info', if not exist - the default is '127.0.0.1'.
def get_port(file_path=PORT_FILE_PATH):
    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()
            if len(lines) == 1:
                return int(lines[0])
            else:
                logger.warning("Port number cannot be found.")
    except FileNotFoundError:
        logger.warning("The port number cannot be found. Default number: ", DEFAULT_PORT_NUM)
        return int(DEFAULT_PORT_NUM)


# Create a server that listening to calls (up to 5), and it creates a thread to handle with every socket.
class Server:
    def __init__(self):
        self.port = get_port()
        self.host = DEFAULT_HOST
        self.meta_db = MetaDB()

    def start(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:

                server.bind((self.host, self.port))
                server.listen(MAX_QUEUE_SIZE)

                logger.info("Start server... \n Waiting for clients...")
                while True:
                    client_socket, address = server.accept()
                    logger.info(f"Got a new client from address {address}.")
                    server_session.Session(client_socket, self.meta_db).start()
        except Exception as e:
            logger.error(f"Oops! An error occurred: {e}")

initialize_log()
server_instance = Server()
server_instance.start()