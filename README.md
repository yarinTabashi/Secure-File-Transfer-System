# Secure-File-Transfer-System
This project presents a client-server software solution designed for secure file transfer. Clients can encrypt and transfer files to a server for storage. The server, written in Python, communicates with the client, which is implemented in C++.

## Functionality Overview
- **Client-Initiated Communication:** The client autonomously establishes contact with the server, initiating the exchange of encryption keys.
- **Secure File Transfer:** Files are transferred via encrypted communication channels. The client ensures file integrity by verifying checksums, and if necessary, attempts retransmission.
- **Encryption Protocols:** The protocol operates over TCP and utilizes both symmetric and asymmetric encryption.
- **Symmetric Encryption:** AES CBC mode is employed for file encryption.
- **Asymmetric Encryption:** RSA encryption facilitates the secure exchange of symmetric keys between the client and server.



## Protocol:
#### Client Requests
| Parameter | Description                       |
| :-------- | :-------------------------------- |
| 1025      | Registration request |
| 1026      | Transmission of public key |
| 1027      | Reconnection request (if client has previously registered) |
| 1028      | File transmission request |
| 1029      | CRC verification successful |
| 1030      | CRC verification failed; file resent |
| 1031      | CRC failure after multiple attempts; operation terminated |

#### Server Responses
| Parameter | Description                       |
| :-------- | :-------------------------------- |
| 1600      | Successful client registration |
| 1601      | Registration failure |
| 1602      | Receipt of public key; encrypted AES key sent |
| 1603      | File received with successful CRC verification |
| 1604      | Confirmation of message receipt |
| 1605      | Reconnection request approved; encrypted AES key sent |
| 1606      | Reconnection request rejected; client must re-register |
| 1607      | General server error |
