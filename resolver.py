import socket

IP = "192.168.40.115"
PORT = 8000
BUFFER_SIZE = 4096


if __name__ == "__main__":
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # TEMPORAL - REMOVER
    # Permite reutilizar rápidamente la dirección/puerto al reiniciar
    # el servidor durante el desarrollo.
    # EVITA... el famoso OSError: [Errno 98] Address already in use
    server_socket.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    socket_address = (IP, PORT)
    server_socket.bind(socket_address)

    print(f'SERVER DNS -> {IP}:{PORT}')

    try:
        while True:
            data, client_address = server_socket.recvfrom(BUFFER_SIZE)

            print("MENSAJE DNS RECIBIDO")
            print(f"CLIENTE: {client_address}")

            print(data)

    finally:
        server_socket.close()