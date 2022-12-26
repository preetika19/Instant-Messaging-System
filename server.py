import os
import socket
import rsa
import string
import random


def shared_key_gen(size=24, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))


HOST = socket.gethostbyname(socket.gethostname())
PORT = 4444
ADDR = (HOST, PORT)
buffer_size = 1024

# UDP Datagram Socket
UDPServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

# Bind Server to ADDR
UDPServerSocket.bind(ADDR)
print("Server is up and running")

users = {}
client_address_dict = {}
client_auth_dict = {}
client_status_dict = {}


def add_client_status(client_name, addr):
    client_address_dict[client_name] = addr
    # client_status_dict[client_name] = 'IDLE'
    client_auth_dict[username] = ''


def encrypt_nonce(name):
    with open(f'keys/{name}public.pem') as filereader:
        pkeydata = filereader.read()

    pubkey = rsa.PublicKey.load_pkcs1(pkeydata)
    nonce = os.urandom(10)

    # msg = random_text.encode('utf8')
    print("Random encoded text: ", nonce)

    encrypt_msg = rsa.encrypt(nonce, pubkey)
    print("encrypted message: ", encrypt_msg)

    return nonce, encrypt_msg


def count_idle_clients(status_dict):
    print(f'count_idle_clients {status_dict}')
    idle_clients = 0
    for k, v in status_dict.items():
        if v == 'IDLE':
            idle_clients += 1

    return idle_clients


def get_available_clients_list(status_dict):
    print(f'get_available_clients_list {status_dict}')
    idle_clients_list = ''
    for k, v in status_dict.items():
        if v == 'IDLE':
            idle_clients_list += '| ' + k
    return idle_clients_list


while (True):

    # read the input from client
    message_address_pair = UDPServerSocket.recvfrom(buffer_size)

    message = message_address_pair[0].decode()
    print(f"message from client {message}")

    # address
    address = message_address_pair[1]

    if message.startswith("CLIENT"):
        username, public_key = message.split(',')
        username = username[6:]

        print(f'Client address {address}')

        # add username and ip in dictionary
        add_client_status(username, address)
        print(f'Client ports list {client_address_dict}')

        # generate random nonce encrypt using client's public key
        nonce, encrypt_msg = encrypt_nonce(username)

        # adding nonce to client_auth_dict
        client_auth_dict[username] = nonce

        # send encrypt_msg to client for auth
        UDPServerSocket.sendto(encrypt_msg, address)

    elif message.startswith("AUTH"):
        msg = message.split(',')
        client_name = msg[0]
        received_nonce = msg[1]
        client_name = client_name[4:]
        generated_nonce = str(client_auth_dict[client_name])
        available_clients_msg = ''
        if received_nonce == generated_nonce:
            print('Authenticated')
            client_status_dict[client_name] = 'IDLE'
            idle_clients_count = count_idle_clients(client_status_dict)
            if idle_clients_count == 1:
                available_clients_msg = f'There are no available clients in the system to talk,ZERO'
            else:
                print('There are one or more clients available to talk')
                clients_list = get_available_clients_list(client_status_dict)
                available_clients_msg = f'Select the client in the list {clients_list},NONZERO'

            # msg = "List of clients with status, " + str(client_status_dict)
        else:
            print('Unable to Authenticate')
            available_clients_msg = "Unable to Authenticate,FAILED"

        print(f'available_clients_msg {available_clients_msg}')
        UDPServerSocket.sendto(available_clients_msg.encode(), address)

    elif message.startswith("@"):
        # intiate conversation between two clients
        client_to = message[1:]

        shared_key = shared_key_gen()
        initial_vector = os.urandom(16)

        client_to_address = str(client_address_dict.get(client_to))
        ticket = client_to_address + '|' + \
            str(shared_key) + '|' + str(initial_vector)
        client_status_dict[client_to] = 'BUSY'
        client_status_dict[username] = 'BUSY'

        print(f'client_to_address {client_to_address}')
        UDPServerSocket.sendto(ticket.encode(), address)

    elif message.startswith("UPDATE"):
        clients_to_idle = message.split(',')
        print(f'clients_to_idle {clients_to_idle}')
        client_status_dict[clients_to_idle[1]] = 'IDLE'
        client_status_dict[clients_to_idle[2]] = 'IDLE'
        print(f'UPDATE {client_status_dict}')
