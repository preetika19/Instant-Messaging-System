import socket
import rsa
import hashlib
from Crypto.Hash import SHA256

bytes_to_send = str.encode("Hello UDP Server")
HOST = socket.gethostbyname(socket.gethostname())
PORT = 4444
ADDR = (HOST, PORT)
buffer_size = 1024

# Create a UDP socket at client side
UDPClientSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)


def get_hash(symmetric_key, iv, plaintext):
    hash = symmetric_key.encode() + iv.encode()
    hashed_data = hashlib.sha256(hash).hexdigest()
    ciphertext = plaintext + '::' + hashed_data
    return ciphertext


def gen_rsa_key(username):
    username = username[6:]
    (public_key, private_key) = rsa.newkeys(1024)
    with open(f'keys/{username}public.pem', 'wb') as p:
        p.write(public_key.save_pkcs1('PEM'))

    return (f'keys/{username}public.pem', private_key)

# Send to server using created UDP socket

# 1.    #send username to authenticate
username = input("Enter your user name:")
# generate rsa_key with and share the public key path with server
public_key, private_key = gen_rsa_key(username)


path_for_public_key_username = username + "," + public_key
# client_socket.send(send_msg.encode())
UDPClientSocket.sendto(path_for_public_key_username.encode(), ADDR)
username = username[6:]

# auth reply received back- has encrypted nonce
msg_for_auth = UDPClientSocket.recvfrom(buffer_size)
# msg_for_auth_decoded = msg_for_auth

decrypted_nonce_auth = rsa.decrypt(msg_for_auth[0], private_key)
decrypted_nonce_auth = 'AUTH' + username + ',' + str(decrypted_nonce_auth)
print("Decrypted message: ", decrypted_nonce_auth)
UDPClientSocket.sendto(decrypted_nonce_auth.encode(), ADDR)


# msg received has list of clients with state
msgFromServer = UDPClientSocket.recvfrom(buffer_size)
msg_status = "Message from Server {}".format(msgFromServer[0].decode())
print(msg_status)

# to check idle counts
# check if no one is idle, if yes then make the client in receiving mode
clients_list, clients_status = msgFromServer[0].decode().split(',')


if (clients_status == 'ZERO'):
    while True:
        # client will go to listening mode message from other clients
        msg_from_client = UDPClientSocket.recvfrom(buffer_size)
        msg_from_client_sk_iv = msg_from_client[0].decode()
        msg_from_client_sk_iv = msg_from_client_sk_iv.split('|')
        symmetric_key = msg_from_client_sk_iv[1]
        iv = msg_from_client_sk_iv[2]
        message_hash = msg_from_client_sk_iv[0].split('::')
        plaintext = message_hash[0]
        hashed_val = message_hash[1]

        latest_hash_val = get_hash(symmetric_key, iv, plaintext)
        latest_hash_val = latest_hash_val.split('::')[1]
        print(f'Message received {plaintext}')
        if plaintext == 'BREAK':
            break

        if latest_hash_val != hashed_val:
            print('Message corrupted')
        else:
            print('Message is authentic')

        address = msg_from_client[1]

        # 1. #send welcome msg to other user
        send_msg = input("Message to requested user ")
        send_hash_val = get_hash(symmetric_key, iv, send_msg)
        send_concat_mess = str(send_hash_val) + '|' + \
            str(symmetric_key) + '|' + str(iv)
        # client_socket.send(send_msg.encode())
        UDPClientSocket.sendto(send_concat_mess.encode(), address)

        if (send_msg == 'BREAK' or plaintext == 'BREAK'):
            break


else:
    # select the client and share the username with the server
    select_client_from_list = input(
        f"Enter the client name you wish to talk to from the list {clients_list}")
    UDPClientSocket.sendto(select_client_from_list.encode(), ADDR)

    # message from server with other client's ADDR
    other_client_details_ticket = UDPClientSocket.recvfrom(buffer_size)
    client_port_ticket_iv = str(other_client_details_ticket[0]).split('|')
    # other_client_details = other_client_details_ticket.decode()

    client_port = client_port_ticket_iv[0]
    shared_key = client_port_ticket_iv[1]
    initial_vector = client_port_ticket_iv[2]

    while True:
        other_client_port = client_port[client_port.index(',')+1:-1]
        other_client_port = int(other_client_port)
        other_client_addr = (HOST, other_client_port)
        # send welcome msg to other user
        conversation = input("Message to other client ")
        # client_socket.send(send_msg.encode())
        # msg_sent = send_msg.encode()

        if (conversation == 'BREAK'):
            select_client_from_list = select_client_from_list[1:]
            update_status_message = f'UPDATE,{username},{select_client_from_list}'
            UDPClientSocket.sendto(
                update_status_message.encode(), (HOST, PORT))
            break

        hashed_message = get_hash(shared_key, initial_vector, conversation)
        concat_mess = str(hashed_message) + '|' + \
            str(shared_key) + '|' + str(initial_vector)

        UDPClientSocket.sendto(concat_mess.encode(), (other_client_addr))

        # msg received other from client
        msg_other_client = UDPClientSocket.recvfrom(buffer_size)
        msg_other_client = msg_other_client[0].decode()
        msg_hash = str(msg_other_client).split('|')
        msg_hash = msg_hash[0]
        plain_text_hash = msg_hash.split('::')
        plain_text_recv = plain_text_hash[0]
        hash_recv = plain_text_hash[1]
        print(f'Received message {plain_text_recv}')
        if plain_text_recv == "BREAK":
            break
        hash_message = get_hash(
            shared_key, initial_vector, plain_text_recv[0])
        gen_hash_value = hash_message.split("::")[1]
        if gen_hash_value != hash_recv:
            print('Message corrupted')
        else:
            print('Message is authentic')
        # send_msg = input("if you want to end type exit ")

    UDPClientSocket.close()
