import socket
import requests

def xor_encrypt_decrypt(message: str, key_string: str):
    key = list(key_string)
    output = []
    for i in range(len(message)):
        char_code = ord(message[i]) ^ ord(key[i % len(key)][0])
        output.append(chr(char_code))
    return "".join(output)

def encrypt(message: str, key: str):
    return xor_encrypt_decrypt(message, key)


def decrypt(encrypted_message: str, key: str):
    return xor_encrypt_decrypt(encrypted_message, key)

def server_program():
    
    BASE_URL = "http://127.0.0.1:5000"
    host = socket.gethostname()
    port = 6789  

    server_socket = socket.socket()  
    
    server_socket.bind((host, port))  
    server = requests.get(f"{BASE_URL}/generate-keys").json()
    server_private, server_public = server["private_key"], server["public_key"]

    
    server_socket.listen(2)
    conn, address = server_socket.accept()  
    print("Conexao realizada com sucesso! Digite algo no chat....")
    first=0
    while True:
        
        data = conn.recv(1024).decode()
        if(first==0):
            server_params = {"local_private_key": server_private, "remote_public_key": data}
            server_shared_key = requests.get(
                f"{BASE_URL}/generate-shared-key", params=server_params
                ).json()["shared_key"]

            conn.send(server_public.encode())
            data = address
            first+=1
        if not data:
            
            break
        if(not (data == address)):
            
            print("Mensagem criptografada recebida: " + data)
            data = decrypt(data, server_shared_key)
            print('Alice -> ' +  str(data))
        print("-----------------------------------------")
        data = input('Bob -> ')

        encrypted_message = encrypt(data, server_shared_key)
        print("Mensagem enviada encryptada : " + encrypted_message)
        conn.send(encrypted_message.encode())  # send data to the client

    conn.close()  # close the connection


if __name__ == '__main__':
    server_program()