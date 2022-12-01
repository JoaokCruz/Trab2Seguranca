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

def client_program():
    host = socket.gethostname()  
    port = 6789  

    client_socket = socket.socket()  
    client_socket.connect((host, port)) 
    print("Esta conectado!....")
    BASE_URL = "http://127.0.0.1:5000" 

    client = requests.get(f"{BASE_URL}/generate-keys").json()
    client_private, client_public = client["private_key"], client["public_key"]
    
    client_socket.send(client_public.encode())
    message = ""  
    first = 0
    msg = False
    while message.lower().strip() != 'bye':
        if (first == 0):
            data = client_socket.recv(1024).decode()
            client_params = {"local_private_key": client_private, "remote_public_key": data}
            client_shared_key = requests.get(
                f"{BASE_URL}/generate-shared-key", params=client_params
                ).json()["shared_key"]

            first+=1
            
        if(msg):
            message = input("Alice -> ")
            encrypted_message = encrypt(message, client_shared_key)
            print("Mensagem enviada encryptada : " + encrypted_message)
            
            client_socket.send(encrypted_message.encode())  
            first+=1

        msg = True
        data = client_socket.recv(1024).decode()  
        print("-----------------------------------------")
        print("Mensagem criptografada recebida: " + data)
        decrypted_message = decrypt(data, client_shared_key)
        
        print('Bob -> ' + decrypted_message)  

        
    client_socket.close() 


if __name__ == '__main__':
    client_program()