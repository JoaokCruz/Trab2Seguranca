# Para rodar primeiro precisamos instalar
1.  Python
2.  Flask
3.  flask_cors

# Ordem de inicializacao do projeto
1. python app.py
2. python server.py
3. python client.py

# app.py
Possui um framework web Python que funciona para realizar a criptografia DiffieHellman

# server.py
Server utilizado a base de socket para realizar a conexao com o cliente (bob)

# cliente.py
Cliente que conecta no server para realizar o chat (alice)

# Funcionalidade
Ao realizar a conexao entre servidor e cliente ha um troca de chaves utilizando a criptografia DiffieHellman, posteriormente a conexao e realizada e a chave e utilizada para criptografar e descriptografar as mensagens do chat.