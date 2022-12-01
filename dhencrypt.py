from binascii import hexlify
from hashlib import sha256
from os import urandom

chaves = {
    # 512-bit
    1: {
        "chave": int(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
            + "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
            + "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
            + "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
            + "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
            + "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
            + "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
            + "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF",
            base=16,
        ),
        "gerador": 2,
    },
    # 1024-bit
    2: {
        "chave": int(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
            + "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
            + "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
            + "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
            + "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
            + "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
            + "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
            + "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF",
            base=16,
        ),
        "gerador": 2,
    },
    # 256-bits
    3: {
        "chave": int(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
            + "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
            + "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
            + "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
            + "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
            + "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
            + "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
            + "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
            + "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
            + "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
            + "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
            base=16,
        ),
        "gerador": 2,
    },
}


class DiffieHellman:
    def __init__(self, bits: int = 3) -> None:
        if bits not in chaves:
            raise ValueError("sem suporte para esses bits")
        self.chave = chaves[bits]["chave"]
        self.gerador = chaves[bits]["gerador"]

        self.__private_key = int(hexlify(urandom(32)), base=16)

    def get_private_key(self) -> str:
        return hex(self.__private_key)[2:]

    def generate_public_key(self) -> str:
        public_key = pow(self.gerador, self.__private_key, self.chave)
        return hex(public_key)[2:]

    def is_valid_public_key(self, key: int) -> bool:
        if 2 <= key and key <= self.chave - 2:
            if pow(key, (self.chave - 1) // 2, self.chave) == 1:
                return True
        return False

    def generate_shared_key(self, other_key_str: str) -> str:
        other_key = int(other_key_str, base=16)
        if not self.is_valid_public_key(other_key):
            raise ValueError("Invalid public key")
        shared_key = pow(other_key, self.__private_key, self.chave)
        return sha256(str(shared_key).encode()).hexdigest()

    @staticmethod
    def is_valid_public_key_static(
        local_private_key_str: str, remote_public_key_str: str, chave: int
    ) -> bool:
        # check if the other public key is valid based on NIST SP800-56
        if 2 <= remote_public_key_str and remote_public_key_str <= chave - 2:
            if pow(remote_public_key_str, (chave - 1) // 2, chave) == 1:
                return True
        return False

    @staticmethod
    def generate_shared_key_static(
        local_private_key_str: str, remote_public_key_str: str, bits: int = 3
    ) -> str:
        local_private_key = int(local_private_key_str, base=16)
        remote_public_key = int(remote_public_key_str, base=16)
        chave = chaves[bits]["chave"]
        if not DiffieHellman.is_valid_public_key_static(
            local_private_key, remote_public_key, chave
        ):
            raise ValueError("Invalid public key")
        shared_key = pow(remote_public_key, local_private_key, chave)
        return sha256(str(shared_key).encode()).hexdigest()