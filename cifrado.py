from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto import Random
from Crypto.Signature import PKCS1_v1_5

class AESCipher:

    def __init__(self, key, file):
        self.key = key
        self.file = file
        self.bs = 1024
        self.exit_file = file + '.enc'
        self.mode = AES.MODE_CBC
        self.tiv = AES.block_size
        self.iv = Random.new().read(self.tiv)

    def cifrar(self):
        cipher = AES.new(self.key.encode("utf8"), self.mode, self.iv)

        with open(self.file, 'rb') as entrada:
            with open(self.exit_file, 'wb') as salida:
                salida.write(self.iv)

                bloque = entrada.read(self.bs)

                while len(bloque) != 0:
                    completar = self.bs - len(bloque) % self.bs
                    bloque += ' '.encode(encoding='UTF-8') * completar
                    salida.write(cipher.encrypt(bloque))
                    bloque = entrada.read(self.bs)

    def descifrar(self):
        exit_file = self.file + '.dec'

        with open(self.exit_file, 'rb') as entrada:
            with open(exit_file, 'wb') as salida:
                iv = entrada.read(AES.block_size)
                decipher = AES.new(self.key.encode("utf8"), self.mode, iv)

                bloque = entrada.read(self.bs)

                while len(bloque) != 0:
                    salida.write(decipher.decrypt(bloque))
                    bloque = entrada.read(self.bs)

class Hash_Cipher:
    def init(self, file):
        self.file = file

    def get_hash(self, save_out=False):
        bs = 1024
        my_hash = SHA256.new()

        with open(self.file, 'rb') as entrada:
            temp = entrada.read(bs)
            while len(temp) > 0:
                my_hash.update(temp)
                temp = entrada.read(bs)

        # Guarda el contenido del hash en un fichero de salida con la extensión '.hash'
        if save_out:
            ficheroSalida = self.file + '.hash'
            with open(ficheroSalida, 'w') as salida:
                salida.write(my_hash.hexdigest())

        return my_hash

class RSACipher:
    def __init__(self, file, password, hash):
        self.hash = hash
        self.file = file
        self.password = password
        self.private_key_file = 'clave.bin'
        self.public_key_file = 'clave.pub'
        self.length_key = 2048
        self.key = RSA.generate(self.length_key)
        self.private_key = self.key.exportKey(passphrase=password)
        self.public_key = self.key.publickey().exportKey()

        with open(self.private_key_file, 'wb') as private:
            with open(self.public_key_file, 'wb') as public:
                private.write(self.private_key)
                public.write(self.public_key)

    def cifrar_RSA(self):
        key = RSA.import_key(open(self.private_key).read(), passphrase=self.password)

        sign = PKCS1_v1_5.new(key)
        signature = sign.sign(self.hash)
        passwd = sign.sign(self.password)

        signature_file = self.file + '.firma'

        with open(signature_file, 'wb') as output:
            output.write(signature)
            output.write()

    def descifrar_RS(self):
        pass










if __name__ == '__main__':
    fichero = "texto"
    passwd = "mysecretpassword"

    my_hash = Hash_Cipher(fichero)
    hash_file = my_hash.get_hash()
    print(hash_file.hexdigest())

    cipher = AESCipher(passwd, fichero)
    cipher.cifrar()
    cipher.descifrar()

