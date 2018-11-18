from Crypto.Cipher import AES
from Crypto import Random

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





if __name__ == '__main__':
    cipher = AESCipher("mysecretpassword", "texto")
    cipher.cifrar()
    cipher.descifrar()

