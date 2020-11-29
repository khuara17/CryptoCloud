# import os
# from Crypto.Cipher import Blowfish
# from struct import pack


# def encrypt(infilepath, outfilepath, key):
#     """ Encrypt the specified file with the specified
#        key and output to the chosen output file."""

#     size = os.path.getsize(infilepath)
#     infile = open(infilepath, 'rb')
#     outfile = open(outfilepath, 'wb')
#     data = infile.read()
#     infile.close()

#     if size % 8 > 0:  # Add padding if size if not divisible by 8
#         extra = 8-(size % 8)
#         padding = [0]*extra
#         padding = pack('b'*extra, *padding)
#         data += padding

#     revdata = reversebytes(data)
#     encrypted_data = encryptbytes(revdata, key)
#     finaldata = reversebytes(encrypted_data)
#     outfile.write(finaldata)
#     outfile.close()


# def encryptbytes(data, key):

#     cipher = Blowfish.new(key, Blowfish.MODE_ECB)
#     return cipher.encrypt(data)


# def decrypt(infilepath, outfilepath, key):
#     """ Decrypt the specified file with the specified
#        key and output to the chosen output file"""

#     infile = open(infilepath, 'rb')
#     outfile = open(outfilepath, 'wb')
#     data = infile.read()
#     infile.close()

#     revdata = reversebytes(data)
#     decrypted_data = decryptbytes(revdata, key)
#     finaldata = reversebytes(decrypted_data)

#     end = len(finaldata) - 1
#     while str(finaldata[end]).encode('hex') == '00':
#         end -= 1

#     finaldata = finaldata[0:end]

#     outfile.write(finaldata)
#     outfile.close()


# def decryptbytes(data, key):

#     cipher = Blowfish.new(key, Blowfish.MODE_ECB)
#     return cipher.decrypt(data)


# def reversebytes(data):
#     """ Takes data and reverses byte order to fit
#         blowfish-compat format. For example, using
#         reversebytes('12345678') will return 43218765."""
#     data_size = 0
#     for n in data:
#         data_size += 1

#     reversedbytes = bytearray()
#     i = 0
#     for x in range(0, data_size/4):
#         a = (data[i:i+4])
#         i += 4
#         z = 0

#         n0 = a[z]
#         n1 = a[z+1]
#         n2 = a[z+2]
#         n3 = a[z+3]
#         reversedbytes.append(n3)
#         reversedbytes.append(n2)
#         reversedbytes.append(n1)
#         reversedbytes.append(n0)

#     return buffer(reversedbytes)



# ############# USES #############
# infilepath = 'input.txt'
# outfilepath = 'output.txt'
# key = "243F6A88" 
# encrypt(infilepath, outfilepath, key)
# decrypt(infilepath, outfilepath, key)


################ New try #################
 
# import os, sys
# from random import randrange
# from Crypto.Cipher import Blowfish
# from getpass import getpass
# import getopt

# class BFCipher:
#     def __init__(self, pword):
#         self.__cipher = Blowfish.new(pword)
#     def encrypt(self, file_buffer):
#         ciphertext = self.__cipher.encrypt(self.__pad_file(file_buffer))
#         return ciphertext
#     def decrypt(self, file_buffer):
#         cleartext = self.__depad_file(self.__cipher.decrypt(file_buffer))
#         return cleartext
#     # Blowfish cipher needs 8 byte blocks to work with
#     def __pad_file(self, file_buffer):
#         pad_bytes = 8 - (len(file_buffer) % 8)                                 
#         for i in range(pad_bytes - 1): file_buffer += chr(randrange(0, 256))
#         # final padding byte; % by 8 to get the number of padding bytes
#         bflag = randrange(6, 248); bflag -= bflag % 8 - pad_bytes
#         file_buffer += chr(bflag)
#         return file_buffer
#     def __depad_file(self, file_buffer):
#         pad_bytes = ord(file_buffer[-1]) % 8
#         if not pad_bytes: pad_bytes = 8
#         return file_buffer[:-pad_bytes]

# if __name__ == '__main__':

#     def print_usage():
#         usage = "Usage: bfc -[e(encrypt) | d(decrypt) | c('cat' like)] infile [outfile]"
#         print (usage); sys.exit()

#     def writefile(outfile_name, file_buffer):
#         outfile = PrivoxyWindowOpen(outfile_name, 'wb')
#         outfile.write(file_buffer)
#         outfile.close()

#     try: opts, args = getopt.getopt(sys.argv[1:], 'e:d:c:')
#     except getopt.GetoptError: print_usage()

#     opts = dict(opts)
#     try: mode = opts.keys()[0]
#     except IndexError: print_usage()

#     ifname = opts[mode]

#     try: ofname = args[0]
#     except IndexError: ofname = ifname

#     if os.path.exists(ifname):
#         infile = PrivoxyWindowOpen(ifname, 'rb')
#         filebuffer = infile.read()
#         infile.close()
#     else:
#         print ("file '%s' does not exist.\n" % ifname)
#         sys.exit()

#     key = getpass()

#     if mode == '-e':
#         bfc = BFCipher(key); filebuffer = bfc.encrypt(filebuffer)
#         writefile(ofname, filebuffer)
#     elif mode == '-d':
#         bfc = BFCipher(key); filebuffer = bfc.decrypt(filebuffer)
#         writefile(ofname, filebuffer)
#     elif mode == '-c':
#         bfc = BFCipher(key); sys.stdout.write(bfc.decrypt(filebuffer))

#     key = 'x'*len(key); del key


################ New try 2 #################

from Crypto.Cipher import AES
from Crypto.Cipher import Blowfish
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto import Random
from Crypto.Protocol import KDF
from Crypto.Hash import SHA256, HMAC
import base64
import os
import struct
from time import process_time 


class AESCipher(object):
    def __init__(self, key, salt):
        """
        AES cipher, 256-bit key, 128-bit block

        :param key: encryption key
        :param salt: encryption salt
        """
        self.key = KDF.PBKDF2(password=key.encode(), salt=salt.encode(), dkLen=32, count=10000, prf=prf)

    def encrypt(self, plaintext):
        """
        Encrypts the plaintext

        :param plaintext: Plaintext to encrypt
        :return: Encrypted message
        :rtype: str
        """

        plaintext = _pad(plaintext.encode(), AES.block_size)
        cipher = AES.new(key=self.key, mode=AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

    def decrypt(self, ciphertext):
        """
        Decrypts the ciphertext

        :param ciphertext: Ciphertext to decrypt
        :return: Decrypted message
        :rtype: str
        """
        ciphertext = base64.b64decode(ciphertext)
        nonce = ciphertext[:16]
        tag = ciphertext[16:32]
        ciphertext = ciphertext[32:]
        cipher = AES.new(key=self.key, mode=AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return _unpad(plaintext).decode()

    def encrypt_file(self, in_file_name, out_file_name=None, chunk_size=1024 * 64):
        """
        Encrypts the file

        :param in_file_name: Encrypting file name
        :param out_file_name: Encrypted file name (default is in_file_name + .enc)
        :param chunk_size: Block size
        """
        if not out_file_name:
            out_file_name = in_file_name + '.enc'

        file_size = os.path.getsize(in_file_name)

        with open(in_file_name, 'rb') as in_file:
            with open(out_file_name, 'wb') as out_file:
                out_file.write(struct.pack('<Q', file_size))

                while True:
                    chunk = in_file.read(chunk_size)
                    if len(chunk) == 0:
                        break
                    elif len(chunk) % 16 != 0:
                        chunk += b' ' * (16 - len(chunk) % 16)
                    cipher = AES.new(key=self.key, mode=AES.MODE_EAX)
                    ciphertext, tag = cipher.encrypt_and_digest(chunk)
                    [out_file.write(x) for x in (cipher.nonce, tag, ciphertext)]

    def decrypt_file(self, in_file_name, out_file_name=None, chunk_size=1024 * 64):
        """
        Decrypts the file

        :param in_file_name: Decrypting file name
        :param out_file_name: Decrypted file name (default in in_file_name without extension,
        if no extension - in_file_name + .decrypted)
        :param chunk_size: Block size
        """
        if not out_file_name:
            out_file_name = os.path.splitext(in_file_name)[0]
            if out_file_name == in_file_name:
                out_file_name += '.decrypted'

        with open(in_file_name, 'rb') as in_file:
            with open(out_file_name, 'wb') as out_file:
                orig_size = struct.unpack('<Q', in_file.read(struct.calcsize('Q')))[0]

                while True:
                    nonce, tag, chunk = [in_file.read(x) for x in (16, 16, chunk_size)]
                    if len(chunk) == 0:
                        break
                    cipher = AES.new(key=self.key, mode=AES.MODE_EAX, nonce=nonce)

                    out_file.write(cipher.decrypt_and_verify(chunk, tag))
                out_file.truncate(orig_size)


class BlowfishCipher(object):
    def __init__(self, key, salt):
        
        """
        Blowfish cipher, 256-bit key, 64-bit block

        :param key: encryption key
        :param salt: encryption salt
        """
        
        self.key = KDF.PBKDF2(password=key.encode(), salt=salt.encode(), dkLen=32, count=10000, prf=prf)

    def encrypt(self, plaintext):
        """
        Encrypts the plaintext

        :param plaintext: Plaintext to encrypt
        :return: Encrypted message
        :rtype: str
        """

        plaintext = _pad(plaintext.encode(), AES.block_size)
        cipher = Blowfish.new(key=self.key, mode=Blowfish.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return base64.b64encode(cipher.nonce + tag + ciphertext).decode()
 

    def decrypt(self, ciphertext):
        """
        Decrypts the ciphertext

        :param ciphertext: Ciphertext to decrypt
        :return: Decrypted message
        :rtype: str
        """
        ciphertext = base64.b64decode(ciphertext)
        nonce = ciphertext[:16]
        tag = ciphertext[16:32]
        ciphertext = ciphertext[32:]
        cipher = Blowfish.new(key=self.key, mode=Blowfish.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return _unpad(plaintext).decode()

    def encrypt_file(self, in_file_name, out_file_name=None, chunk_size=1024 * 64):
        """
        Encrypts the file

        :param in_file_name: Encrypting file name
        :param out_file_name: Encrypted file name (default is in_file_name + .enc)
        :param chunk_size: Block size
        """
        if not out_file_name:
            out_file_name = in_file_name + '.enc'

        file_size = os.path.getsize(in_file_name)

        with open(in_file_name, 'rb') as in_file:
            with open(out_file_name, 'wb') as out_file:
                out_file.write(struct.pack('<Q', file_size))

                while True:
                    chunk = in_file.read(chunk_size)
                    if len(chunk) == 0:
                        break
                    elif len(chunk) % 16 != 0:
                        chunk += b' ' * (16 - len(chunk) % 16)
                    cipher = Blowfish.new(key=self.key, mode=Blowfish.MODE_EAX)
                    ciphertext, tag = cipher.encrypt_and_digest(chunk)
                    [out_file.write(x) for x in (cipher.nonce, tag, ciphertext)]

    def decrypt_file(self, in_file_name, out_file_name=None, chunk_size=1024 * 64):
        """
        Decrypts the file

        :param in_file_name: Decrypting file name
        :param out_file_name: Decrypted file name (default in in_file_name without extension,
        if no extension - in_file_name + .decrypted)
        :param chunk_size: Block size
        """
        if not out_file_name:
            out_file_name = os.path.splitext(in_file_name)[0]
            if out_file_name == in_file_name:
                out_file_name += '.decrypted'

        with open(in_file_name, 'rb') as in_file:
            with open(out_file_name, 'wb') as out_file:
                orig_size = struct.unpack('<Q', in_file.read(struct.calcsize('Q')))[0]

                while True:
                    nonce, tag, chunk = [in_file.read(x) for x in (16, 8, chunk_size)]
                    if len(chunk) == 0:
                        break
                    cipher = Blowfish.new(key=self.key, mode=Blowfish.MODE_EAX, nonce=nonce)

                    out_file.write(cipher.decrypt_and_verify(chunk, tag))
                out_file.truncate(orig_size)


class RSACipher(object):
    def __init__(self, public_key_loc=None, private_key_loc=None):
        """,
                 public_key_passphrase=None, private_key_passphrase=None
        RSA cipher

        :param public_key_loc: Path to public key file
        :param private_key_loc: Path to private key file
        :param public_key_passphrase: Public key passphrase
        :param private_key_passphrase: Private key passphrase
        """
        self.public_key_loc = public_key_loc
        self.private_key_loc = private_key_loc
        # self.public_key_passphrase = public_key_passphrase
        # self.private_key_passphrase = private_key_passphrase

    def generate_keys(self, keys_size=2048):
        """
        Generate new RSA keys

        :param keys_size: Keys size
        """
        random_generator = Random.new().read
        keys = RSA.generate(keys_size, random_generator)

        with open(self.public_key_loc, 'wb') as public_key_file:
            public_key_file.write(keys.publickey().exportKey(format='PEM')) #, passphrase=self.public_key_passphrase

        with open(self.private_key_loc, 'wb') as private_key_file:
            private_key_file.write(keys.exportKey(format='PEM'))

    def encrypt(self, plaintext):
        """
        Encrypts the plaintext

        :param plaintext: Plaintext to encrypt
        :return: Encrypted message
        :rtype: str
        """
        with open(self.public_key_loc, 'rb') as public_key_file:
            cipher = PKCS1_OAEP.new(RSA.import_key(public_key_file.read()))
            print(cipher)

        return base64.b64encode(cipher.encrypt(plaintext.encode())).decode()

    def decrypt(self, ciphertext):
        """
        Decrypts the ciphertext

        :param ciphertext: Ciphertext to decrypt
        :return: Decrypted message
        :rtype: str
        """
        with open(self.private_key_loc, 'rb') as private_key_file:
            cipher = PKCS1_OAEP.new(RSA.import_key(private_key_file.read()))

        return cipher.decrypt(base64.b64decode(ciphertext.encode())).decode()

    def encrypt_file(self, plaintext, out_file_name, chunk_size=1024 * 64):
        """
        Encrypts the file

        :param in_file_name: Encrypting file name
        :param out_file_name: Encrypted file name (default is in_file_name + .enc)
        :param chunk_size: Block size
        """
        out_file_name = out_file_name + '.enc'

        # file_size = os.path.getsize(in_file_name)
        #
        # with open(in_file_name, 'rb') as in_file:
        with open(out_file_name, 'w') as out_file:
            # out_file.write(struct.pack('<Q', file_size))

            # while True:
            #     chunk = in_file.read(chunk_size)
            #     if len(chunk) == 0:
            #         break
            #     elif len(chunk) % 16 != 0:
            #         chunk += b' ' * (16 - len(chunk) % 16)
            with open(self.public_key_loc, 'rb') as public_key_file:
                cipher = PKCS1_OAEP.new(RSA.import_key(public_key_file.read()))
                print(cipher)
                ciphertext = base64.b64encode(cipher.encrypt(plaintext.encode())).decode()
                out_file.write(ciphertext)

                    # #cipher = Blowfish.new(key=self.key, mode=Blowfish.MODE_EAX)
                    # ciphertext, tag = cipher.encrypt_and_digest(chunk)
                    # [out_file.write(x) for x in (cipher.nonce, tag, ciphertext)]

    def decrypt_file(self, in_file_name, out_file_name=None, chunk_size=1024 * 64):
        """
        Decrypts the file

        :param in_file_name: Decrypting file name
        :param out_file_name: Decrypted file name (default in in_file_name without extension,
        if no extension - in_file_name + .decrypted)
        :param chunk_size: Block size
        """
        if not out_file_name:
            out_file_name = os.path.splitext(in_file_name)[0]
            if out_file_name == in_file_name:
                out_file_name += '.decrypted'

        with open(in_file_name, 'rb') as in_file:
            with open(out_file_name, 'wb') as out_file:
                orig_size = struct.unpack('<Q', in_file.read(struct.calcsize('Q')))[0]

                while True:
                    nonce, tag, chunk = [in_file.read(x) for x in (16, 8, chunk_size)]
                    if len(chunk) == 0:
                        break
                    cipher = Blowfish.new(key=self.key, mode=Blowfish.MODE_EAX, nonce=nonce)

                    out_file.write(cipher.decrypt_and_verify(chunk, tag))
                out_file.truncate(orig_size)

    def sign(self, data):
        """
        Signs the data

        :param data: Data to sign
        :return: Signature
        :rtype: str
        """
        with open(self.private_key_loc, 'rb') as private_key_file:
            signer = PKCS1_v1_5.new(RSA.import_key(private_key_file.read(), passphrase=self.private_key_passphrase))
        digest = SHA256.new(data.encode())

        return base64.b64encode(signer.sign(digest)).decode()

    def verify(self, signature, data):
        """
        Verifies data signature

        :param signature: Signature to verify
        :param data: Signed data
        :return: True / False
        :rtype: Boolean
        """
        with open(self.public_key_loc, 'rb') as public_key_file:
            signer = PKCS1_v1_5.new(RSA.import_key(public_key_file.read(), passphrase=self.public_key_passphrase))
        digest = SHA256.new(data.encode())

        if signer.verify(digest, base64.b64decode(signature)):
            return True
        return False


class HybridAESRSACipher(object):
    def __init__(self, public_key_loc=None, private_key_loc=None,
                 public_key_passphrase=None, private_key_passphrase=None):
        """
        Hybrid AES-RSA cipher

        :param public_key_loc: Path to public key file
        :param private_key_loc: Path to private key file
        :param public_key_passphrase: Public key passphrase
        :param private_key_passphrase: Private key passphrase
        """
        self.public_key_loc = public_key_loc
        self.private_key_loc = private_key_loc
        self.public_key_passphrase = public_key_passphrase
        self.private_key_passphrase = private_key_passphrase

    def generate_keys(self, keys_size=2048):
        """
        Generate new RSA keys

        :param keys_size: Keys size
        """
        random_generator = Random.new().read
        keys = RSA.generate(keys_size, random_generator)

        with open(self.public_key_loc, 'wb') as public_key_file:
            public_key_file.write(keys.publickey().exportKey(format='PEM', passphrase=self.public_key_passphrase))

        with open(self.private_key_loc, 'wb') as private_key_file:
            private_key_file.write(keys.exportKey(format='PEM', passphrase=self.private_key_passphrase))

    def encrypt(self, plaintext):
        """
        Encrypts the plaintext

        :param plaintext: Plaintext to encrypt
        :return: Encrypted message
        :rtype: str
        """
        plaintext = _pad(plaintext.encode(), AES.block_size)
        session_key = Random.get_random_bytes(32)

        print("public key passphrase :",self.public_key_passphrase)
        print("private key passphrase :",self.private_key_passphrase)

        with open(self.public_key_loc, 'rb') as public_key_file:
            cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key_file.read(), passphrase=self.public_key_passphrase))

        cipher_aes = AES.new(key=session_key, mode=AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext)

        return base64.b64encode(cipher_rsa.encrypt(session_key) + cipher_aes.nonce + tag + ciphertext).decode()

    def decrypt(self, ciphertext):
        """
        Decrypts the ciphertext

        :param ciphertext: Ciphertext to decrypt
        :return: Decrypted message
        :rtype: str
        """
        with open(self.private_key_loc, 'rb') as private_key_file:
            private_key = RSA.import_key(private_key_file.read(), passphrase=self.private_key_passphrase)
        cipher_rsa = PKCS1_OAEP.new(private_key)

        ciphertext = base64.b64decode(ciphertext)
        session_key = cipher_rsa.decrypt(ciphertext[:private_key.size_in_bytes()])
        nonce = ciphertext[private_key.size_in_bytes():private_key.size_in_bytes() + 16]
        tag = ciphertext[private_key.size_in_bytes() + 16:private_key.size_in_bytes() + 32]

        ciphertext = ciphertext[32 + private_key.size_in_bytes():]
        cipher_aes = AES.new(key=session_key, mode=AES.MODE_EAX, nonce=nonce)
        plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)
        return _unpad(plaintext).decode()

    def encrypt_file(self, in_file_name, out_file_name=None, chunk_size=1024 * 64):
        """
        Encrypts the file

        :param in_file_name: Encrypting file name
        :param out_file_name: Encrypted file name (default is in_file_name + .enc)
        :param chunk_size: Block size
        """
        if not out_file_name:
            out_file_name = in_file_name + '.enc'

        file_size = os.path.getsize(in_file_name)
        session_key = Random.get_random_bytes(32)

        with open(self.public_key_loc, 'rb') as public_key_file:
            cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key_file.read(), passphrase=self.public_key_passphrase))
        with open(in_file_name, 'rb') as in_file:
            with open(out_file_name, 'wb') as out_file:
                out_file.write(struct.pack('<Q', file_size))
                out_file.write(cipher_rsa.encrypt(session_key))

                while True:
                    chunk = in_file.read(chunk_size)
                    if len(chunk) == 0:
                        break
                    elif len(chunk) % 16 != 0:
                        chunk += b' ' * (16 - len(chunk) % 16)
                    cipher_aes = AES.new(key=session_key, mode=AES.MODE_EAX)
                    ciphertext, tag = cipher_aes.encrypt_and_digest(chunk)
                    [out_file.write(x) for x in (cipher_aes.nonce, tag, ciphertext)]

    def decrypt_file(self, in_file_name, out_file_name=None, chunk_size=1024 * 64):
        """
        Decrypts the file

        :param in_file_name: Decrypting file name
        :param out_file_name: Decrypted file name (default in in_file_name without extension,
        if no extension - in_file_name + .decrypted)
        :param chunk_size: Block size
        """
        if not out_file_name:
            out_file_name = os.path.splitext(in_file_name)[0]
            if out_file_name == in_file_name:
                out_file_name += '.decrypted'

        with open(self.private_key_loc, 'rb') as private_key_file:
            private_key = RSA.import_key(private_key_file.read(), passphrase=self.private_key_passphrase)
        cipher_rsa = PKCS1_OAEP.new(private_key)

        with open(in_file_name, 'rb') as in_file:
            with open(out_file_name, 'wb') as out_file:
                orig_size = struct.unpack('<Q', in_file.read(struct.calcsize('Q')))[0]
                session_key = cipher_rsa.decrypt(in_file.read(private_key.size_in_bytes()))

                while True:
                    nonce, tag, chunk = [in_file.read(x) for x in (16, 16, chunk_size)]
                    if len(chunk) == 0:
                        break
                    cipher_aes = AES.new(key=session_key, mode=AES.MODE_EAX, nonce=nonce)

                    out_file.write(cipher_aes.decrypt_and_verify(chunk, tag))
                out_file.truncate(orig_size)


def _pad(s, bs):
    return s + (bs - len(s) % bs) * chr(bs - len(s) % bs).encode()


def _unpad(s):
    return s[:-ord(s[len(s)-1:])]


def prf(p, s):
    return HMAC.new(p, s, SHA256).digest()

t1_start = process_time()

#########  Blowfish  ##########
#blowfish = BlowfishCipher('85a698d3','248f6a08')

#blowfish.encrypt_file('Happy.png','encrypted.png')

#blowfish.decrypt_file('out.txt','decryptedout.txt')

########  AES  ###########

# aes = AESCipher('85a698d3','248f6a08')
# # #aes.encrypt_file('Happy.png','encrypted.png')
# aes.decrypt_file('input.txt.enc')

algo = RSACipher('public.txt','private.txt')
# t = algo.decrypt("q9tjoeuDRH4mAL7NThZeNOVy+Ubxezxy0uLE6fTTg7Udf8+yWW9AcTDCWcWDrtNhecbd106fo1ghi7hZSjfM4jRaOH+ziLgDLUeGrrCnuYZHt3G2RSrBEw+iiZz6rSK+tWFZQwRk6VwxJLx4RtVf4K0ZeN6/NgR55jJZZeHv8n4J046+4hvw3pUw3r2/QrI5+c9Equ/TLacWlDbgHUaMDvJLOqh2fHyD6q7wlDFOHjfj1Ocnr5MqwaR34POwnBBQaUouNtQXNWxwPFGnbkFk4mQnjWjO6Z8PqMKSZTtGz98huKcCBpSuDU/S4PbX2bNHp3+HQhy/IEZmDUprsHcSAA==")
# print(t)
algo.generate_keys()
algo.encrypt_file("helloworld","out")
# print(algo.encrypt('hello world'))
# print(algo.decrypt('FGVaCXTJ/lgh+taIhfaaz1bFL6igL3vJoLBIWyq2LiLUAzd/bmbgOlzr7UYEAFUdaAmTn5lAvABIT6YSEDYrXbmECUzUYJvhVq/5MSJNYzRPwZrTUiafZNlWDgS1n5EiPqHN6wYY9E1lqjD/FsmAhFvwqJMeYQS8x1G6g183Wk12hnDpx/cEfwx1ZzPfafTl6O8cXwtUu+6P8CW503d/VW8CUJLyMZ8TMc9xvGSxpV6g5KJQawmo5VlJ1IDBqmemnXqQGfH0sn0Z+ELgQ5UOUQRDDCq8wkeS9Zv61cOTHxXsBS8rZuPGA6C9HT2VhHYfVmC3tJsiHEWmBRc0Li9E7w=='))


# HybridAESRSACipher('85a698d3','248f6a08')
t1_stop = process_time()
print("Elapsed time during the whole program in seconds:", 
                                 t1_stop-t1_start) 

