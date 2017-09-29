"""aes crypto."""

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class AESCrypto(object):
    """AESCrypto."""

    def __init__(self, cbc_key, cbc_iv):
        self.cbc_key = cbc_key
        self.cbc_iv = cbc_iv

    def encrypt(self, data, mode='cbc'):
        """encrypt."""
        func_name = '{}_encrypt'.format(mode)
        func = getattr(self, func_name)
        return func(data)

    def decrypt(self, data, mode='cbc'):
        """decrypt."""
        func_name = '{}_decrypt'.format(mode)
        func = getattr(self, func_name)
        return func(data)

    def cbc_encrypt(self, data):
        """cbc_encrypt."""
        if not isinstance(data, bytes):
            data = data.encode()

        cipher = Cipher(algorithms.AES(self.cbc_key),
                        modes.CBC(self.cbc_iv),
                        backend=default_backend())
        encryptor = cipher.encryptor()

        padded_data = encryptor.update(self.pkcs7_padding(data))

        return padded_data

    def cbc_decrypt(self, data):
        """cbc_decrypt."""
        if not isinstance(data, bytes):
            data = data.encode()

        cipher = Cipher(algorithms.AES(self.cbc_key),
                        modes.CBC(self.cbc_iv),
                        backend=default_backend())
        decryptor = cipher.decryptor()

        uppaded_data = self.pkcs7_unpadding(decryptor.update(data))

        uppaded_data = uppaded_data.decode()
        return uppaded_data

    @staticmethod
    def pkcs7_padding(data):
        """pkcs7_padding."""
        if not isinstance(data, bytes):
            data = data.encode()

        padder = padding.PKCS7(algorithms.AES.block_size).padder()

        padded_data = padder.update(data) + padder.finalize()

        return padded_data

    @staticmethod
    def pkcs7_unpadding(padded_data):
        """pkcs7_unpadding."""
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(padded_data)

        try:
            uppadded_data = data + unpadder.finalize()
        except ValueError:
            raise Exception('Invalid')
        else:
            return uppadded_data

# Here's an example of how I use my crypto class to encrypt and decrypt a string
message = "hello cryptokit"
lv = 'm2VYHdx41zRgvg6f'
lv_byte = lv.encode()
key = 'WDMG1e38igW53YuxkE0SsKUDeLbULAts'
key_byte = key.encode()
crypto = AESCrypto(key_byte, lv_byte)
data = crypto.encrypt(message)
b'\xaa<\x9d\xe9\xde\x0b\xd7\xe9\xfd\xac\xfc\xdd\x9f\xe2V\xd4'
decrypted_message = crypto.decrypt(data)
'hello cryptokit'


# Now let's try to decrypt our ts file.
try:
    src_binary_key = open('hls-vodkey (1).bin', 'rb')
    key_byte = src_binary_key.read()

    # Doubt 1: whether the first 16 bytes consists of the  128 bit key: (test result: negative)
    the_first_key = key_byte[0 : 16]
    # Doubt 2: compare between 'hls-vodkey (1).bin' and 'hls-vodkey (2).bin' I find there's some similarity in them. Use the first different 16 bytes as the key: (test result: negative)
    the_first_key = b'\x05\x1c\x1e\x15\x13\xc4\x1e\xbc\x2e\xa9\x15\xc4\x27\x9a\x82\x8c'
    # Please continue work on it. the original binary key is 'hls-vodkey (1).bin' and the target encrrpt_file is '2017kysxcxjcgs03.mp4tipsid0.ts'
    # To Do:
    src_encrypt_file = open('2017kysxcxjcgs03.mp4tipsid0.ts', 'rb')
    file_byte = src_encrypt_file.read()
    lv = '0000000000000000'
    lv_byte = lv.encode()
    crypto = AESCrypto(the_first_key, lv_byte)
    file_byte = crypto.decrypt(file_byte)
    output_file = open('output.ts','wb')
    output_file.write(file_byte)
except:
    pass
finally:
    src_binary_key.close()
    src_encrypt_file.close()
    output_file.close()