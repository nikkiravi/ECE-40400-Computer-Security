#!/usr/bin/env python3
from BitVector import *

def cryptBreak(ciphertextFile, key_bv):
	BLOCKSIZE = 16
	numbytes = BLOCKSIZE // 8
	PassPhrase = "Hopes and dreams of a million years"

	vector = BitVector(bitlist = [0] * BLOCKSIZE)
	for i in range(len(PassPhrase) // numbytes):
		text = PassPhrase[i * numbytes: (i + 1) * numbytes]
		vector ^= BitVector(textstring = text)

	file_obj = open(ciphertextFile)
	encrypted_bv = BitVector(hexstring = file_obj.read())
	msg_decrypted = BitVector(size = 0)

	previous_decryption = vector
	for i in range(len(encrypted_bv) // BLOCKSIZE):
		bv = encrypted_bv[i * BLOCKSIZE: (i + 1) * BLOCKSIZE]
		temp = bv.deep_copy()
		bv ^= previous_decryption
		previous_decryption = temp
		bv ^= key_bv
		msg_decrypted += bv

	output = msg_decrypted.get_text_from_bitvector()

	return output


if __name__ == '__main__':
	for i in range(1, (2**16)):
		key_bv = BitVector(intVal = i, size = 16)
		decrypted_msg = cryptBreak('encrypted.txt', key_bv)

		if('Yogi Berra' in decrypted_msg):
			print("Encryption Broken with key: " + str(i))
			print("Decrypted message is " + decrypted_msg)
			break


# This code is based off of Professor Avi Kak’s DecryptForFun.py program. 