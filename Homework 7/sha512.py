#!/usr/bin/env python3

"""
Homework Number: #7
Name: Nikita Ravi
ECN Login: ravi30
Due Date: 03/19/2021

"""

from BitVector import *
import sys
import hashlib
import warnings

# Constants from Professor Kak's Lecture 15 Notes
# From Lecture 15 notes p. 44
K = ["428a2f98d728ae22", "7137449123ef65cd", "b5c0fbcfec4d3b2f", "e9b5dba58189dbbc",
                    "3956c25bf348b538", "59f111f1b605d019", "923f82a4af194f9b", "ab1c5ed5da6d8118",
                    "d807aa98a3030242", "12835b0145706fbe", "243185be4ee4b28c", "550c7dc3d5ffb4e2",
                    "72be5d74f27b896f", "80deb1fe3b1696b1", "9bdc06a725c71235", "c19bf174cf692694",
                    "e49b69c19ef14ad2", "efbe4786384f25e3", "0fc19dc68b8cd5b5", "240ca1cc77ac9c65",
                    "2de92c6f592b0275", "4a7484aa6ea6e483", "5cb0a9dcbd41fbd4", "76f988da831153b5",
                    "983e5152ee66dfab", "a831c66d2db43210", "b00327c898fb213f", "bf597fc7beef0ee4",
                    "c6e00bf33da88fc2", "d5a79147930aa725", "06ca6351e003826f", "142929670a0e6e70",
                    "27b70a8546d22ffc", "2e1b21385c26c926", "4d2c6dfc5ac42aed", "53380d139d95b3df",
                    "650a73548baf63de", "766a0abb3c77b2a8", "81c2c92e47edaee6", "92722c851482353b",
                    "a2bfe8a14cf10364", "a81a664bbc423001", "c24b8b70d0f89791", "c76c51a30654be30",
                    "d192e819d6ef5218", "d69906245565a910", "f40e35855771202a", "106aa07032bbd1b8",
                    "19a4c116b8d2d0c8", "1e376c085141ab53", "2748774cdf8eeb99", "34b0bcb5e19b48a8",
                    "391c0cb3c5c95a63", "4ed8aa4ae3418acb", "5b9cca4f7763e373", "682e6ff3d6b2b8a3",
                    "748f82ee5defb2fc", "78a5636f43172f60", "84c87814a1f0ab72", "8cc702081a6439ec",
                    "90befffa23631e28", "a4506cebde82bde9", "bef9a3f7b2c67915", "c67178f2e372532b",
                    "ca273eceea26619c", "d186b8c721c0c207", "eada7dd6cde0eb1e", "f57d4f7fee6ed178",
                    "06f067aa72176fba", "0a637dc5a2c898a6", "113f9804bef90dae", "1b710b35131c471b",
                    "28db77f523047d84", "32caab7b40c72493", "3c9ebe0a15c9bebc", "431d67c49c100d4c",
                    "4cc5d4becb3e42b6", "597f299cfc657e2a", "5fcb6fab3ad6faec", "6c44198c4a475817"]

def read_file(message, format = "r"):
    # Reading from file

    FILEIN = open(message, format)
    contents = FILEIN.read()

    FILEIN.close()
    return contents

def pad_message(bv_message):
    # Padding the input message so that its length is a multiple of 1024. Last 128 bits of the message must indicate length of input message
    # Inspired by Professor Kak's Lecture 15 notes, p.41

    message_length = bv_message.length()

    bv = bv_message + BitVector(bitstring = "1")
    zero_list = [0] * ((1024 - 128 - bv.length()) % 1024)

    bv += BitVector(bitlist = zero_list) + BitVector(intVal = message_length, size = 128)

    return bv

def generate_message_schedule(n, bv, words):
    # Create a message schedule for this 1024-bit input block.  The message schedule contains 80 words, each 64-bits long.
    # Inspired by Professor Kak's Lecture 15 notes, p.44

    bitvec = bv[n : n + 1024]

    words[0: 16] = [bitvec[i: i + 64] for i in range(0, 1024, 64)]

    for i in range(16, 80):
        i_minus_2_word = words[i - 2]
        i_minus_15_word = words[i - 15]

        sigma0 = (i_minus_15_word.deep_copy() >> 1) ^ (i_minus_15_word.deep_copy() >> 8) ^ (i_minus_15_word.deep_copy().shift_right(7))
        sigma1 = (i_minus_2_word.deep_copy() >> 19) ^ (i_minus_2_word.deep_copy() >> 61) ^ (i_minus_2_word.deep_copy().shift_right(6))

        words[i] = BitVector(intVal = (int(words[i - 16]) + int(sigma1) + int(words[i - 7]) + int(sigma0)) & 0xFFFFFFFFFFFFFFFF, size = 64)


    return words

def round_base_processing(a, b, c, d, e, f, g, h, words, k_bv):
    # In round_base_processing of 1024-bit message block. Total of 80 rounds and in each round consists of permuting the hash buffer previously stored
    # Inspired by Professor Kak's Lecture 15 notes, p. 45

    for i in range(80):
        ch = (e & f) ^ ((~e) & g)
        maj = (a & b) ^ (a & c) ^ (b & c)

        sum_a = ((a.deep_copy()) >> 28) ^ ((a.deep_copy()) >> 34) ^ ((a.deep_copy()) >> 39)
        sum_e = ((e.deep_copy()) >> 14) ^ ((e.deep_copy()) >> 18) ^ ((e.deep_copy()) >> 41)

        T1 = BitVector(intVal = (h.int_val() + ch.int_val() + sum_e.int_val() + int(words[i]) + k_bv[i].int_val()) & 0xFFFFFFFFFFFFFFFF, size = 64)
        T2 = BitVector(intVal = (sum_a.int_val() + maj.int_val()) & 0xFFFFFFFFFFFFFFFF, size = 64)

        h = g
        g = f
        f = e
        e = BitVector(intVal = (d.int_val() + T1.int_val()) & 0xFFFFFFFFFFFFFFFF, size = 64)
        d = c
        c = b
        b = a
        a = BitVector(intVal = (T1.int_val() + T2.int_val()) & 0xFFFFFFFFFFFFFFFF, size = 64)

    return a, b, c, d, e, f, g, h

def SHA512(message):
    #Generating a hashcode-512 for input message

    bv = BitVector(textstring = message)
    K_bv = [BitVector(hexstring = k) for k in K]

    # Step 1
    bv = pad_message(bv)

    # From Lecture 15 notes p. 43
    h0 = BitVector(hexstring = '6a09e667f3bcc908')
    h1 = BitVector(hexstring = 'bb67ae8584caa73b')
    h2 = BitVector(hexstring = '3c6ef372fe94f82b')
    h3 = BitVector(hexstring = 'a54ff53a5f1d36f1')
    h4 = BitVector(hexstring = '510e527fade682d1')
    h5 = BitVector(hexstring = '9b05688c2b3e6c1f')
    h6 = BitVector(hexstring = '1f83d9abfb41bd6b')
    h7 = BitVector(hexstring = '5be0cd19137e2179')

    # Initialize the array of words for storing the message schedule for a block of the input message
    words = [None] * 80

    for n in range(0, bv.length(), 1024):
        # Step 2
        words = generate_message_schedule(n, bv, words)

        # Step 3
        # store the hash buffer contents obtained from the previous input message block in the variables a,b,c,d,e,f,g,h:
        a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7
        a, b, c, d, e, f, g, h = round_base_processing(a, b, c, d, e, f, g, h, words, K_bv)

        # Step 4
        # After 80 rounds of processing, the a-h values are mixed with h0-h7
        # Inspired by Professor Kak's Lecture 15 code

        h0 = BitVector(intVal=(h0.int_val() + a.int_val()) & 0xFFFFFFFFFFFFFFFF, size=64)
        h1 = BitVector(intVal=(h1.int_val() + b.int_val()) & 0xFFFFFFFFFFFFFFFF, size=64)
        h2 = BitVector(intVal=(h2.int_val() + c.int_val()) & 0xFFFFFFFFFFFFFFFF, size=64)
        h3 = BitVector(intVal=(h3.int_val() + d.int_val()) & 0xFFFFFFFFFFFFFFFF, size=64)
        h4 = BitVector(intVal=(h4.int_val() + e.int_val()) & 0xFFFFFFFFFFFFFFFF, size=64)
        h5 = BitVector(intVal=(h5.int_val() + f.int_val()) & 0xFFFFFFFFFFFFFFFF, size=64)
        h6 = BitVector(intVal=(h6.int_val() + g.int_val()) & 0xFFFFFFFFFFFFFFFF, size=64)
        h7 = BitVector(intVal=(h7.int_val() + h.int_val()) & 0xFFFFFFFFFFFFFFFF, size=64)

    hash_message = h0 + h1 + h2 + h3 + h4 + h5 + h6 + h7
    return hash_message

def test_on_hashlib(plaintext):
    # Testing output of code against hashlib

    hasher = hashlib.sha512()
    hasher.update(plaintext)

    return hasher.hexdigest()


def write_to_file(contents, target):
    # Writing to file in hexstring format

    FILEOUT = open(target, 'w')
    FILEOUT.write(contents.get_bitvector_in_hex())

    FILEOUT.close()


if __name__ == "__main__":
    warnings.filterwarnings(action='ignore') #Ignore all warnings
    argList = sys.argv

    if(len(argList) >= 3):
        message = read_file(argList[1])
        hashed_output = SHA512(message)
        write_to_file(hashed_output, argList[2])


        if(len(argList) == 4):
            message = read_file(argList[1], "rb")
            hashlib_output = test_on_hashlib(message)

            if(hashlib_output == hashed_output.get_bitvector_in_hex()):
                print("The Program Works! No Difference found")

            else:
                print("There is a difference...Program does not work")
                print(hashlib_output)
                print(hashed_output.get_bitvector_in_hex())

    else:
        sys.stderr.write("Usage: %s <name of input file to hash> <name of file containing hash (out" % argList[0])
        sys.exit(1)
