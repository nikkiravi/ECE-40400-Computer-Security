#!/usr/bin/env python3

"""
Homework Number: #5
Name: Nikita Ravi
ECN Login: ravi30
Due Date: 03/02/2021

"""

from BitVector import *
import warnings

AES_modulus = BitVector(bitstring='100011011') #The Irreducible Polynomial in 2^8
sub_table = [] #substitution bytes table for encryption and key generation
inv_sub_table = [] #inverse substitution bytes table for decryption and key generation

def generate_state_array(bitvec):
    """
    Parameters
    1) bitvec - the bitvec required to transform into a 2d matrix

    Description of Function
    Using the bitvector generated from the input file, a state array is formed by appending each
    consecutive words (bytes 0 - 4 for example) column-wise

    Return: state_array as a 2d matrix
    """
    state_array = [[0 for i in range(4)] for i in range(4)]

    for row in range(4):
        for col in range(4):
            state_array[col][row] = bitvec[(32 * row) + (8 * col): (32 * row) + (8 * (col + 1))].int_val()

    return state_array

def convert_state_array_to_bitvector(state_array):
    """
    Parameter: 2d matrix state_array

    Description of Function
    This function converts the 2d matrix integer state array to one long bitvector

    Return: converted bitvector

    """
    bv = BitVector(size = 0)

    for row in range(4):
        for col in range(4):
            temp = BitVector(intVal = state_array[col][row])

            if(len(temp) < 8):
                temp.pad_from_left(8 - len(temp))

            bv += temp

    return bv

def encryption(iv, round_keys_list, num_rounds):
    """
    Parameters
    1) iv: initialization vector
    2) round_keys_list: the list of round keys generated from the round_keys_generate function
    3) num_rounds: The number of rounds needed to substitute bytes, shift rows, and mix columns

    Description of Function
    The encryption function is responsible for encrypting the plaintext file. It first writes the header information to the targer file. It then
    converts the contents of the file into a bitvector. The bitvec is first XORed with the first round
    key in the round key list. A state_array is created. The for loop iterates between 1 to 13 rounds, where each time,
    the state_array is updated to whenever it then goes through byte substitution, shift rows, mixing columns, and gets XORed with the round_key
    found at index round in round_keys_list. Once the for loop is terminated, the state_array is once again subject to byte substitutions and shift_rows and
    also getting XORed with the last round key in the round_key_list.

    Return: current state_array

    """
    # output = BitVector(size = 0)

    iv = iv ^ round_keys_list[0]

    state_array = generate_state_array(iv)

    for round in range(1, num_rounds):
        state_array = sub_bytes(state_array)
        state_array = shift_rows(state_array)
        state_array = mix_columns(state_array)
        state_array = round_keys_list[round] ^ convert_state_array_to_bitvector(state_array)

        state_array = generate_state_array(state_array)

    state_array = sub_bytes(state_array)
    state_array = shift_rows(state_array)
    state_array = round_keys_list[14] ^ convert_state_array_to_bitvector(state_array)

    return state_array

def sub_bytes(state_array):
    """
    Parameters
    1) state_array: 2d matrix state_array

    Description of Function
    Each element of the state array will get substituted by a value
    found at the index of the sub_table. This index is determined by the original element found in the state array.

    """
    for row in range(4):
        for col in range(4):
            state_array[row][col] = sub_table[state_array[row][col]]

    return state_array

def shift_rows(state_array):
    """
    Parameters
    1) state_array: state_array in 2d matrix form

    Description of Function
    The columns are shifted are shifted to the left, using the first column as the base point, by whatever row we are in.

    Return: state_array
    """

    for shift in range(1, 4):
        state_array[shift][:] = state_array[shift][shift:] + state_array[shift][:shift]

    return state_array

def mix_columns(state_array):
    """
    Parameters
    1) state_array: 2d matrix state_array

    Description of Function
    Matrix multiplication of the hex factors with state array. For encryption the hex factors are 0x1 - 0x2 whereas for

    Return: state_array

    """
    for row in range(4):
        for col in range(4):
            state_array[row][col] = BitVector(intVal= state_array[row][col], size = 8)

    temp = [[BitVector(size = 8) for i in range(4)] for i in range(4)]

    for row in range(4):
        for col in range(4):
            temp[row][col] = state_array[row][col].deep_copy()

    bit2 = BitVector(intVal=2)
    bit3 = BitVector(intVal=3)

    for col in range(4):
        state_array[0][col] = temp[0][col].gf_multiply_modular(bit2, AES_modulus, 8) ^ temp[1][col].gf_multiply_modular(bit3, AES_modulus, 8) ^ temp[2][col] ^ temp[3][col]
        state_array[1][col] = temp[0][col] ^ temp[1][col].gf_multiply_modular(bit2, AES_modulus, 8) ^ temp[2][col].gf_multiply_modular(bit3, AES_modulus, 8) ^ temp[3][col]
        state_array[2][col] = temp[0][col] ^ temp[1][col] ^ temp[2][col].gf_multiply_modular(bit2, AES_modulus, 8) ^ temp[3][col].gf_multiply_modular(bit3, AES_modulus, 8)
        state_array[3][col] = temp[0][col].gf_multiply_modular(bit3, AES_modulus, 8) ^ temp[1][col] ^ temp[2][col] ^ temp[3][col].gf_multiply_modular(bit2, AES_modulus, 8)

    for row in range(4):
        for col in range(4):
            state_array[row][col] = state_array[row][col].int_val()

    return state_array

def round_keys_generate(key_words, num_rounds):
    """
    Parameters
    1) key_words: the words (4 bytes long) generated from gen_key_schedule_256
    2) num_rounds: the number of rounds required to do operations on in encryption and decryption

    Description of Function
    Generate num_rounds long list of round_keys using the key words generated from gen_key_schedule_256 function

    Return: round_keys

    Source: Professor Avinash Kak's code from the AES lecture
    """

    round_keys = [None for i in range(num_rounds + 1)]
    for i in range(num_rounds + 1):
        round_keys[i] = (key_words[i * 4] + key_words[i * 4 + 1] + key_words[i * 4 + 2] + key_words[i * 4 + 3])

    return round_keys

def gen_key_schedule_256(key_file):
    """
    Parameters
    1) key_file: text file with information on keu

    Description of Function
    Generate a list of key words from the key text file

    Return: key_words

    Source: Professor Avinash Kak's code from the AES lecture
    """
    gen_subbytes_table()

    FILEIN = open(key_file)
    contents = FILEIN.read()

    key_bv = BitVector(textstring = contents)

    FILEIN.close()

    key_words = [None for i in range(60)]
    round_constant = BitVector(intVal = 0x01, size=8)

    for i in range(8):
        key_words[i] = key_bv[i * 32 : (i * 32) + 32]

    for i in range(8,60):
        if(i % 8 == 0):
            kwd, round_constant = g_function(key_words[i - 1], round_constant, sub_table)
            key_words[i] = key_words[i-8] ^ kwd

        elif((i - (i // 8) * 8) < 4): #w9 - w11
            key_words[i] = key_words[i-8] ^ key_words[i-1]

        elif((i - (i // 8) * 8) == 4): #w12 folds back on w8
            key_words[i] = BitVector(size = 0)

            for j in range(4):
                key_words[i] += BitVector(intVal = sub_table[key_words[i - 1][8 * j: (8 * j) + 8].intValue()], size = 8)

            key_words[i] ^= key_words[i-8]

        elif(((i - (i // 8) * 8) > 4) and ((i - (i // 8) * 8) < 8)): #w13 - w16
            key_words[i] = key_words[i-8] ^ key_words[i-1]

        else:
            sys.exit("error in key scheduling algo for i = %d" % i)

    return key_words

def gen_subbytes_table():
    """
    Parameters: None

    Description of Function
    Generate the substitution bytes lookup table and inverse substitution bytes look up table

    Return: round_keys

    Source: Professor Avinash Kak's code from the AES lecture
    """

    c = BitVector(bitstring='01100011')
    d = BitVector(bitstring='00000101')

    for i in range(0, 256):
        #Sub Table Generation
        a = BitVector(intVal = i, size = 8).gf_MI(AES_modulus, 8) if i != 0 else BitVector(intVal = 0)
        a1, a2, a3, a4 = [a.deep_copy() for x in range(4)]

        a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c

        sub_table.append(int(a))

        #Inverse Sub Table Generation
        b = BitVector(intVal=i, size=8)
        b1, b2, b3 = [b.deep_copy() for x in range(3)]

        b = (b1 >> 2) ^ (b2 >> 5) ^ (b3 >> 7) ^ d
        MI_exists = b.gf_MI(AES_modulus, 8)

        b = MI_exists if isinstance(MI_exists, BitVector) else 0

        inv_sub_table.append(int(b))

def g_function(keyword, round_constant, byte_sub_table):
    """
    Parameters
    1) keyword: The current keyword passed from keyword list
    2) round_constant: The shifting to compensate for the fact that MI of 0 is 0
    3) byte_sub_table: the substitution table

    Description of Function
    Perform one byte left circular rotation on a word and perform byte substitution on each byte of the word using the substitution bytes lookup table

    Return
    1) The new word generated
    2) The updated round_constant

    Source: Professor Avinash Kak's code from the AES lecture
    """
    rotated_word = keyword.deep_copy()
    rotated_word = rotated_word << 8

    newword = BitVector(size = 0)
    for i in range(4):
        newword += BitVector(intVal = byte_sub_table[rotated_word[(8 * i): (8 * i) + 8].intValue()], size = 8)

    newword[:8] ^= round_constant

    round_constant = round_constant.gf_multiply_modular(BitVector(intVal = 0x02), AES_modulus, 8)

    return newword, round_constant

def ctr_aes_image(iv, image_file = "image.ppm", out_file = "enc_image.ppm", key_file = "key.txt"):
    """
    Parameters
    1) iv: initialization vector
    2) image_file: input image to be encrypted
    3) out_file: encrypted image
    4) key_file: file containing key in ASCII

    Description: This function first generates the round keys and then writes the header information into out_file. It then
    encrypts iv using the key and xors with the input image block. Once this is done, iv is incremented and the process repeats

    return: None

    """

    key_words = gen_key_schedule_256(key_file)
    round_keys = round_keys_generate(key_words, 14)

    FILEOUT = open(out_file, 'wb')
    FILEIN = open(image_file, 'rb')

    headers = []

    for i in range(3):
        headers.append(FILEIN.readline())

    FILEIN.close()

    header_binary = b"".join(headers)
    FILEOUT.write(header_binary)

    header_bv = BitVector(rawbytes = header_binary)


    bv = BitVector(filename = image_file)
    header_bits = bv.read_bits_from_file(header_bv.length())

    while (bv.more_to_read):
        bitvec = bv.read_bits_from_file(128)

        if (len(bitvec) < 128):
            bitvec.pad_from_right(128 - len(bitvec))

        block_encrypt = encryption(iv, round_keys, 14)

        encrypted = block_encrypt ^ bitvec
        encrypted.write_to_file(FILEOUT)

        iv = BitVector(intVal = iv.int_val() + 1)


    FILEOUT.close()

if __name__ == '__main__':
    warnings.filterwarnings(action='ignore')  # Ignore all warnings
    iv = BitVector(textstring = "computersecurity")
    ctr_aes_image(iv)
