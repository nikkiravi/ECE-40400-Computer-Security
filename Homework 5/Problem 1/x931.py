#!/usr/bin/env python3

"""
Homework Number: #5
Name: Nikita Ravi
ECN Login: ravi30
Due Date: 03/02/2021

"""

from BitVector import *

AES_modulus = BitVector(bitstring='100011011') #The Irreducible Polynomial in 2^8
sub_table = [] #substitution bytes table for encryption and key generation

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

def encryption(bv, round_keys_list, num_rounds):
    """
    Parameters
    1) bv: input bitvector
    2) round_keys_list: the list of round keys generated from the round_keys_generate function
    3) num_rounds: The number of rounds needed to substitute bytes, shift rows, and mix columns

    Description of Function
    The encryption function is responsible for encrypting the plaintext file. It first converts the contents of the file into a bitvector.
    An empty bitvector of size 0, with the name output is also created. The while loop first checks if there is anything more left to read
    from the file using the bv file pointer created when the bitvector of the file contents was created using the parameter filename.
    If there is something to read from the file, enter the while loop, the bv pointer moves 128 bits ahead to get a block of 128 bits from
    the file and this is stored in bitvec. The bitvec is first XORed with the first round key in the round key list. A state_array is created.
    The for loop iterates between 1 to 13 rounds, where each time,
    the state_array is updated to whenever it then goes through byte substitution, shift rows, mixing columns, and gets XORed with the round_key
    found at index round in round_keys_list. Once the for loop is terminated, the state_array is once again subject to byte substitutions and
    shift_rows and also getting XORed with the last round key in the round_key_list. The resulting state_array is appended to the output bitvector.

    Return: The final output bitvector

    """
    output = BitVector(size = 0)

    bitvec = bv[0: 128]
    bitvec = bitvec ^ round_keys_list[0]

    state_array = generate_state_array(bitvec)

    for round in range(1, num_rounds):
        state_array = sub_bytes(state_array)
        state_array = shift_rows(state_array)
        state_array = mix_columns(state_array)
        state_array = round_keys_list[round] ^ convert_state_array_to_bitvector(state_array)

        state_array = generate_state_array(state_array)

    state_array = sub_bytes(state_array)
    state_array = shift_rows(state_array)
    state_array = round_keys_list[14] ^ convert_state_array_to_bitvector(state_array)

    output += state_array

    return output

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
    Matrix multiplication of the hex factors with state array. For encryption the hex factors are 0x1 - 0x2

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
    Generate the substitution bytes lookup table

    Return: round_keys

    Source: Professor Avinash Kak's code from the AES lecture
    """

    c = BitVector(bitstring='01100011')

    for i in range(0, 256):
        #Sub Table Generation
        a = BitVector(intVal = i, size = 8).gf_MI(AES_modulus, 8) if i != 0 else BitVector(intVal = 0)
        a1, a2, a3, a4 = [a.deep_copy() for x in range(4)]

        a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c

        sub_table.append(int(a))

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

def x931(v0, dt, totalNum, key_file):
    """
    Parameters
    1) v0: seed value
    2) dt: date and time
    3) totalNum: number of random numbers to be generated
    4) key_file: the file containing the key in ASCII

    Description: This function first generates the round keys. It then encrypts dt with the round keys. In a for loop that iterates
    totalNum times, a random number is generated by encrypting the XORed value of v0 and output of the dt encryption. v0 is then updated by encryption
    the XORed version of the randomNum and encrypted_output from dt. The only time v0 will not be incremented is when we we reach the maximum index

    return: num_list (list of random numbers generated)

    """
    num_list = []

    key_words = gen_key_schedule_256(key_file)  # Generate key words
    round_keys = round_keys_generate(key_words, 14)  # Generate round keys list

    enc_output = encryption(dt, round_keys, 14)

    for i in range(totalNum):
        randomNum = encryption(enc_output ^ v0, round_keys, 14)
        num_list.append(randomNum.int_val())

        if(i == totalNum - 1):
            break

        v0 = encryption(enc_output ^ randomNum, round_keys, 14)

    return num_list