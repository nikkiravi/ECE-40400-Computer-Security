#!/usr/bin/env python3

"""
Homework Number: #4
Name: Nikita Ravi
ECN Login: ravi30
Due Date: 02/23/2021

"""

from BitVector import *
import sys
import time
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

def encryption(message, round_keys_list, num_rounds):
    """
    Parameters
    1) message: the plaintext file
    2) round_keys_list: the list of round keys generated from the round_keys_generate function
    3) num_rounds: The number of rounds needed to substitute bytes, shift rows, and mix columns

    Description of Function
    The encryption function is responsible for encrypting the plaintext file. It first converts the contents of the file into a bitvector.
    An empty bitvector of size 0, with the name output is also created. The while loop first checks if there is anything more left to read
    from the file using the bv file pointer created when the bitvector of the file contents was created using the parameter filename.
    If there is something to read from the file, enter the while loop, the bv pointer moves 128 bits ahead to get a block of 128 bits from
    the file and this is stored in bitvec. If the length of the file is not a multiple of 128, then the bitvec is padded from the right to
    align the most significant bits by the difference between 128 bits and the length of bitvec. The bitvec is first XORed with the first round
    key in the round key list. A state_array is created. The for loop iterates between 1 to 13 rounds, where each time,
    the state_array is updated to whenever it then goes through byte substitution, shift rows, mixing columns, and gets XORed with the round_key
    found at index round in round_keys_list. Once the for loop is terminated, the state_array is once again subject to byte substitutions and shift_rows and
    also getting XORed with the last round key in the round_key_list. The resulting state_array is appended to the output bitvector.

    Return: The final output bitvector

    """
    bv = BitVector(filename = message)
    output = BitVector(size = 0)

    while(bv.more_to_read):
        bitvec = bv.read_bits_from_file(128)

        if(len(bitvec) % 128  != 0):
            bitvec.pad_from_right(128 - len(bitvec))

        bitvec = bitvec ^ round_keys_list[0]

        state_array = generate_state_array(bitvec)

        for round in range(1, num_rounds):
            state_array = sub_bytes(state_array, 'e')
            state_array = shift_rows(state_array, 'e')
            state_array = mix_columns(state_array, 'e')
            state_array = round_keys_list[round] ^ convert_state_array_to_bitvector(state_array)

            state_array = generate_state_array(state_array)


        state_array = sub_bytes(state_array, 'e')
        state_array = shift_rows(state_array, 'e')
        state_array = round_keys_list[14] ^ convert_state_array_to_bitvector(state_array)

        output += state_array

    return output

def decryption(encrypted, round_keys_list, num_rounds):
    """
    Parameters
    1) encrypted: cipher file
    2) round_keys_list: the list of round keys generated from the round_keys_generate function
    3) num_rounds: The number of rounds needed to substitute bytes, shift rows, and mix columns

    Description of Function
    The encryption function is responsible for encrypting the plaintext file. It first converts the contents of the file into a bitvector.
    An empty bitvector of size 0, with the name output is also created. If the length of the contents bitvector is not a multiple of 128,
    the bitvector is padded from the right to align the most significant bits. The while loop first checks if there is anything more left
    to read from the file using a counter + 128 bits check. If there is something to read from the file, a variable bitvec is created to
    store the spliced contents bitvector of size 128. If the length of the file is not a multiple of 128, then the bitvec is padded from the right to
    align the most significant bits by the difference between offset and the length of bitvec. The bitvec is first XORed with the last round
    key in the round key list. An state_array is created. The for loop iterates between 13 to 1 rounds, where each time,
    the state_array is updated when it goes through inverse shift rows, inverse byte substitution, getting XORed with the round_key
    found at index round in round_keys_list, and going through inverse mixing columns. Once the for loop is terminated, the state_array is once
    again subject to inverse shift rows, inverse byte substitution, and also getting XORed with the first round key in the round_key_list.
    The resulting state_array is appended to the output bitvector.

    Return: The final output bitvector

    """
    FILEIN = open(encrypted)
    contents = FILEIN.read()

    contents = BitVector(hexstring = contents)
    FILEIN.close()

    output = BitVector(size = 0)
    counter = 0

    remainder = contents.length() % 128

    if(not remainder):
        quotient = (contents.length() // 128) + 1
        offset = quotient * 128
        contents.pad_from_right(offset - contents.length())

    while(contents.length() > counter + 128):
        bitvec = contents[counter: counter + 128]

        bitvec = bitvec ^ round_keys_list[0]

        state_array = generate_state_array(bitvec)

        for round in range(1, num_rounds):
            state_array = shift_rows(state_array, 'd')
            state_array = sub_bytes(state_array, 'd')
            state_array = round_keys_list[round] ^ convert_state_array_to_bitvector(state_array)

            state_array = generate_state_array(state_array)
            state_array = mix_columns(state_array, 'd')


        state_array = shift_rows(state_array, 'd')
        state_array = sub_bytes(state_array, 'd')
        state_array = round_keys_list[14] ^ convert_state_array_to_bitvector(state_array)

        output += state_array

        counter += 128

    return output

def sub_bytes(state_array, type):
    """
    Parameters
    1) state_array: 2d matrix state_array
    2) type: check if whether encryption or decryption

    Description of Function
    If the type passed is an e (encryption) then each element of the state array will get substituted by a value
    found at the index of the sub_table. This index is determined by the original element found in the state array.
    The same process for decryption except this time a inverse subs_table is used

    """
    if(type == 'e'):
        for row in range(4):
            for col in range(4):
                state_array[row][col] = sub_table[state_array[row][col]]

        return state_array

    elif(type == 'd'):
        for row in range(4):
            for col in range(4):
                state_array[row][col] = inv_sub_table[state_array[row][col]]

        return state_array

def shift_rows(state_array, type):
    """
    Parameters
    1) state_array: state_array in 2d matrix form
    2) type: check whether encryption or decryption

    Description of Function
    If encryption, the columns are shifted are shifted to the left, using the first column as the base point, by whatever row we are in.
    The same with decryption except the base point is the last column

    Return: state_array
    """
    if(type == 'e'):
        for shift in range(1, 4):
            state_array[shift][:] = state_array[shift][shift:] + state_array[shift][:shift]

        return state_array

    elif(type == 'd'):
        for shift in range(1, 4):
            state_array[shift][:] = state_array[shift][(4 - shift):] + state_array[shift][:(4 - shift)]

        return state_array

def mix_columns(state_array, type):
    """
    Parameters
    1) state_array: 2d matrix state_array
    2) type: encryption or decryption

    Description of Function
    Matrix multiplication of the hex factors with state array. If encryption the hex factors are 0x1 - 0x2 whereas for
    decryption it is 0xb, 0xd, 0xe, 0x9

    Return: state_array

    """
    for row in range(4):
        for col in range(4):
            state_array[row][col] = BitVector(intVal= state_array[row][col], size = 8)

    temp = [[BitVector(size = 8) for i in range(4)] for i in range(4)]

    for row in range(4):
        for col in range(4):
            temp[row][col] = state_array[row][col].deep_copy()

    if(type == 'e'):
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

    elif(type == 'd'):
        bitB = BitVector(hexstring='0b')
        bitD = BitVector(hexstring='0d')
        bitE = BitVector(hexstring='0e')
        bit9 = BitVector(hexstring='09')

        for col in range(4):
            state_array[0][col] = temp[0][col].gf_multiply_modular(bitE, AES_modulus, 8) ^ temp[1][col].gf_multiply_modular(bitB, AES_modulus, 8) ^ temp[2][col].gf_multiply_modular(bitD, AES_modulus, 8) ^ temp[3][col].gf_multiply_modular(bit9, AES_modulus, 8)
            state_array[1][col] = temp[0][col].gf_multiply_modular(bit9, AES_modulus, 8) ^ temp[1][col].gf_multiply_modular(bitE, AES_modulus, 8) ^ temp[2][col].gf_multiply_modular(bitB, AES_modulus, 8) ^ temp[3][col].gf_multiply_modular(bitD, AES_modulus, 8)
            state_array[2][col] = temp[0][col].gf_multiply_modular(bitD, AES_modulus, 8) ^ temp[1][col].gf_multiply_modular(bit9, AES_modulus, 8) ^ temp[2][col].gf_multiply_modular(bitE, AES_modulus, 8) ^ temp[3][col].gf_multiply_modular(bitB, AES_modulus, 8)
            state_array[3][col] = temp[0][col].gf_multiply_modular(bitB, AES_modulus, 8) ^ temp[1][col].gf_multiply_modular(bitD, AES_modulus, 8) ^ temp[2][col].gf_multiply_modular(bit9, AES_modulus, 8) ^ temp[3][col].gf_multiply_modular(bitE, AES_modulus, 8)

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
    key_schedule = []

    for word_index,word in enumerate(key_words):
        keyword_in_ints = []

        for i in range(4):
            keyword_in_ints.append(word[i * 8: (i * 8) + 8].intValue())

        if(word_index % 4 == 0):
            continue

        key_schedule.append(keyword_in_ints)

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

def write_to_file(content, target, type):
    """
    Parameter
    1) content: contents to write to file
    2) target: target file to write to
    3) type: encryption of decryption

    Description of Function
    Write the contents of the output bitvector from either decryption or encryption into a new text file. If this is for
    encryption, write the file in hex. If this is decryption, write the file in ASCII

    Return: None

    """

    if(type == 'e'):
        FILEOUT = open(target, 'w')
        FILEOUT.write(content.get_bitvector_in_hex())

        FILEOUT.close()

    elif(type == 'd'):
        FILEOUT = open(target, 'wb')
        content.write_to_file(FILEOUT)

        FILEOUT.close()


if __name__ == '__main__':
    start_time = time.time() # Programming starting time
    warnings.filterwarnings(action='ignore') #Ignore all warnings

    argList = sys.argv #Get list of use inputs

    num_rounds = 14 #Number of rounds to process

    #Check if 5 inputs are given by the user
    if (len(argList) != 5):
        sys.stderr.write("Usage: %s   <-e or -d>   <input file>   <key file>    <output file>\n" % sys.argv[0])
        sys.exit(1)
    else:
        key_words = gen_key_schedule_256(argList[3]) #Generate key words
        round_keys = round_keys_generate(key_words, num_rounds) #Generate round keys list

        if (argList[1] == "-e"): #Check if encryption
            encrypted_output = encryption(argList[2], round_keys, num_rounds) #encrypt the file
            write_to_file(encrypted_output, argList[4], 'e') #write encrypted file in hex to target file

        elif (argList[1] == "-d"): #Check if decryption
            decrypted_output = decryption(argList[2], round_keys[::-1], num_rounds) #decrypt the file
            write_to_file(decrypted_output, argList[4], 'd') #write decrypted file to target file

        else:
            print("Invalid argument") #If neither encrypt or decrypt, argument is invalid

        print("Runtime: %s seconds" % (time.time() - start_time)) #Print the runtime of the program


# This code is based off of the lecture notes by Professor Avinash Kak from the AES lecture
