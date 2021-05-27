#!/usr/bin/env python3

"""
Homework Number: #6
Name: Nikita Ravi
ECN Login: ravi30
Due Date: 03/9/2021

"""

from BitVector import *
from PrimeGenerator import *
import sys

def bgcd(a,b):
    # Function from Professor Avi Kak's Lecture notes. Used to find the gcd of two values
    if a == b:
        return a

    if a == 0:
        return b

    if b == 0:
        return a

    if (~a & 1):
        if (b & 1):
            return bgcd(a >> 1, b)

        else:
            return bgcd(a >> 1, b >> 1) << 1

    if (~b & 1):
        return bgcd(a, b >> 1)

    if (a > b):
        return bgcd( (a-b) >> 1, b)

    return bgcd( (b-a) >> 1, a)

def private_key_generation(p, q):
    # Generates the private key in bitvector, d

    mod_n = int(p) * int(q)
    n_totient_bv = BitVector(intVal = (int(p) - 1) * (int(q) - 1))

    private_key_bv = BitVector(intVal = e).multiplicative_inverse(n_totient_bv)
    private_key = private_key_bv.int_val()

    return private_key_bv

def pq_generation(p_file, q_file, e):
    # Generates a random p value and q value

    genPrime = PrimeGenerator(bits = 128)
    p = 0
    q = 0

    check = True
    while check:
        p = BitVector(intVal=genPrime.findPrime(), size=128)
        q = BitVector(intVal=genPrime.findPrime(), size=128)

        eq_cond = (p == q)

        msb_cond = (not p[0:2]) and (not q[0:2])

        co_prime_cond = ((bgcd(p.int_val() - 1, e) != 1) or (bgcd(q.int_val() - 1, e) != 1))

        if eq_cond or co_prime_cond or msb_cond:
            pass
        else:
            break

    FILEOUT = open(p_file, 'w')
    FILEOUT.write(str(p.int_val()))
    FILEOUT.close()

    FILEOUT = open(q_file, 'w')
    FILEOUT.write(str(q.int_val()))
    FILEOUT.close()

def exponentiation(bitvec_int, e, n):
    # Helper function uses exponentiation to assist with encryption. From Professor Avi's Lecture Notes

    result = 1
    while(e > 0):
        if(e & 1):
            result = (result * bitvec_int) % n

        e >>= 1
        bitvec_int = (bitvec_int ** 2) % n

    return result

def CRT(bitvec, private_key, n, p, q):
    # Helper function uses Chinese Remainder Theorem to assist with decryption

    V_p = exponentiation(bitvec.int_val(), private_key.int_val(), int(p))
    V_q = exponentiation(bitvec.int_val(), private_key.int_val(), int(q))

    MI_pq = int(q) * (BitVector(intVal = int(q)).multiplicative_inverse(BitVector(intVal = int(p)))).int_val()
    MI_qp = int(p) * (BitVector(intVal = int(p)).multiplicative_inverse(BitVector(intVal = int(q)))).int_val()

    dec_out = ((V_p * MI_pq) + (V_q * MI_qp)) % n.int_val()

    return dec_out

def encryption(message, p_file, q_file, e):
    # Encrypts the file

    bv = BitVector(filename = message)
    output = BitVector(size = 0)
    p = ""
    q = ""

    FILEIN = open(p_file)
    p = FILEIN.read()
    FILEIN.close()

    FILEIN = open(q_file)
    q = FILEIN.read()
    FILEIN.close()

    while(bv.more_to_read):
        bitvec = bv.read_bits_from_file(128)

        if(bitvec.length() < 128):
            bitvec.pad_from_right(128 - bitvec.length())

        result = exponentiation(bitvec.int_val(), e, (int(p) * int(q)))

        output += BitVector(intVal = result, size = 256)

    return output

def decryption(cipher, p_file, q_file, e):
    # decrypts the file

    FILEIN = open(p_file)
    p = FILEIN.read()
    FILEIN.close()

    FILEIN = open(q_file)
    q = FILEIN.read()
    FILEIN.close()

    n = BitVector(intVal = (int(p) * int(q)))
    private_key_bv = private_key_generation(int(p), int(q))

    output = BitVector(size = 0)

    FILEIN = open(cipher)
    contents = FILEIN.read()

    contents = BitVector(hexstring = contents)
    FILEIN.close()

    counter = 0
    remainder = contents.length() % 256

    if (not remainder):
        quotient = (contents.length() // 256) + 1
        offset = quotient * 256
        contents.pad_from_right(offset - contents.length())

    while (contents.length() > counter + 256):
        bitvec = contents[counter: counter + 256]
        result = CRT(bitvec, private_key_bv, n, p, q)

        output += BitVector(intVal = result, size = 128)
        counter += 256

    return output

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
        FILEOUT = open(target, 'w')
        FILEOUT.write(content.get_bitvector_in_ascii().strip('\0'))

        FILEOUT.close()

if __name__ == '__main__':
    argList = sys.argv
    e = 65537


    if(len(argList) < 2):
        print("Need more arguments")

    else:
        if(argList[1] == '-g'):
            if(len(argList) == 4):
                pq_generation(argList[2], argList[3], e)

            else:
                print("Need more arguments")

        elif(argList[1] == '-e'):
            encrypted = encryption(argList[2], argList[3], argList[4], e)
            write_to_file(encrypted, argList[5], 'e')

        elif(argList[1] == '-d'):
            decrypted = decryption(argList[2], argList[3], argList[4], e)
            write_to_file(decrypted, argList[5], 'd')

        else:
            print("Wrong argument provided")

