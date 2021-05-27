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
from solve_pRoot_BST import *

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
    n_totient_bv = BitVector(intVal=(int(p) - 1) * (int(q) - 1))

    private_key_bv = BitVector(intVal=e).multiplicative_inverse(n_totient_bv)
    private_key = private_key_bv.int_val()

    return private_key_bv

def pq_generation(e):
    # Generates a random p value and q value

    genPrime = PrimeGenerator(bits=128)
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

    d = private_key_generation(p.int_val(), q.int_val())
    n = BitVector(intVal = p.int_val() * q.int_val())

    private_key = (d, n)
    public_key = (e, n)

    return (private_key, public_key)

def exponentiation(bitvec_int, e, n):
    # Helper function uses exponentiation to assist with encryption. From Professor Avi's Lecture Notes

    result = 1
    while(e > 0):
        if(e & 1):
            result = (result * bitvec_int) % n

        e >>= 1
        bitvec_int = (bitvec_int ** 2) % n

    return result

def encryption(plaintext, n, e):
    # Encrypts the file

    bv = BitVector(filename = plaintext)
    output = BitVector(size = 0)

    while(bv.more_to_read):
        bitvec = bv.read_bits_from_file(128)

        if(bitvec.length() < 128):
            bitvec.pad_from_right(128 - bitvec.length())

        result = exponentiation(bitvec.int_val(), e, n.int_val())
        output += BitVector(intVal = result, size = 256)

    return output

def crack_RSA(n1, n2, n3, bv1, bv2, bv3, e):
    # This function is used to break the RSA encryption
    output = BitVector(size = 0)

    n1 = int(n1)
    n2 = int(n2)
    n3 = int(n3)

    n1_bv = BitVector(intVal = n1)
    n2_bv = BitVector(intVal = n2)
    n3_bv = BitVector(intVal = n3)


    N = n1 * n2 * n3

    N1 = BitVector(intVal = (N // n1))
    MI1 = N1.multiplicative_inverse(n1_bv).int_val()

    N2 = BitVector(intVal = (N // n2))
    MI2 = N2.multiplicative_inverse(n2_bv).int_val()

    N3 = BitVector(intVal=(N // n3))
    MI3 = N3.multiplicative_inverse(n3_bv).int_val()

    counter = 0
    remainder = bv1.length() % 256

    if (not remainder):
        quotient = (bv1.length() // 256) + 1
        offset = quotient * 256
        bv1.pad_from_right(offset - bv1.length())
        bv2.pad_from_right(offset - bv1.length())
        bv3.pad_from_right(offset - bv1.length())


    while(bv1.length() > counter + 256):
        bitvec1 = bv1[counter: counter + 256]
        bitvec2 = bv2[counter: counter + 256]
        bitvec3 = bv3[counter: counter + 256]


        result = ((bitvec1.int_val() * N1.int_val() * MI1) + (bitvec2.int_val() * N2.int_val() * MI2) + (bitvec3.int_val() * N3.int_val() * MI3)) % N

        result = BitVector(intVal = solve_pRoot(e, result), size = 128)
        output += result

        counter += 256
    return output

def writeFile(type, target, content):
    """
    Parameter
    1) content: contents to write to file
    2) target: target file to write to
    3) type: encryption of decryption

    Description of Function
    Write the contents of the output into the designated target file

    Return: None

    """

    if(type == 'e'):
        FILEOUT = open(target, 'w')
        FILEOUT.write(content.get_bitvector_in_hex())

        FILEOUT.close()

    elif(type == 'n'):
        FILEOUT = open(target, 'w')
        # print(content)
        FILEOUT.write(content)

        FILEOUT.close()

    elif(type == 'c'):
        FILEOUT = open(target, 'w')
        FILEOUT.write(content.get_bitvector_in_ascii().strip('\0'))

        FILEOUT.close()

if __name__ == '__main__':
    argList = sys.argv
    e = 3

    if(len(argList) != 7):
        print("Need 7 Arguments")

    else:
        (priv1, pub1) = pq_generation(e)
        (priv2, pub2) = pq_generation(e)
        (priv3, pub3) = pq_generation(e)

        if(argList[1] == '-e'):
            encrypt1 = encryption(argList[2], pub1[1], e)
            encrypt2 = encryption(argList[2], pub2[1], e)
            encrypt3 = encryption(argList[2], pub3[1], e)

            writeFile('e', argList[3], encrypt1)
            writeFile('e', argList[4], encrypt2)
            writeFile('e', argList[5], encrypt3)

            output = ""
            for public in [pub1[1].int_val(), pub2[1].int_val(), pub3[1].int_val()]:
                output += str(public) + "\n"

            writeFile('n', argList[6], output)

        elif(argList[1] == '-c'):
            FILEIN = open(argList[2])
            encrypt1 = BitVector(hexstring = FILEIN.read())
            FILEIN.close()

            FILEIN = open(argList[3])
            encrypt2 = BitVector(hexstring = FILEIN.read())
            FILEIN.close()

            FILEIN = open(argList[4])
            encrypt3 = BitVector(hexstring = FILEIN.read())
            FILEIN.close()

            FILEIN = open(argList[5])
            pub1 = FILEIN.readline()
            pub2 = FILEIN.readline()
            pub3 = FILEIN.readline()

            output = crack_RSA(pub1, pub2, pub3, encrypt1, encrypt2, encrypt3, e)
            writeFile('c', argList[6], output)