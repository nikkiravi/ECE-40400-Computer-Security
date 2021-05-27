"""
Homework Number: #3
Name: Nikita Ravi
ECN Login: ravi30
Due Date: 02/11/2021

"""

#!/usr/bin/env python3
import sys

def findQuotient(a, b, origB):
    # This function was inspired by the code written in C by person with UserId Viaan(https://stackoverflow.com/questions/5284898/implement-division-with-bit-wise-operator)

    quotient = 1
    sign = 1

    if ((a < 0) ^ (b < 0)):
        sign = -1

    a = abs(a)
    b = abs(b)

    if(a == b):
        return 1

    elif(a < b):
        return 0

    while (a >= b):
        b = b << 1
        quotient = quotient << 1

    if(a < b):
        b = b >> 1
        quotient = quotient >> 1

    quotient = quotient + findQuotient(a - b, origB, origB)

    if(sign == -1):
        return ~quotient + 1

    return quotient

def multiply(a, b):
    # This function was inspired by the code presented on geeksforgeeks by Ssanjit_Prasad (https://www.geeksforgeeks.org/multiplication-two-numbers-shift-operator/)
    product = 0
    shift = 0
    sign = 1

    if((b < 0) ^ (a < 0)):
        sign = -1

    b = abs(b)
    a = abs(a)

    while (b):
        if (b % 2 == 1):
            product += a << shift

        shift += 1
        b = findQuotient(b,2,2)

    if(sign == -1):
        product = ~product + 1

    return product

def find_MI(a, b):
    # This function is inspired by Professor Avi Kak's lecture 5.7 notes and his FindMI.py file
    x, x_old = 0, 1
    y, y_old = 1, 0

    num, mod = a, b

    while b:
        quotient = findQuotient(a, b, b)

        a, b = b, a % b

        x, x_old = x_old - multiply(quotient, x), x # x_old - q * 2(x/2)
        y, y_old = y_old - multiply(quotient, y), y # y_old - q * 2(y/2)

    if a != 1:
        return -1
    else:
        MI = (x_old + mod) % mod
        return MI

if __name__ == '__main__':
    argList = sys.argv

    if(len(argList) != 3):
        sys.stderr.write("Usage: %s   <integer>   <modulus>\n" % sys.argv[0])
        sys.exit(1)

    else:
        MI = find_MI(int(argList[1]), int(argList[2]))

        if(MI != -1):
            print("\nMI of %d modulo %d is: %s\n" % (int(argList[1]), int(argList[2]), str(MI)))
        else:
            print("No MI exists ")
