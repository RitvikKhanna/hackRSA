# Q1 Assignment 9 Bisan Hasasneh 1505703 Ritvik Khanna 1479093
# CMPUT 299 Win 2018
# This module computes p,q,d of a private key of an RSA cipher given the 
# public key and a threshold which no primes are assumed to be larger than
#
# Some functions taken from cryptomath.py and primeSieve.py in Hacking Secret
# Ciphers with Python by Al Sweigart https://inventwithpython.com/hacking/

import math


def main():
    # for testing purposes
    # Example 1
    print(finitePrimeHack(100,493,5))

    # For problem 2 and problem 3
    print(finitePrimeHack(10000000,2477818381681,1286683))
    print(finitePrimeHack(10000000,3242852403407,1179839))
    print(finitePrimeHack(10000000,3328101456763,1827871))
    print(finitePrimeHack(10000000,1818082065277,1649429))
    print(finitePrimeHack(10000000,3221875170443,1659169))
    return



def finitePrimeHack(t, n, e):
    # returns a list containing p, q, d
    # t is the threshold which we assume no primes are larger than
    # n and e form a public RSA key

    # Assign p = -1 to use it later as a condition to check if the correct values for p and q were found or not
    p = -1

    # We know for sure that either one of p and q cannot be greater than the square root of the n.
    # We use this logic to make the program more efficiet.
    # However, if we have a threshold which is less than the square root of n, then we call primeSieve for that threshold.
    # This allows us to make sure that p and q are always in the threshold range if we have been provided with that.
    # If we don't have a threshold we can just use the square root of n as the threshold as a general assumption.
    sieveSize = math.floor(math.sqrt(n))
    if sieveSize > t:
        primes = primeSieve(t)
    else:
        primes = primeSieve(sieveSize)
    

    # After getting all the prime numbers we try finding p.
    # p will be a number such that remainder of n/p will be 0 and then q will be n/p
    for prime in primes:
        
        if n%prime == 0:
            p = n/prime
            q = n/p
            break

    # The initial condition we set for testing comes handy now, i.e if p = -1 no valid values were found.
    if p == -1:
        print('Valid p and q not found')
        return

    # Just for simplicity purposes, this sorts p and q such that p < q.
    # p and q were casted to int because while finding the values they were float numbers instead
    if p>q:
        p,q = int(q),int(p)
        
        
    # Now that we know p and q we can use this findModInverse function to find 'd' for decryption
    d = findModInverse(e, (p-1)*(q-1))
    
    # return a list of p,q,d
    return [p, q, d]
        



######### functions from cryptomath.py #########

def gcd(a, b):
    # Return the GCD of a and b using Euclid's Algorithm
    while a != 0:
        a, b = b % a, a
    return b


def findModInverse(a, m):
    # Returns the modular inverse of a % m, which is
    # the number x such that a*x % m = 1

    if gcd(a, m) != 1:
        return None # no mod inverse if a & m aren't relatively prime

    # Calculate using the Extended Euclidean Algorithm:
    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m
    while v3 != 0:
        q = u3 // v3 # // is the integer division operator
        v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
    return u1 % m

######### end functions from cryptomath.py #########

###############################################################
###############################################################
###############################################################

######### functions from primeSieve.py #########

def primeSieve(sieveSize):
    # Returns a list of prime numbers calculated using
    # the Sieve of Eratosthenes algorithm.

    sieve = [True] * sieveSize
    sieve[0] = False # zero and one are not prime numbers
    sieve[1] = False

    # create the sieve
    for i in range(2, int(math.sqrt(sieveSize)) + 1):
        pointer = i * 2
        while pointer < sieveSize:
            sieve[pointer] = False
            pointer += i

    # compile the list of primes
    primes = []
    for i in range(sieveSize):
        if sieve[i] == True:
            primes.append(i)

    return primes

######### end functions from primeSieve.py #########

###############################################################
###############################################################
###############################################################

# So that this can be used as a module
if __name__ == '__main__':
    main()
