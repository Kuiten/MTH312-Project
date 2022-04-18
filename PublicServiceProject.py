import math
import random
import numpy as np
import sympy as sp

#print strengths and weaknesses of caesar cipher
def caesar_info():
    print("Strengths:")
    print("Better than no encryption\n")
    print("-------------------------------\n")
    print("Weaknesses:")    
    print("All letters are shifted by the same amount, once you crack one youve cracked all of them")
    print("Susceptible to frequency analysis that doesnt take very long to crack")
    print("A single letter that stands alone in the encrypted message is either A or I")
#print strengths and weaknesses of affine shifts
def affine_info():
    caesar_info()
    print("If not careful a letter may not end up changing")
#print strengths and weaknesses of RSA encryption
def RSA_info():
    print("Strengths:")
    print("Fairly simple to implement")
    print("Rather secure as cracking RSA requires significant computing power/math knowledge")
    print("Frequency analysis not efficient for cracking\n")
    print("-------------------------------\n")
    print("Weaknesses:")
    print("if the two primes chosen are too small RSA can be broken easily")
    print("the larger primes can result in larger computational times")
    print("If private key is lost, all messaged encrypted using it cannot be decrypted")
#print strengths and weaknesses of hill ciphers
def hill_info():
    print("Strengths:")
    print("Larger alphabet results in more combinations")
    print("Can have proper grammar")
    print("Cannot be cracked using freqeuncy analysis on the individual letters\n")
    print("-------------------------------\n")
    print("Weaknesses:")
    print("Alphabet cant be even in length")
    print("boils down to a simple substituion cipher applied to digraphs")
#function to encrypt using caesar cipher
def encrypt_caesar(m):
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    mod = len(alphabet)
    m = m.lower()
    m = m.replace(" ", "")
    encrypted = []
    for i in range(len(m)):
        encrypted.append((alphabet.index(m[i])+3) % mod)
    message = ""
    for j in encrypted:
        message += alphabet[j]
    print("\nRemoved spaces for ease of encryption")
    print(f"Encrypted message using caesar cipher: {message}\n")
    caesar_info()
#function to encrypt using affine shift
def encrypt_affine(m, mshift, ashift):
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    mod = len(alphabet)
    m = m.lower()
    m = m.replace(" ", "")
    if math.gcd(mshift, mod) != 1:
        print("multiplicative shift does not have an inverse mod 26, please try another number\n")
        return
    encrypted = []
    for i in range(len(m)):
        encrypted.append(((alphabet.index(m[i])*mshift) + ashift) % mod)
    message = ""
    for j in encrypted:
        message += alphabet[j]
    print(f"\nencrypted using multiplicative shift of {mshift}")
    print(f"and an additive shift of {ashift}")
    print("Removed spaces for ease of encryption")
    print(f"Encrypted message using affine shifts: {message}\n")
    affine_info()

def encrypt_vegenere(m):
    a = "placeholder"
#function to encrypt using RSA
def encrypt_RSA(m, d):
    p = 32771
    q = 62017
    m = int(m)
    mod = p * q
    phi = (p-1)*(q-1)
    #find the value of e(mult inverse of d mod phi)
    e = int(sp.invert(d, phi))
    n = pow(m, e, mod)
    print(f"\nEncrypted using RSA with this programs default primes(p and q): {n}\n")
    RSA_info()
#function to encrypt using hill ciphers
def encrypt_hill(m):
    alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .,!?'
    matrix = sp.Matrix([[3, 7], [9, 5]])
    mod = len(alphabet)
    if len(m) % 2 != 0:
        print("Message is odd length adding space to the end for encrypting")
        m += " "
    encode = sp.Matrix([alphabet.index(i) for i in m])
    a,b = len(m)//2,2
    shaped_encode = encode.reshape(a,b).T
    encrypted = matrix @ shaped_encode % mod
    encrypted_message = ''
    for i in list(encrypted.T.reshape(1,len(m))):
        encrypted_message += alphabet[i]
    print(f"\nencrypted using: {matrix}")
    print(f"Encrypted message using hill cipher: {encrypted_message}\n")
    hill_info()
#function to decrypt caesar cipher
def decrypt_caesar(m):
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    mod = len(alphabet)
    m = m.lower()
    m = m.replace(" ", "")
    decrypted = []
    for i in range(len(m)):
        decrypted.append((alphabet.index(m[i]) - 3) % mod)
    message = ""
    for j in decrypted:
        message += alphabet[j]
    print("\nRemoved spaces for ease of decryption")
    print(f"Decrypted message using caesar cipher: {message}\n")
    caesar_info()
#function to decrypt affine shifts
def decrypt_affine(m, mshift, ashift):
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    mod = len(alphabet)
    m = m.lower()
    m = m.replace(" ", "")
    if math.gcd(mshift, mod) != 1:
        print("multiplicative shift does not have a multiplicative inverse mod 26, cannot decrypt\n")
        return
    inverse = sp.invert(mshift, mod)
    decrypted = []
    for i in range(len(m)):
        decrypted.append(((alphabet.index(m[i]) - ashift) * inverse) % mod)
    message = ""
    for j in decrypted:
        message += alphabet[j]
    print("\nRemoved spaces for ease of decryption")
    print(f"Decrypted message using affine shift of *{mshift} +{ashift}: {message}\n")
    affine_info()

def decrypt_vegenere(m):
    a = "placeholder"
#function to decrypt using RSA
def decrypt_RSA(m,d):
    p = 32771
    q = 62017
    m = int(m)
    mod = p * q
    c = pow(m, d, mod)
    print(f"\nDecrypted using RSA with this programs default primes(p and q): {c}\n")
    RSA_info()
#function to decrypt using hill ciphers
def decrypt_hill(m, a, b, c, d):
    alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .,!?'
    matrix = sp.Matrix([[a, b], [c, d]])
    mod = len(alphabet)
    if matrix.det() % mod == 1:
        print("Matrix given does not have an inverse matrix cannot decrypt\n")
        return
    encode = sp.Matrix([alphabet.index(i) for i in m])
    k,s = len(m)//2,2
    encrypted = encode.reshape(k,s).T
    det = matrix.det()
    inverse = sp.invert(det, mod)
    adj_matrix = matrix.adjugate() % mod
    inverse_matrix = inverse * adj_matrix % mod
    decrypted = inverse_matrix @ encrypted % mod
    decrypted_message = ''
    for i in list(decrypted.T.reshape(1,len(decrypted))):
        decrypted_message += alphabet[i]
    print(f"\nDecrypted using: Inverse {inverse_matrix}")
    print(f"Decrypted message using hill cipher: {decrypted_message}\n")
    hill_info()
#main loop of the program
def main():
    #calculate d key for RSA for this run of the program
    rsa_p = 32771
    rsa_q = 62017
    rsa_phi = (rsa_p-1)*(rsa_q-1)
    rsa_d = random.randint(2, rsa_phi-2)
    while math.gcd(rsa_d,rsa_phi) != 1:
        rsa_d = random.randint(2, rsa_phi-2)
    #Continue program until user quits
    while True:
        #Get if the user would like to encrypt(e) or decrypt(d)
        encrypt_or_decrypt = input("\nType 'e' to encrypt or 'd' to decrypt or 'q' to quit: ")
        #If neither are given return an error
        if(encrypt_or_decrypt != "e" and encrypt_or_decrypt != "d"):
            if encrypt_or_decrypt == "q":
                print("'q' recieved, exiting program")
                return
            else:
                print("Did not enter 'e' or 'd' please try again")
                return
        #get which cipher the user would like to use
        cipher = int(input("Type '1' for caesar cipher, '2' for affine shift '3' for Vegenere cipher '4' for RSA '5' for hill cipher: "))
        #get the users message tto be encrypted or decrypted
        if encrypt_or_decrypt == "e":
            message = input("Please enter your message(integer for RSA) to be encrypted: ")
        if encrypt_or_decrypt == "d":
            message = input("Please enter your message(integer for RSA) to be decrypted: ")
        #Depending on user input call appropriate functon for the requested action
        #encrypt caesar
        if encrypt_or_decrypt == "e" and cipher == 1:
            encrypt_caesar(message)
        #encrypt affine
        elif encrypt_or_decrypt == "e" and cipher == 2:
            mult_shift = int(input("Enter the multiplicative shift to use in your affine shift(make sure it as an inverse): "))
            add_shift = int(input("Enter the additive shift to use in your affine shift: "))
            encrypt_affine(message, mult_shift, add_shift)
        #encrypt vegenere
        elif encrypt_or_decrypt == "e" and cipher == 3:
            encrypt_vegenere(message)
        #encrypt RSA
        elif encrypt_or_decrypt == "e" and cipher == 4:
            encrypt_RSA(message, rsa_d)
        #encrypt hill
        elif encrypt_or_decrypt == "e" and cipher == 5:
            encrypt_hill(message)
        #decrypt caesar
        elif encrypt_or_decrypt == "d" and cipher == 1:
            decrypt_caesar(message)
        #decrypt affine
        elif encrypt_or_decrypt == "d" and cipher == 2:
            mult_shift = int(input("Enter the multiplicative shift used in your affine shift(make sure it as an inverse): "))
            add_shift = int(input("Enter the additive shift used in your affine shift: "))
            decrypt_affine(message, mult_shift, add_shift)
        #decrypt vegenere
        elif encrypt_or_decrypt == "d" and cipher == 3:
            decrypt_vegenere(message)
        #decrypt RSA
        elif encrypt_or_decrypt == "d" and cipher == 4:
            decrypt_RSA(message, rsa_d)
        #decrypt hill
        elif encrypt_or_decrypt == "d" and cipher == 5:
            a = int(input("enter the first value of the matrix used: "))
            b = int(input("enter the second value of the matrix used: "))
            c = int(input("enter the third value of the matrix used: "))
            d = int(input("enter the fourth value of the matrix used: "))
            decrypt_hill(message, a, b, c, d)
if __name__ == "__main__":
	main()