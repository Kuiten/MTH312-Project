import math
import numpy as np
import sympy as sp

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
    #FIXME: explain strengths and weaknesses of this cipher

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
    #FIXME: explain strengths and weaknesses of this cipher

def encrypt_vegenere(m):
    a = "placeholder"

def encrypt_RSA(m):
    a = "placeholder"

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
    #FIXME: explain strengths and weaknesses
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
    #FIXME: explain strengths and weaknesses of this cipher

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
    #FIXME: explain strengths and weaknesses of this cipher

def decrypt_vegenere(m):
    a = "placeholder"

def decrypt_RSA(m):
    a = "placeholder"

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

def main():
    while True:
        #Get if the user would like to encrypt(e) or decrypt(d)
        encrypt_or_decrypt = input("Type 'e' to encrypt or 'd' to decrypt or 'q' to quit: ")
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
            message = input("Please enter your message to be encrypted: ")
        if encrypt_or_decrypt == "d":
            message = input("Please enter your message to be decrypted: ")
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
            encrypt_RSA(message)
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
            decrypt_RSA(message)
        #decrypt hill
        elif encrypt_or_decrypt == "d" and cipher == 5:
            a = int(input("enter the first value of the matrix used: "))
            b = int(input("enter the second value of the matrix used: "))
            c = int(input("enter the third value of the matrix used: "))
            d = int(input("enter the fourth value of the matrix used: "))
            decrypt_hill(message, a, b, c, d)
if __name__ == "__main__":
	main()