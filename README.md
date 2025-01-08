ECDSA attack when same nonce are used
===========

PROJECT OVERVIEW 
-------------------------
This project is a proof-of-concept of nonce reuse attack on ECDSA algorithm. I didn't used modules to compute different calcuations steps. I only used cypari2 to provides me different mathematical objects but apart from that all the algorithm has been coded by myself according to FIPS 186-5 standard.   
**It is for educational purpose only and must not be used to perpetrate real attacks.**  
I used the SECP521r1 curve and SHA-256 hash function.


REQUIREMENTS 
-------------------------
This is a python project tested and developped on python 3.12.3.  
Only has two dependencies : cypary2 and cryptography (only used to generate asn1 DER encoded output signatures)  
You will find all the dependencies in the requirements.txt file.  
I recommend to use virtual environment but even if not in both cases the needed modules can be installed with this command :
```
pip install -r requirements.txt
```


USING AND IMPLEMENTATION DETAILS 
-------------------------
There is only one script named attack.py. The script takes two text messages and their corresponding ECDSA signatures, checks if both messages have been signed with the same nonce.  
If yes, it recovers the private key used to sign these two messages. Takes also another text message that you want to sign with the recovered private key and generate the corresponding signature in a file. 

To do all this stuff, the corresponding parameters are needed : 

1. Takes two text messages from two different files. 
2. Takes the two ECDSA signatures corresponding to each of the text messages (be careful asn1 DER base64 encoded format waited).
3. Takes the public key used to sign the two different messages in pem format.
4. You have to specify a text file containing the message you want to sign with the recovered private key.
5. You can specify the output file format of the generated signature : in both cases it's asn1 format and DER encoded but you can specify binary format or base64 format according to your needs.  
This gives the following command : 

```
python3 attack.py -m1 message1.txt -m2 message2.txt -s1 signature1.txt -s2 signature2.txt -pub public.pem -sign_msg msg.txt -output_type binary 
```

IN DEPTH MATHEMATICAL EXPLANATION
-------------------------
To be completed. 

AUTHOR 
-------------------------

Antoine CHAPEL # ECDSA-same-nonce-attack
