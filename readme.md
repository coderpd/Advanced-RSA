# RSA Encryption/Decryption
![image](https://user-images.githubusercontent.com/28496314/116994612-8ea45a00-acf6-11eb-94b5-578b978093ec.png)

In this project, a public-key crypto system RSA is implemented, that is widely used for secure data transmission. It is also one of the oldest secure system.
A string from client to the server is sent.

> - A client (for example browser) sends its public key to the server and requests for some data. 
> - The server encrypts the data using client’s public key and sends the encrypted data.
> - Client receives this data and decrypts it.

###Input taken on server side
    Public Key
    Private Key

###Input taken on client side
    Public Key
    Private Key
    Message
    16 bit secret key

###Output Shown by the server side
    Secret Key
    Decoded Message
    Message Digest
    Immediate Verification Code
    Signature Verification Status

## Algorithm
### Server Socket
*new ServerSocket(7999)*
> Create a server on the port 7999

### Client Socket
*new Socket(7999)*
> Connect to the server running on localhost and port 7999

###BigInteger Class
BigInteger class is used, which converts the resultant byte array into its sign-magnitude representation.

### Functions of Server

**shiftRows(int c)**
>  - Shifting the 2nd and 4th nibble into right and left respectively

**subNib(int c)**
> - Divide all 16bits into Nibble  & store in t1,t2,t3,t4 variable and using s - box or S-Inv-box
> - Finally merge all the value of t1,t2,t3,t4 and return it.

**keyGeneration()**
>  - Using value of Round Constant  , Substitute Nibble , Shift Rows and formula
>  we can calculate all the subkeys

**roundKey()**
> - Key0  = w0w1,  key1  = w2w3  ,  key2  = w4w5

**addRoundKey(int m, int k)**
> - Plaintext XOR Round Key

**gmul(int  m1,int  m2)**
> - used for polynomial multiplication

**bitMod(int b1,int b2)**
> - bitwise polynomial modulo 19 multiplication

**columnMixing(int c)**
> - for multiply the matrix with nibbles of cipher text
> mix columns [1,4 ; 4,1] 
> encoding Inv Mix columns [9,2;2,9]

####Decryption Rounds
> - decryptionRound0() 
> - decryptionRound1()
> - decryptionRound2()

**hexadecimalToString(String str)**
> - function to convert hexadecimal to string

**rsa()**
> - The RSA algorithm involves four steps: key generation, key distribution, encryption, and decryption. 
> - RSA involves a public key and a private key. The public key can be known by everyone, and it is used for encrypting messages. The intention is that messages encrypted with the public key can only be decrypted in a reasonable amount of time by using the private key. The public key is represented by the integers n and e; and, the private key, by the integer d (although n is also used during the decryption process, so it might be considered to be a part of the private key, too). m represents the message.

**encrypt(BigInteger msg)**
> - Encrypt the message using modPow

**decrypt(BigInteger msg)**
> - Decrypt the message using modPow

**hashingFunction(String input)**
> - Hash function is uded to map key and value
> - *MD5 HASH FUNCTION IS USED IN THE ALGORITHM*
> - It is done for faster access to elements.

**main(String[] args)**
> - main function to perform the tasks

### Functions of Client
**shiftRows(int c)**
> - Shifting the 2nd and 4th nibble into right and left respectively

**subNib(int c)**
> - Divide all 16bits into Nibble  & store in t1,t2,t3,t4 variable and using s - box or S-Inv-box
> - Finally merge all the value of t1,t2,t3,t4 and return it.

**keyGeneration()**
>  - Using value of Round Constant  , Substitute Nibble , Shift Rows and formula
     >  we can calculate all the subkeys

**gmul(int  m1,int  m2)**
> - used for polynomial multiplication

**roundKey()**
> - Key0  = w0w1,  key1  = w2w3  ,  key2  = w4w5

**addRoundKey(int m, int k)**
> - Plaintext XOR Round Key

**bitMod(int b1,int b2)**
> - bitwise polynomial modulo 19 multiplication

**columnMixing(int c)**
> - for multiply the matrix with nibbles of cipher text
    > mix columns [1,4 ; 4,1]
    > encoding Inv Mix columns [9,2;2,9]

####Encryption Rounds
> - encryptionRound0()
> - encryptionRound1()
> - encryptionRound2()

**stringToHexadecimal(String str)**
> - function to convert hexadecimal to string

**rsa()**
> - The RSA algorithm involves four steps: key generation, key distribution, encryption, and decryption.
> - RSA involves a public key and a private key. The public key can be known by everyone, and it is used for encrypting messages. The intention is that messages encrypted with the public key can only be decrypted in a reasonable amount of time by using the private key. The public key is represented by the integers n and e; and, the private key, by the integer d (although n is also used during the decryption process, so it might be considered to be a part of the private key, too). m represents the message.

**encrypt(BigInteger msg)**
> - Encrypt the message using modPow

**decrypt(BigInteger msg)**
> - Decrypt the message using modPow

**hashingFunction(String input)**
> - Hash function is uded to map key and value
> - *MD5 HASH FUNCTION IS USED IN THE ALGORITHM*
> - It is done for faster access to elements.

**main(String[] args)**
> - main function to perform the tasks
