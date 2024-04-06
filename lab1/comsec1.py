from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256, SHA3_256
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import sys, os

#Putting a new password
def putpassword():
    if (confirmkey(sys.argv[2]) == False): #Confirm master key
        print("Master passphrase incorrect or integrity check failed. ")
        exit();
    try:
        with open('salt.txt', 'r') as f: #Open salt
            salt = f.readline()
            salt = bytes.fromhex(salt)
    except FileNotFoundError:
        print('Master passphrase incorrect or integrity check failed. ')

    master_key = PBKDF2(sys.argv[2], salt, 32, count=1000000, hmac_hash_module=SHA256) #Calculate master key PBKDF2
    
    addr_hash = SHA3_256.new()
    addr_hash.update(sys.argv[3].encode('ascii')) #Encrypt the address
    with open(addr_hash.hexdigest() + '.txt', "w+") as f: #Create file with address hash name
        cipher = AES.new(master_key, AES.MODE_EAX) #Encrypt the address with AES and save to file
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(sys.argv[3].encode('ascii'))
        f.write(ciphertext.hex() + '\n')
        f.write(nonce.hex() + '\n')
        f.write(tag.hex() + '\n')

        hash_object = SHA256.new(data=(master_key.hex()+sys.argv[3]).encode('ascii')) #Create master plus address hash for encrypting password
        #Encrypting the password with hash
        cipher = AES.new(hash_object.digest(), AES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(sys.argv[4].encode('ascii'))
        f.write(ciphertext.hex() + '\n')
        f.write(nonce.hex() + '\n')
        f.write(tag.hex() + '\n')
        print("Stored password for", sys.argv[3])

#Decrypt password
def getpassword():
    if (confirmkey(sys.argv[2]) == False): #Confirm if master key is correct
        print("Master passphrase incorrect or integrity check failed.")
        exit();
    
    with open('salt.txt', 'r') as f:
        salt = f.readline() #Open salt
        salt = bytes.fromhex(salt)
    #Create secret master key
    master_key = PBKDF2(sys.argv[2], salt, 32, count=1000000, hmac_hash_module=SHA256) #Calculate key
    
    addr_hash = SHA3_256.new()
    addr_hash.update(sys.argv[3].encode('ascii')) #Encrypt the address
    try:
        with open(addr_hash.hexdigest() + '.txt', "r") as f: #Find correct file
            ciphertext = f.readline()
            nonce = f.readline()
            tag = f.readline()
            cipher = AES.new(master_key, AES.MODE_EAX, nonce = bytes.fromhex(nonce)) #Decrypt the address with master key
            plaintext = cipher.decrypt(bytes.fromhex(ciphertext))
            try:
                cipher.verify(bytes.fromhex(tag)) #Verify tag
            except ValueError:
                print("Master passphrase incorrect or integrity check failed.")
                exit()

            master_key2 = SHA256.new(data=(master_key.hex()+plaintext.decode()).encode('ascii')) #Use decrypted address and master key to create key for password decryption
            ciphertext = f.readline()
            nonce = f.readline()
            tag = f.readline()
            cipher = AES.new(master_key2.digest(), AES.MODE_EAX, nonce=bytes.fromhex(nonce)) #Decrypt the password with AES
            plaintext = cipher.decrypt(bytes.fromhex(ciphertext))
            try:
                cipher.verify(bytes.fromhex(tag)) #verify tag
                print('Password for',sys.argv[3],'is:',plaintext.decode())
            except ValueError:
                print("Master passphrase incorrect or integrity check failed.")

    except FileNotFoundError:
        print('Master passphrase incorrect or integrity check failed.')

 #Initialise master password       
def initialise():
    if (os.path.isfile('mkey.txt') == True): #Check fi already initialised
        print("Already initialised")
        exit()

    with open('mkey.txt', 'w+') as f: #Create master password hash
        pswd_hash = SHA3_256.new()
        pswd_hash.update(sys.argv[2].encode('ascii'))
        f.write(pswd_hash.hexdigest())

    with open('salt.txt', 'w+') as f: #Create random salt
        f.write(get_random_bytes(16).hex())
    print("Initialised")

#Check SHA3 password
def confirmkey(password): #Confirm master password from SHA
    with open('mkey.txt', 'r') as f:
        pswd_hash = SHA3_256.new()
        pswd_hash.update(password.encode('ascii'))
        hash = f.readline()

        if (hash == pswd_hash.hexdigest()):
            return True
        else:
            return False

if sys.argv[1] == 'put':
    putpassword()
elif sys.argv[1] == 'get':
    getpassword()
elif sys.argv[1] == 'init':
    initialise()