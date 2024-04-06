from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256, SHA3_256
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import sys, os, getpass


def checkPassword(usr_hash, password):
    try:
        with open(usr_hash + '.txt', "r") as f:
            pswdsalt = bytes.fromhex(f.read(32))
            pswd_hash_file = f.read(64)#Create file with address hash name
            change_pswd = f.read(1)
    except:
        print("Password or username incorrect")
        exit(-1)

    pswd_hash = PBKDF2(password, pswdsalt, 32, count=1000000, hmac_hash_module=SHA256) #Calculate key
    if (pswd_hash_file == pswd_hash.hex()):
        
        print("Login successful")
        if (change_pswd == '1'):
            return 2
        else:
            return 1
    else:
        print("Password or username incorrect")
        return -1


def changePassword(user_hash):
    password = getpass.getpass("Enter New Password : ")
    with open(user_hash + '.txt', "w") as f: #Create file with address hash name
        salt = get_random_bytes(16)
        pswd_hash = PBKDF2(password, salt, 32, count=1000000, hmac_hash_module=SHA256) #Calculate key
        f.write(salt.hex())
        f.write(pswd_hash.hex())
        f.write('1')
        print("Password changed")


if (len(sys.argv) > 2):
    print("Wrong amount of arguments")
    exit()

password = getpass.getpass("Enter Password : ")
with open('salt.txt', 'r') as f:
    salt = f.readline() #Open salt
usr_hash = SHA3_256.new()
usr_hash.update((sys.argv[1]+salt).encode('ascii'))

if (checkPassword(usr_hash.hexdigest(), password) == 2):
   changePassword(usr_hash.hexdigest())


