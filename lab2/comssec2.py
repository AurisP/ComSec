from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA3_256, SHA256
from Crypto.Random import get_random_bytes
import sys, os, getpass
FILELEN = 96

def checkExist(user):
    if (os.path.isfile(user.hexdigest() + '.txt') == True): #Check fi already initialised
        return 1
    else:
        return 0


def addUser():
    usr_hash = SHA3_256.new()
    with open('salt.txt', 'r') as f:
        salt = f.readline() #Open salt
    usr_hash.update((sys.argv[2]+salt).encode('ascii'))
    if (checkExist(usr_hash) == 1):
        print("User already exists")
        exit()

    password = getpass.getpass("Enter Password : ")  
    passwordrepeat = getpass.getpass("Repeat Password : ") 
    if (passwordrepeat != password):
        print("Password mismatch")
        exit()
    with open(usr_hash.hexdigest() + '.txt', "w+") as f: #Create file with address hash name
        salt = get_random_bytes(16)
        pswd_hash = PBKDF2(password, salt, 32, count=1000000, hmac_hash_module=SHA256)
        f.write(salt.hex())
        f.write(pswd_hash.hex())
        print("User added")


def changePassword():
    with open('salt.txt', 'r') as f:
        salt = f.readline() #Open salt
    usr_hash = SHA3_256.new()
    usr_hash.update((sys.argv[2]+salt).encode('ascii'))
    if (checkExist(usr_hash) == 0):
        print("User doesnt exist")
        exit(-1)
    password = getpass.getpass("Enter New Password : ")
      
    with open(usr_hash.hexdigest() + '.txt', "w") as f: #Create file with address hash name
        salt = get_random_bytes(16)
        pswd_hash = PBKDF2(password, salt, 32, count=1000000, hmac_hash_module=SHA256) #Calculate key
        f.write(salt.hex())
        f.write(pswd_hash.hex())
        print("Password changed")


def forceChange():
    with open('salt.txt', 'r') as f:
        salt = f.readline() #Open salt
    usr_hash = SHA3_256.new()
    usr_hash.update((sys.argv[2]+salt).encode('ascii'))
    if (checkExist(usr_hash) == 0):
        print("User doesnt exist")
        exit(-1)
    with open(usr_hash.hexdigest() + '.txt', "r+") as f:
        f.seek(FILELEN)     
        if (f.read() == '1'):
            f.seek(FILELEN)
            f.truncate()
            print("Password change set to no for user " + sys.argv[2])
        else:
            f.write('1')
            print("Password change set to yes for user " + sys.argv[2])


def removeUser():
    with open('salt.txt', 'r') as f:
        salt = f.readline() #Open salt
    usr_hash = SHA3_256.new()
    usr_hash.update((sys.argv[2]+salt).encode('ascii'))
    if (checkExist(usr_hash) == 1):
        os.remove(usr_hash.hexdigest() + '.txt')
        print("User removed")
    else:
        print("User doesnt exist")

if (os.path.isfile('salt.txt') == False):
    with open('salt.txt', 'w+') as f: #Create random salt
            f.write(get_random_bytes(16).hex())


if sys.argv[1] == 'add':
    addUser()
elif sys.argv[1] == 'passwd':
    changePassword()
elif sys.argv[1] == 'forcepass':
    forceChange()
elif sys.argv[1] == 'del':
    removeUser()
