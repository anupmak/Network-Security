import pwd
import crypt
import getpass
import fileinput
import socket
import json
import hashlib
import base64
import os
from Crypto.Cipher import AES

#----------------------------------------------------------
def reverseFn(text):
	if len(text) <= 1:
		return text
	return reverseFn(text[1:]) + text[0]
#----------------------------------------------------------


#----------------------------------------------------------
def reversedEightChar(givenHash):
	shortened 	= givenHash[len(givenHash)-8:]
	reversedString 	= reverseFn(shortened);
	return reversedString
#----------------------------------------------------------


#----------------------------------------------------------
def reduction(reversedString):
	reducedC = ""
	s = ord('a')
	for x in xrange(0, len(reversedString)):
			t = ord(reversedString[x])
			u = s + t%26
			reducedC = reducedC + chr(u)
	#print reducedC	
	return reducedC
#----------------------------------------------------------


#----------------------------------------------------------
def cryptFn(reducitonValue,salt):
	newHash = crypt.crypt(reducitonValue,salt)
	return newHash
#----------------------------------------------------------


#----------------------------------------------------------
def readJSONFile(givenHash,salt):

	flag = 0
	for h in xrange(0,65538):
		
		# reduciton for last 8 char of given hash
		a = reversedEightChar(givenHash)
		b = reduction(a)
	
		# check if reduction present in file
		fileJSON = open('table.json', 'r')
		for line in fileJSON:
			flag = line.find(b)
			# break if found
			if flag > 0:
				break
		
		fileJSON.close()
		
		# break if found else convert reduciton to new hash
		if(flag >0):
			break
		else:
			givenHash = cryptFn(b,salt)
	
	return flag
#----------------------------------------------------------
def getStart(flag):
	fileJSON = open('table.json','r')
	start = ""
	for x in range(flag-17,flag-9):
		start11 = fileJSON.seek(x)
		start11 =  fileJSON.read(1)
		start = start + start11
	return start
#----------------------------------------------------------

def getPassword(startVal,hashVal):
	flag = 0
	for x in range(0,65536):
		hash = cryptFn(startVal,salt)
		if(hash == hashVal):
			return startVal
		else:	
			reversedHash = reversedEightChar(hash)
			reduced = reduction(reversedHash)
			startVal = reduced

		
		
#----------------------------------------------------------
def getHashPasswd(password):
	hashObj = hashlib.sha1(password)
	hex_dig = hashObj.hexdigest()
	hex_str = str(hex_dig)
	hex_str = hex_str[0:32]
	return hex_str
#--------------------------------------------------------------
def AESencrypt(password, plaintext): 
    iv = os.urandom(16)
    cipherSpec = AES.new(password, AES.MODE_CFB,iv)
    ciphertext = cipherSpec.encrypt(plaintext)
    return base64.b64encode(iv+ciphertext)
    
#--------------------------------------------------------------
def keyExchange(user):
	data = {"client_id": user,"server_id": "token_server","nonce" :2}
	dataLen = len(str(data))
	dataL = str(dataLen)
	lengOfl = len(dataL)
	lengOl = dataL
	while(lengOfl<8):
		lengOl = "0" + lengOl
		lengOfl = lengOfl + 1
	s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	s.connect(('guldendraak.ccs.neu.edu', 5452))
	data1 = json.dumps(data)
	s.send(lengOl+data1)
	result = s.recv(1024)
	s.close()
	return result
#--------------------------------------------------------------

def getBase64Decoded(encodedText):
	return base64.b64decode(encodedText)
	
#--------------------------------------------------------------
def AESdecrypt(password, ciphertext):
	decodedCiphertext = base64.b64decode(ciphertext)
	startIv = len(decodedCiphertext)-32
	startSalt = len(decodedCiphertext)-16
	data = decodedCiphertext
	iv = decodedCiphertext[startIv:startSalt]
	derivedKey = password
	cipherSpec = AES.new(derivedKey, AES.MODE_CFB, iv)
	decrypted = cipherSpec.decrypt(data)
	return decrypted
#--------------------------------------------------------------

def keyExchangeWithTokenServer(nsMsg,token):
	
	data = nsMsg
	dataLen = len(str(data))
	dataL = str(dataLen)
	lengOfl = len(dataL)
	lengOl = dataL
	while(lengOfl<8):
		lengOl = "0" + lengOl
		lengOfl = lengOfl + 1
	s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	s.connect(('guldendraak.ccs.neu.edu', 5453))
	data1 = json.dumps(data)
	s.send(lengOl+data)
	result = s.recv(1024)
	respFromTS = str(result)
	respTS= respFromTS[8:]
	nonce = (str(AESdecrypt(token,respTS)))
	nonce = nonce[16:]
	nonce1 = json.loads(nonce)
	nonce1 = nonce1['nonce']
	nonce1 = nonce1-1
	data1= {"nonce" : nonce1}
	data1= json.dumps(data1)
	data = AESencrypt(token,data1)
	dataLen = len(str(data))
	dataL = str(dataLen)
	lengOfl = len(dataL)
	lengOl = dataL
	while(lengOfl<8):
		lengOl = "0" + lengOl
		lengOfl = lengOfl + 1
	s.send(lengOl+data)
	result = s.recv(1024)
	s.close()
	return result
#--------------------------------------------------------------	
def sendtoDB(user,token):
	data = {"command": "AUTH","client_id": user, "token":token}
	dataLen = len(str(data))
	dataL = str(dataLen)
	lengOfl = len(dataL)
	lengOl = dataL
	while(lengOfl<8):
		lengOl = "0" + lengOl
		lengOfl = lengOfl + 1
	s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	s.connect(('guldendraak.ccs.neu.edu', 2002))
	data1 = json.dumps(data)
	data2 = lengOl+data1
	fh = open("data2.txt","w")
	fh.write(data2)
	fh.close()
	fi = open("data2.txt", "r")
	buf = fi.read(68)
	while (buf):
		s.send(buf)
		buf = fi.read(68)
	fi.close()
	result = s.recv(1024)
	s.close()	
	return result
#----------------------------------------------------------
def driverFn(givenHash,user,salt):
	flag = readJSONFile(givenHash,salt)
	start = getStart(flag)
	password = getPassword( start, givenHash)
	hashPasswd= getHashPasswd(password)
	base64Encoded = str(keyExchange(user))
	base64Encoded = base64Encoded[8:]
	decryptedMsg =  str(AESdecrypt(hashPasswd,base64Encoded))
	decryptedMsg = decryptedMsg[16:]
	NSreply = json.loads(decryptedMsg)
	token = NSreply['key']
	nsMsg = NSreply['server_msg']
	result = keyExchangeWithTokenServer(nsMsg,token)
	result = result[8:]
	result = AESdecrypt(token,result)
	result = result[16:]
	decryptedMsg = json.loads(result)
	decryptedMsg1 = decryptedMsg['token'] 
	secret = sendtoDB(str(user),str(decryptedMsg1))
	secret = secret[8:]
	secret1 = json.loads(secret)
	secret1 = secret1['secret']
	print secret1 + " is the secret for user " + user


#----------------------------------------------------------

user1 = "aoun"
user2 = "curry"
user3 = "ryder"

givenHash1	= "$1$HUSKIES!$v/mh7SBLm8/3SBL6w0Z9M1"
givenHash2	= "$1$HUSKIES!$xk2VnxpJYAGOxEl0W8uEP0"
givenHash3	= "$1$HUSKIES!$R9bstTQ9eG2Pzql0cq7kd/"
salt		= "$1$HUSKIES!$"

driverFn(givenHash1,user1,salt)
driverFn(givenHash2,user2,salt)
driverFn(givenHash3,user3,salt)

#----------------------------------------------------------
