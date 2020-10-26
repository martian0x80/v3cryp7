from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from os import urandom
import struct
import base64
import sys,getopt
dic=dict()
def key_iv_generatorformechanics(passwd):
		#for cbc mode of AES-256/Rijndael-256 cipher these are required
		#iv(initialization vector), salt for entropy in KDF output
		iv=urandom(AES.block_size) #AES.block_size=16
		salt=urandom(AES.block_size)
		kdfed_key=PBKDF2(passwd.encode('utf-8'),salt,dkLen=32,count=10000)
		dic={'key':kdfed_key,'salt':salt,'iv':iv} #remove key and make a mysql db and encrypt the file
		return iv,kdfed_key,salt;
class mechanicsAES256:
	def __init__(self,iv=None,key=None,salt=None):
		self.key=key
		self.iv=iv
		self.encsalt=salt
	def encrypt_file(self,filein,fileout=None,chunkSize=32*1024):
		if not fileout:
			fileout=filein+'.enc'
		filesize=os.path.filesize(filein)
		cipher_config_en=AES.new(self.key,AES.MODE_CBC,self.iv)
		with open(filein,'rb') as infile:
			with open(fileout,'wb') as outfile:
				outfile.write(struct.pack('<Q',filesize)) #first 8 bytes
				outfile.write(self.encsalt) #second 16 bytes
				outfile.write(iv) #second 16 bytes
				while True:
					chunk=infile.read(chunkSize)
					if len(chunk)==0:
						break
					elif len(chunk) % AES.block_size != 0:
						chunk+=' ' * (16 - len(chunk) % 16)
					outfile.write(base64.b64encode(cipher_config.encrypt(chunk)))
	@staticmethod
	def decrypt_file(encfile,passwd,plainTextfile=None,chunkSize=32*1024):
		encfile=base64.b64decode(encfile)
		if not plainTextfile:
			plainTextfile=encfile.replace('.enc','')
		with open(encfile,'rb') as infile:
			filesize_original=struct.unpack('<Q',infile.read(struct.calcsize('Q')))[0]
			salt=infile.read(16)
			deckey=PBKDF2(passwd.encode('utf-8'),salt,dkLen=32,count=10000)
			iv=infile.read(16)
			cipher_config_de=AES.new(deckey,AES.MODE_CBC,iv)
			with open(plainTextfile,'wb') as outfile:
				while True:
					chunk=outfile.read(chunkSize)
					if len(chunk)==0:
						break
					outfile.write(cipher_config_de.decrypt(chunk))
				outfile.truncate(filesize_original)
	def encrypt_text(self,plainTexttoencrypt):
		cipher_config_entext=AES.new(self.key,AES.MODE_CBC,self.iv)
		chunkl=0
		while True: #·ÿ(è²Å¸×Å9è=ö
			if len(plainTexttoencrypt)==0:
				break
			elif len(plainTexttoencrypt) % 16 != 0:
				chunkl += 16 - len(plainTexttoencrypt)%16
				plainTexttoencrypt+=chr(chunkl)*chunkl
			return self.encsalt+self.iv+cipher_config_entext.encrypt(plainTexttoencrypt) #doubtful
	def decrypt_text(self,enctext):
		####read bytes from enctext
		cipher_config_detext=AES.new(key,AES.MODE_CBC,iv) #add padding support
		return cipher_config_detext.decrypt(enctext.encode('utf-8'));
iv,key,salt=key_iv_generatorformechanics('password')
print(iv,key,salt)
y=mechanicsAES256(iv,key,salt).encrypt_text('thisisatext')
print(y)