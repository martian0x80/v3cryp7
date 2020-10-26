from Crypto.Cipher import AES
from Cryptodome.Protocol.KDF import PBKDF2
from os import urandom
import struct
import base64
import sys,getopt
lis=[]
class mechanicsAES256:
	def __init__(self,iv,key):
		self.key=key
		self.iv=iv
	def encrypt_file(self,filein,fileout=None,chunkSize=32*1024):
		if not fileout:
			fileout=filein+'.enc'
		filesize=os.path.filesize(filein)
		cipher_config_en=AES.new(self.key,AES.MODE_CBC,self.iv)
		with open(filein,'rb') as infile:
			with open(fileout,'wb') as outfile:
				outfile.write(struct.pack('<Q',filesize))
				outfile.write(iv)
				while True:
					chunk=infile.read(chunkSize)
					if len(chunk)==0:
						break
					elif len(chunk) % AES.block_size != 0:
						chunk+=' ' * (16 - len(chunk) % 16)
					outfile.write(base64.b64encode(cipher_config.encrypt(chunk)))
	def decrypt_file(self,encfile,plainTextfile=None,chunkSize=32*1024):
		encfile=base64.b64decode(encfile)
		if not plainTextfile:
			plainTextfile=encfile.replace('.enc','')
		with open(encfile,'rb') as infile:
			filesize_original=struct.unpack('<Q',infile.read(struct.calcsize('Q')))[0]
			iv=infile.read(16)
			cipher_config_de=AES.new(self.key,AES.MODE_CBC,iv)
			with open(plainTextfile,'wb') as outfile:
				while True:
					chunk=outfile.read(chunkSize)
					if len(chunk)==0:
						break
					outfile.write(cipher_config_de.decrypt(chunk))
				outfile.truncate(filesize_original)
	def encrypt_text(self,plainTexttoencrypt):
		cipher_config_entext=AES.new(self.key,AES.MODE_CBC,self.iv)
		while True:
			if len(plainTexttoencrypt)==0:
				break
			elif len(plainTexttoencrypt) % 16 != 0:
				chunkl+=16  - len(plainTexttoencrypt)%16
				plainTexttoencrypt+=chr(chunkl)*chunkl
			return cipher_config_entext.encrypt(plainTexttoencrypt);
	def decrypt_text(self,enctext):
		cipher_config_detext=AES.new(self.key,AES.MODE_CBC,self.iv) #add padding support
		return cipher_config_detext.decrypt(enctext.encode('utf-8'));
def key_iv_generatorformechanics(passwd):
		#for cbc mode of AES-256/Rijndael-256 cipher these are required
		#iv(initialization vector), salt for entropy in KDF output
		iv=urandom(AES.block_size) #AES.block_size=16
		salt=urandom(2*AES.block_size)
		kdfed_key=PBKDF2(passwd.encode('utf-8'),salt,dkLen=32,count=10000)
		lis.update([kdfed_key,salt,iv])
		#blank the list after using the mechanics class once
print(key_iv_generatorformechanics('kunj2004'))
