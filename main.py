from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from os import urandom
import struct
import base64
import sys
import argparse
from argparse import RawTextHelpFormatter
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
		while True: 
			if len(plainTexttoencrypt)==0:
				break
			elif len(plainTexttoencrypt) % 16 != 0:
				chunkl += 16 - len(plainTexttoencrypt)%16
				plainTexttoencrypt+=chr(chunkl)*chunkl
			return self.encsalt+self.iv+cipher_config_entext.encrypt(plainTexttoencrypt) #doubtful
	@staticmethod	
	def decrypt_text(key,enctext):
		####read bytes from enctext
		salt,iv_de=enctext[:16],enctext[16:32]  #first 
		cipher_config_detext=AES.new(key,AES.MODE_CBC,iv_de)
		return cipher_config_detext.decrypt(enctext[32:]);
'''
iv,key,salt=key_iv_generatorformechanics('password')
print(iv,key,salt)
y=mechanicsAES256(iv,key,salt)
d=y.encrypt_text('thisisareallyreallyreallylongtext')
print(d)
print(y.decrypt_text(d))
'''
def runtime_mode():
	modes=['filenc','filedec','textenc','textdec','passwdmngr']
	desc='''
	v3cryp7: File encryption/decryption with AES-256, Password manager tool written in Python\n
	file modes : {0} & {1}
	\'-I\' is required in file modes, but \'-O\' is optional\n
	text modes : {2} & {3}
	\'Either \'--ptext\' or \'--ctext\' is required in text modes
	for {4} \'--ptext\' is required
	for {5} \'--ctext\' is required\n
	password manager : {6}
	'''.format(modes[0],modes[1],modes[2],modes[3],modes[2],modes[3],modes[4])
	mode='''
	Available modes :
	{0}			File Encryption Mode,
	{1} 		File Decryption Mode,
	{2}			Text Encryption Mode,
	{3}			Text Decryption Mode,
	{4}			Password Manager
	'''.format(modes[0],modes[1],modes[2],modes[3],modes[4])
	parser=argparse.ArgumentParser(prog='v3cryp7',prefix_chars='-',formatter_class=RawTextHelpFormatter,description=desc,epilog='Enjoy!')
	parser.add_argument('-i','--interactive',action='store_true',help='use this option to enable interactive mode')
	parser.add_argument('mode',action='store',help=mode)
	parser.add_argument('-I','--input-file',action='store',help='file to be encrypted/decrypted')
	parser.add_argument('-O','--output-file',action='store',default=None,help='output file name')
	parser.add_argument('--ptext',action='store',help='plaintext to encrypt')
	parser.add_argument('--ctext',action='store',help='cipher text to decrypt')
	#add more arguments for export after creating missc funcs
	args_parsed=parser.parse_args()
	if args_parsed.interactive==True:
		print('[-]Starting interactive mode...')
		#add interactive func
	else:
		if args_parsed.mode=='filenc':
			print('File Encryption Mode\n')
		elif args_parsed.mode=='filedec':
			print('File Decryption Mode\n')
		elif args_parsed.mode=='textenc':
			print('Text Encryption Mode\n')
		elif args_parsed.mode=='textdec':
			print('Text Decryption Mode\n')
		elif args_parsed.mode=='passwdmngr':
			pass
			#add password manager
		else:
			print('v3cryp7: unrecognized mode: \'{}\''.format(args_parsed.mode))
			print('v3cryp7: Try \'v3cryp7 --help\' for more information')
runtime_mode()
