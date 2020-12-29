from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import os
import struct
import base64
import sys
import argparse
from argparse import RawTextHelpFormatter
import textwrap 
import getpass
import time
import timeit
from colorama import Fore as color
import tarfile

dic=dict()

def clear_screen():
	if os.name=='nt':
		os.system('cls')
	else:
		os.system('clear')
		
def spinner():

	print('processing.../')
	syms = ['\\', '|', '/', '-']
	bs = '\b'

	for _ in range(5):
		for sym in syms:
			sys.stdout.write("\b%s" % sym)
			sys.stdout.flush()
			time.sleep(.25)
'''
def check_ifmoredirs(paths,returndirs=False):
    count=0
    pathdirs=[]
    for subdirs in os.listdir(paths):
        if os.path.isdir(subdirs): #doubtl
            if '.git' in subdirs:
                dustlist.remove('.git')
            count+=1
            pathdirs.append(os.path.abspath(subdirs))
    inform=True 
    if count==0:
       inform=False
    else:
        pass
    if returndirs!=False:
        return inform,pathdirs;
    else:
        return inform;
'''
def _unpad(s):
	return s[:-ord(s[len(s)-1:])]
	
def key_iv_generatorformechanics(passwd):
		#for cbc mode of AES-256/Rijndael-256 cipher these are required
		#iv(initialization vector), salt for entropy in KDF output
		iv=os.urandom(AES.block_size) #AES.block_size=16
		salt=os.urandom(AES.block_size)
		kdfed_key=PBKDF2(passwd.encode('utf-8'),salt,dkLen=32,count=10000)
		dic={'key':kdfed_key,'salt':salt,'iv':iv} #remove key and make a mysql db and encrypt the file
		return iv,kdfed_key,salt;
		
class mechanicsAES256:
	def __init__(self,iv=None,key=None,salt=None):
		self.key=key
		self.iv=iv
		self.encsalt=salt
		
	def encrypt_file(self,filein,fileout=None,chunkSize=64*1024):
		#filein=os.path.basename(os.path.splitext(filein))[0]	
		chunkl=0	
		if not fileout:
			if filein[-7:]=='.tar.gz':
				fileout=filein[:-7]+'.flenc'
			else:
				fileout=filein+'.enc'
		else:
			fileout=fileout+'.enc'
		filesize=os.path.getsize(filein)
		if filesize>104857600:
			print('\nFilesize is big, wait...')
		cipher_config_en=AES.new(self.key,AES.MODE_CBC,self.iv)
		with open(filein,'rb') as infile:
			with open(fileout,'wb') as outfile:
				outfile.write(struct.pack('<Q',filesize)) #first 8 bytes
				outfile.write(self.encsalt) #second 16 bytes
				outfile.write(self.iv) #second 16 bytes
				start=timeit.default_timer()
				while True:
					chunk=infile.read(chunkSize)
					if len(chunk)==0:
						break
					elif len(chunk) % AES.block_size != 0:
						chunkl+=16-len(chunk)%16
						chunk+=chr(chunkl).encode('utf-8') * chunkl	#changed padding from b' '*paddingneed to chr(paddingneed)
					outfile.write(cipher_config_en.encrypt(chunk))
				stop=timeit.default_timer()
				print('\nFile : {}{}{}'.format(color.MAGENTA,fileout,color.RESET))
				print('File size: {}{}MiB or {}MB{}'.format(color.LIGHTGREEN_EX,float(filesize/(1024**2)),float(filesize/(1000**2)),color.RESET))
				print('Encryption time: {}{}s{}'.format(color.LIGHTMAGENTA_EX,stop-start,color.RESET))
				return str(fileout);
				
	@staticmethod
	def decrypt_file(encfile,passwd,plainTextfile=None,chunkSize=24*1024):
		#encfile=base64.b64decode(encfile)
		if not plainTextfile:
			plainTextfile=encfile.replace('.enc','')
			if encfile[-6:]=='.flenc':
				plainTextfile=encfile.replace('.flenc','')+'_decrypted'
		tpfile=plainTextfile+'.decf'
		filesize=os.path.getsize(encfile)
		if filesize>104857600:
			print('\nFilesize is big, wait...')
		with open(encfile,'rb') as infile:
			filesize_original=struct.unpack('<Q',infile.read(struct.calcsize('Q')))[0]
			salt=infile.read(16)
			deckey=PBKDF2(passwd.encode('utf-8'),salt,dkLen=32,count=10000)
			iv=infile.read(16)
			cipher_config_de=AES.new(deckey,AES.MODE_CBC,iv)
			start=timeit.default_timer()
			with open(tpfile,'wb+') as tpfile:
				while True:
					chunk=infile.read(chunkSize)
					if len(chunk)==0:
						break
					tpfile.write(cipher_config_de.decrypt(chunk))
					tpfile.flush()
				with open(plainTextfile,'wb') as outfile:
					tpfile.seek(0)
					outfile.write(_unpad(tpfile.read()))
				stop=timeit.default_timer()	
				os.remove(tpfile.name)
				#outfile.truncate(filesize_original)
				print('\nFile : {}{}{}'.format(color.MAGENTA,plainTextfile,color.RESET))
				print('File size: {}{}MiB or {}MB{}'.format(color.LIGHTGREEN_EX,float(os.path.getsize(plainTextfile)/(1024**2)),float(os.path.getsize(plainTextfile)/(1000**2)),color.RESET))
				print('Decryption time: {}{}s{}'.format(color.LIGHTMAGENTA_EX,stop-start,color.RESET))
				return str(plainTextfile);
				
	def encrypt_text(self,plainTexttoencrypt):
		cipher_config_entext=AES.new(self.key,AES.MODE_CBC,self.iv)
		chunkl=0
		while True: 
			if len(plainTexttoencrypt)==0:
				break
			elif len(plainTexttoencrypt) % 16 != 0:
				chunkl += 16 - len(plainTexttoencrypt)%16
				plainTexttoencrypt+=chr(chunkl)*chunkl
			return self.encsalt+self.iv+cipher_config_entext.encrypt(plainTexttoencrypt.encode('utf-8')) #doubtful
			
	@staticmethod	
	def decrypt_text(passwd,enctext):
		####read bytes from enctext
		salt,iv_de=enctext[:16],enctext[16:32]  #first 16 bytes are salt, next 16 are iv
		key=PBKDF2(passwd.encode('utf-8'),salt,dkLen=32,count=10000)
		cipher_config_detext=AES.new(key,AES.MODE_CBC,iv_de)
		return _unpad(cipher_config_detext.decrypt(enctext[32:]));
	
'''
iv,key,salt=key_iv_generatorformechanics('password')
print(iv,key,salt)
y=mechanicsAES256(iv,key,salt)
d=y.encrypt_text('thisisareallyreallyreallylongtext')
print(d)
print(y.decrypt_text(d))
'''

def get_input(flag=False,exceptt=False): #to reduce code and logics
	try:
		if flag: #flag for password inputs
			passwd = getpass.getpass('Enter session password: ')
			return passwd;
		else:
			inp=str(input('\n>> '))
			if exceptt: #empty input exception when taking outfile file
				return inp;
			else:
				if inp=='':
					print('Empty input supplied\nTry again. Or exit')
					get_input()
				else:
					return inp;
	except KeyboardInterrupt: #ctrl+c handling
		print('\n[{}!!{}]Execution stopped, user interruption.\n[{}!!{}]Exiting...'.format(color.RED,color.RESET,color.RED,color.RESET))
		spinner()
		sys.exit(1)
'''		Deprecated way, inefficient and prone to problems
def encrypt_folder(flin,passwd,flout): #no separate iv,salt,key needed, generates for each file
		if not flout:
			flout=flin
		dustlist=os.listdir(flin)
		subdirs_path=[]
		file_paths=[]
		print('Scanning directory for files and folders.\n') #'and folders.'
		print('\n[{}*{}]Subdirectories found: '.format(color.MAGENTA,color.RESET))
		for subdirs in dustlist:
			if os.path.isdir(flin+'/'+subdirs): #doubtl
				if '.git' in subdirs:
					dustlist.remove('.git')
				print('\t'+os.path.abspath(flin+'/'+subdirs))
				subdirs_path.append(os.path.abspath(flin+'/'+subdirs))
#		for paths in subdirs_path:
#			inf=check_ifmoredirs(paths)
#			while inf!=False:
#				inf,moredirs=check_ifmoredirs(paths,returndirs=True)
#				subdirs_path.extend(moredirs)
		print('[{}*{}]Files found: '.format(color.MAGENTA,color.RESET))
		for dirpath,dirnames,filenames in os.walk(flin):
			if '.git' in dirnames:
				dirnames.remove('.git')
			else:
				for names in filenames:
					print('\t'+os.path.join(dirpath,names))
					file_paths.append(os.path.join(dirpath,names))
		#print('\n[{}!{}]Do you want the original files deleted? [Y/n]'.format(color.RED,color.RESET))
		#remfiles=get_input()
		#start=timeit.default_timer()
		#for files in file_paths:
			#iv,key,salt=key_iv_generatorformechanics(passwd)
			#y=mechanicsAES256(iv,key,salt).encrypt_file(files)
			#if remfiles=='Y' or remfiles=='y' or remfiles=='yes': #might cause inaccurate encryption benchmark
			#	os.remove(files)
		#stop=timeit.default_timer()
		#print('\nEncryption timed for all files: {}{}s{}\nArchiving and encrypting again.'.format(color.LIGHTMAGENTA_EX,stop-start,color.RESET))
		tarfile.shutil.make_archive(flout,'tar',flin)
		#finally encrypt the archived directory
		iv,key,salt=key_iv_generatorformechanics(passwd)
		y=mechanicsAES256(iv,key,salt).encrypt_file(flout+'.tar')
		os.remove(flout+'.tar')
		return len(file_paths);
'''
	
def encrypt_folder(flin,passwd,flout):
	count=0
	if not flout:
		flout=flin
	print('[{}*{}]Files found: '.format(color.MAGENTA,color.RESET))
	for dirpath,dirnames,filenames in os.walk(flin):
		if '.git' in dirnames:
			dirnames.remove('.git')
		else:
			for names in filenames:
				print('\t'+os.path.join(dirpath,names))
				count+=1
	print('\n[{}-{}]Archiving files and Encrypting.'.format(color.CYAN,color.RESET))
	tarfile.shutil.make_archive(flout,'gztar',flin,verbose=1)
	iv,key,salt=key_iv_generatorformechanics(passwd)
	start=timeit.default_timer()
	_=mechanicsAES256(iv,key,salt).encrypt_file(flout+'.tar.gz')
	stop=timeit.default_timer()
	print('\nEncryption time for archived file: {}{}s{}'.format(color.LIGHTMAGENTA_EX,stop-start,color.RESET))
	os.remove(flout+'.tar.gz')
	return count;

def decrypt_folder(flin,passwd,flout):
		curr_dir=os.path.abspath(os.getcwd())
		decfl=mechanicsAES256.decrypt_file(flin,passwd,flout)
		assert tarfile.is_tarfile(decfl)
		with tarfile.open(decfl,'r:gz') as fl:
			os.makedirs('Decrypted/'+flin.replace('.flenc',''))
			os.chdir('Decrypted/'+flin.replace('.flenc',''))
			fl.extractall()
		os.chdir(curr_dir)
		os.remove(decfl)
def interactive_mode(flag=False): #interactive mode with argument switch -i or --interactive
	if flag: #flag for faster menu access, no need of ambigious 'starting interactive mode...' everytime returning to menu 
		print(color.GREEN+"\t\tStarting interactive mode..."+color.RESET)
		spinner()
	menu='''
	Functions :\n
	1. Text Encryption	(1 or textenc)
	2. Text Decryption	(2 or textdec)
	3. File Encryption	(3 or filenc)
	4. File Decryption	(4 or filedec)
	5. Folder Encryption (5 or flenc)
	6. Folder Decryption (6 or fldec)
	99. Exit (99 or exit)
	'''
	print(menu)
	try:
		inp=get_input()
		if inp=='1' or inp=='textenc':
			print('\n[{}++{}]Text Encryption Mode...'.format(color.GREEN,color.RESET))
			passwd=get_input(flag=True)
			iv,key,salt=key_iv_generatorformechanics(passwd)
			flagy=False
			while flagy==False:
				print('\nInput the text to encrypt')
				plaintext=get_input()
				encrypt=mechanicsAES256(iv,key,salt).encrypt_text(plaintext)
				print('\n{}Ciphertext{}: {}'.format(color.LIGHTGREEN_EX,color.RESET,base64.b64encode(encrypt).decode('utf-8')))
				print('\nMore text to encrypt? [y/N]')
				inpp=get_input(exceptt=True)
				if inpp=='Y' or inpp=='y':
					pass
				else:
					flagy=True
			clear_screen()
			print('[{}-{}]Taking back to menu...'.format(color.CYAN,color.RESET))
			interactive_mode()
			
		elif inp=='2' or inp=='textdec':
			print('[{}++{}]Text Decryption Mode...'.format(color.GREEN,color.RESET))
			passwd=get_input(flag=True)
			flagy=False
			while flagy==False:
				print('\nInput the text to decrypt')
				ciphertext=get_input()
				decrypt=mechanicsAES256.decrypt_text(passwd,base64.b64decode(ciphertext))
				print('\n{}Plaintext{}: {}'.format(color.LIGHTGREEN_EX,color.RESET,base64.b64decode(decrypt).decode('utf-8')))
				print('\nMore text to decrypt? [y/N]')
				inpp=get_input(exceptt=True)
				if inpp=='Y' or inpp=='y':
					pass
				else:
					print('[{}-{}]Taking back to menu...'.format(color.CYAN,color.RESET))
					flagy=True
			clear_screen()
			interactive_mode()
			
		elif inp=='3' or inp=='fileenc':
			print('[{}++{}]File Encryption Mode...'.format(color.GREEN,color.RESET))
			fileout=None
			passwd=get_input(flag=True)
			iv,key,salt=key_iv_generatorformechanics(passwd)
			flagy=False
			while flagy==False:
				print('\nThe file to encrypt [{}*{}]'.format(color.MAGENTA,color.RESET))
				filein=get_input()
				print('\nOutput file name [you can skip it]')
				fileout=get_input(exceptt=True)
				encrypt=mechanicsAES256(iv,key,salt).encrypt_file(filein,fileout)
				print('\nFile \'{}{}{}\' saved to {}'.format(color.MAGENTA,encrypt,color.RESET,os.getcwd()))
				print('\nMore files to encrypt? [y/N]')
				inpp=get_input(exceptt=True)
				if inpp=='Y' or inpp=='y':
					pass
				else:
					print('[{}-{}]Taking back to menu...'.format(color.CYAN,color.RESET))
					flagy=True
			clear_screen()
			interactive_mode()
			
		elif inp=='4' or inp=='filedec':
			print('[{}++{}]File Decryption Mode...'.format(color.GREEN,color.RESET))
			fileout=None
			passwd=get_input(flag=True)
			flagy=False
			while flagy==False:
				print('\nThe file to decrypt [{}*{}]'.format(color.MAGENTA,color.RESET))
				filein=get_input()
				print('\nOutput file name [you can skip it]')
				fileout=get_input(exceptt=True)
				decrypt=mechanicsAES256.decrypt_file(filein,passwd,fileout)
				print('\nFile \'{}{}{}\' saved to {}'.format(color.MAGENTA,decrypt,color.RESET,os.getcwd()))
				print('\nMore files to decrypt? [y/N]')
				inpp=get_input(exceptt=True)
				if inpp=='Y' or inpp=='y':
					pass
				else:
					print('[{}-{}]Taking back to menu...'.format(color.CYAN,color.RESET))
					flagy=True
			clear_screen()
			interactive_mode()
			
		elif inp=='5' or inp=='flenc':
			print('[{}++{}]Folder Encryption Mode...'.format(color.GREEN,color.RESET))
			fileout=None
			passwd=get_input(flag=True)
			flagy=False
			while flagy==False:
				print('\nThe folder to encrypt [{}*{}]'.format(color.MAGENTA,color.RESET))
				filein=get_input()
				print('\nOutput file name [you can skip it]')
				fileout=get_input(exceptt=True)
				encrypt_folder(filein,passwd,fileout)
				print('\nMore folders to encrypt? [y/N]')
				inpp=get_input(exceptt=True)
				if inpp=='Y' or inpp=='y':
					pass
				else:
					print('[{}-{}]Taking back to menu...'.format(color.CYAN,color.RESET))
					flagy=True
			clear_screen()
			interactive_mode()
		
		elif inp=='6' or inp=='fldec':
			print('[{}++{}]Folder Decryption Mode...'.format(color.GREEN,color.RESET))
			fileout=None
			passwd=get_input(flag=True)
			flagy=False
			while flagy==False:
				print('\nThe folder to decrypt [{}*{}]'.format(color.MAGENTA,color.RESET))
				filein=get_input()
				print('\nOutput file name [you can skip it]')
				fileout=get_input(exceptt=True)
				decrypt_folder(filein,passwd,fileout)
				print('\nMore files to decrypt? [y/N]')
				inpp=get_input(exceptt=True)
				if inpp=='Y' or inpp=='y':
					pass
				else:
					print('[{}-{}]Taking back to menu...'.format(color.CYAN,color.RESET))
					flagy=True
			clear_screen()
			interactive_mode()
			
		elif inp=='7' or inp=='passwdmngr':
			print('[{}++{}]Password Manager...'.format(color.GREEN,color.RESET))
			#password manager
			
		elif inp=='99' or inp=='exit' or inp=='quit':
			print('[{}!!{}] Execution stopped, user interruption.\n[{}!!{}]Exiting...'.format(color.RED,color.RESET,color.RED,color.RESET))
			spinner()
			clear_screen()
			sys.exit(1)
			
		else:
			print('[{}!!{}]Invalid mode recieved.\nRetry...'.format(color.RED,color.RESET))
			interactive_mode()
			
	except KeyboardInterrupt:
		print('[{}!!{}]Execution stopped, user interruption.\n[{}!!{}]Exiting...'.format(color.RED,color.RESET,color.RED,color.RESET))
		spinner()
		sys.exit(1)
		
def runtime_mode():
	modes=['filenc','filedec','textenc','textdec','passwdmngr','i']
	desc='''
	v3cryp7: File encryption/decryption with AES-256, Password manager tool written in Python\n
	file modes : {0} & {1}\n
	\'-I\' is required in file modes for input file, but \'-O\' is optional for output file name\n
	text modes : {2} & {3}\n
	Either \'--ptext\' or \'--ctext\' is required in text modes
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
	{4}		Password Manager
	'''.format(modes[0],modes[1],modes[2],modes[3],modes[4])
	parser=argparse.ArgumentParser(prog='v3cryp7',usage='use: %(prog)s [mode]... [options]...',prefix_chars='-',description=textwrap.dedent(desc),formatter_class=RawTextHelpFormatter,epilog='Enjoy!')
	parser.add_argument('-i','--interactive',action='store_true',help='use this option to enable interactive mode')
	#parser.add_argument('mode',action='store',help=textwrap.dedent(mode)) 
	mode=parser.add_argument_group('mode')
	mode.add_argument('--filenc',action='store_true',help='File Encryption Mode')
	mode.add_argument('--filedec',action='store_true',help='File Decryption Mode')
	mode.add_argument('--flenc',action='store_true',help='Folder Encryption Mode')
	mode.add_argument('--fldec',action='store_true',help='Folder Decryption Mode')
	mode.add_argument('--textenc',action='store_true',help='Text Encryption Mode')
	mode.add_argument('--textdec',action='store_true',help='Text Decryption Mode')
	mode.add_argument('--passwdmngr',action='store_true',help='Password Manager')
	parser.add_argument('-I','--input-fl',dest='inpf',action='store',help='file to be encrypted/decrypted')
	parser.add_argument('-O','--output-fl',dest='outf',action='store',default=None,help='output file name')
	parser.add_argument('--ptext',action='store',help='plaintext to encrypt')
	parser.add_argument('--ctext',action='store',help='cipher text to decrypt')
	parser.add_argument('-o','--output',action='store_true',help='to enable saving encrypted/decrypted data to files')
	#add more arguments for export after creating missc funcs
	##remove mode pos arg and add opt arg for each mode with action='store_true' 
	args_parsed=parser.parse_args()
	if args_parsed.interactive:
		interactive_mode(flag=True)
	else:
		#print(args_parsed.mode,args_parsed.inpf)
		if args_parsed.filenc:
			try:
				print('\n[{}+{}]File Encryption mode\n'.format(color.GREEN,color.RESET))
				if not args_parsed.inpf=='':
					if os.path.isfile(args_parsed.inpf):
						iv,key,salt=key_iv_generatorformechanics(getpass.getpass('Enter password: '))
						filenc=mechanicsAES256(iv,key,salt).encrypt_file(args_parsed.inpf,args_parsed.outf)
						print('\'{}{}{}\' has been saved to {}/'.format(color.MAGENTA,str(filenc),color.RESET,os.getcwd()))
					else: raise Exception('[{}!{}]File: \'{}{}{}\' does not exist'.format(color.RED,color.RESET,color.RED,args_parsed.inpf,color.RESET))
			except TypeError:
				print('{}v3cryp7{}: No inputs given, \'-I\' is required, \'-O\' is optional'.format(color.RED,color.RESET))
				print('{}v3cryp7{}: Try \'v3cryp7 --help\' for more information'.format(color.RED,color.RESET))

		if args_parsed.filedec:
			try:
				print('\n[{}+{}]File Decryption Mode\n'.format(color.GREEN,color.RESET))
				if not args_parsed.inpf=='':
					if os.path.isfile(args_parsed.inpf):
						filedec=mechanicsAES256.decrypt_file(args_parsed.inpf,getpass.getpass('Enter password: '),args_parsed.outf)
						print('\'{}{}{}\' has been saved to {}/'.format(color.MAGENTA,str(filedec),color.RESET,os.getcwd()))
					else: raise Exception('[{}!{}]File: \'{}{}{}\' does not exist'.format(color.RED,color.RESET,color.RED,args_parsed.inpf,color.RESET))
			except TypeError:
				print('{}v3cryp7{}: No inputs given, \'-I\' is required, \'-O\' is optional'.format(color.RED,color.RESET))
				print('{}v3cryp7{}: Try \'v3cryp7 --help\' for more information'.format(color.RED,color.RESET))
				
		if args_parsed.flenc:
			try:
				print('\n[{}+{}]Folder Encryption Mode\n'.format(color.GREEN,color.RESET))
				if not args_parsed.inpf=='':
					if os.path.isdir(args_parsed.inpf):
						start=timeit.default_timer()
						filec=encrypt_folder(args_parsed.inpf,getpass.getpass('Enter password: '),args_parsed.outf)
						stop=timeit.default_timer()
						print('\n{}{}{} files in \'{}\' are encrypted\nTime elapsed: {}{}{}'.format(color.MAGENTA,filec,color.RESET,args_parsed.inpf,color.LIGHTMAGENTA_EX,stop-start,color.RESET))
					else: raise Exception('[{}!{}]Folder: \'{}{}{}\' does not exist'.format(color.RED,color.RESET,color.RED,args_parsed.inpf,color.RESET))
			except TypeError:
				print('{}v3cryp7{}: No inputs given, \'-I\' is required, \'-O\' is optional'.format(color.RED,color.RESET))
				print('{}v3cryp7{}: Try \'v3cryp7 --help\' for more information'.format(color.RED,color.RESET))
		
		if args_parsed.fldec:
			try:
				print('\n[{}+{}]Folder Decryption Mode\n'.format(color.GREEN,color.RESET))
				if not args_parsed.inpf=='':
					if os.path.isfile(args_parsed.inpf):
						start=timeit.default_timer()
						decrypt_folder(args_parsed.inpf,getpass.getpass('Enter password: '),args_parsed.outf)
						stop=timeit.default_timer()
					else: raise Exception('[{}!{}]File: \'{}{}{}\' does not exist'.format(color.RED,color.RESET,color.RED,args_parsed.inpf,color.RESET))
			except TypeError:
				print('{}v3cryp7{}: No inputs given, \'-I\' is required, \'-O\' is optional'.format(color.RED,color.RESET))
				print('{}v3cryp7{}: Try \'v3cryp7 --help\' for more information'.format(color.RED,color.RESET))
		if args_parsed.textenc: #add clipboard support
			try:
				print('\n[{}+{}]Text Encryption Mode\n'.format(color.GREEN,color.RESET))
				if not args_parsed.ptext=='':
					iv,key,salt=key_iv_generatorformechanics(getpass.getpass('Enter password: '))
					textenc=mechanicsAES256(iv,key,salt).encrypt_text(args_parsed.ptext)
					print('\n{}Cipher text{}: {}\t(base64)\n'.format(color.LIGHTGREEN_EX,color.RESET,base64.b64encode(textenc).decode('utf-8')))
					#print('Want the cipher text saved to a file? [y/N]')
					if args_parsed.output:
						#ask=raw_input('\n>> ')
						#if ask=='y' or ask=='Y':
						with open('ciphertext'+str(time.time())+'.txt','w') as cipherfile:
							cipherfile.write(base64.b64encode(textenc).decode('utf-8'))
							print('File: \'{}{}{}\' saved in {}'.format(color.MAGENTA,str(cipherfile.name),color.RESET,str(os.getcwd())))
			except TypeError:
				print('{}v3cryp7{}: No inputs given, \'--ptext\' is required'.format(color.RED,color.RESET))
				print('{}v3cryp7{}: Try \'v3cryp7 --help\' for more information'.format(color.RED,color.RESET))
				
		if args_parsed.textdec:
			try:
				print('\n[{}+{}]Text Decryption Mode\n'.format(color.GREEN,color.RESET))
				if not args_parsed.ctext=='':
					textdec=mechanicsAES256.decrypt_text(getpass.getpass('Enter password: '),base64.b64decode(args_parsed.ctext))
					print('\n{}Decrypted text{}: {}'.format(color.LIGHTGREEN_EX,color.RESET,textdec.decode('utf-8')))
					if textdec=='':
						print("[{}!{}]Invalid password or no decryption occured.\n".format(color.RED,color.RESET))
					else:
						if args_parsed.output:
							with open('plaintext'+str(time.time())+'.txt','w') as plaintextfile:
								plaintextfile.write(textdec.decode('utf-8'))
								print('File: \'{}{}{}\' saved in {}'.format(color.MAGENTA,str(plaintextfile.name),color.RESET,str(os.getcwd())))
			except TypeError:
				print('{}v3cryp7{}: No inputs given, \'--ctext\' is required'.format(color.RED,color.RESET))
				print('{}v3cryp7{}: Try \'v3cryp7 --help\' for more information'.format(color.RED,color.RESET))
				
		if args_parsed.passwdmngr:
			pass
			#add password manager
		
		if not args_parsed.textdec and not args_parsed.textenc and not args_parsed.filenc and not args_parsed.filedec and not args_parsed.interactive and not args_parsed.passwdmngr and not args_parsed.flenc and not args_parsed.fldec:
			print('{}v3cryp7{}: unrecognized mode'.format(color.RED,color.RESET))
			print('{}v3cryp7{}: Try \'v3cryp7 --help\' for more information'.format(color.RED,color.RESET))
#iv,key,salt=key_iv_generatorformechanics('password')
#mechanicsAES256.decrypt_file('en.py.enc','password')
if __name__=="__main__":
	runtime_mode()
