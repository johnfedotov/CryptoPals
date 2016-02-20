import base64
from collections import Counter
import string
from Crypto.Cipher import AES
# base64.b64encode(*bytes*)
# bytes.fromhex(*str*)
# str.encode() -> to bytes
# b''.decode() -> to sting
# for (a,b) in zip("a","b")
# //from collections import Counter
# //c = Counter(iter)
# all(ch in valid_characters for ch in str)

def Challenge1():
	# Convert hex to base64
	h = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	b64 = base64.b64encode(bytes.fromhex(h))
	print(b64.decode())

def Challenge2():
	# Fixed XOR
	h1 = "1c0111001f010100061a024b53535009181c"
	h2 = "686974207468652062756c6c277320657965"
	a1 = bytes.fromhex(h1)
	a2 = bytes.fromhex(h2)
	b = bytes([a^b for (a,b) in zip(a1,a2)])
	print(b.hex())

def Challenge3():
	# Single-byte XOR cipher
	h="1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	s=""
	a = bytes.fromhex(h)
	c = Counter(a)
	for byte in a:
		s+=chr(byte^88)
	print(s)

def Challenge4():
	# Detect single-character XOR
	f = open("4.txt","r")
	valid_characters = set(string.printable)-set(string.digits)-set(['#','$','%','/','~','`'])
	candidates = []
	for line in f:
		l = bytes.fromhex(line.strip())
		for ch in string.printable:
			xored = bytes([a^b for (a,b) in zip(l, bytes(ch*len(l),'ascii'))])
			if all(map(lambda c: chr(c) in valid_characters, xored)):
				candidates.append((ch, xored))
	f.close()
	print(candidates)

def Challenge5():
	#  Implement repeating-key XOR 
	plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	pt = plaintext.encode()
	key = "ICE"
	k = (key*(int(len(plaintext)/len(key))+1)).encode()
	ct = bytes([a^b for (a,b) in zip(pt,k)])
	ciphertext = ct.hex()
	print(ciphertext)

def Challenge6():
	# Break repeating-key XOR
	f = open("6.txt","r")
	ciphertext = ''.join([line.strip() for line in f.readlines()])
	ct = base64.b64decode(ciphertext)
	dists = list()
	for keysize in range(2,40):
		dists.append((keysize,Avg_Hamming_Dist(ct,keysize)))
	dists = sorted(dists, key=lambda x: x[1])
	print('smallest distance {1} was found with key size {0}'.format(*dists[0]))
	keysize = dists[0][0];
	transposed = [ct[i::keysize] for i in range(keysize)]
	most_common_char = ord(' ')
	candidate = bytearray()
	for part in transposed:
		c = Counter(part)
		char, _ = c.most_common()[0]
		candidate.append(char^most_common_char)
	print(candidate.decode())

def Hamming_Dist(s1,s2):
	xor = bytes([a^b for (a,b) in zip(s1,s2)])
	count = sum( (xor[j] >> i) & 1 for i in range(8) for j in range(len(xor)) )
	return count

def Avg_Hamming_Dist(ct,size):
	parts = [ct[i:i+size] for i in range(0,len(ct)-size,size)]
	return sum(Hamming_Dist(c1,c2)/size for c1,c2 in zip(parts,parts[1:]))/len(parts[1:])

def Challenge7():
	# AES in ECB mode
	f = open("7.txt","r")
	ciphertext = ''.join([line.strip() for line in f.readlines()])
	ct = base64.b64decode(ciphertext)
	key = "YELLOW SUBMARINE"
	aes = AES.new(key,AES.MODE_ECB)
	plain = aes.decrypt(ct)
	print(plain)

def Challenge8():
	# Detect AES in ECB mode
	f = open("8.txt","r")	
	for line in f.readlines():
		blocks = [line[i:i+16] for i in range(0,len(line)-16,16)]
		for block in blocks:
			if blocks.count(block) > 1:
				print(line)
				break

Challenge1()
