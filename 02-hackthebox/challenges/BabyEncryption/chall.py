import string
#from secret import MSG

#def encryption(msg):
#    ct = []
#    for char in msg:
#        ct.append((123 * char + 18) % 256)
#    return bytes(ct)

#ct = encryption(MSG)
#f = open('./msg.enc','w')
#f.write(ct.hex())
#f.close()


def decrypt(msg):
	pt = []
	for char in msg:
		char = char - 18
		# 179 = multiplicative inverse of 123 and modulo 256
		# multiplicative inverse of a number x is given by x^-1
		# multiplicative inverse of 
		char = 179 * char % 256
		pt.append(char)
	return bytes(pt)

with open("msg.enc") as f:
	ct = bytes.fromhex(f.read())

pt = decrypt(ct)
print(pt)