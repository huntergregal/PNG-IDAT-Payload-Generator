# PNG-IDAT-Payload-Generator
Generate a PNG with a payload embedded in the IDAT chunk (Based off of previous concepts and code -- credit given below)
Additionally, bruteforce payloads matching a regex pattern

This is a Python3, PEP8-compatible, fully-working version of huntergregal's initial project. Rewritten and fixed by https://github.com/TheZ3ro @TheZ3Pro

Update: Added prepopulated payload tables, improved bruteforce speeds, added xqi.cc payload to table

## Based Off of Previous Concepts and Research
* Hunter Gregal -- https://github.com/huntergregal/PNG-IDAT-Payload-Generator
* Adam Logue -- https://www.adamlogue.com/revisiting-xss-payloads-in-png-idat-chunks
* IDontPlayDarts -- https://www.idontplaydarts.com/2012/06/encoding-web-shells-in-png-idat-chunks
* fin1te -- https://whitton.io/articles/xss-on-facebook-via-png-content-types
* Vavkamil -- https://github.com/vavkamil/PNG-IDAT-chunks

## Usage
```
usage: generate.py [-h] [-q] -m {xss,php} [-r REMOTE_DOMAIN] -o OUTPUT_IMAGE [-u UPDATE] [-p PAYLOAD] [-t THREADS]

Tool to generate PNG-IDAT Payloads.

options:
  -h, --help            show this help message and exit
  -q, --quiet           Optional: quiet mode
  -m {xss,php}, --method {xss,php}
                        Choose payload method, -h to view available methods
  -r REMOTE_DOMAIN, --remote-domain REMOTE_DOMAIN
                        Remote domain to retrieve payload from (shorter the better: ex. xx.xxx. use xqi.cc for generic XSS)
  -o OUTPUT_IMAGE, --output-file OUTPUT_IMAGE
                        Output payload to PNG file
  -u UPDATE, --update UPDATE
                        Update the payload tables
  -p PAYLOAD, --payload PAYLOAD
                        Use the provided payload - no bruteforce
  -t THREADS, --threads THREADS
                        Number of threads to use for bruteforce
```

* use `tld_tool.py` and `prefix_tool.py` to help generate templates and populate payload tables
* use a target of `xqi.cc` to create a payload for a generic XSS reflector. thanks idontplaydarts for the tip
  * usage for this payload is `xqi.cc/?zz=alert(1)`

## Generic XSS Payload
* usage `target.com/evil.png?zz=alert(1)`

<img src="https://user-images.githubusercontent.com/6970250/215236480-a05b524a-27b1-4fc7-8ce7-191cd3795747.png" width="250" height="250">

s/o idontplaywithdarts for the domain tip


## Concept
1. Generate PNG payload
 1. Bruteforce hex string that Gzdeflates into target payload
 2. Engineer discovered Gzdeflate string to bypass PNG filters
 3. Generate PNG file with payload embeded in IDAT chunk
2. Upload PNG payload to vulnerable target web application
3. Take control of web application response content-type (example: .png.html)

## To Do
* Vavkamil Bruteforce method(s) , tld vs prefix
* Pure Bruteforce method (long)
* Port `payloadPatternBruter.py` to Python3
