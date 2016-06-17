# PNG-IDAT-Payload-Generator
Generate a PNG with a payload embedded in the IDAT chunk (Based off of previous concepts and code -- credit given below)

##Based Off of Previous Concepts and Research
* Adam Logue -- https://www.adamlogue.com/revisiting-xss-payloads-in-png-idat-chunks
* IDontPlayDarts -- https://www.idontplaydarts.com/2012/06/encoding-web-shells-in-png-idat-chunks
* fin1te -- https://whitton.io/articles/xss-on-facebook-via-png-content-types
* Vavkamil -- https://github.com/vavkamil/PNG-IDAT-chunks

##Usage
```
usage: generate.py [-h] -m {xss,php} [-r REMOTEDOMAIN] -o OUTPUTIMAGE

Tool to generate PNG-IDAT Payloads.

optional arguments:
  -h, --help            show this help message and exit
  -m {xss,php}, --method {xss,php}
                        Choose payload method, -h to view available methods
  -r REMOTEDOMAIN, --remote-domain REMOTEDOMAIN
                        Remote domain to retrieve payload from (shorter the
                        better: ex. xx.xxx)
  -o OUTPUTIMAGE, --output-file OUTPUTIMAGE
                        Output payload to PNG file
```
##Concept
1. Generate PNG payload
 1. Bruteforce hex string that Gzdeflates into target payload
 2. Engineer discovered Gzdeflate string to bypass PNG filters
 3. Generate PNG file with payload embeded in IDAT chunk
2. Upload PNG payload to vulnerable target web application
3. Take control of web application response content-type (example: .png.html)

##To Do
* Threading
* Logging (maybe)
* Vavkamil Bruteforce method(s) , tld vs prefix
* Pure Bruteforce method (long)
