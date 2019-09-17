from utils import *

if __name__ == "__main__":
    attack = Attack("f399281922111510691928276e6e{}1e581b1f576e69b16375535b6f0e7f", 0x6e1111, 0x6effff)

    for result in attack.pool.imap_unordered(attack.f, range(attack.start, attack.end + 1)):
        m = re.match(rb".*//([A-Z0-9\-]{3}.\w{2})", result[0])
        if m is not None:
            print("{},{}".format(m.group(1).decode(), result[1]))
