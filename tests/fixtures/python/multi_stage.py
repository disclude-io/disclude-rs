import base64
import zlib
import codecs

# A payload that prints "Connection established to CNC"
# Wrapped in: ROT13 -> Base64 -> Zlib Compression
payload = b'x\x9c\x0bI\xcd\xca\x0b\xce\xcfK\xccM\xce\xca\x04\x12\xf3\x13\x0b\x12\xf3\xf3\x12K\x0b\x12\x8b\xf3\x0b\x12SRJ\xf4\x8a\xf3\x13L\x12\r\x00_u\x0e\xda'

def unpack_stage_1(data):
    return zlib.decompress(data)

def unpack_stage_2(data):
    return base64.b64decode(data).decode()

def unpack_stage_3(data):
    return codecs.decode(data, 'rot_13')

# The "Sink": Analyzing this should trigger an alert for recursive execution
exec(unpack_stage_3(unpack_stage_2(unpack_stage_1(payload))))
