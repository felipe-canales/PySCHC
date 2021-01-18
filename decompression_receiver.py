import binascii

from SCHC_Decompressor import SCHC_Decompressor
from SCHC_RuleManager import SCHC_RuleManager
from common import *

rm_network = SCHC_RuleManager()
#rm_network.add_rule(rule_64)
#rm_network.add_rule(rule_32)
#rm_network.add_rule(rule_62)
#rm_network.add_rule(rule_63)
#rm_network.add_rule(rule_30)
#rm_network.add_rule(rule_31)
#rm_network.add_rule(rule_48)
#rm_network.add_rule(rule_16)
rm_network.add_rule(rule_test)

decompressor = SCHC_Decompressor(rm_network)

print("Esperando paquete...")

with open("signal", "rb") as inp:
    schc_packet = inp.read()

print('Recibido')
print('SCHC Packet: ' + str(binascii.hexlify(schc_packet)))
print('Lenght SCHC Packet: ' + str(len(schc_packet)))

ip_packet = decompressor.decompress(schc_packet, "Up")

print('Paquete descomprimido: ' + str(binascii.hexlify(ip_packet)))