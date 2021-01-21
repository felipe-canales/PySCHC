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
rm_network.add_rule(rule_97)
rm_network.add_rule(rule_98)
rm_network.add_rule(rule_99)

decompressor = SCHC_Decompressor(rm_network)

dirs = [
    "Up",
    "Up",
    "Down",
    "Up",
    "Down",
    "Up",
    "Down",
    "Up",
    "Down",
    "Up",
    "Down",
    "Up",
    "Down"
]

for i in range(13):
    print("Esperando paquete...")
    inp = open("signal", "rb")
    schc_packet = inp.read()
    inp.close()

    print('Recibido')
    print('SCHC Packet: ' + str(binascii.hexlify(schc_packet)))
    print('Lenght SCHC Packet: ' + str(len(schc_packet)))

    ip_packet = decompressor.decompress(schc_packet, dirs[i])

    print('Paquete descomprimido: ' + str(binascii.hexlify(ip_packet)))