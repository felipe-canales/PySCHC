import time, binascii

from PacketGenerator import PacketGenerator
from SCHC_Compressor import SCHC_Compressor
from SCHC_RuleManager import SCHC_RuleManager
from common import *

package = PacketGenerator.generate()[0] #full packet

rm_device = SCHC_RuleManager()
#rm_device.add_rule(rule_63)
#rm_device.add_rule(rule_48)
rm_device.add_rule(rule_test)
rm_device.add_rule(rule_97)
rm_device.add_rule(rule_98)
rm_device.add_rule(rule_99)

compressor = SCHC_Compressor(rm_device)

print('Paquete original:', str(binascii.hexlify(package)))
schc_packet = compressor.compress(package,"Up")[0]

print('Enviando paquete test')

with open("signal", "wb") as out:
    out.write(schc_packet)

time.sleep(2)

dirs = ["Up", "Down"]
for i in range(12):
    with open("packets/ipv6_{}".format(i), "rb") as pkt:
        packet = pkt.read()
    print('Paquete original:', str(binascii.hexlify(packet)))
    print('Enviando paquete', i)
    to_send = compressor.compress(packet, dirs[i%2])[0] # just the packet
    with open("signal", "wb") as out:
        out.write(to_send)
    
    time.sleep(2)
    
