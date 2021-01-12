import binascii

from PacketGenerator import PacketGenerator
from SCHC_Compressor import SCHC_Compressor
from SCHC_RuleManager import SCHC_RuleManager
from common import rule_63, rule_48, rule_test

package = PacketGenerator.generate()

rm_device = SCHC_RuleManager()
#rm_device.add_rule(rule_63)
#rm_device.add_rule(rule_48)
rm_device.add_rule(rule_test)

compressor = SCHC_Compressor(rm_device)
headers_compressed = compressor.compress(package,"Up")
udp_payload = package[1]
schc_packet = b''.join([headers_compressed, udp_payload])

print('SCHC Packet: ' + str(binascii.hexlify(schc_packet)))
print('Lenght SCHC Packet: ' + str(len(schc_packet)))
print("Largo Paquete sin comprimir: " + str(len(package[2])) + " bytes")
print("Largo Paquete comprimido: " + str(len(headers_compressed)-1) + " bytes")
hc_len = len(headers_compressed)-1
pkg_len = len(package[2])
temp = (pkg_len - hc_len) * 100 / pkg_len
print('Porcentaje de compresion: %.2f%%' % temp)

print('Enviando paquete')

with open("signal", "wb") as out:
    out.write(schc_packet)

print('Enviado')