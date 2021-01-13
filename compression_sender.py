from PacketGenerator import PacketGenerator
from SCHC_Compressor import SCHC_Compressor
from SCHC_RuleManager import SCHC_RuleManager
from common import rule_63, rule_48, rule_test

package = PacketGenerator.generate()[0] #full packet

rm_device = SCHC_RuleManager()
#rm_device.add_rule(rule_63)
#rm_device.add_rule(rule_48)
rm_device.add_rule(rule_test)

compressor = SCHC_Compressor(rm_device)
schc_packet = compressor.compress(package,"Up")

print('Enviando paquete')

with open("signal", "wb") as out:
    out.write(schc_packet)

print('Enviado')