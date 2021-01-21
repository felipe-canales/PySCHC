#                           fID                  Pos  DI  TV                  MO           CDA
rule_64 = {"ruleid": 63,
          "devid": None,
          "content": [["IPv6.version", 4, 1, "Bi", 6, "equal", "not-sent"],
                      ["IPv6.trafficClass", 8, 1, "Bi", 0x95, "equal", "not-sent"],
                      ["IPv6.flowLabel", 20, 1, "Bi", 0xFDFD3, "equal", "not-sent"],
                      ["IPv6.payloadLength", 16, 1, "Bi", None, "ignore", "compute-length"],
                      ["IPv6.nextHeader", 8, 1, "Bi", 17, "equal", "not-sent"],
                      ["IPv6.hopLimit", 8, 1, "Up", 64, "equal", "not-sent"],
                      ["IPv6.prefixES", 64, 1, "Bi", 0xfc0c000000000000, "equal", "not-sent"],
                      ["IPv6.iidES", 64, 1, "Bi", 0x0000000000000094, "equal", "not-sent"],
                      ["IPv6.prefixLA", 64, 1, "Bi", 0xfc0c000000000000, "equal", "not-sent"],
                      ["IPv6.iidLA", 64, 1, "Bi", 0x0000000000000008, "equal", "not-sent"],
                      ["UDP.devPort", 16, 1, "Bi", 32513, "equal", "not-sent"],
                      ["UDP.appPort", 16, 1, "Bi", 32640, "equal", "not-sent"],
                      ["UDP.length", 16, 1, "Bi", None, "ignore", "compute-length"],
                      ["UDP.checksum", 16, 1, "Bi", None, "ignore", "compute-checksum"]
                      ]}

rule_32 = {"ruleid": 31,
          "devid": None,
          "content": [["IPv6.version", 4, 1, "Bi", 6, "equal", "not-sent"],
                      ["IPv6.trafficClass", 8, 1, "Bi", None, "ignore", "value-sent"],
                      ["IPv6.flowLabel", 20, 1, "Bi", 0xFDFD3, "equal", "not-sent"],
                      ["IPv6.payloadLength", 16, 1, "Bi", None, "ignore", "compute-length"],
                      ["IPv6.nextHeader", 8, 1, "Bi", 17, "equal", "not-sent"],
                      ["IPv6.hopLimit", 8, 1, "Up", 64, "equal", "not-sent"],
                      ["IPv6.prefixES", 64, 1, "Bi", 0xfc0c000000000000, "equal", "not-sent"],
                      ["IPv6.iidES", 64, 1, "Bi", 0x0000000000000094, "equal", "not-sent"],
                      ["IPv6.prefixLA", 64, 1, "Bi", 0xfc0c000000000000, "equal", "not-sent"],
                      ["IPv6.iidLA", 64, 1, "Bi", 0x0000000000000008, "equal", "not-sent"],
                      ["UDP.devPort", 16, 1, "Bi", 32513, "equal", "not-sent"],
                      ["UDP.appPort", 16, 1, "Bi", 32640, "equal", "not-sent"],
                      ["UDP.length", 16, 1, "Bi", None, "ignore", "compute-length"],
                      ["UDP.checksum", 16, 1, "Bi", None, "ignore", "compute-checksum"]
                      ]}

rule_62 = {"ruleid": 61,
          "devid": None,
          "content": [["IPv6.version", 4, 1, "Bi", 6, "equal", "not-sent"],
                      ["IPv6.trafficClass", 8, 1, "Bi", [0x9, 4], "MSB", "LSB"],
                      ["IPv6.flowLabel", 20, 1, "Bi", 0xFDFD3, "equal", "not-sent"],
                      ["IPv6.payloadLength", 16, 1, "Bi", None, "ignore", "compute-length"],
                      ["IPv6.nextHeader", 8, 1, "Bi", 17, "equal", "not-sent"],
                      ["IPv6.hopLimit", 8, 1, "Up", 64, "equal", "not-sent"],
                      ["IPv6.prefixES", 64, 1, "Bi", 0xfc0c000000000000, "equal", "not-sent"],
                      ["IPv6.iidES", 64, 1, "Bi", 0x0000000000000094, "equal", "not-sent"],
                      ["IPv6.prefixLA", 64, 1, "Bi", 0xfc0c000000000000, "equal", "not-sent"],
                      ["IPv6.iidLA", 64, 1, "Bi", 0x0000000000000008, "equal", "not-sent"],
                      ["UDP.devPort", 16, 1, "Bi", None, "ignore", "value-sent"],
                      ["UDP.appPort", 16, 1, "Bi", 32640, "equal", "not-sent"],
                      ["UDP.length", 16, 1, "Bi", None, "ignore", "compute-length"],
                      ["UDP.checksum", 16, 1, "Bi", None, "ignore", "compute-checksum"]
                      ]}

rule_63 = {"ruleid": 62,
          "devid": None,
          "content": [["IPv6.version", 4, 1, "Bi", 6, "equal", "not-sent"],
                      ["IPv6.trafficClass", 8, 1, "Bi", 0x95, "equal", "not-sent"],
                      ["IPv6.flowLabel", 20, 1, "Bi", 0xFDFD3, "equal", "not-sent"],
                      ["IPv6.payloadLength", 16, 1, "Bi", None, "ignore", "compute-length"],
                      ["IPv6.nextHeader", 8, 1, "Bi", 17, "equal", "not-sent"],
                      ["IPv6.hopLimit", 8, 1, "Up", 64, "equal", "not-sent"],
                      ["IPv6.prefixES", 64, 1, "Bi", 0xfc0c000000000000, "equal", "not-sent"],
                      ["IPv6.iidES", 64, 1, "Bi", 0x0000000000000094, "equal", "not-sent"],
                      ["IPv6.prefixLA", 64, 1, "Bi", 0xfc0c000000000000, "equal", "not-sent"],
                      ["IPv6.iidLA", 64, 1, "Bi", 0x0000000000000008, "equal", "not-sent"],
                      ["UDP.devPort", 16, 1, "Bi", 32513, "equal", "not-sent"],
                      ["UDP.appPort", 16, 1, "Bi", None, "ignore", "value-sent"],
                      ["UDP.length", 16, 1, "Bi", None, "ignore", "compute-length"],
                      ["UDP.checksum", 16, 1, "Bi", None, "ignore", "compute-checksum"]
                      ]}

rule_30 = {"ruleid": 29,
          "devid": None,
          "content": [["IPv6.version", 4, 1, "Bi", 6, "equal", "not-sent"],
                      ["IPv6.trafficClass", 8, 1, "Bi", None, "ignore", "value-sent"],
                      ["IPv6.flowLabel", 20, 1, "Bi", 0xFDFD3, "equal", "not-sent"],
                      ["IPv6.payloadLength", 16, 1, "Bi", None, "ignore", "compute-length"],
                      ["IPv6.nextHeader", 8, 1, "Bi", 17, "equal", "not-sent"],
                      ["IPv6.hopLimit", 8, 1, "Up", 64, "equal", "not-sent"],
                      ["IPv6.prefixES", 64, 1, "Bi", 0xfc0c000000000000, "equal", "not-sent"],
                      ["IPv6.iidES", 64, 1, "Bi", 0x0000000000000094, "equal", "not-sent"],
                      ["IPv6.prefixLA", 64, 1, "Bi", 0xfc0c000000000000, "equal", "not-sent"],
                      ["IPv6.iidLA", 64, 1, "Bi", 0x0000000000000008, "equal", "not-sent"],
                      ["UDP.devPort", 16, 1, "Bi", None, "ignore", "value-sent"],
                      ["UDP.appPort", 16, 1, "Bi", 32640, "equal", "not-sent"],
                      ["UDP.length", 16, 1, "Bi", None, "ignore", "compute-length"],
                      ["UDP.checksum", 16, 1, "Bi", None, "ignore", "compute-checksum"]
                      ]}

rule_31 = {"ruleid": 30,
          "devid": None,
          "content": [["IPv6.version", 4, 1, "Bi", 6, "equal", "not-sent"],
                      ["IPv6.trafficClass", 8, 1, "Bi", None, "ignore", "value-sent"],
                      ["IPv6.flowLabel", 20, 1, "Bi", 0xFDFD3, "equal", "not-sent"],
                      ["IPv6.payloadLength", 16, 1, "Bi", None, "ignore", "compute-length"],
                      ["IPv6.nextHeader", 8, 1, "Bi", 17, "equal", "not-sent"],
                      ["IPv6.hopLimit", 8, 1, "Up", 64, "equal", "not-sent"],
                      ["IPv6.prefixES", 64, 1, "Bi", 0xfc0c000000000000, "equal", "not-sent"],
                      ["IPv6.iidES", 64, 1, "Bi", 0x0000000000000094, "equal", "not-sent"],
                      ["IPv6.prefixLA", 64, 1, "Bi", 0xfc0c000000000000, "equal", "not-sent"],
                      ["IPv6.iidLA", 64, 1, "Bi", 0x0000000000000008, "equal", "not-sent"],
                      ["UDP.devPort", 16, 1, "Bi", 32513, "equal", "not-sent"],
                      ["UDP.appPort", 16, 1, "Bi", None, "ignore", "value-sent"],
                      ["UDP.length", 16, 1, "Bi", None, "ignore", "compute-length"],
                      ["UDP.checksum", 16, 1, "Bi", None, "ignore", "compute-checksum"]
                      ]}

rule_48 = {"ruleid": 47,
          "devid": None,
          "content": [["IPv6.version", 4, 1, "Bi", 6, "equal", "not-sent"],
                      ["IPv6.trafficClass", 8, 1, "Bi", 0x95, "equal", "not-sent"],
                      ["IPv6.flowLabel", 20, 1, "Bi", None, "ignore", "value-sent"],
                      ["IPv6.payloadLength", 16, 1, "Bi", None, "ignore", "compute-length"],
                      ["IPv6.nextHeader", 8, 1, "Bi", 17, "equal", "not-sent"],
                      ["IPv6.hopLimit", 8, 1, "Up", 64, "equal", "not-sent"],
                      ["IPv6.prefixES", 64, 1, "Bi", 0xfc0c000000000000, "equal", "not-sent"],
                      ["IPv6.iidES", 64, 1, "Bi", 0x0000000000000094, "equal", "not-sent"],
                      ["IPv6.prefixLA", 64, 1, "Bi", 0xfc0c000000000000, "equal", "not-sent"],
                      ["IPv6.iidLA", 64, 1, "Bi", 0x0000000000000008, "equal", "not-sent"],
                      ["UDP.devPort", 16, 1, "Bi", 32513, "equal", "not-sent"],
                      ["UDP.appPort", 16, 1, "Bi", 32640, "equal", "not-sent"],
                      ["UDP.length", 16, 1, "Bi", None, "ignore", "compute-length"],
                      ["UDP.checksum", 16, 1, "Bi", None, "ignore", "compute-checksum"]
                      ]}

rule_16 = {"ruleid": 15,
          "devid": None,
          "content": [["IPv6.version", 4, 1, "Bi", 6, "equal", "not-sent"],
                      ["IPv6.trafficClass", 8, 1, "Bi", None, "ignore", "value-sent"],
                      ["IPv6.flowLabel", 20, 1, "Bi", None, "ignore", "value-sent"],
                      ["IPv6.payloadLength", 16, 1, "Bi", None, "ignore", "compute-length"],
                      ["IPv6.nextHeader", 8, 1, "Bi", 17, "equal", "not-sent"],
                      ["IPv6.hopLimit", 8, 1, "Up", 64, "equal", "not-sent"],
                      ["IPv6.prefixES", 64, 1, "Bi", 0xfc0c000000000000, "equal", "not-sent"],
                      ["IPv6.iidES", 64, 1, "Bi", 0x0000000000000094, "equal", "not-sent"],
                      ["IPv6.prefixLA", 64, 1, "Bi", 0xfc0c000000000000, "equal", "not-sent"],
                      ["IPv6.iidLA", 64, 1, "Bi", 0x0000000000000008, "equal", "not-sent"],
                      ["UDP.devPort", 16, 1, "Bi", 32513, "equal", "not-sent"],
                      ["UDP.appPort", 16, 1, "Bi", 32640, "equal", "not-sent"],
                      ["UDP.length", 16, 1, "Bi", None, "ignore", "compute-length"],
                      ["UDP.checksum", 16, 1, "Bi", None, "ignore", "compute-checksum"]
                      ]}

#rule for testing
rule_test = {"ruleid": 68,
          "devid": None,
          "content": [["IPv6.version", 4, 1, "Bi", 6, "ignore", "value-sent"],
                      ["IPv6.trafficClass", 8, 1, "Bi", 0x9, "MSB(4)", "LSB"],
                      ["IPv6.flowLabel", 20, 1, "Bi", [0xFDFD4, 0xFDFD3], "match-mapping", "mapping-sent"],
                      ["IPv6.payloadLength", 16, 1, "Bi", None, "ignore", "compute-length"],
                      ["IPv6.nextHeader", 8, 1, "Bi", 17, "equal", "not-sent"],
                      ["IPv6.hopLimit", 8, 1, "Up", 64, "equal", "not-sent"],
                      ["IPv6.prefixES", 64, 1, "Bi", 0xfc0c000000000000, "equal", "not-sent"],
                      ["IPv6.iidES", 64, 1, "Bi", 0x0000000000000094, "equal", "not-sent"],
                      ["IPv6.prefixLA", 64, 1, "Bi", 0xfc0c000000000000, "equal", "not-sent"],
                      ["IPv6.iidLA", 64, 1, "Bi", 0x0000000000000008, "equal", "not-sent"],
                      ["UDP.devPort", 16, 1, "Bi", None, "ignore", "value-sent"],
                      ["UDP.appPort", 16, 1, "Bi", 0x7, "MSB(4)", "LSB"],
                      ["UDP.length", 16, 1, "Bi", None, "ignore", "compute-length"],
                      ["UDP.checksum", 16, 1, "Bi", None, "ignore", "compute-checksum"]
                      ]}

rule_97 = {"ruleid": 96,
          "devid": None,
          "content": [["IPv6.version", 4, 1, "Bi", 6, "equal", "not-sent"],
                      ["IPv6.trafficClass", 8, 1, "Bi", 0, "MSB(6)", "LSB"],
                      ["IPv6.flowLabel", 20, 1, "Bi", [0x00000, 0x15a3c, 0x440e8], "match-mapping", "mapping-sent"],
                      ["IPv6.payloadLength", 16, 1, "Bi", None, "ignore", "compute-length"],
                      ["IPv6.nextHeader", 8, 1, "Bi", 17, "equal", "not-sent"],
                      ["IPv6.hopLimit", 8, 1, "Up", 63, "equal", "not-sent"],
                      ["IPv6.prefixES", 64, 1, "Bi", 0x200, "MSB(12)", "LSB"],
                      ["IPv6.iidES", 64, 1, "Bi", [0x020102fffee27596, 0x0000000051834383, 0x0000000000000008], "match-mapping", "mapping-sent"],
                      ["IPv6.prefixLA", 64, 1, "Bi", 0x200, "MSB(12)", "LSB"],
                      ["IPv6.iidLA", 64, 1, "Bi", [0x020102fffee27596, 0x0000000051834383, 0x0000000000000008], "match-mapping", "mapping-sent"],
                      ["UDP.devPort", 16, 1, "Bi", None, "ignore", "value-sent"],
                      ["UDP.appPort", 16, 1, "Bi", None, "ignore", "value-sent"],
                      ["UDP.length", 16, 1, "Bi", None, "ignore", "value-sent"],
                      ["UDP.checksum", 16, 1, "Bi", None, "ignore", "value-sent"]
                      ]}

rule_98 = {"ruleid": 97,
          "devid": None,
          "content": [["IPv6.version", 4, 1, "Bi", 6, "equal", "not-sent"],
                      ["IPv6.trafficClass", 8, 1, "Bi", 0, "MSB(6)", "LSB"],
                      ["IPv6.flowLabel", 20, 1, "Bi", [0x00000, 0x15a3c, 0x440e8], "match-mapping", "mapping-sent"],
                      ["IPv6.payloadLength", 16, 1, "Bi", None, "ignore", "compute-length"],
                      ["IPv6.nextHeader", 8, 1, "Bi", 17, "equal", "not-sent"],
                      ["IPv6.hopLimit", 8, 1, "Up", 128, "equal", "not-sent"],
                      ["IPv6.prefixES", 64, 1, "Bi", 0x800, "MSB(14)", "LSB"],
                      ["IPv6.iidES", 64, 1, "Bi", [0x020102fffee27596, 0x0000000051834383, 0x0000000000000008], "match-mapping", "mapping-sent"],
                      ["IPv6.prefixLA", 64, 1, "Bi", 0x800, "MSB(14)", "LSB"],
                      ["IPv6.iidLA", 64, 1, "Bi", [0x020102fffee27596, 0x0000000051834383, 0x0000000000000008], "match-mapping", "mapping-sent"],
                      ["UDP.devPort", 16, 1, "Bi", None, "ignore", "value-sent"],
                      ["UDP.appPort", 16, 1, "Bi", None, "ignore", "value-sent"],
                      ["UDP.length", 16, 1, "Bi", None, "ignore", "value-sent"],
                      ["UDP.checksum", 16, 1, "Bi", None, "ignore", "value-sent"]
                      ]}

rule_99 = {"ruleid": 98,
          "devid": None,
          "content": [["IPv6.version", 4, 1, "Bi", 6, "equal", "not-sent"],
                      ["IPv6.trafficClass", 8, 1, "Bi", 0, "MSB(6)", "LSB"],
                      ["IPv6.flowLabel", 20, 1, "Bi", [0x00000, 0x15a3c, 0x440e8], "match-mapping", "mapping-sent"],
                      ["IPv6.payloadLength", 16, 1, "Bi", None, "ignore", "compute-length"],
                      ["IPv6.nextHeader", 8, 1, "Bi", 17, "equal", "not-sent"],
                      ["IPv6.hopLimit", 8, 1, "Down", 1, "ignore", "not-sent"],
                      ["IPv6.prefixES", 64, 1, "Bi", 0x800, "MSB(14)", "LSB"],
                      ["IPv6.iidES", 64, 1, "Bi", [0x020102fffee27596, 0x0000000051834383, 0x0000000000000008], "match-mapping", "mapping-sent"],
                      ["IPv6.prefixLA", 64, 1, "Bi", 0x800, "MSB(14)", "LSB"],
                      ["IPv6.iidLA", 64, 1, "Bi", [0x020102fffee27596, 0x0000000051834383, 0x0000000000000008], "match-mapping", "mapping-sent"],
                      ["UDP.devPort", 16, 1, "Bi", None, "ignore", "value-sent"],
                      ["UDP.appPort", 16, 1, "Bi", None, "ignore", "value-sent"],
                      ["UDP.length", 16, 1, "Bi", None, "ignore", "value-sent"],
                      ["UDP.checksum", 16, 1, "Bi", None, "ignore", "value-sent"]
                      ]}