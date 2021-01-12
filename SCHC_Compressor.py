import struct

from SCHC_Parser import SCHC_Parser
from SCHC_RuleManager import SCHC_RuleManager


class SCHC_Compressor:

    def __init__(self, rm):
        self.rule_manager = rm
        self.context = rm.context
        self.parser = SCHC_Parser()
        self.CompressionActions = {
            "not-sent": self.ca_not_sent,
            "value-sent": self.ca_value_sent,
            "mapping-sent": self.ca_mapping_sent,
            "LSB": self.ca_lsb,
            "compute-length": self.ca_not_sent,
            "compute-checksum": self.ca_not_sent
        }

    def ca_not_sent(self, length, tv, fv, mo):
        if mo is "equal":
            return None
        else:
            print("Warning: The CDA \"not-send\" SHOULD be used with the \"equal\" MO")
            return None

    def ca_value_sent(self, length, tv, fv, mo):
        length_cociente = length // 8
        length_resto = length % 8
        mask = 0xFF
        buff = bytearray(length_cociente + 1)
        for i in range(length_cociente):
            struct.pack_into(">B", buff, i, (fv[0]>>(length_resto + (length_cociente - i - 1) * 8)) & mask)

        if length_resto != 0:
            struct.pack_into(">B", buff, length_cociente, fv[0]<<(8 - length_resto))

        return bytes(buff), length

    def ca_mapping_sent(self, length, tv, fv, mo):
        return

    def ca_lsb(self, length, tv, fv, mo):
        return

    def compress(self, package_full, direction):
        package = package_full[0]
        # Parsing Package
        self.parser.parser(package)

        # Get Rule ID
        rule_id = self.rule_manager.find_rule_from_headers(self.parser.header_fields, direction)
        rule_id_bf = struct.pack(">B", rule_id)
        if rule_id == SCHC_RuleManager.RULE_ID_NOT_COMPRESSED:
            return b''.join([rule_id_bf, package_full[2]])

        # Get Compression Residue
        comp_res_bf = self.calc_compression_residue(self.parser.header_fields, self.rule_manager.get_rule_from_id(rule_id), direction)

        return b''.join([rule_id_bf, comp_res_bf])



    def calc_compression_residue(self, headers, rule, direction):
        buffer = []
        offset = 0
        mask = 0xFF
        for fd in rule["content"]:
            for header in headers:
                if header[0] == fd[0] and (direction == fd[3] or fd[3] == 'Bi'):
                    fv = headers[header]
                    length = fd[1]
                    tv = fd[4]
                    mo = fd[5]
                    cda = fd[6]
                    result = self.CompressionActions.get(cda)(length, tv, fv, mo)
                    if result is not None:
                        residue, res_length = result
                        for byte in residue:
                            if offset % 8 == 0:
                                buffer.append(byte)
                            else:
                                buffer[-1] += byte >> (offset % 8)
                                buffer.append((byte << (8 - offset % 8)) & mask)
                        offset += res_length

        return bytes(buffer)[:(offset+7) // 8]
