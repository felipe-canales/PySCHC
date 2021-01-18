class SCHC_Parser:

    def __init__(self):
        self.header_fields = {}
        self.udp_data = []
        self.unparsed_headers = []

    def parser(self, buffer):
        data_buffer = list(buffer)

        # Mask definition
        mask_high = int('F0', 16)
        mask_low = int('0F', 16)

        # validating if it is an ipv6 package
        if (data_buffer[0] >> 4) == 6:
            self.header_fields["IPv6.version", 1] = [data_buffer[0] >> 4, "fixed"]
            self.header_fields["IPv6.trafficClass", 1] = [(data_buffer[0] << 4) & mask_high | (data_buffer[1] >> 4) & mask_low, "fixed"]
            self.header_fields["IPv6.flowLabel", 1] = [(data_buffer[1] & mask_low) << 16 | data_buffer[2] << 8 | data_buffer[3], "fixed"]
            self.header_fields["IPv6.payloadLength", 1] = [data_buffer[4] << 8 | data_buffer[5], "fixed"]
            self.header_fields["IPv6.nextHeader", 1] = [data_buffer[6], "fixed"]
            self.header_fields["IPv6.hopLimit", 1] = [data_buffer[7], "fixed"]
            self.header_fields["IPv6.prefixES", 1] = [data_buffer[8] << 56 | data_buffer[9] << 48 | data_buffer[10] << 40 | data_buffer[11] << 32 | data_buffer[12] << 24 | data_buffer[13] << 16 | data_buffer[14] << 8 | data_buffer[15], "fixed"]
            self.header_fields["IPv6.iidES", 1] = [data_buffer[16] << 56 | data_buffer[17] << 48 | data_buffer[18] << 40 | data_buffer[19] << 32 | data_buffer[20] << 24 | data_buffer[21] << 16 | data_buffer[22] << 8 | data_buffer[23], "fixed"]
            self.header_fields["IPv6.prefixLA", 1] = [data_buffer[24] << 56 | data_buffer[25] << 48 | data_buffer[26] << 40 | data_buffer[27] << 32 | data_buffer[28] << 24 | data_buffer[29] << 16 | data_buffer[30] << 8 | data_buffer[31], "fixed"]
            self.header_fields["IPv6.iidLA", 1] = [data_buffer[32] << 56 | data_buffer[33] << 48 | data_buffer[34] << 40 | data_buffer[35] << 32 | data_buffer[36] << 24 | data_buffer[37] << 16 | data_buffer[38] << 8 | data_buffer[39], "fixed"]

            if self.header_fields["IPv6.nextHeader", 1][0] == 17:
                self.header_fields["UDP.devPort", 1] = [data_buffer[40] << 8 | data_buffer[41], "fixed"]
                self.header_fields["UDP.appPort", 1] = [data_buffer[42] << 8 | data_buffer[43], "fixed"]
                self.header_fields["UDP.length", 1] = [data_buffer[44] << 8 | data_buffer[45], "fixed"]
                self.header_fields["UDP.checksum", 1] = [data_buffer[46] << 8 | data_buffer[47], "fixed"]
                self.udp_data = [data_buffer[48:len(data_buffer)], "variable"]
                self.unparsed_headers = data_buffer[:48]

            else:
                print("Unsupported L4 protocol")
        else:
            print("The message is not an IPv6 package")
            return False

        return True

    @staticmethod
    def build(headers, payload):
        data_buffer = bytearray(48)

        # Mask definition
        mask_byte = int('FF', 16)
        mask_low = int('0F', 16)

        # IPv6 Header
        # version
        data_buffer[0] = headers["IPv6.version"] << 4
        
        # traffic class
        data_buffer[0] += headers["IPv6.trafficClass"] >> 4
        data_buffer[1] = (headers["IPv6.trafficClass"] & mask_low) << 4
        
        # flow label
        data_buffer[1] += headers["IPv6.flowLabel"] >> 16
        data_buffer[2] = (headers["IPv6.flowLabel"] >> 8) & mask_byte
        data_buffer[3] = headers["IPv6.flowLabel"] & mask_byte

        # payload length
        data_buffer[4] = headers["IPv6.payloadLength"] >> 8
        data_buffer[5] = headers["IPv6.payloadLength"] & mask_byte

        # next header
        data_buffer[6] = headers["IPv6.nextHeader"]

        # hop limit
        data_buffer[7] = headers["IPv6.hopLimit"]

        # source address
        data_buffer[8] = headers["IPv6.prefixES"] >> 56
        data_buffer[9] = (headers["IPv6.prefixES"] >> 48) & mask_byte
        data_buffer[10] = (headers["IPv6.prefixES"] >> 40) & mask_byte
        data_buffer[11] = (headers["IPv6.prefixES"] >> 32) & mask_byte
        data_buffer[12] = (headers["IPv6.prefixES"] >> 24) & mask_byte
        data_buffer[13] = (headers["IPv6.prefixES"] >> 16) & mask_byte
        data_buffer[14] = (headers["IPv6.prefixES"] >> 8) & mask_byte
        data_buffer[15] = headers["IPv6.prefixES"] & mask_byte

        data_buffer[16] = headers["IPv6.iidES"] >> 56
        data_buffer[17] = (headers["IPv6.iidES"] >> 48) & mask_byte
        data_buffer[18] = (headers["IPv6.iidES"] >> 40) & mask_byte
        data_buffer[19] = (headers["IPv6.iidES"] >> 32) & mask_byte
        data_buffer[20] = (headers["IPv6.iidES"] >> 24) & mask_byte
        data_buffer[21] = (headers["IPv6.iidES"] >> 16) & mask_byte
        data_buffer[22] = (headers["IPv6.iidES"] >> 8) & mask_byte
        data_buffer[23] = headers["IPv6.iidES"] & mask_byte

        # destination address
        data_buffer[24] = headers["IPv6.prefixLA"] >> 56
        data_buffer[25] = (headers["IPv6.prefixLA"] >> 48) & mask_byte
        data_buffer[26] = (headers["IPv6.prefixLA"] >> 40) & mask_byte
        data_buffer[27] = (headers["IPv6.prefixLA"] >> 32) & mask_byte
        data_buffer[28] = (headers["IPv6.prefixLA"] >> 24) & mask_byte
        data_buffer[29] = (headers["IPv6.prefixLA"] >> 16) & mask_byte
        data_buffer[30] = (headers["IPv6.prefixLA"] >> 8) & mask_byte
        data_buffer[31] = headers["IPv6.prefixLA"] & mask_byte

        data_buffer[32] = headers["IPv6.iidLA"] >> 56
        data_buffer[33] = (headers["IPv6.iidLA"] >> 48) & mask_byte
        data_buffer[34] = (headers["IPv6.iidLA"] >> 40) & mask_byte
        data_buffer[35] = (headers["IPv6.iidLA"] >> 32) & mask_byte
        data_buffer[36] = (headers["IPv6.iidLA"] >> 24) & mask_byte
        data_buffer[37] = (headers["IPv6.iidLA"] >> 16) & mask_byte
        data_buffer[38] = (headers["IPv6.iidLA"] >> 8) & mask_byte
        data_buffer[39] = headers["IPv6.iidLA"] & mask_byte

        # UDP Header
        # source port
        data_buffer[40] = headers["UDP.devPort"] >> 8
        data_buffer[41] = headers["UDP.devPort"] & mask_byte

        # destination port
        data_buffer[42] = headers["UDP.appPort"] >> 8
        data_buffer[43] = headers["UDP.appPort"] & mask_byte

        # length
        data_buffer[44] = headers["UDP.length"] >> 8
        data_buffer[45] = headers["UDP.length"] & mask_byte

        # checksum
        data_buffer[46] = headers["UDP.checksum"] >> 8
        data_buffer[47] = headers["UDP.checksum"] & mask_byte

        return bytes(data_buffer) + bytes(payload)
