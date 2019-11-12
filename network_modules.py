class ARP():
    name = "ARP"
    fields_desc = [
        XShortField("hwtype", 0x0001),
        XShortEnumField("ptype", 0x0800, ETHER_TYPES),
        FieldLenField("hwlen", None, fmt="B", length_of="hwsrc"),
        FieldLenField("plen", None, fmt="B", length_of="psrc"),
        ShortEnumField("op", 1, {
            "who-has": 1,
            "is-at": 2,
            "RARP-req": 3,
            "RARP-rep": 4,
            "Dyn-RARP-req": 5,
            "Dyn-RAR-rep": 6,
            "Dyn-RARP-err": 7,
            "InARP-req": 8,
            "InARP-rep": 9
        }),
        MultipleTypeField(
            [
                (SourceMACField("hwsrc"),
                 (lambda pkt: pkt.hwtype == 1 and pkt.hwlen == 6,
                  lambda pkt, val: pkt.hwtype == 1 and (
                      pkt.hwlen == 6 or (pkt.hwlen is None and
                                         (val is None or len(val) == 6 or
                                          valid_mac(val)))
                  ))),
            ],
            StrFixedLenField("hwsrc", None, length_from=lambda pkt: pkt.hwlen),
        ),
        MultipleTypeField(
            [
                (SourceIPField("psrc", "pdst"),
                 (lambda pkt: pkt.ptype == 0x0800 and pkt.plen == 4,
                  lambda pkt, val: pkt.ptype == 0x0800 and (
                      pkt.plen == 4 or (pkt.plen is None and
                                        (val is None or valid_net(val)))
                  ))),
                (SourceIP6Field("psrc", "pdst"),
                 (lambda pkt: pkt.ptype == 0x86dd and pkt.plen == 16,
                  lambda pkt, val: pkt.ptype == 0x86dd and (
                      pkt.plen == 16 or (pkt.plen is None and
                                         (val is None or valid_net6(val)))
                  ))),
            ],
            StrFixedLenField("psrc", None, length_from=lambda pkt: pkt.plen),
        ),
        MultipleTypeField(
            [
                (MACField("hwdst", ETHER_ANY),
                 (lambda pkt: pkt.hwtype == 1 and pkt.hwlen == 6,
                  lambda pkt, val: pkt.hwtype == 1 and (
                      pkt.hwlen == 6 or (pkt.hwlen is None and
                                         (val is None or len(val) == 6 or
                                          valid_mac(val)))
                  ))),
            ],
            StrFixedLenField("hwdst", None, length_from=lambda pkt: pkt.hwlen),
        ),
        MultipleTypeField(
            [
                (IPField("pdst", "0.0.0.0"),
                 (lambda pkt: pkt.ptype == 0x0800 and pkt.plen == 4,
                  lambda pkt, val: pkt.ptype == 0x0800 and (
                      pkt.plen == 4 or (pkt.plen is None and
                                        (val is None or valid_net(val)))
                  ))),
                (IP6Field("pdst", "::"),
                 (lambda pkt: pkt.ptype == 0x86dd and pkt.plen == 16,
                  lambda pkt, val: pkt.ptype == 0x86dd and (
                      pkt.plen == 16 or (pkt.plen is None and
                                         (val is None or valid_net6(val)))
                  ))),
            ],
            StrFixedLenField("pdst", None, length_from=lambda pkt: pkt.plen),
        ),
    ]

    def hashret(self):
        return struct.pack(">HHH", self.hwtype, self.ptype,
                           ((self.op + 1) // 2)) + self.payload.hashret()

    def answers(self, other):
        if not isinstance(other, ARP):
            return False
        if self.op != other.op + 1:
            return False
        # We use a loose comparison on psrc vs pdst to catch answers
        # with ARP leaks
        self_psrc = self.get_field('psrc').i2m(self, self.psrc)
        other_pdst = other.get_field('pdst').i2m(other, other.pdst)
        return self_psrc[:len(other_pdst)] == other_pdst[:len(self_psrc)]

    def route(self):
        fld, dst = self.getfield_and_val("pdst")
        fld, dst = fld._find_fld_pkt_val(self, dst)
        if isinstance(dst, Gen):
            dst = next(iter(dst))
        if isinstance(fld, IP6Field):
            return conf.route6.route(dst)
        elif isinstance(fld, IPField):
            return conf.route.route(dst)
        else:
            return None, None, None

    def extract_padding(self, s):
        return "", s

    def mysummary(self):
        if self.op == 1:
            return self.sprintf("ARP who has %pdst% says %psrc%")
        if self.op == 2:
            return self.sprintf("ARP is at %hwsrc% says %psrc%")
        return self.sprintf("ARP %op% %psrc% > %pdst%")


class Ether():
    name = "Ethernet"
    fields_desc = [DestMACField("dst"),
                   SourceMACField("src"),
                   XShortEnumField("type", 0x9000, ETHER_TYPES)]
    __slots__ = ["_defrag_pos"]

    def hashret(self):
        return struct.pack("H", self.type) + self.payload.hashret()

    def answers(self, other):
        if isinstance(other, Ether):
            if self.type == other.type:
                return self.payload.answers(other.payload)
        return 0

    def mysummary(self):
        return self.sprintf("%src% > %dst% (%type%)")

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 14:
            if struct.unpack("!H", _pkt[12:14])[0] <= 1500:
                return Dot3
        return cls

@conf.commands.register
def sr1(x, promisc=None, filter=None, iface=None, nofilter=0, *args, **kargs):
    """Send packets at layer 3 and return only the first answer"""
    iface = _interface_selection(iface, x)
    s = conf.L3socket(promisc=promisc, filter=filter,
                      nofilter=nofilter, iface=iface)
    ans, _ = sndrcv(s, x, *args, **kargs)
    s.close()
    if len(ans) > 0:
        return ans[0][1]
    else:
        return None

@conf.commands.register
def srp(x, promisc=None, iface=None, iface_hint=None, filter=None,
        nofilter=0, type=ETH_P_ALL, *args, **kargs):
    """Send and receive packets at layer 2"""
    if iface is None and iface_hint is not None:
        iface = conf.route.route(iface_hint)[0]
    s = conf.L2socket(promisc=promisc, iface=iface,
                      filter=filter, nofilter=nofilter, type=type)
    result = sndrcv(s, x, *args, **kargs)
    s.close()
    return result
class ICMP():
    name = "ICMP"
    fields_desc = [ByteEnumField("type", 8, icmptypes),
                   MultiEnumField("code", 0, icmpcodes, depends_on=lambda pkt:pkt.type, fmt="B"),  # noqa: E501
                   XShortField("chksum", None),
                   ConditionalField(XShortField("id", 0), lambda pkt:pkt.type in [0, 8, 13, 14, 15, 16, 17, 18]),  # noqa: E501
                   ConditionalField(XShortField("seq", 0), lambda pkt:pkt.type in [0, 8, 13, 14, 15, 16, 17, 18]),  # noqa: E501
                   ConditionalField(ICMPTimeStampField("ts_ori", None), lambda pkt:pkt.type in [13, 14]),  # noqa: E501
                   ConditionalField(ICMPTimeStampField("ts_rx", None), lambda pkt:pkt.type in [13, 14]),  # noqa: E501
                   ConditionalField(ICMPTimeStampField("ts_tx", None), lambda pkt:pkt.type in [13, 14]),  # noqa: E501
                   ConditionalField(IPField("gw", "0.0.0.0"), lambda pkt:pkt.type == 5),  # noqa: E501
                   ConditionalField(ByteField("ptr", 0), lambda pkt:pkt.type == 12),  # noqa: E501
                   ConditionalField(ByteField("reserved", 0), lambda pkt:pkt.type in [3, 11]),  # noqa: E501
                   ConditionalField(ByteField("length", 0), lambda pkt:pkt.type in [3, 11, 12]),  # noqa: E501
                   ConditionalField(IPField("addr_mask", "0.0.0.0"), lambda pkt:pkt.type in [17, 18]),  # noqa: E501
                   ConditionalField(ShortField("nexthopmtu", 0), lambda pkt:pkt.type == 3),  # noqa: E501
                   ConditionalField(ShortField("unused", 0), lambda pkt:pkt.type in [11, 12]),  # noqa: E501
                   ConditionalField(IntField("unused", 0), lambda pkt:pkt.type not in [0, 3, 5, 8, 11, 12, 13, 14, 15, 16, 17, 18])  # noqa: E501
                   ]

    def post_build(self, p, pay):
        p += pay
        if self.chksum is None:
            ck = checksum(p)
            p = p[:2] + chb(ck >> 8) + chb(ck & 0xff) + p[4:]
        return p

    def hashret(self):
        if self.type in [0, 8, 13, 14, 15, 16, 17, 18, 33, 34, 35, 36, 37, 38]:
            return struct.pack("HH", self.id, self.seq) + self.payload.hashret()  # noqa: E501
        return self.payload.hashret()

    def answers(self, other):
        if not isinstance(other, ICMP):
            return 0
        if ((other.type, self.type) in [(8, 0), (13, 14), (15, 16), (17, 18), (33, 34), (35, 36), (37, 38)] and  # noqa: E501
            self.id == other.id and
                self.seq == other.seq):
            return 1
        return 0

    def guess_payload_class(self, payload):
        if self.type in [3, 4, 5, 11, 12]:
            return IPerror
        else:
            return None

    def mysummary(self):
        if isinstance(self.underlayer, IP):
            return self.underlayer.sprintf("ICMP %IP.src% > %IP.dst% %ICMP.type% %ICMP.code%")  # noqa: E501
        else:
            return self.sprintf("ICMP %ICMP.type% %ICMP.code%")

class IP(IPTools):
    __slots__ = ["_defrag_pos"]
    name = "IP"
    fields_desc = [BitField("version", 4, 4),
                   BitField("ihl", None, 4),
                   XByteField("tos", 0),
                   ShortField("len", None),
                   ShortField("id", 1),
                   FlagsField("flags", 0, 3, ["MF", "DF", "evil"]),
                   BitField("frag", 0, 13),
                   ByteField("ttl", 64),
                   ByteEnumField("proto", 0, IP_PROTOS),
                   XShortField("chksum", None),
                   # IPField("src", "127.0.0.1"),
                   Emph(SourceIPField("src", "dst")),
                   Emph(DestIPField("dst", "127.0.0.1")),
                   PacketListField("options", [], IPOption, length_from=lambda p:p.ihl * 4 - 20)]  # noqa: E501

    def post_build(self, p, pay):
        ihl = self.ihl
        p += b"\0" * ((-len(p)) % 4)  # pad IP options if needed
        if ihl is None:
            ihl = len(p) // 4
            p = chb(((self.version & 0xf) << 4) | ihl & 0x0f) + p[1:]
        if self.len is None:
            tmp_len = len(p) + len(pay)
            p = p[:2] + struct.pack("!H", tmp_len) + p[4:]
        if self.chksum is None:
            ck = checksum(p)
            p = p[:10] + chb(ck >> 8) + chb(ck & 0xff) + p[12:]
        return p + pay

    def extract_padding(self, s):
        tmp_len = self.len - (self.ihl << 2)
        if tmp_len < 0:
            return s, b""
        return s[:tmp_len], s[tmp_len:]

    def route(self):
        dst = self.dst
        if isinstance(dst, Gen):
            dst = next(iter(dst))
        if conf.route is None:
            # unused import, only to initialize conf.route
            import scapy.route  # noqa: F401
        return conf.route.route(dst)

    def hashret(self):
        if ((self.proto == socket.IPPROTO_ICMP) and
            (isinstance(self.payload, ICMP)) and
                (self.payload.type in [3, 4, 5, 11, 12])):
            return self.payload.payload.hashret()
        if not conf.checkIPinIP and self.proto in [4, 41]:  # IP, IPv6
            return self.payload.hashret()
        if self.dst == "224.0.0.251":  # mDNS
            return struct.pack("B", self.proto) + self.payload.hashret()
        if conf.checkIPsrc and conf.checkIPaddr:
            return (strxor(inet_pton(socket.AF_INET, self.src),
                           inet_pton(socket.AF_INET, self.dst)) +
                    struct.pack("B", self.proto) + self.payload.hashret())
        return struct.pack("B", self.proto) + self.payload.hashret()

    def answers(self, other):
        if not conf.checkIPinIP:  # skip IP in IP and IPv6 in IP
            if self.proto in [4, 41]:
                return self.payload.answers(other)
            if isinstance(other, IP) and other.proto in [4, 41]:
                return self.answers(other.payload)
            if conf.ipv6_enabled \
               and isinstance(other, scapy.layers.inet6.IPv6) \
               and other.nh in [4, 41]:
                return self.answers(other.payload)
        if not isinstance(other, IP):
            return 0
        if conf.checkIPaddr:
            if other.dst == "224.0.0.251" and self.dst == "224.0.0.251":  # mDNS  # noqa: E501
                return self.payload.answers(other.payload)
            elif (self.dst != other.src):
                return 0
        if ((self.proto == socket.IPPROTO_ICMP) and
            (isinstance(self.payload, ICMP)) and
                (self.payload.type in [3, 4, 5, 11, 12])):
            # ICMP error message
            return self.payload.payload.answers(other)

        else:
            if ((conf.checkIPaddr and (self.src != other.dst)) or
                    (self.proto != other.proto)):
                return 0
            return self.payload.answers(other.payload)

    def mysummary(self):
        s = self.sprintf("%IP.src% > %IP.dst% %IP.proto%")
        if self.frag:
            s += " frag:%i" % self.frag
        return s

    def fragment(self, fragsize=1480):
        """Fragment IP datagrams"""
        fragsize = (fragsize + 7) // 8 * 8
        lst = []
        fnb = 0
        fl = self
        while fl.underlayer is not None:
            fnb += 1
            fl = fl.underlayer

        for p in fl:
            s = raw(p[fnb].payload)
            nb = (len(s) + fragsize - 1) // fragsize
            for i in range(nb):
                q = p.copy()
                del(q[fnb].payload)
                del(q[fnb].chksum)
                del(q[fnb].len)
                if i != nb - 1:
                    q[fnb].flags |= 1
                q[fnb].frag += i * fragsize // 8
                r = conf.raw_layer(load=s[i * fragsize:(i + 1) * fragsize])
                r.overload_fields = p[fnb].payload.overload_fields.copy()
                q.add_payload(r)
                lst.append(q)
        return lst