#!/usr/bin/env python3
"""Writes the sniffer captures of the tests and the answers of tshark for them.

The captures hold every frame type, every link layer sniffindex reads, truncated frames and
payloads with and without an IP header. Run it again only when adding cases, it needs tshark
and editcap, the tests themselves compare with the files it wrote.

    make_fixture.py <folder for the files> [folder with tshark and editcap]
"""

import random
import struct
import subprocess
import sys
from pathlib import Path

RADIOTAP = 127
RAW_80211 = 105
PRISM = 119
AVS = 163
PPI = 192

COLUMNS = ("frame.number", "frame.time_relative", "wlan.fc.type_subtype", "wlan.addr",
           "wlan.ta", "wlan.seq", "wlan.fc.retry", "wlan.fc.protected", "ip.id")

ADDR1 = bytes.fromhex("02aa00000001")
ADDR2 = bytes.fromhex("02bb00000002")
ADDR3 = bytes.fromhex("02cc00000003")
ADDR4 = bytes.fromhex("02dd00000004")
LLC_IPV4 = bytes.fromhex("aaaa030000000800")
LLC_ARP = bytes.fromhex("aaaa030000000806")


def control_word(frame_type: int, subtype: int) -> int:
    return frame_type << 2 | subtype << 4


def ipv4(ip_id: int) -> bytes:
    return struct.pack(">BBHHHBBH4s4s", 0x45, 0, 40, ip_id, 0, 64, 253, 0,
                       bytes((10, 0, 0, 1)), bytes((10, 0, 0, 2))) + bytes(20)


def header(frame_type, subtype, flags=0, seq=100, addr4=None):
    return (struct.pack("<BB", control_word(frame_type, subtype), flags) + b"\0\0"
            + ADDR1 + ADDR2 + ADDR3 + struct.pack("<H", seq << 4) + (addr4 or b""))


def frames():
    # Management and data, every subtype
    for subtype in range(16):
        yield header(0, subtype, seq=subtype) + bytes(40)
    for subtype in range(16):
        yield header(2, subtype, flags=0x01, seq=subtype + 20) + bytes(40)

    # Control, every subtype, with room for all the addresses they can have
    for subtype in range(16):
        # The extension follows, a control wrapper holds another frame and is not supported
        if subtype in (6, 7):
            continue
        yield struct.pack("<BB", control_word(1, subtype), 0) + b"\0\0" + ADDR1 + ADDR2 + bytes(40)
    # Control frame extension: the subtype goes on in the flags byte
    for extension in (2, 3, 4, 5, 6, 7, 8, 9, 10):
        yield struct.pack("<BB", control_word(1, 6), extension) + b"\0\0" + ADDR1 + ADDR2 + bytes(40)

    # Every direction, with the retry and protected flags
    for flags in (0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x41, 0x42, 0x49, 0x43):
        addr4 = ADDR4 if flags & 3 == 3 else None
        yield header(2, 0, flags, seq=flags, addr4=addr4) + bytes(8) + bytes(30)
        yield header(2, 8, flags, seq=flags + 300, addr4=addr4) + b"\0\0" + bytes(8) + bytes(30)

    # Sequence numbers at both ends, a fragment number that must not leak into them
    yield header(0, 8, seq=0) + bytes(20)
    yield header(0, 8, seq=4095) + bytes(20)

    # Payloads: IPv4, QoS or not, four addresses, other ethertypes, IPv6, ids at both ends
    for ip_id in (0, 1, 0xbeef, 0xffff):
        yield header(2, 0, 0x01, seq=ip_id % 4096) + LLC_IPV4 + ipv4(ip_id)
        yield header(2, 8, 0x02, seq=ip_id % 4096) + b"\0\0" + LLC_IPV4 + ipv4(ip_id)
    yield header(2, 0, 0x03, seq=7, addr4=ADDR4) + LLC_IPV4 + ipv4(0x1234)
    yield header(2, 8, 0x03, seq=8, addr4=ADDR4) + b"\0\0" + LLC_IPV4 + ipv4(0x1235)
    yield header(2, 8, 0x01, seq=9) + b"\0\0" + LLC_ARP + bytes(28)
    yield header(2, 0, 0x01, seq=10) + bytes.fromhex("aaaa0300000086dd") + bytes(40)
    # The same with the protected flag set: encrypted, so no ip.id
    yield header(2, 8, 0x41, seq=11) + b"\0\0" + bytes(16) + bytes(40)

    # A-MSDU: subframes of DA, SA, length and the LLC header, padded to 4 bytes
    subframe = LLC_IPV4 + ipv4(0x2222)
    first = ADDR1 + ADDR2 + struct.pack(">H", len(subframe)) + subframe
    subframe2 = LLC_IPV4 + ipv4(0x3333)
    second = ADDR1 + ADDR2 + struct.pack(">H", len(subframe2)) + subframe2
    padding = bytes(-len(first) % 4)
    yield header(2, 8, 0x01, seq=12) + b"\x80\0" + first + padding + second
    yield header(2, 8, 0x00, seq=22) + b"\x80\0" + first
    yield header(2, 8, 0x02, seq=23) + b"\x80\0" + first
    yield header(2, 8, 0x03, seq=24, addr4=ADDR4) + b"\x80\0" + first
    yield header(2, 8, 0x41, seq=25) + b"\x80\0" + bytes(60)

    # HT control behind the QoS control moves the payload
    yield header(2, 8, 0x81, seq=14) + b"\0\0" + bytes(4) + LLC_IPV4 + ipv4(0x5555)
    # Fragments: the payload of a fragment does not start with an LLC header
    yield header(2, 0, 0x05, seq=15) + LLC_IPV4 + ipv4(0x6666)
    fragment = bytearray(header(2, 0, 0x01, seq=16) + LLC_IPV4 + ipv4(0x7777))
    fragment[22] |= 0x03
    yield bytes(fragment)
    # Null data has no payload, whatever follows the header
    yield header(2, 4, 0x01, seq=17) + LLC_IPV4 + ipv4(0x7878)
    # An LLC header that announces IPv4 with something else behind it
    yield header(2, 0, 0x01, seq=18) + LLC_IPV4 + b"\x60" + ipv4(0x7979)[1:]

    # Cut somewhere behind the MAC header
    full = header(2, 8, 0x01, seq=13) + b"\0\0" + LLC_IPV4 + ipv4(0x4444)
    for size in (26, 33, 34, 35, 39, 40, 41, 42, 45, 53, 54):
        yield full[:size]
    four = header(2, 0, 0x03, seq=19, addr4=ADDR4) + LLC_IPV4 + ipv4(0x4545)
    for size in (30, 37, 38, 43, 44):
        yield four[:size]
    yield header(0, 8, seq=21)
    yield struct.pack("<BB", control_word(1, 11), 0) + b"\0\0" + ADDR1 + ADDR2
    yield struct.pack("<BB", control_word(1, 13), 0) + b"\0\0" + ADDR1
    yield struct.pack("<BB", control_word(1, 6), 4) + b"\0\0" + ADDR1 + ADDR2


def frames_cut_inside_the_header():
    full = header(2, 8, 0x01, seq=13) + b"\0\0" + bytes(40)
    for size in (0, 1, 2, 4, 9, 10, 15, 16, 21, 22, 23, 24, 25):
        yield full[:size]
    four = header(2, 0, 0x03, seq=19, addr4=ADDR4)
    for size in (24, 29):
        yield four[:size]
    yield header(0, 8, seq=21)[:23]
    rts = struct.pack("<BB", control_word(1, 11), 0) + b"\0\0" + ADDR1 + ADDR2
    for size in (3, 9, 10, 12, 15):
        yield rts[:size]
    ack = struct.pack("<BB", control_word(1, 13), 0) + b"\0\0" + ADDR1
    for size in (3, 9):
        yield ack[:size]
    extension = struct.pack("<BB", control_word(1, 6), 4) + b"\0\0" + ADDR1 + ADDR2
    for size in (3, 9, 10, 15):
        yield extension[:size]
    # A radiotap header that claims more than the frame holds
    yield None


def write_cut_frames(folder: Path):
    """tshark is not the reference here: it fills in some columns, depending on how far its
    dissector got. sniffindex keeps the row, for the frame numbers, and leaves it empty."""
    rows = ["\t".join(COLUMNS)]
    with (folder / "cut.pcap").open("wb") as output:
        output.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, RADIOTAP))
        for index, frame in enumerate(frames_cut_inside_the_header()):
            data = struct.pack("<BBHI", 0, 0, 200, 0) if frame is None else wrap(RADIOTAP, frame)
            output.write(struct.pack("<IIII", 1_700_000_000 + index, 0, len(data), len(data)))
            output.write(data)
            rows.append(f"{index + 1}\t{index}.000000000" + "\t" * 7)
    (folder / "cut.pcap.tsv").write_text("\n".join(rows) + "\n", newline="\n")


def wrap(link_type: int, frame: bytes) -> bytes:
    if link_type == RADIOTAP:
        return struct.pack("<BBHI", 0, 0, 8, 0) + frame
    if link_type == RAW_80211:
        return frame
    if link_type == PRISM:
        return struct.pack("<II16s", 0x44, 144, b"wlan0") + bytes(120) + frame
    if link_type == AVS:
        return struct.pack(">II", 0x80211001, 64) + bytes(56) + frame
    if link_type == PPI:
        return struct.pack("<BBHI", 0, 0, 8, RAW_80211) + frame
    raise ValueError(link_type)


def write_pcap(path: Path, link_type: int, big_endian=False, nanoseconds=False):
    order = ">" if big_endian else "<"
    magic = 0xa1b23c4d if nanoseconds else 0xa1b2c3d4
    rng = random.Random(link_type)
    seconds, fraction = 1_700_000_000, 123456
    with path.open("wb") as output:
        output.write(struct.pack(order + "IHHiIII", magic, 2, 4, 0, 0, 65535, link_type))
        for frame in frames():
            data = wrap(link_type, frame)
            output.write(struct.pack(order + "IIII", seconds, fraction, len(data), len(data)))
            output.write(data)
            seconds += rng.randrange(2)
            fraction = rng.randrange(1_000_000)


def write_radiotap_with_fields(path: Path):
    """Radiotap with fields and a frame check sequence, the way real drivers write it."""
    with path.open("wb") as output:
        output.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, RADIOTAP))
        for index, frame in enumerate(frames()):
            present = 0x2 | 0x4 | 0x8 | 0x20  # flags, rate, channel, signal
            radiotap = struct.pack("<BBHI", 0, 0, 16, present)
            radiotap += struct.pack("<BBHHb", 0x10, 0x0c, 2437, 0x00a0, -40) + b"\0"
            data = radiotap[:16] + frame + bytes(4)
            output.write(struct.pack("<IIII", 1_700_000_000, index, len(data), len(data)))
            output.write(data)


def tshark_answer(tools: Path, capture: Path, answer: Path):
    arguments = [str(tools / "tshark"), "-r", str(capture), "-T", "fields", "-E", "header=y"]
    for column in COLUMNS:
        arguments += ["-e", column]
    output = subprocess.run(arguments, capture_output=True, check=True)
    answer.write_bytes(output.stdout)


def main() -> int:
    folder = Path(sys.argv[1])
    tools = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("/Applications/Wireshark.app/Contents/MacOS")
    folder.mkdir(parents=True, exist_ok=True)

    write_pcap(folder / "radiotap.pcap", RADIOTAP)
    write_pcap(folder / "raw80211.pcap", RAW_80211)
    write_pcap(folder / "prism.pcap", PRISM)
    write_pcap(folder / "avs.pcap", AVS)
    write_pcap(folder / "ppi.pcap", PPI)
    write_pcap(folder / "bigendian.pcap", RADIOTAP, big_endian=True)
    write_pcap(folder / "nanoseconds.pcap", RADIOTAP, nanoseconds=True)
    write_radiotap_with_fields(folder / "fields.pcap")
    subprocess.run([str(tools / "editcap"), "-F", "pcapng", str(folder / "radiotap.pcap"),
                    str(folder / "radiotap.pcapng")], check=True)

    for capture in sorted(folder.iterdir()):
        if capture.suffix in (".pcap", ".pcapng") and capture.name != "cut.pcap":
            tshark_answer(tools, capture, capture.with_suffix(capture.suffix + ".tsv"))

    write_cut_frames(folder)

    # Input that has to be refused
    bad = folder / "bad"
    bad.mkdir(exist_ok=True)
    (bad / "gzip.pcap").write_bytes(bytes.fromhex("1f8b0800000000000000"))
    (bad / "text.pcap").write_bytes(b"not a capture")
    (bad / "ethernet.pcap").write_bytes(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
