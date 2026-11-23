#!/usr/bin/env python3
"""Student starter code: implement an iterative DNS resolver."""
from __future__ import annotations

import argparse
import random
import socket
import struct
import sys

from dns_model import DNSMessage, DNSQuestion, DNSRecord

QTYPE = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16}
IN = 1


class DNSError(RuntimeError):
    pass


def fqdn(name: str) -> str:
    return name.rstrip(".").lower() + "."


def encode_name(name: str) -> bytes:
    """Encode an uncompressed QNAME. Provided as a starting point."""
    result = bytearray()  # initialise result as a bytearray

    name = name.strip('.')  # remove final . if there is one
    if not name:  # if the name is now an empty string then return an empty bytearray
        return b'\x00'

    # create a list of all sections split on the '.'
    sections = name.split('.')

    for section in sections:
        # turn each section into ascii instead of letters
        bytes_section = section.encode('ascii')
        # get the number of letters and append to result
        result.append(len(bytes_section))
        result.extend(bytes_section)  # add the letters to the result

    result.append(0)
    return bytes(result)


def decode_name(packet: bytes, offset: int) -> tuple[str, int]:
    """Decode a QNAME from PACKET starting at OFFSET.

    Return the decoded name and the offset of the next byte after the name.
    """

    # byte packet looks like [ 9 199 199 199 2 899 299 299 ...]
    sections = []  # end up looking like ['www', 'lancaster', 'ac', 'uk']
    curr = offset  # location where we start
    jumped = False

    # \x00 (which is 0) is the end byte so we know when to stop
    while packet[curr] != 0:

        # Task 3 - Compression
        # Check if top two bits are 11 (compression pointer)
        if packet[curr] & 0xC0 == 0xC0:
            pointer = packet[curr:curr+2]  # Grab 2 bytes for the pointer
            # Convert bytes to int and mask 0x3FFF for target offset
            target_offset = int.from_bytes(pointer, byteorder='big') & 0x3FFF
            # Decode name from target offset
            jump_name, _ = decode_name(packet, target_offset)
            # Split and add jumped labels to sections
            sections.extend(jump_name.split('.'))
            jumped = True  # Mark that a jump occurred
            break  # Pointer marks end of name, exit loop

        length = packet[curr]  # first digit is length of digits
        # read from the one after where we are for the length
        bytes_label = packet[(curr + 1): (curr + 1 + length)]
        # decode it and append to sections
        sections.append((bytes_label.decode('ascii')))
        curr += length + 1  # update where we are now

    # loop through sections adding dots between each section
    name = ""
    for section in sections:
        name += section + "."
    name = name.strip('.')

    # this is so the computer knows where the byte after this data packet is

    next_offset = curr + 2 if jumped else curr + 1

    return (name, next_offset)


def make_query(msg: DNSMessage) -> bytes:
    """Build a standard UDP DNS query with recursion disabled."""
    result = bytearray()
    # ! = Network(Big-Endian) and HHHHHH allocates 2 bytes per arguement after it
    # msg.ident = the transaction ID of the packet being sent
    # msg.flags = the control bit for requests
    # len(msg.questions) = how many questions are in this data packet
    # 0 = answer count
    # 0 = authority count
    # 0 = additional count   -->> all are 0 as our queries wont have any
    header = struct.pack("!HHHHHH", msg.ident, msg.flags,
                         len(msg.questions), 0, 0, 0)
    result.extend(header)

    # loop through every question (msg.questions)
    # for every question encode it (encode_name()) and pack it up with the question type and class
    """
    Byte Offset  0       2       4       6       8       10      12
                +-------+-------+-------+-------+-------+-------+-------------------------+-------+-------+
    Bytes:      | ID    | Flags | QDCNT | ANCNT | NSCNT | ARCNT | QNAME                   | QTYPE | QCLASS|
                | 12 34 | 00 00 | 00 01 | 00 00 | 00 00 | 00 00 | \x03www\x09lancaster... | 00 01 | 00 01 |
                +-------+-------+-------+-------+-------+-------+-------------------------+-------+-------+
                \__________________ header __________________/ \_____ questions + qtype and class _________/
    """
    for question in msg.questions:

        encoded_name = encode_name(question.name)
        result.extend(encoded_name)

        qtype_qclass = struct.pack("!HH", question.type, 1)
        result.extend(qtype_qclass)

    return bytes(result)


def query_server(msg: DNSMessage, timeout: float, server: str) -> bytes:
    """Send one UDP query to SERVER and return the raw response bytes."""
    data = make_query(msg)  # pack up query into bytes
    attempts = 5  # max tries before giving up
    response = b'0'  # initialising response
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:  # open udp socket
        for _ in range(attempts):  # loop through number of attempts
            try:
                sock.sendto(data, (server, 53))  # send query to server port 53
                sock.settimeout(timeout)  # set timer limit
                response, _ = sock.recvfrom(4096)  # grab incoming reply bytes
                return response
            except:
                continue  # skip and try again if timeout hits

    if response == b'0':  # if still nothing after all tries
        raise socket.timeout  # raise timeout error
    else:
        return response


def query(server: str, name: str, qtype: int, timeout: float, ident: int = -1) -> DNSMessage:
    """Send ONE query for NAME and QTYPE to SERVER and return the parsed reply.

    Recursion desired is off. If IDENT is -1 a random identifier is used.
    """
    if ident == -1:
        ident = random.randrange(0, 65536)
    msg = DNSMessage(ident=ident, flags=0, questions=[
        DNSQuestion(fqdn(name), qtype)])

    response = query_server(msg, timeout, server)
    reply = parse_response(response, msg.ident)
    if reply.ident != msg.ident:
        raise DNSError("unexpected DNS response ID")

    rcode = reply.flags & 0x000F
    if rcode != 0:
        raise DNSError(f"DNS server returned error RCODE: {rcode}")
    return reply


def parse_response(packet: bytes, expected_id: int):
    """TODO: parse header, question, and all resource-record sections.

    Your parser must support compressed names (RFC 1035 section 4.1.4) in
    owner names and NS, CNAME, and MX RDATA. Return a useful representation
    containing answer, authority, and additional records. Use the supplied
    DNSMessage, DNSQuestion, and DNSRecord classes from dns_model.py.
    QTYPE = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16}
    """

    def convert(type, rdlength):
        rdata = packet[curr+10:curr+10+rdlength]
        offset = curr + 10
        if type == 1:  # A - IPv4 Address
            return ".".join(str(b) for b in rdata)
        elif type == 2 or type == 5:  # NS - Name Server or  CNAME - Canonical Name
            domain_name, _ = decode_name(packet, offset)
            return domain_name
        elif type == 15:  # MX - Mail Exchange
            preference = struct.unpack("!H", packet[offset:offset+2])[0]
            domain_name, _ = decode_name(packet, offset + 2)
            return (preference, domain_name)
        elif type == 16:  # TXT
            offset = 0
            parts = []
            while offset < len(rdata):
                length = rdata[offset]
                parts.append(rdata[offset+1:offset+1+length].decode('utf-8'))
                offset += 1 + length
            string = "".join(parts)
            return string
        else:
            return rdata

            # get the first 12 bytes for the header info
    id, flag, qcount, acount, nscount, arcount = struct.unpack(
        "!HHHHHH", packet[:12])

    # check if the ID matches what we sent out
    if id != expected_id:
        raise DNSError("Wrong DNS response ID")

    # task 3.3
    rcode = flag & 0x000F
    if rcode != 0:
        raise DNSError(f"DNS server returned RCODE: {rcode}")
    ##

    curr = 12  # location of first question

    # lists to store all our parsed objects
    qobjects, aobjects, nsobjects, arobjects = [], [], [], []

    # loop through and grab all the questions
    for _ in range(qcount):
        # unpack qname and location of question after
        qname, curr = decode_name(packet, curr)
        qtype, qclass = struct.unpack("!HH", packet[curr:curr+4])
        qobjects.append(DNSQuestion(qname, qtype, qclass))
        curr += 4  # skip 4 bytes as 2 for QTYPE and 2 for QCLASS

    # loop through and grab all the answers
    for _ in range(acount):
        # unpack name and where it ends
        aname, curr = decode_name(packet, curr)
        atype, aclass, ttl, RDLENGTH = struct.unpack(
            "!HHIH", packet[curr:curr+10])
        # grab the rdata bytes using rdlength
        rdata = convert(atype, RDLENGTH)
        aobjects.append(DNSRecord(aname, atype, rdata, aclass, ttl))
        curr += 10 + RDLENGTH  # move past trailer and data

    # loop through and grab authority records
    for _ in range(nscount):
        nsname, curr = decode_name(packet, curr)
        nstype, nsclass, ttl, RDLENGTH = struct.unpack(
            "!HHIH", packet[curr:curr+10])
        rdata = convert(nstype, RDLENGTH)
        nsobjects.append(DNSRecord(nsname, nstype, rdata, nsclass, ttl))
        curr += 10 + RDLENGTH

    # loop through and grab additional records
    for _ in range(arcount):
        arname, curr = decode_name(packet, curr)
        artype, arclass, ttl, RDLENGTH = struct.unpack(
            "!HHIH", packet[curr:curr+10])
        rdata = convert(artype, RDLENGTH)
        arobjects.append(DNSRecord(arname, artype, rdata, arclass, ttl))
        curr += 10 + RDLENGTH

    # bundle everything together into the final message object and send it back
    return DNSMessage(id, flag, qobjects, aobjects, nsobjects, arobjects)


def resolve_iteratively(name: str, qtype: int, root: str, timeout: float = 2.0,
                        trace: bool = False) -> list[DNSRecord]:
    """TODO: resolve NAME iteratively, starting at the ROOT server.

    Follow referrals using glue A records. Handle timeouts and NXDOMAIN/NODATA responses. Return the list of final answer DNSRecord objects.
    With TRACE, print each query and referral step.
    """

    servers = [root]

    for _ in range(15):
        reply = None
        last_error = None

        for server in servers:
            try:
                if trace:
                    print(f"server: {server}, name: {name}, qtype: {qtype}")
                reply = query(server, name, qtype, timeout)
                break  # dont need to query back serves if one replies
            except Exception as e:
                if "RCODE: 3" in str(e):
                    raise DNSError("DNS server returned error RCODE: 3")
                else:
                    last_error = e

        if reply is None:
            raise DNSError(
                f"Servers didn't reply or invalid glue record: {last_error}")

        if reply.answers:
            return reply.answers

        ns_names = []
        for record in reply.authority:
            if record.type == 2:
                ns_names.append(record.value.rstrip('.').lower())

        if not ns_names:
            return []

        glue_ips = []
        for record in reply.additional:
            if record.type == 1:
                if record.name.rstrip('.').lower() in ns_names:
                    glue_ips.append(record.value)

        if glue_ips:
            servers = glue_ips
        else:
            ns_records = resolve_iteratively(
                ns_names[0], 1, root, timeout, trace)
            servers = []
            for record in ns_records:
                if record.type == 1:
                    servers.append(record.value)
            if not servers:
                raise DNSError(
                    f"Failed to resolve IP for nameserver {ns_names}")
        if trace:
            print(f"Referral -> next server(s): {', '.join(servers)}")
    raise DNSError("Too many referrals")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("name")
    parser.add_argument("type", choices=QTYPE)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--server", metavar="ADDRESS",
                        help="send one query to this server")
    target.add_argument("--root", metavar="ADDRESS",
                        help="resolve iteratively, starting at this root server")
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--trace", action="store_true",
                        help="print each resolution step (only with --root)")
    args = parser.parse_args()

    try:
        if args.server:
            response = query(args.server, args.name,
                             QTYPE[args.type], args.timeout)
            print(str(response))
        else:
            records = resolve_iteratively(
                args.name, QTYPE[args.type], args.root, args.timeout, args.trace)
            answer = DNSMessage(0, 0x8000, [DNSQuestion(fqdn(args.name), QTYPE[args.type])],
                                answers=records)
            print(str(answer))

    except DNSError as e:
        print(f"DNS error: {e}")
        return 1
    except socket.timeout:
        print("Query timed out")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
