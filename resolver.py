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
    result = bytearray() # initialise result as a bytearray

    name = name.strip('.') # remove final . if there is one
    if not name: # if the name is now an empty string then return an empty bytearray
        return b'\x00'

    sections = name.split('.') # create a list of all sections split on the '.'

    for section in sections:
        bytes_section = section.encode('ascii') # turn each section into ascii instead of letters
        result.append(len(bytes_section)) # get the number of letters and append to result
        result.extend(bytes_section) # add the letters to the result

    result.append(0)
    return bytes(result)


def decode_name(packet: bytes, offset: int) -> tuple[str, int]:
    """Decode a QNAME from PACKET starting at OFFSET.

    Return the decoded name and the offset of the next byte after the name.
    """

    # byte packet looks like [ 9 199 199 199 2 899 299 299 ...]
    sections = [] # end up looking like ['www', 'lancaster', 'ac', 'uk']
    curr = offset # location where we start
    jumped = False

    while packet[curr] != 0: # \x00 (which is 0) is the end byte so we know when to stop

        # Task 3 - Compression
        if packet[curr] & 0xC0 == 0xC0: # Check if top two bits are 11 (compression pointer)
            pointer = packet[curr:curr+2] # Grab 2 bytes for the pointer
            target_offset = int.from_bytes(pointer, byteorder='big') & 0x3FFF # Convert bytes to int and mask 0x3FFF for target offset
            jump_name, _ = decode_name(packet, target_offset) # Decode name from target offset
            sections.extend(jump_name.split('.')) # Split and add jumped labels to sections
            jumped = True # Mark that a jump occurred
            break # Pointer marks end of name, exit loop


        length = packet[curr] # first digit is length of digits
        bytes_label = packet[(curr + 1) : (curr + 1 + length)] # read from the one after where we are for the length 
        sections.append((bytes_label.decode('ascii'))) # decode it and append to sections
        curr += length + 1 # update where we are now

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
    header = struct.pack("!HHHHHH", msg.ident, msg.flags, len(msg.questions), 0, 0, 0)
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
        
        encoded_name = encode_name(question.fqdn)
        result.extend(encoded_name)
        
        qtype_qclass = struct.pack("!HH", question.qtype, 1)
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
    """

    # get the first 12 bytes for the header info
    id, flag, qcount, acount, nscount, arcount = struct.unpack("!HHHHHH", packet[:12])
    
    # check if the ID matches what we sent out
    if id != expected_id:
        raise DNSError("Wrong DNS response ID")

    ## task 3.3
    rcode = flag & 0x000F
    if rcode != 0:
        raise DNSError(f"DNS server returned RCODE: {rcode}")
    ##
    
    curr = 12 # location of first question

    # lists to store all our parsed objects
    qobjects, aobjects, nsobjects, arobjects= [], [], [], []
    
    # loop through and grab all the questions
    for _ in range(qcount): 
        qname, curr = decode_name(packet, curr) # unpack qname and location of question after
        qtype, qclass= struct.unpack("!HH", packet[curr:curr+4])
        qobjects.append(DNSQuestion(qname, qtype, qclass))
        curr += 4 # skip 4 bytes as 2 for QTYPE and 2 for QCLASS

    # loop through and grab all the answers
    for _ in range(acount): 
        aname, curr = decode_name(packet, curr) # unpack name and where it ends
        atype, aclass, ttl, RDLENGTH = struct.unpack("!HHIH", packet[curr:curr+10])
        rdata = packet[curr+10:curr+10+RDLENGTH] # grab the rdata bytes using rdlength
        aobjects.append(DNSRecord(aname, atype, rdata, aclass, ttl))
        curr += 10 + RDLENGTH # move past trailer and data

    # loop through and grab authority records
    for _ in range(nscount): 
        nsname, curr = decode_name(packet, curr) 
        nstype, nsclass, ttl, RDLENGTH = struct.unpack("!HHIH", packet[curr:curr+10])
        rdata = packet[curr+10:curr+10+RDLENGTH]
        nsobjects.append(DNSRecord(nsname, nstype, rdata, nsclass, ttl))
        curr += 10 + RDLENGTH

    # loop through and grab additional records
    for _ in range(arcount): 
        arname, curr = decode_name(packet, curr) 
        artype, arclass, ttl, RDLENGTH = struct.unpack("!HHIH", packet[curr:curr+10])
        rdata = packet[curr+10:curr+10+RDLENGTH]
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
    tracing = [] # track query steps
    current_server = root # begin at root server
    reply = None # init reply variable
    count = 0

    while reply is None or not reply.answers:
        reply = query(current_server, name, qtype, timeout)
        if trace: tracing.append(f"server: {current_server}, name: {name}, qtype: {qtype}")
        
        if reply.answers: # stop if we hit answers
            break

        try:
            # look through additional records for correct ip
            ip = None
            for arobject in reply.additional:
                if arobject.type == 1:
                    ip = socket.inet_ntoa(arobject.rdata)
                    if trace and ip: tracing[count] += f" -> next server: {ip}"
                    break
            current_server = ip # update server for next iteration
            if not ip: raise DNSError("Missing or invalid glue record")
        except DNSError:
            raise
        except:
            raise DNSError("Failed to resolve next referral IP")

        count += 1

    if trace:
        # print each step if trace is true
        for step in tracing:
            print(step)

    return reply.answers


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
