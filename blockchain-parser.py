# -*- coding: utf-8 -*-
#
# Blockchain parser
# Copyright (c) 2015-2020 Denis Leonov <466611@gmail.com>
#

import datetime
import hashlib
import os
import sys
import time


assert sys.version_info >= (3, 6)


def reverse_pairs(string_of_pairs):
    L = len(string_of_pairs)
    if L % 2:
        return None
    if L == 2:
        return string_of_pairs
    result = ""
    for x, y in zip(*[iter(string_of_pairs)] * 2):
        result = f"{x}{y}{result}"
    return result


def get_merkle_root(lst):  # https://gist.github.com/anonymous/7eb080a67398f648c1709e41890f8c44
    sha256d = lambda x: hashlib.sha256(hashlib.sha256(x).digest()).digest()
    hash_pair = lambda x, y: sha256d(x[::-1] + y[::-1])[::-1]
    if len(lst) == 1:
        return lst[0]
    if len(lst) % 2 == 1:
        lst.append(lst[-1])
    return get_merkle_root([hash_pair(x, y) for x, y in zip(*[iter(lst)] * 2)])


input_dir = "_blocks"  # Folder with blk*.dat files
output_dir = "_result"
if len(sys.argv) == 3:
    input_dir, output_dir = sys.argv[1], sys.argv[2]
if not os.path.isdir(output_dir):
    os.makedirs(output_dir)

fnames = os.listdir(input_dir)
fnames = [x for x in fnames if (x.endswith(".dat") and x.startswith("blk"))]
fnames.sort()

for input_fname in fnames:
    output_fname = input_fname.replace(".dat", ".txt")
    output = []
    a = 0
    t = f"{input_dir}/{input_fname}"
    print(f"Parsing {input_fname}, started at {time.strftime('%H:%M:%S', time.localtime())}...", end=" ", flush=True)
    start = time.monotonic()
    with open(t, "rb") as f:
        tmp_hex = ""
        input_fsize = os.path.getsize(t)
        while f.tell() != input_fsize:
            for j in range(4):
                b = f.read(1)
                b = b.hex().upper()
                tmp_hex = b + tmp_hex
            tmp_hex = ""
            for j in range(4):
                b = f.read(1)
                b = b.hex().upper()
                tmp_hex = b + tmp_hex
            output.append("Block size = " + tmp_hex)
            tmp_hex = ""
            pos_3 = f.tell()
            while f.tell() != pos_3 + 80:
                b = f.read(1)
                b = b.hex().upper()
                tmp_hex = tmp_hex + b
            tmp_hex = bytes.fromhex(tmp_hex)
            tmp_hex = hashlib.new("sha256", tmp_hex).digest()
            tmp_hex = hashlib.new("sha256", tmp_hex).digest()
            tmp_hex = tmp_hex.hex().upper()
            tmp_hex = reverse_pairs(tmp_hex)
            output.append("SHA256 hash of the current block hash = " + tmp_hex)
            f.seek(pos_3, 0)
            tmp_hex = ""
            for j in range(4):
                b = f.read(1)
                b = b.hex().upper()
                tmp_hex = b + tmp_hex
            output.append("Version number = " + tmp_hex)
            tmp_hex = ""
            for j in range(32):
                b = f.read(1)
                b = b.hex().upper()
                tmp_hex = b + tmp_hex
            output.append("SHA256 hash of the previous block hash = " + tmp_hex)
            tmp_hex = ""
            for j in range(32):
                b = f.read(1)
                b = b.hex().upper()
                tmp_hex = b + tmp_hex
            output.append("MerkleRoot hash = " + tmp_hex)
            merkle_root = tmp_hex
            tmp_hex = ""
            for j in range(4):
                b = f.read(1)
                b = b.hex().upper()
                tmp_hex = b + tmp_hex
            output.append("Time stamp > " + tmp_hex)
            tmp_hex = ""
            for j in range(4):
                b = f.read(1)
                b = b.hex().upper()
                tmp_hex = b + tmp_hex
            output.append("Difficulty = " + tmp_hex)
            tmp_hex = ""
            for j in range(4):
                b = f.read(1)
                b = b.hex().upper()
                tmp_hex = b + tmp_hex
            output.append("Random number > " + tmp_hex)
            tmp_hex = ""
            b = f.read(1)
            b_int = int(b.hex(), 16)
            c = 0
            if b_int < 253:
                c = 1
                tmp_hex = b.hex().upper()
            if b_int == 253:
                c = 3
            if b_int == 254:
                c = 5
            if b_int == 255:
                c = 9
            for j in range(1, c):
                b = f.read(1)
                b = b.hex().upper()
                tmp_hex = b + tmp_hex
            tx_count = int(tmp_hex, 16)
            output.append("Transactions count = " + str(tx_count))
            output.append("")
            tmp_hex = ""
            pos_1 = 0
            pos_2 = 0
            raw_tx = ""
            tx_hashes = []
            for k in range(tx_count):
                pos_1 = f.tell()
                for j in range(4):
                    b = f.read(1)
                    b = b.hex().upper()
                    tmp_hex = b + tmp_hex
                output.append("transactionVersionNumber = " + tmp_hex)
                raw_tx = reverse_pairs(tmp_hex)
                tmp_hex = ""
                b = f.read(1)
                tmp_b = b.hex().upper()
                b_int = int(b.hex(), 16)
                is_witness = False
                if b_int == 0:
                    tmp_b = ""
                    c = 0
                    c = f.read(1)
                    b_int = int(c.hex(), 16)
                    c = 0
                    c = f.read(1)
                    b_int = int(c.hex(), 16)
                    tmp_b = c.hex().upper()
                    is_witness = True
                    output.append("Witness activated >>")
                c = 0
                if b_int < 253:
                    c = 1
                    tmp_hex = hex(b_int)[2:].upper().zfill(2)
                    tmp_b = ""
                if b_int == 253:
                    c = 3
                if b_int == 254:
                    c = 5
                if b_int == 255:
                    c = 9
                for j in range(1, c):
                    b = f.read(1)
                    b = b.hex().upper()
                    tmp_hex = b + tmp_hex
                in_count = int(tmp_hex, 16)
                output.append("Inputs count = " + tmp_hex)
                tmp_hex = tmp_hex + tmp_b
                raw_tx = raw_tx + reverse_pairs(tmp_hex)
                tmp_hex = ""
                for m in range(in_count):
                    for j in range(32):
                        b = f.read(1)
                        b = b.hex().upper()
                        tmp_hex = b + tmp_hex
                    output.append("TX from hash = " + tmp_hex)
                    raw_tx = raw_tx + reverse_pairs(tmp_hex)
                    tmp_hex = ""
                    for j in range(4):
                        b = f.read(1)
                        b = b.hex().upper()
                        tmp_hex = b + tmp_hex
                    output.append("N output = " + tmp_hex)
                    raw_tx = raw_tx + reverse_pairs(tmp_hex)
                    tmp_hex = ""
                    b = f.read(1)
                    tmp_b = b.hex().upper()
                    b_int = int(b.hex(), 16)
                    c = 0
                    if b_int < 253:
                        c = 1
                        tmp_hex = b.hex().upper()
                        tmp_b = ""
                    if b_int == 253:
                        c = 3
                    if b_int == 254:
                        c = 5
                    if b_int == 255:
                        c = 9
                    for j in range(1, c):
                        b = f.read(1)
                        b = b.hex().upper()
                        tmp_hex = b + tmp_hex
                    script_length = int(tmp_hex, 16)
                    tmp_hex = tmp_hex + tmp_b
                    raw_tx = raw_tx + reverse_pairs(tmp_hex)
                    tmp_hex = ""
                    for j in range(script_length):
                        b = f.read(1)
                        b = b.hex().upper()
                        tmp_hex = tmp_hex + b
                    output.append("Input script = " + tmp_hex)
                    raw_tx = raw_tx + tmp_hex
                    tmp_hex = ""
                    for j in range(4):
                        b = f.read(1)
                        b = b.hex().upper()
                        tmp_hex = tmp_hex + b
                    output.append("sequenceNumber = " + tmp_hex)
                    raw_tx = raw_tx + tmp_hex
                    tmp_hex = ""
                b = f.read(1)
                tmp_b = b.hex().upper()
                b_int = int(b.hex(), 16)
                c = 0
                if b_int < 253:
                    c = 1
                    tmp_hex = b.hex().upper()
                    tmp_b = ""
                if b_int == 253:
                    c = 3
                if b_int == 254:
                    c = 5
                if b_int == 255:
                    c = 9
                for j in range(1, c):
                    b = f.read(1)
                    b = b.hex().upper()
                    tmp_hex = b + tmp_hex
                output_count = int(tmp_hex, 16)
                tmp_hex = tmp_hex + tmp_b
                output.append("Outputs count = " + str(output_count))
                raw_tx = raw_tx + reverse_pairs(tmp_hex)
                tmp_hex = ""
                for m in range(output_count):
                    for j in range(8):
                        b = f.read(1)
                        b = b.hex().upper()
                        tmp_hex = b + tmp_hex
                    value = tmp_hex
                    raw_tx = raw_tx + reverse_pairs(tmp_hex)
                    tmp_hex = ""
                    b = f.read(1)
                    tmp_b = b.hex().upper()
                    b_int = int(b.hex(), 16)
                    c = 0
                    if b_int < 253:
                        c = 1
                        tmp_hex = b.hex().upper()
                        tmp_b = ""
                    if b_int == 253:
                        c = 3
                    if b_int == 254:
                        c = 5
                    if b_int == 255:
                        c = 9
                    for j in range(1, c):
                        b = f.read(1)
                        b = b.hex().upper()
                        tmp_hex = b + tmp_hex
                    script_length = int(tmp_hex, 16)
                    tmp_hex = tmp_hex + tmp_b
                    raw_tx = raw_tx + reverse_pairs(tmp_hex)
                    tmp_hex = ""
                    for j in range(script_length):
                        b = f.read(1)
                        b = b.hex().upper()
                        tmp_hex = tmp_hex + b
                    output.append("Value = " + value)
                    output.append("Output script = " + tmp_hex)
                    raw_tx = raw_tx + tmp_hex
                    tmp_hex = ""
                if is_witness == True:
                    for m in range(in_count):
                        tmp_hex = ""
                        b = f.read(1)
                        b_int = int(b.hex(), 16)
                        c = 0
                        if b_int < 253:
                            c = 1
                            tmp_hex = b.hex().upper()
                        if b_int == 253:
                            c = 3
                        if b_int == 254:
                            c = 5
                        if b_int == 255:
                            c = 9
                        for j in range(1, c):
                            b = f.read(1)
                            b = b.hex().upper()
                            tmp_hex = b + tmp_hex
                        witness_length = int(tmp_hex, 16)
                        tmp_hex = ""
                        for j in range(witness_length):
                            tmp_hex = ""
                            b = f.read(1)
                            b_int = int(b.hex(), 16)
                            c = 0
                            if b_int < 253:
                                c = 1
                                tmp_hex = b.hex().upper()
                            if b_int == 253:
                                c = 3
                            if b_int == 254:
                                c = 5
                            if b_int == 255:
                                c = 9
                            for j in range(1, c):
                                b = f.read(1)
                                b = b.hex().upper()
                                tmp_hex = b + tmp_hex
                            witness_item_length = int(tmp_hex, 16)
                            tmp_hex = ""
                            for p in range(witness_item_length):
                                b = f.read(1)
                                b = b.hex().upper()
                                tmp_hex = b + tmp_hex
                            output.append("Witness " + str(m) + " " + str(j) + " " + str(witness_item_length) + " " + tmp_hex)
                            tmp_hex = ""
                is_witness = False
                for j in range(4):
                    b = f.read(1)
                    b = b.hex().upper()
                    tmp_hex = b + tmp_hex
                output.append("Lock time = " + tmp_hex)
                raw_tx = raw_tx + reverse_pairs(tmp_hex)
                tmp_hex = ""
                tmp_hex = raw_tx
                tmp_hex = bytes.fromhex(tmp_hex)
                tmp_hex = hashlib.new("sha256", tmp_hex).digest()
                tmp_hex = hashlib.new("sha256", tmp_hex).digest()
                tmp_hex = tmp_hex.hex().upper()
                tmp_hex = reverse_pairs(tmp_hex)
                output.append("TX hash = " + tmp_hex)
                tx_hashes.append(tmp_hex)
                tmp_hex = ""
                output.append("")
                raw_tx = ""
            a += 1
            tx_hashes = [bytes.fromhex(h) for h in tx_hashes]
            tmp_hex = get_merkle_root(tx_hashes).hex().upper()
            if tmp_hex != merkle_root:
                print("Merkle roots does not match! >", merkle_root, tmp_hex)
            tmp_hex = ""
    with open(f"{output_dir}/{output_fname}", "w") as f:
        f.write("\n".join(output))
    print(f"Done in {time.monotonic() - start :.1f} seconds.")
