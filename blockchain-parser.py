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


def sha256digdig(x):
    return hashlib.sha256(hashlib.sha256(x).digest()).digest()


def get_merkle_root(lst):  # https://gist.github.com/anonymous/7eb080a67398f648c1709e41890f8c44
    hash_pair = lambda x, y: sha256digdig(x[::-1] + y[::-1])[::-1]
    if len(lst) == 1:
        return lst[0]
    if len(lst) % 2 == 1:
        lst.append(lst[-1])
    return get_merkle_root([hash_pair(x, y) for x, y in zip(*[iter(lst)] * 2)])


def read_from_file(file, count):
    raw = file.read(count)
    return raw[::-1].hex().upper()


def flagged_read_from_file(file):
    b = file.read(1)
    flag = ord(b)
    amount_to_read = 2 if flag == 253 else \
                     4 if flag == 254 else \
                     8 if flag == 255 else 0
    return read_from_file(file, amount_to_read) if amount_to_read else b.hex().upper()



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
    input_path = f"{input_dir}/{input_fname}"
    print(f"Parsing {input_fname}, started at {time.strftime('%H:%M:%S', time.localtime())}...", end=" ", flush=True)
    start = time.monotonic()
    with open(input_path, "rb") as f:
        input_fsize = os.path.getsize(input_path)
        while f.tell() != input_fsize:
            f.seek(4, 1)  # skip 4 bytes
            value = read_from_file(f, 4)
            output.append(f"Block size: {value}")
            value = ""
            pos_hash = f.tell()
            while f.tell() != pos_hash + 80:
                b = f.read(1).hex().upper()
                value = value + b
            value = bytes.fromhex(value)
            value = sha256digdig(value)
            value = reverse_pairs(value.hex().upper())
            output.append(f"SHA256 hash of the current block hash: {value}")
            f.seek(pos_hash, 0)
            output.append(f"Version: {read_from_file(f, 4)}")
            output.append(f"SHA256 hash of the previous block hash: {read_from_file(f, 32)}")
            merkle_root = read_from_file(f, 32)
            output.append(f"MerkleRoot hash: {merkle_root}")
            output.append(f"Time stamp: {read_from_file(f, 4)}")
            output.append(f"Difficulty: {read_from_file(f, 4)}")
            output.append(f"Random number: {read_from_file(f, 4)}")
            value = flagged_read_from_file(f)
            trans_count = int(value, 16)
            output.append(f"Transactions count: {trans_count}")
            output.append("")
            tx_hashes = []
            for _ in range(trans_count):
                raw_tx = ""
                value = read_from_file(f, 4)
                output.append(f"Transaction version: {value}")
                raw_tx = reverse_pairs(value)
                value = ""
                b = f.read(1)
                tmp_b = b.hex().upper()
                b_int = int(b.hex(), 16)
                is_witness = False
                if b_int == 0:
                    f.seek(1, 1)  # skip 1 byte
                    c = f.read(1)
                    b_int = int(c.hex(), 16)
                    tmp_b = c.hex().upper()
                    is_witness = True
                    output.append("Witness activated")
                c = 0
                if b_int < 253:
                    c = 1
                    value = hex(b_int)[2:].upper().zfill(2)
                    tmp_b = ""
                if b_int == 253:
                    c = 3
                if b_int == 254:
                    c = 5
                if b_int == 255:
                    c = 9
                for j in range(1, c):
                    b = f.read(1).hex().upper()
                    value = b + value
                inputs_count = int(value, 16)
                output.append(f"Inputs count: {value}")
                value = value + tmp_b
                raw_tx = raw_tx + reverse_pairs(value)
                for _ in range(inputs_count):
                    value = read_from_file(f, 32)
                    output.append(f"TX from hash: {value}")
                    raw_tx = raw_tx + reverse_pairs(value)
                    value = read_from_file(f, 4)
                    output.append(f"N output: {value}")
                    raw_tx = raw_tx + reverse_pairs(value)
                    value = ""
                    b = f.read(1)
                    tmp_b = b.hex().upper()
                    b_int = int(b.hex(), 16)
                    c = 0
                    if b_int < 253:
                        c = 1
                        value = b.hex().upper()
                        tmp_b = ""
                    if b_int == 253:
                        c = 3
                    if b_int == 254:
                        c = 5
                    if b_int == 255:
                        c = 9
                    for j in range(1, c):
                        b = f.read(1).hex().upper()
                        value = b + value
                    script_length = int(value, 16)
                    value = value + tmp_b
                    raw_tx = raw_tx + reverse_pairs(value)
                    value = ""
                    for j in range(script_length):
                        b = f.read(1).hex().upper()
                        value = value + b
                    output.append(f"Input script: {value}")
                    raw_tx = raw_tx + value
                    value = ""
                    for j in range(4):
                        b = f.read(1).hex().upper()
                        value = value + b
                    output.append(f"Sequence: {value}")
                    raw_tx = raw_tx + value
                value = ""
                b = f.read(1)
                tmp_b = b.hex().upper()
                b_int = int(b.hex(), 16)
                c = 0
                if b_int < 253:
                    c = 1
                    value = b.hex().upper()
                    tmp_b = ""
                if b_int == 253:
                    c = 3
                if b_int == 254:
                    c = 5
                if b_int == 255:
                    c = 9
                for j in range(1, c):
                    b = f.read(1).hex().upper()
                    value = b + value
                outputs_count = int(value, 16)
                value = value + tmp_b
                output.append(f"Outputs count: {outputs_count}")
                raw_tx = raw_tx + reverse_pairs(value)
                for m in range(outputs_count):
                    value = read_from_file(f, 8)
                    output.append(f"Value: {value}")
                    raw_tx = raw_tx + reverse_pairs(value)
                    value = ""
                    b = f.read(1)
                    tmp_b = b.hex().upper()
                    b_int = int(b.hex(), 16)
                    c = 0
                    if b_int < 253:
                        c = 1
                        value = b.hex().upper()
                        tmp_b = ""
                    if b_int == 253:
                        c = 3
                    if b_int == 254:
                        c = 5
                    if b_int == 255:
                        c = 9
                    for j in range(1, c):
                        b = f.read(1).hex().upper()
                        value = b + value
                    script_length = int(value, 16)
                    value = value + tmp_b
                    raw_tx = raw_tx + reverse_pairs(value)
                    value = ""
                    for j in range(script_length):
                        b = f.read(1).hex().upper()
                        value = value + b
                    output.append(f"Output script: {value}")
                    raw_tx = raw_tx + value
                if is_witness:
                    for m in range(inputs_count):
                        value = flagged_read_from_file(f)
                        witness_length = int(value, 16)
                        for j in range(witness_length):
                            value = flagged_read_from_file(f)
                            witness_item_length = int(value, 16)
                            value = read_from_file(f, witness_item_length)
                            output.append(f"Witness {m} {j} {witness_item_length} {value}")
                is_witness = False
                value = read_from_file(f, 4)
                output.append(f"Lock time: {value}")
                raw_tx = raw_tx + reverse_pairs(value)
                value = bytes.fromhex(raw_tx)
                value = sha256digdig(value)
                value = reverse_pairs(value.hex().upper())
                output.append(f"TX hash: {value}")
                tx_hashes.append(bytes.fromhex(value))
                output.append("")
            output.append("")

            computed_merkle_root = get_merkle_root(tx_hashes).hex().upper()
            if computed_merkle_root != merkle_root:
                print("Merkle roots do not match!\n{merkle_root}\n{computed_merkle_root}")

    with open(f"{output_dir}/{output_fname}", "w") as f:
        f.write("\n".join(output))
    print(f"Done in {time.monotonic() - start :.1f} seconds.")
