# -*- coding: utf-8 -*-
#
# Blockchain parser
# Copyright (c) 2015-2020 Denis Leonov <466611@gmail.com>
#

import hashlib
import os
import sys
import time


assert sys.version_info >= (3, 6)


input_dir = "_blocks"  # Folder with blk*.dat files
output_dir = "_result"
if len(sys.argv) == 3:
    input_dir, output_dir = sys.argv[1], sys.argv[2]
if not os.path.isdir(output_dir):
    os.makedirs(output_dir)


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


def read_flag(file):
    b = file.read(1)
    flag = ord(b)
    amount_to_read = 2 if flag == 253 else \
                     4 if flag == 254 else \
                     8 if flag == 255 else 0
    flag_value = f.read(amount_to_read)[::-1] if amount_to_read else b
    return int(flag_value.hex(), 16)


def read_value_and_len(file):
    b = file.read(1)
    flag = ord(b)
    if flag < 253:
        value = b
    amount_to_read = 2 if flag == 253 else \
                     4 if flag == 254 else \
                     8 if flag == 255 else 0
    if amount_to_read:
        value = file.read(amount_to_read)[::-1]
    length = int(value.hex(), 16)
    if amount_to_read:
        value = value + b
    return value.hex().upper(), length


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
            value = f.read(4)[::-1]
            output.append(f"Block size: {value.hex().upper()}")
            pos_hash = f.tell()
            value = f.read(80)
            value = sha256digdig(value)[::-1]
            output.append(f"SHA256 hash of the current block hash: {value.hex().upper()}")
            f.seek(pos_hash, 0)
            output.append(f"Version: {f.read(4)[::-1].hex().upper()}")
            output.append(f"SHA256 hash of the previous block hash: {f.read(32)[::-1].hex().upper()}")
            merkle_root = f.read(32)[::-1].hex().upper()
            output.append(f"MerkleRoot hash: {merkle_root}")
            output.append(f"Time stamp: {f.read(4)[::-1].hex().upper()}")
            output.append(f"Difficulty: {f.read(4)[::-1].hex().upper()}")
            output.append(f"Random number: {f.read(4)[::-1].hex().upper()}")
            trans_count = read_flag(f)
            output.append(f"Transactions count: {trans_count}")
            output.append("")
            tx_hashes = []
            for _ in range(trans_count):
                raw = ""
                value = f.read(4)[::-1].hex().upper()
                output.append(f"Transaction version: {value}")
                raw = reverse_pairs(value)

                value = ""
                b = f.read(1)
                flag = ord(b)
                appendix_2 = b.hex().upper()
                is_witness = False
                if flag == 0:
                    f.seek(1, 1)  # skip 1 byte
                    c = f.read(1)
                    flag = ord(c)
                    appendix_2 = c.hex().upper()
                    is_witness = True
                    output.append("Witness activated")
                c = 0
                if flag < 253:
                    value = hex(flag)[2:].upper().zfill(2)
                    appendix_2 = ""
                if flag == 253:
                    c = 2
                if flag == 254:
                    c = 4
                if flag == 255:
                    c = 8
                value = f.read(c)[::-1].hex().upper() + value
                inputs_count = int(value, 16)
                output.append(f"Inputs count: {value}")
                value = value + appendix_2

                raw = raw + reverse_pairs(value)
                for _ in range(inputs_count):
                    value = f.read(32)[::-1].hex().upper()
                    output.append(f"TX from hash: {value}")
                    raw = raw + reverse_pairs(value)
                    value = f.read(4)[::-1].hex().upper()
                    output.append(f"N output: {value}")
                    raw = raw + reverse_pairs(value)

                    value = ""
                    b = f.read(1)
                    flag = ord(b)
                    appendix_2 = b.hex().upper()
                    c = 0
                    if flag < 253:
                        value = b.hex().upper()
                        appendix_2 = ""
                    if flag == 253:
                        c = 2
                    if flag == 254:
                        c = 4
                    if flag == 255:
                        c = 8
                    value = f.read(c)[::-1].hex().upper() + value
                    script_length = int(value, 16)
                    value = value + appendix_2

                    raw = raw + reverse_pairs(value)
                    value = f.read(script_length).hex().upper()
                    output.append(f"Input script: {value}")
                    raw = raw + value
                    value = f.read(4).hex().upper()
                    output.append(f"Sequence: {value}")
                    raw = raw + value

                value = ""
                b = f.read(1)
                flag = ord(b)
                appendix_2 = b.hex().upper()
                c = 0
                if flag < 253:
                    value = b.hex().upper()
                    appendix_2 = ""
                if flag == 253:
                    c = 2
                if flag == 254:
                    c = 4
                if flag == 255:
                    c = 8
                value = f.read(c)[::-1].hex().upper() + value
                outputs_count = int(value, 16)
                value = value + appendix_2

                output.append(f"Outputs count: {outputs_count}")
                raw = raw + reverse_pairs(value)
                for _ in range(outputs_count):
                    value = f.read(8)[::-1].hex().upper()
                    output.append(f"Value: {value}")
                    raw = raw + reverse_pairs(value)

                    value, script_length = read_value_and_len(f)
                    raw = raw + reverse_pairs(value)
                    value = f.read(script_length).hex().upper()
                    output.append(f"Output script: {value}")
                    raw = raw + value
                if is_witness:
                    for i_input in range(inputs_count):
                        witness_length = read_flag(f)
                        for i_witness in range(witness_length):
                            witness_item_length = read_flag(f)
                            value = f.read(witness_item_length)[::-1].hex().upper()
                            output.append(f"Witness {i_input} {i_witness} {witness_item_length} {value}")
                is_witness = False
                value = f.read(4)[::-1].hex().upper()
                output.append(f"Lock time: {value}")
                raw = raw + reverse_pairs(value)
                value = bytes.fromhex(raw)
                value = reverse_pairs(sha256digdig(value).hex().upper())
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
