#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Apr  2 13:24:41 2023
@author: jayanphilip
"""
substitution_box = [
    [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
    [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
    [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
    [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
    [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
    [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
    [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
    [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
    [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
    [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
    [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
    [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
    [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
    [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
    [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
    [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16],
]

def AES_Encyption(plain_text: bytes, key: bytes, choice):
    encrypt = AES()
    intermediate_cipher = plain_text[:]
    key_scheduler_value = encrypt.key_expansion_func(key)
    block_size = 4
    r_key_val = key_scheduler_value[:encrypt.key_len * block_size]
    intermediate_cipher = encrypt.add_round_key_func(intermediate_cipher, r_key_val)
    print('Round:0')
    print('Cipher Text')
    print(intermediate_cipher.hex())
    print('Key:0')
    print(r_key_val.hex())
    print('--------------------------------')
    for iteration in range(1, encrypt.rounds_of_encyption):
        intermediate_cipher = encrypt.substitution_byte_func(intermediate_cipher)
        intermediate_cipher = encrypt.shift_rows_func(intermediate_cipher)
        intermediate_cipher = encrypt.mix_columns_func(intermediate_cipher)
        key_start = iteration * encrypt.block_size * block_size
        key_end = key_start + encrypt.key_len * block_size
        r_key_val = key_scheduler_value[key_start:key_end]
        intermediate_cipher = encrypt.add_round_key_func(intermediate_cipher, r_key_val)
        print('Round:',iteration)
        print(intermediate_cipher.hex())
        print('Key:',iteration)
        print(r_key_val.hex())
        print('--------------------------------')

    intermediate_cipher = encrypt.substitution_byte_func(intermediate_cipher)
    intermediate_cipher = encrypt.shift_rows_func(intermediate_cipher)
    key_start = encrypt.rounds_of_encyption * encrypt.block_size * block_size
    key_end = key_start + encrypt.key_len * block_size
    r_key_val = key_scheduler_value[key_start:key_end]
    intermediate_cipher = encrypt.add_round_key_func(intermediate_cipher, r_key_val)
    print('Round:10')
    print(intermediate_cipher.hex())
    print('Key:10')
    print(r_key_val.hex())
    print('--------------------------------')
    return intermediate_cipher

class AES:

    def __init__(self):
        self.key_len = 4
        self.block_size = 4
        self.rounds_of_encyption = 10
        self.round_constant_list = [0x1]
        if choice == 'a':
            for i in range(self.rounds_of_encyption):
                 self.round_constant_list.append(self.xmult_func(self.round_constant_list[i], 2))
        else:
            self.round_constant_list = [30,60,120,240,251,237,193,153,41,82]
        print(self.round_constant_list)
            
    def substitution_byte_func(self, intermediate_cipher):
        new_intermediate_cipher = bytearray(intermediate_cipher)
        for index_val, byte in enumerate(intermediate_cipher):
            x_val = byte // 0x10
            y_val = byte % 0x10
            new_intermediate_cipher[index_val] = substitution_box[x_val][y_val]
        return bytes(new_intermediate_cipher)

    def shift_rows_func(self, intermediate_cipher: bytes):
        matrix_array = self.make_matrix_func(intermediate_cipher)
        for index_val, row in enumerate(matrix_array):
            matrix_array[index_val] = self.rotate_func(row, index_val)
        return bytes(self.inv_make_matrix_func(matrix_array))

    def mix_columns_func(self, intermediate_cipher):
        columns = self.make_column_func(bytearray(intermediate_cipher))
        xmult_func = self.xmult_func
        for column in columns:
            tmp = column[:]
            column[0] = xmult_func(2, tmp[0]) ^ xmult_func(3, tmp[1]) ^ xmult_func(1, tmp[2]) ^ xmult_func(1, tmp[3])
            column[1] = xmult_func(1, tmp[0]) ^ xmult_func(2, tmp[1]) ^ xmult_func(3, tmp[2]) ^ xmult_func(1, tmp[3])
            column[2] = xmult_func(1, tmp[0]) ^ xmult_func(1, tmp[1]) ^ xmult_func(2, tmp[2]) ^ xmult_func(3, tmp[3])
            column[3] = xmult_func(3, tmp[0]) ^ xmult_func(1, tmp[1]) ^ xmult_func(1, tmp[2]) ^ xmult_func(2, tmp[3])
        return self.inv_make_column_func(columns)

    def add_round_key_func(self, intermediate_cipher, key_scheduler_value):
        columns = self.make_column_func(intermediate_cipher)
        key_vals = self.make_column_func(key_scheduler_value)
        for index_val, (col, key_val) in enumerate(zip(columns, key_vals)):
            columns[index_val] = [c^k for c,k in zip(col, key_val)]
        return bytes(self.inv_make_column_func(columns))

    def key_expansion_func(self, key_val):
        schedule_size = self.block_size * (self.rounds_of_encyption + 1)
        block_size = 4
        key_sch_val = bytearray(schedule_size*block_size)
        temp_1 = bytearray(block_size)
        key_sch_val[0:16] = key_val[:]
        word_sch_list = []
        for i in range(0, len(key_sch_val), block_size):
            word_sch_list += [key_sch_val[i:i+block_size]]
        for i in range(self.key_len, len(word_sch_list)):
            temp_1 = word_sch_list[i-1]
            if (i % self.key_len == 0):
                temp_1 = self.rotate_func(temp_1)
                r_con = self.round_constant_list[(i//self.key_len)-1]
                temp_1 = self.substitution_byte_func(temp_1)
                temp_1 = self.constant_word_xor_func(temp_1, r_con)
            word_sch_list[i] = self.word_xor_func(word_sch_list[i-self.key_len], temp_1)
        for i, word in enumerate(word_sch_list):
            pos = i*4
            key_sch_val[pos:pos + block_size] = bytearray(word)
        return bytes(key_sch_val)

    def make_matrix_func(self, intermediate_cipher):
        mtx_array = [
            [0, 0, 0, 0],
            [0, 0, 0, 0],
            [0, 0, 0, 0],
            [0, 0, 0, 0]
        ]
        for index_val, byte in enumerate(intermediate_cipher):
            row = index_val % 4
            column = index_val // 4
            mtx_array[row][column] = byte
        return mtx_array

    def inv_make_matrix_func(self, mtx_array):
        intermediate_cipher = bytearray(16)

        for index_val in range(len(intermediate_cipher)):
            row = index_val % 4
            column = index_val // 4
            intermediate_cipher[index_val] = mtx_array[row][column]
        return bytes(intermediate_cipher)

    def make_column_func(self, intermediate_cipher):
        return [
            intermediate_cipher[:4],
            intermediate_cipher[4:8],
            intermediate_cipher[8:12],
            intermediate_cipher[12:]
        ]
    def inv_make_column_func(self, columns):
        return columns[0] + columns[1] + columns[2] + columns[3]

    def xmult_func(self, a, b):
        if a > 255 or b > 255 or a < 0 or b < 0:
            raise ValueError(f'{a=} and {b=} must be between 0 and 255')
        product_val = 0
        poly_val = 0b1_0001_1011
        while a and b:
            if b & 1 != 0:
                product_val ^= a
            if a & 128:
                a = (a << 1) ^ poly_val
            else:
                a *= 2
            b //= 2
        return product_val

    def rotate_func(self, iter_val, amt_val=1, reverse_val=False):
        if reverse_val:
            amt_val *= -1
        return iter_val[amt_val:] + iter_val[:amt_val]

    def constant_word_xor_func(self, word, constant):
        return self.word_xor_func(word, [constant, 0, 0, 0])

    def word_xor_func(self, word, other):
        return [x^y for x, y in zip(word, other)]

def text_to_bytes_func(text):
    try:
        return bytes.fromhex(text)
    except ValueError:
        return bytes(text, 'utf-8')

if __name__ == '__main__':
    text = '0000 0000 0000 0000 0000 0000 0000 abca'
    key = '1a0c 24f2 8754 95bc b708 0e43 920f 567a'
    text = text_to_bytes_func(text)
    key = text_to_bytes_func(key)
    choice=''
    while (choice!='a' or choice != 'm'):
        choice = input("Type 'a' for Normal AES and 'm' for Modified AES:")
        if choice == 'a' or choice == 'm':
            ciphertext = AES_Encyption(text, key, choice)
            break
        else:
            print('You have entered wrong value')
    print('Final Output:')
    print(ciphertext.hex())