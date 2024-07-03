import secrets

import numpy as np
import scipy.special as spc
import sys
import os
import random

sys.path.append(os.getcwd())



def hexStr_bin(num):
    if num == '0':
        return [0, 0, 0, 0]
    elif num == '1':
        return [0, 0, 0, 1]
    elif num == '2':
        return [0, 0, 1, 0]
    elif num == '3':
        return [0, 0, 1, 1]
    elif num == '4':
        return [0, 1, 0, 0]
    elif num == '5':
        return [0, 1, 0, 1]
    elif num == '6':
        return [0, 1, 1, 0]
    elif num == '7':
        return [0, 1, 1, 1]
    elif num == '8':
        return [1, 0, 0, 0]
    elif num == '9':
        return [1, 0, 0, 1]
    elif num == 'a':
        return [1, 0, 1, 0]
    elif num == 'b':
        return [1, 0, 1, 1]
    elif num == 'c':
        return [1, 1, 0, 0]
    elif num == 'd':
        return [1, 1, 0, 1]
    elif num == 'e':
        return [1, 1, 1, 0]
    elif num == 'f':
        return [1, 1, 1, 1]

def bin_hexStr(b0, b1, b2, b3):
    if b0 == 0 and b1 == 0 and b2 == 0 and b3 == 0:
        return '0'
    elif b0 == 0 and b1 == 0 and b2 == 0 and b3 == 1:
        return '1'
    elif b0 == 0 and b1 == 0 and b2 == 1 and b3 == 0:
        return '2'
    elif b0 == 0 and b1 == 0 and b2 == 1 and b3 == 1:
        return '3'
    elif b0 == 0 and b1 == 1 and b2 == 0 and b3 == 0:
        return '4'
    elif b0 == 0 and b1 == 1 and b2 == 0 and b3 == 1:
        return '5'
    elif b0 == 0 and b1 == 1 and b2 == 1 and b3 == 0:
        return '6'
    elif b0 == 0 and b1 == 1 and b2 == 1 and b3 == 1:
        return '7'
    elif b0 == 1 and b1 == 0 and b2 == 0 and b3 == 0:
        return '8'
    elif b0 == 1 and b1 == 0 and b2 == 0 and b3 == 1:
        return '9'
    elif b0 == 1 and b1 == 0 and b2 == 1 and b3 == 0:
        return 'a'
    elif b0 == 1 and b1 == 0 and b2 == 1 and b3 == 1:
        return 'b'
    elif b0 == 1 and b1 == 1 and b2 == 0 and b3 == 0:
        return 'c'
    elif b0 == 1 and b1 == 1 and b2 == 0 and b3 == 1:
        return 'd'
    elif b0 == 1 and b1 == 1 and b2 == 1 and b3 == 0:
        return 'e'
    elif b0 == 1 and b1 == 1 and b2 == 1 and b3 == 1:
        return 'f'

def hex_binStr(num):
    if num == '0':
        return '0000'
    elif num == '1':
        return '0001'
    elif num == '2':
        return '0010'
    elif num == '3':
        return '0011'
    elif num == '4':
        return '0100'
    elif num == '5':
        return '0101'
    elif num == '6':
        return '0110'
    elif num == '7':
        return '0111'
    elif num == '8':
        return '1000'
    elif num == '9':
        return '1001'
    elif num == 'a':
        return '1010'
    elif num == 'b':
        return '1011'
    elif num == 'c':
        return '1100'
    elif num == 'd':
        return '1101'
    elif num == 'e':
        return '1110'
    elif num == 'f':
        return '1111'

def hexStr_binStr(hexStr):
    binStr = ''
    for c in hexStr:
        binStr += hex_binStr(c)
    return binStr

def hex_binList(hex):
    hex = str(hex)
    bin = hexStr_bin(hex[0]) + hexStr_bin(hex[1]) + hexStr_bin(hex[2]) + hexStr_bin(hex[3])
    return np.array(bin)

def binList_hexStr(bin):
    hex = ''
    bin = bin.tolist()
    for i in range(0, len(bin), 4):
        hex += bin_hexStr(bin[i], bin[i + 1], bin[i + 2], bin[i + 3])

    return hex

def sbox_inverse(x):
    if x == 'a':
        return '0'
    elif x == '4':
        return '1'
    elif x == '3':
        return '2'
    elif x == 'b':
        return '3'
    elif x == '8':
        return '4'
    elif x == 'e':
        return '5'
    elif x == '2':
        return '6'
    elif x == 'c':
        return '7'
    elif x == '5':
        return '8'
    elif x == '7':
        return '9'
    elif x == '6':
        return 'a'
    elif x == 'f':
        return 'b'
    elif x == '0':
        return 'c'
    elif x == '1':
        return 'd'
    elif x == '9':
        return 'e'
    elif x == 'd':
        return 'f'

def sbox(x):
    if x == '0':
        return 'a'
    elif x == '1':
        return '4'
    elif x == '2':
        return '3'
    elif x == '3':
        return 'b'
    elif x == '4':
        return '8'
    elif x == '5':
        return 'e'
    elif x == '6':
        return '2'
    elif x == '7':
        return 'c'
    elif x == '8':
        return '5'
    elif x == '9':
        return '7'
    elif x == 'a':
        return '6'
    elif x == 'b':
        return 'f'
    elif x == 'c':
        return '0'
    elif x == 'd':
        return '1'
    elif x == 'e':
        return '9'
    elif x == 'f':
        return 'd'

def sub_bytes(state):
    h0 = sbox(state[0])
    h1 = sbox(state[1])
    h2 = sbox(state[2])
    h3 = sbox(state[3])
    return h0 + h1 + h2 + h3


def inv_sub_bytes(state):
    h0 = sbox_inverse(state[0])
    h1 = sbox_inverse(state[1])
    h2 = sbox_inverse(state[2])
    h3 = sbox_inverse(state[3])
    return h0 + h1 + h2 + h3

def shift_rows(state):
    return state[0] + state[3] + state[2] + state[1]

# After Shift rows
# h0h3h2h1 =>   h0  h2
#               h3  h1

def mix_columns(state):
    t = [[1, 0, 1, 0, 0, 0, 1, 1], [1, 1, 0, 1, 0, 0, 0, 1], [1, 1, 1, 0, 1, 0, 0, 0], [0, 1, 0, 1, 0, 1, 1, 1],
         [0, 0, 1, 1, 1, 0, 1, 0], [0, 0, 0, 1, 1, 1, 0, 1], [1, 0, 0, 0, 1, 1, 1, 0], [0, 1, 1, 1, 0, 1, 0, 1]]

    b0 = hexStr_bin(state[0])
    b3 = hexStr_bin(state[1])
    b2 = hexStr_bin(state[2])
    b1 = hexStr_bin(state[3])

    B = [b0 + b3, b2 + b1]
    B = np.array(B)
    t = np.array(t)
    B_T = np.transpose(B)
    B_m = np.dot(t, B_T) % 2
    B_m = B_m.tolist()

    # h0  h2
    # h1  h3

    h0 = bin_hexStr(B_m[0][0], B_m[1][0], B_m[2][0], B_m[3][0])
    h1 = bin_hexStr(B_m[4][0], B_m[5][0], B_m[6][0], B_m[7][0])
    h2 = bin_hexStr(B_m[0][1], B_m[1][1], B_m[2][1], B_m[3][1])
    h3 = bin_hexStr(B_m[4][1], B_m[5][1], B_m[6][1], B_m[7][1])

    state = h0 + h1 + h2 + h3

    return state

def inv_mix_columns(state):
    ti = [[0, 0, 1, 0, 0, 1, 0, 1], [1, 0, 0, 1, 1, 0, 1, 0], [1, 1, 0, 0, 1, 1, 0, 1], [0, 1, 0, 0, 1, 0, 1, 1],
          [0, 1, 0, 1, 0, 0, 1, 0], [1, 0, 1, 0, 1, 0, 0, 1], [1, 1, 0, 1, 1, 1, 0, 0], [1, 0, 1, 1, 0, 1, 0, 0]]


    b0 = hexStr_bin(state[0])
    b3 = hexStr_bin(state[1])
    b2 = hexStr_bin(state[2])
    b1 = hexStr_bin(state[3])

    B = [b0 + b3, b2 + b1]
    B = np.array(B)
    ti = np.array(ti)
    B_T = np.transpose(B)
    B_m = np.dot(ti, B_T) % 2
    B_m = B_m.tolist()

    # h0  h2
    # h1  h3

    h0 = bin_hexStr(B_m[0][0], B_m[1][0], B_m[2][0], B_m[3][0])
    h1 = bin_hexStr(B_m[4][0], B_m[5][0], B_m[6][0], B_m[7][0])
    h2 = bin_hexStr(B_m[0][1], B_m[1][1], B_m[2][1], B_m[3][1])
    h3 = bin_hexStr(B_m[4][1], B_m[5][1], B_m[6][1], B_m[7][1])

    state = h0 + h1 + h2 + h3

    return state


def add_round_key(key, state):
    key0 = np.array(hexStr_bin(key[0]))
    key1 = np.array(hexStr_bin(key[1]))
    key2 = np.array(hexStr_bin(key[2]))
    key3 = np.array(hexStr_bin(key[3]))

    state0 = np.array(hexStr_bin(state[0]))
    state1 = np.array(hexStr_bin(state[1]))
    state2 = np.array(hexStr_bin(state[2]))
    state3 = np.array(hexStr_bin(state[3]))

    n_state0 = (state0 ^ key0).tolist()
    n_state1 = (state1 ^ key1).tolist()
    n_state2 = (state2 ^ key2).tolist()
    n_state3 = (state3 ^ key3).tolist()

    n_state0 = bin_hexStr(n_state0[0], n_state0[1], n_state0[2], n_state0[3])
    n_state1 = bin_hexStr(n_state1[0], n_state1[1], n_state1[2], n_state1[3])
    n_state2 = bin_hexStr(n_state2[0], n_state2[1], n_state2[2], n_state2[3])
    n_state3 = bin_hexStr(n_state3[0], n_state3[1], n_state3[2], n_state3[3])

    return n_state0 + n_state1 + n_state2 + n_state3


def rcon(round):
    if round == 1:
        return np.array([0, 0, 0, 1])
    elif round == 2:
        return np.array([0, 0, 1, 0])
    elif round == 3:
        return np.array([0, 1, 0, 0])
    elif round == 4:
        return np.array([1, 0, 0, 0])

# k0k1k2k3 =>   k0  k2
#               k1  k3
def key_expansion(key, round):
    w0 = key[0] + key[1]
    w1 = key[2] + key[3]

    # reverse & subbytes
    w1_rev = sbox(key[3]) + sbox(key[2])

    w0_0 = np.array(hexStr_bin(w0[0]))
    w0_1 = np.array(hexStr_bin(w0[1]))

    w1_0 = np.array(hexStr_bin(w1[0]))
    w1_1 = np.array(hexStr_bin(w1[1]))

    w1_rev_0 = np.array(hexStr_bin(w1_rev[0]))
    w1_rev_1 = np.array(hexStr_bin(w1_rev[1]))

    w2_0 = (w0_0 ^ w1_rev_0) ^ rcon(round)
    w2_1 = (w0_1 ^ w1_rev_1) ^ np.array([0, 0, 0, 0])

    w3_0 = w1_0 ^ w2_0
    w3_1 = w1_1 ^ w2_1

    w2_0 = w2_0.tolist()
    w2_1 = w2_1.tolist()

    w3_0 = w3_0.tolist()
    w3_1 = w3_1.tolist()

    w2_0 = bin_hexStr(w2_0[0], w2_0[1], w2_0[2], w2_0[3])
    w2_1 = bin_hexStr(w2_1[0], w2_1[1], w2_1[2], w2_1[3])
    w3_0 = bin_hexStr(w3_0[0], w3_0[1], w3_0[2], w3_0[3])
    w3_1 = bin_hexStr(w3_1[0], w3_1[1], w3_1[2], w3_1[3])

    return w2_0 + w2_1 + w3_0 + w3_1

def key_expansion_inv(key, round):
    w0 = key[0] + key[1]
    w1 = key[2] + key[3]

    w0_0 = np.array(hexStr_bin(w0[0]))
    w0_1 = np.array(hexStr_bin(w0[1]))

    w1_0 = np.array(hexStr_bin(w1[0]))
    w1_1 = np.array(hexStr_bin(w1[1]))

    w3_0 = w0_0 ^ w1_0
    w3_1 = w0_1 ^ w1_1

    w3_0 = w3_0.tolist()
    w3_1 = w3_1.tolist()

    w3_0 = bin_hexStr(w3_0[0], w3_0[1], w3_0[2], w3_0[3])
    w3_1 = bin_hexStr(w3_1[0], w3_1[1], w3_1[2], w3_1[3])

    w3_rev = sbox(w3_1) + sbox(w3_0)

    w3_rev_0 = np.array(hexStr_bin(w3_rev[0]))
    w3_rev_1 = np.array(hexStr_bin(w3_rev[1]))

    wt_0 = w0_0 ^ rcon(round)
    wt_1 = w0_1 ^ np.array([0, 0, 0, 0])

    w2_0 = w3_rev_0 ^ wt_0
    w2_1 = w3_rev_1 ^ wt_1

    w2_0 = w2_0.tolist()
    w2_1 = w2_1.tolist()

    w2_0 = bin_hexStr(w2_0[0], w2_0[1], w2_0[2], w2_0[3])
    w2_1 = bin_hexStr(w2_1[0], w2_1[1], w2_1[2], w2_1[3])

    return w2_0 + w2_1 + w3_0 + w3_1

# h0h1h2h3 =>   h0  h2
#               h1  h3

def aes_encryption(key, state):
    # initial round
    state = add_round_key(key, state)

    # round1 to round4
    for r in range(1, 5):
        key = key_expansion(key, r)
        state = sub_bytes(state)
        state = shift_rows(state)
        if r < 4:
            state = mix_columns(state)
        state = add_round_key(key, state)

    return state

def aes_decryption(key, state):
    # initial round
    state = add_round_key(key, state)

    for r in range(1, 5):
        key = key_expansion_inv(key, 5 - r)
        if r > 1:
            state = inv_mix_columns(state)

        state = shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(key, state)

    return state


# print(aes_encryption('6b5d', '2ca5'))
# print(aes_decryption('0358', '6855'))



#################### Phase 2 ######################

def completeness(pk, key, plaintext):
    com_cnt = 0
    ciphertext = aes_encryption(key, plaintext)
    print('ciphertext :' + ciphertext)
    if pk == 1:
        temp = plaintext
    else:
        temp = key

    temp = int(temp)

    for i in range(16):
        modified = temp ^ (1 << i)
        modified = str(modified)
        if len(modified) < 4:
            cnt = 4 - len(modified)
            while cnt > 0:
                modified = '0' + modified
                cnt -= 1

        if pk == 1:
            print('modified plaintext' + str(i) + ' : ' + modified)
            modified_ciphertext = aes_encryption(key, modified)
        else:
            print('modified key' + str(i) + ' : ' + modified)
            modified_ciphertext = aes_encryption(modified, plaintext)

        print('modified ciphertext' + str(i) + ' : ' + modified_ciphertext)

        if modified_ciphertext != ciphertext:
            com_cnt += 1

    if com_cnt == 16:
        print('Completeness test passed')
    else:
        print('Completeness test failed')


def avalanche(pk, key, plaintext):
    av_cnt = 0
    ciphertext = aes_encryption(key, plaintext)
    print('ciphertext :' + ciphertext)
    ciphertext = hexStr_binStr(ciphertext)

    if pk == 1:
        temp = plaintext
    else:
        temp = key

    temp = int(temp)

    for i in range(16):
        modified = temp ^ (1 << i)
        modified = str(modified)
        if len(modified) < 4:
            cnt = 4 - len(modified)
            while cnt > 0:
                modified = '0' + modified
                cnt -= 1
        if pk == 1:
            print('modified plaintext' + str(i) + ' : ' + modified)
            modified_ciphertext = aes_encryption(key, modified)
        else:
            print('modified key' + str(i) + ' : ' + modified)
            modified_ciphertext = aes_encryption(modified, plaintext)

        print('modified ciphertext' + str(i) + ' : ' + modified_ciphertext)

        modified_ciphertext = hexStr_binStr(modified_ciphertext)
        for j in range(len(ciphertext)):
            if modified_ciphertext[j] != ciphertext[j]:
                av_cnt += 1


    av_perc = av_cnt / 256

    if 0.4 < av_perc < 0.6:
        print('Avalanche test passed')
    else:
        print('Avalanche test failed')


def strict_avalanche(pk, key, plaintext):
    s_av_cnt = 0
    ciphertext = aes_encryption(key, plaintext)
    print('ciphertext :' + ciphertext)
    ciphertext = hexStr_binStr(ciphertext)

    if pk == 1:
        temp = plaintext
    else:
        temp = key

    temp = int(temp)

    for i in range(16):
        modified = temp ^ (1 << i)
        modified = str(modified)
        if len(modified) < 4:
            cnt = 4 - len(modified)
            while cnt > 0:
                modified = '0' + modified
                cnt -= 1
        if pk == 1:
            print('modified plaintext' + str(i) + ' : ' + modified)
            modified_ciphertext = aes_encryption(key, modified)
        else:
            print('modified key' + str(i) + ' : ' + modified)
            modified_ciphertext = aes_encryption(modified, plaintext)

        print('modified ciphertext' + str(i) + ' : ' + modified_ciphertext)

        modified_ciphertext = hexStr_binStr(modified_ciphertext)
        for j in range(len(ciphertext)):
            if modified_ciphertext[j] != ciphertext[j]:
                s_av_cnt += 1


    av_perc = s_av_cnt / 256

    if 0.5 == av_perc:
        print('Strict Avalanche test passed')
    else:
        print('Strict Avalanche test failed')


# completeness(1, '1873', '2694')
# avalanche(0, '7302', '9752')
# strict_avalanche(1, '5268', '6710')


#################### Phase 3 ######################

def DFT_test(bin_data: str):
    n = len(bin_data)
    plus_minus_one = []
    for char in bin_data:
        if char == '0':
            plus_minus_one.append(-1)
        elif char == '1':
            plus_minus_one.append(1)
    # Product discrete fourier transform of plus minus one
    s = np.fft.fft(plus_minus_one)
    modulus = np.abs(s[0:n // 2])
    tau = np.sqrt(np.log(1 / 0.05) * n)
    # Theoretical number of peaks
    count_n0 = 0.95 * (n / 2)
    # Count the number of actual peaks m > T
    count_n1 = len(np.where(modulus < tau)[0])
    # Calculate d and return the p value statistic
    d = (count_n1 - count_n0) / np.sqrt(n * 0.95 * 0.05 / 4)
    p_val = spc.erfc(abs(d) / np.sqrt(2))
    return p_val


def generate_random_key(block_size=16):
    # Use the secrets module for secure random key generation
    key = secrets.randbits(block_size)
    key = str(key)
    if len(key) < 4:
        count = 4 - len(key)
        while count > 0:
            key += '0'
            count -= 1
    elif len(key) > 4:
        key = key[0:4]

    return key


################ HIGH DENSITY KEY ###################

def generate_plaintext_str(size=1000):
    plaintext = ''
    for _ in range(size):
        plaintext += str(random.randint(0, 0xFFFF))

    return plaintext

def encrypt_high_density_key_dataset(size, key_density=0.8):
    ciphertext = ''
    plaintext = generate_plaintext_str(size)
    paddings = 4 - (len(plaintext) % 4)
    if paddings == 4:
        paddings = 0

    for _ in range(paddings):
        plaintext += '0'

    for i in range(0, len(plaintext), 4):

        # Generate a random 16-bit key with high density
        key = 0
        for j in range(16):
            if random.random() < key_density:
                key |= 1 << j


        key = corr_block(key)
        ciphertext += aes_encryption(key, plaintext[i:i+4])

    return hexStr_binStr(ciphertext)


################ LOW DENSITY KEY ###################

def encrypt_low_density_key_dataset(size, key_density=0.2):
    ciphertext = ''
    plaintext = generate_plaintext_str(size)
    paddings = 4 - (len(plaintext) % 4)
    if paddings == 4:
        paddings = 0

    for _ in range(paddings):
        plaintext += '0'


    for i in range(0, len(plaintext), 4):

        # Generate a random 16-bit key with high density
        key = 0
        for j in range(16):
            if random.random() < key_density:
                key |= 1 << j


        key = corr_block(key)
        ciphertext += aes_encryption(key, plaintext[i:i+4])

    return hexStr_binStr(ciphertext)


################ HIGH DENSITY PLAINTEXT ###################

def generate_high_density_plaintext_str(size=1000, plaintext_density=0.8):
    plaintext_str = ''
    for _ in range(size):
        plaintext = 0
        for i in range(16):
            if random.random() < plaintext_density:
                plaintext |= 1 << i

        plaintext_str += str(plaintext)
    return plaintext_str

def encrypt_high_density_plaintext_dataset(size, plaintext_density=0.8):
    ciphertext = ''
    plaintext = generate_high_density_plaintext_str(size, plaintext_density)
    paddings = 4 - (len(plaintext) % 4)
    if paddings == 4:
        paddings = 0

    for _ in range(paddings):
        plaintext += '0'

    for i in range(0, len(plaintext), 4):
        key = random.randint(0, 0xFFFF)
        key = corr_block(key)

        ciphertext += aes_encryption(key, plaintext[i:i+4])

    return hexStr_binStr(ciphertext)


################ LOW DENSITY PLAINTEXT ###################

def generate_low_density_plaintext_str(size=1000, plaintext_density=0.2):
    plaintext_str = ''
    for _ in range(size):
        plaintext = 0
        for i in range(16):
            if random.random() < plaintext_density:
                plaintext |= 1 << i

        plaintext_str += str(plaintext)
    return plaintext_str


def encrypt_low_density_plaintext_dataset(size, plaintext_density=0.2):
    ciphertext = ''
    plaintext = generate_low_density_plaintext_str(size, plaintext_density)
    paddings = 4 - (len(plaintext) % 4)
    if paddings == 4:
        paddings = 0

    for _ in range(paddings):
        plaintext += '0'

    for i in range(0, len(plaintext), 4):
        key = random.randint(0, 0xFFFF)
        key = corr_block(key)
        ciphertext += aes_encryption(key, plaintext[i:i + 4])

    return hexStr_binStr(ciphertext)

################ RANDOM ###################

def encrypt_random_dataset(size):
    ciphertext = ''
    plaintext = generate_plaintext_str(size)
    paddings = 4 - (len(plaintext) % 4)
    if paddings == 4:
        paddings = 0

    for _ in range(paddings):
        plaintext += '0'

    for i in range(0, len(plaintext), 4):
        key = random.randint(0, 0xFFFF)
        key = corr_block(key)
        ciphertext += aes_encryption(key, plaintext[i:i + 4])

    return hexStr_binStr(ciphertext)


################ CBC DATASET ###################

def corr_block(block):
    block = str(block)
    if len(block) > 4:
        block = block[0:4]
    elif len(block) < 4:
        zeros = 4 - len(block)

        while zeros > 0:
            block = '0' + block
            zeros -= 1

    return block


def random_block_generator():
    block = str(random.randint(0, 0xFFFF))
    block = int(corr_block(block))
    return block


def convert_bytes_list_to_hex_integer(bytes_list: list) -> int:

    hex_representation = ''.join([hex(x)[2:].zfill(2) for x in bytes_list])

    # Convert the concatenated hexadecimal string to an integer
    return int(hex_representation, 16)


def generate_cbc_dataset(size=100):
    dataset = []
    for _ in range(size):
        # Generate a random 16-bit plaintext and key
        plaintext = hex_binList(corr_block(random_block_generator()))
        key = corr_block(random_block_generator())

        # Generate a random 16-bit Initialization Vector (IV)
        initialization_vector = random_block_generator()

        # Encrypt the plaintext using CBC mode
        ciphertext = initialization_vector  # Initialization Vector for the first block
        ciphertext = hex_binList(corr_block(ciphertext))
        for i in range(16):
            # XOR the plaintext with the previous ciphertext (or IV for the first block)
            plaintext ^= ciphertext
            # Encrypt the XORed result
            ciphertext = aes_encryption(key, binList_hexStr(plaintext))

            # Append the encrypted block to the dataset
            dataset.append((binList_hexStr(plaintext), key, ciphertext))
            ciphertext = hex_binList(ciphertext)

    return dataset

def encrypt_CBC_dataset(size=100):
    cbc_dataset = generate_cbc_dataset(size)
    print('************  CBC DATASET  ************')
    for data in cbc_dataset:
        print('plaintext : ' + data[0])
        print('key : ' + data[1])
        print('ciphertext : ' + data[2])
        randomness = DFT_test(hexStr_binStr(data[2]))
        print('ciphertext randomness : ' + str(randomness))
        print('***********************************************')

################ CORRELATION PLAIN CIPHER ###################

def plaintext_ciphertext_correlation_dataset(num_samples=1000):

    dataset = []
    for _ in range(num_samples):
        # Generate a random plaintext
        plaintext = random_block_generator()

        # Generate a random key
        key = random_block_generator()

        # Encrypt the plaintext with the key
        ciphertext = aes_encryption(corr_block(key), corr_block(plaintext))

        # Record the sample in the dataset
        dataset.append((corr_block(plaintext), corr_block(key), ciphertext))

    return dataset

def encrypt_correlation_plaincipher_dataset(size=100):
    correlation_dataset = plaintext_ciphertext_correlation_dataset(size)
    print('************  CORRELATION PLAIN CIPHER DATASET  ************')
    for data in correlation_dataset:
        print('plaintext : ' + data[0])
        print('key : ' + data[1])
        print('ciphertext : ' + data[2])
        randomness = DFT_test(hexStr_binStr(data[2]))
        print('ciphertext randomness : ' + str(randomness))
        print('***********************************************')

################ AVALANCHE DATASET ###################

def avalanche_dataset(num_samples=10, block_size=16):
    dataset = []

    for _ in range(num_samples):
        # Generate a random plaintext
        plaintext = corr_block(random.randint(0, 2 ** block_size - 1))

        # Generate two slightly different keys
        original_key = corr_block(generate_random_key())

        # Record the sample in the dataset
        dataset.append((plaintext, original_key))

    return dataset


def avalanche_key():
    av_dataset = avalanche_dataset()
    print('************  AVALANCHE KEY DATASET  ************')
    for data in av_dataset:
        print('plaintext :' + data[0])
        print('original key :' + data[1])
        completeness(0, data[1], data[0])
        avalanche(0, data[1], data[0])
        strict_avalanche(0, data[1], data[0])

        print('*************************************************')

def avalanche_plaintext():
    av_dataset = avalanche_dataset()
    print('************  AVALANCHE PLAINTEXT DATASET  ************')
    for data in av_dataset:
        print('original plaintext :' + str(data[0]))
        print('key :' + str(data[1]))
        completeness(1, data[1], data[0])
        avalanche(1, data[1], data[0])
        strict_avalanche(1, data[1], data[0])

        print('*************************************************')

print('high density key randomness : ')
print(DFT_test(encrypt_high_density_key_dataset(8)))

print('low density key randomness : ')
print(DFT_test(encrypt_low_density_key_dataset(3)))

print('high density plaintext randomness : ')
print(DFT_test(encrypt_high_density_plaintext_dataset(3)))

print('low density plaintext randomness : ')
print(DFT_test(encrypt_low_density_plaintext_dataset(20)))
print(DFT_test(encrypt_random_dataset(20)))
encrypt_CBC_dataset(10)
encrypt_correlation_plaincipher_dataset(10)
avalanche_key()
avalanche_plaintext()



