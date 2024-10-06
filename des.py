import random
import string

IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

FP = [40, 8, 48, 16, 56, 24, 64, 32,
      39, 7, 47, 15, 55, 23, 63, 31,
      38, 6, 46, 14, 54, 22, 62, 30,
      37, 5, 45, 13, 53, 21, 61, 29,
      36, 4, 44, 12, 52, 20, 60, 28,
      35, 3, 43, 11, 51, 19, 59, 27,
      34, 2, 42, 10, 50, 18, 58, 26,
      33, 1, 41, 9, 49, 17, 57, 25]

def permute(block, table):
    return [block[x-1] for x in table]

def split(block):
    return block[:32], block[32:]

def feistel(r_block, sub_key):
    expanded_r = r_block
    xor_result = [a ^ b for a, b in zip(expanded_r, sub_key)]
    return xor_result

def des_encrypt(plaintext, key):
    plaintext_bits = [int(b) for b in format(int.from_bytes(plaintext.encode(), 'big'), '064b')]
    key_bits = [int(b) for b in format(int.from_bytes(key.encode(), 'big'), '064b')]
    initial_permuted = permute(plaintext_bits, IP)
    L, R = split(initial_permuted)

    for round_num in range(16):
        sub_key = key_bits[:48]
        L_prev = L
        L = R
        R = [a ^ b for a, b in zip(L_prev, feistel(R, sub_key))]

    final_block = R + L
    ciphertext_bits = permute(final_block, FP)
    ciphertext = ''.join(map(str, ciphertext_bits))
    return ciphertext

def des_decrypt(ciphertext, key):
    ciphertext_bits = [int(b) for b in ciphertext]
    key_bits = [int(b) for b in format(int.from_bytes(key.encode(), 'big'), '064b')]
    initial_permuted = permute(ciphertext_bits, IP)
    L, R = split(initial_permuted)

    for round_num in range(16):
        sub_key = key_bits[:48]
        L_prev = L
        L = R
        R = [a ^ b for a, b in zip(L_prev, feistel(R, sub_key))]

    final_block = R + L
    decrypted_bits = permute(final_block, FP)
    decrypted_text = ''.join(map(str, decrypted_bits))
    return decrypted_text

def generate_random_key():
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(8))

def bits_to_string(bits):
    chars = [chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8)]
    return ''.join(chars)

def pretty_print_bits(bits, label):
    formatted_bits = ' '.join([bits[i:i+8] for i in range(0, len(bits), 8)])
    print(f"{label}: {formatted_bits}")

plaintext = input("Message: ")
if len(plaintext) != 8:
    raise ValueError("Panjang pesan harus 8 karakter.")

key = generate_random_key()
print(f"Generated random key: {key}")

ciphertext = des_encrypt(plaintext, key)
pretty_print_bits(ciphertext, "Ciphertext")

decrypted_bits = des_decrypt(ciphertext, key)
decrypted_text = bits_to_string(decrypted_bits)
pretty_print_bits(decrypted_bits, "Decrypted Bits")
print(f"Decrypted text: {decrypted_text}")
