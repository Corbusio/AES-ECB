import streamlit as st
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import numpy as np
from PIL import Image
import matplotlib.pyplot as plt
from scipy.stats import entropy
import pandas as pd
import io

Sbox = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

def decrypt_image(encrypted_image_array, key):
    cipher = AES.new(key, AES.MODE_ECB)
    flat_image = encrypted_image_array.flatten().tobytes()
    padded_image = pad(flat_image, AES.block_size)
    decrypted_image = cipher.decrypt(padded_image)
    return np.frombuffer(decrypted_image, dtype=np.uint8)

# Fungsi untuk mengenkripsi gambar dengan pelacakan proses enkripsi
def encrypt_image_with_trace(image_array, key):
    cipher = AES.new(key, AES.MODE_ECB)
    flat_image = image_array.flatten().tobytes()
    padded_image = pad(flat_image, AES.block_size)
    encrypted_image = cipher.encrypt(padded_image)
    
    # Inisialisasi variabel pelacakan
    state = padded_image[:16]
    state2 = padded_image[16:32]
    state3 = padded_image[-16:]
    round_results = []

    def add_round_key(state, round_key):
        return bytes([_a ^ _b for _a, _b in zip(state, round_key)])

    def sub_bytes(state):
        return bytes([Sbox[b] for b in state])

    def shift_rows(state):
        state = list(state)
        state[1], state[5], state[9], state[13] = state[5], state[9], state[13], state[1]
        state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
        state[3], state[7], state[11], state[15] = state[15], state[3], state[7], state[11]
        return bytes(state)

    def gmult(a, b):
        p = 0
        hi_bit_set = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi_bit_set = a & 0x80
            a <<= 1
            if hi_bit_set:
                a ^= 0x1b
            b >>= 1
        return p % 256

    def mix_columns(state):
        state = np.frombuffer(state, dtype=np.uint8).reshape(4, 4).T
        state = state.astype(np.uint8)
        for i in range(4):
            a = state[i]
            state[i] = [
                gmult(a[0], 2) ^ gmult(a[3], 1) ^ gmult(a[2], 1) ^ gmult(a[1], 3),
                gmult(a[1], 2) ^ gmult(a[0], 1) ^ gmult(a[3], 1) ^ gmult(a[2], 3),
                gmult(a[2], 2) ^ gmult(a[1], 1) ^ gmult(a[0], 1) ^ gmult(a[3], 3),
                gmult(a[3], 2) ^ gmult(a[2], 1) ^ gmult(a[1], 1) ^ gmult(a[0], 3)
                ]
        return bytes(state.T.flatten())

    def bytes_to_hex_str(byte_data):
        return ' '.join([f'{b:02x}' for b in byte_data])

    round_keys = [key]  # Inisialisasi kunci ronde dengan kunci awal

    def key_expansion(key):
        # Ekspansi kunci menggunakan AES-128
        Rcon = [
            0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f,
            0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91
        ]
        key_symbols = [b for b in key]
        if len(key_symbols) < 4 * 4:
            for i in range(4 * 4 - len(key_symbols)):
                key_symbols.append(0x01)
        key_schedule = [[key_symbols[row + col * 4] for row in range(4)] for col in range(4)]
        
        for col in range(4, 4 * 11):
            if col % 4 == 0:
                temp = [key_schedule[row][col - 1] for row in range(1, 4)]
                temp.append(key_schedule[0][col - 1])
                temp = [Sbox[b] for b in temp]
                temp[0] ^= Rcon[col // 4 - 1]
                for row in range(4):
                    key_schedule[row].append(key_schedule[row][col - 4] ^ temp[row])
            else:
                for row in range(4):
                    key_schedule[row].append(key_schedule[row][col - 4] ^ key_schedule[row][col - 1])
        
        for i in range(1, 11):
            round_key = []
            for row in range(4):
                round_key.extend(key_schedule[row][i * 4:(i + 1) * 4])
            round_keys.append(bytes(round_key))
    
    key_expansion(key)

    # Initial AddRoundKey
    state = add_round_key(state, round_keys[0])
    state2 = add_round_key(state2, round_keys[0])
    state3 = add_round_key(state3, round_keys[0])
    round_results.append(['Initial', 'AddRoundKey', bytes_to_hex_str(state), bytes_to_hex_str(state2), bytes_to_hex_str(state3)])

    # Rounds 1 to 9
    for round_num in range(1, 10):
        state = sub_bytes(state)
        state2 = sub_bytes(state2)
        state3 = sub_bytes(state3)
        round_results.append([f'Ronde {round_num}', 'SubBytes', bytes_to_hex_str(state), bytes_to_hex_str(state2), bytes_to_hex_str(state3)])
        
        state = shift_rows(state)
        state2 = shift_rows(state2)
        state3 = shift_rows(state3)
        round_results.append([f'Ronde {round_num}', 'ShiftRows', bytes_to_hex_str(state), bytes_to_hex_str(state2), bytes_to_hex_str(state3)])
        
        state = mix_columns(state)
        state2 = mix_columns(state2)
        state3 = mix_columns(state3)
        round_results.append([f'Ronde {round_num}', 'MixColumns', bytes_to_hex_str(state), bytes_to_hex_str(state2), bytes_to_hex_str(state3)])
        
        state = add_round_key(state, round_keys[round_num])
        state2 = add_round_key(state2, round_keys[round_num])
        state3 = add_round_key(state3, round_keys[round_num])
        round_results.append([f'Ronde {round_num}', 'AddRoundKey', bytes_to_hex_str(state), bytes_to_hex_str(state2), bytes_to_hex_str(state3)])

    # Round 10
    state = sub_bytes(state)
    state2 = sub_bytes(state2)
    state3 = sub_bytes(state3)
    round_results.append([f'Ronde 10', 'SubBytes', bytes_to_hex_str(state), bytes_to_hex_str(state2), bytes_to_hex_str(state3)])

    state = shift_rows(state)
    state2 = shift_rows(state2)
    state3 = shift_rows(state3)
    round_results.append([f'Ronde 10', 'ShiftRows', bytes_to_hex_str(state), bytes_to_hex_str(state2), bytes_to_hex_str(state3)])

    state = add_round_key(state, round_keys[10])
    state2 = add_round_key(state2, round_keys[10])
    state3 = add_round_key(state3, round_keys[10])
    round_results.append([f'Ronde 10', 'AddRoundKey', bytes_to_hex_str(state), bytes_to_hex_str(state2), bytes_to_hex_str(state3)])

    encrypted_image_array = np.frombuffer(encrypted_image, dtype=np.uint8)
    return encrypted_image_array, round_results

# Fungsi untuk menghitung NPCR
def calculate_npcr(original, encrypted):
    original_flat = original.flatten()
    encrypted_flat = encrypted.flatten()[:original_flat.size]  # Ensure both arrays are of the same size
    diff = np.sum(original_flat != encrypted_flat)
    return (diff / len(original_flat)) * 100

# Fungsi untuk menampilkan histogram
def plot_histogram(image, title):
    plt.figure(figsize=(10, 5))
    colors = ('r', 'g', 'b')
    for i, color in enumerate(colors):
        histogram, bin_edges = np.histogram(image[:, :, i], bins=256, range=(0, 256))
        plt.plot(bin_edges[0:-1], histogram, color=color)
    plt.title(title)
    plt.xlabel('Pixel Value')
    plt.ylabel('Frequency')
    st.pyplot(plt)

# Fungsi untuk menghitung entropi
def calculate_entropy(image):
    hist, _ = np.histogram(image, bins=256, range=(0, 256))
    return entropy(hist)

# Judul aplikasi
st.title('Enkripsi dan Dekripsi Gambar Menggunakan AES ECB')
tab1, tab2 = st.tabs(["Encryption", "Decryption"])

with tab1: 
    # Mengunggah gambar
    uploaded_file = st.file_uploader("Pilih gambar untuk diunggah", type=["png", "jpg", "jpeg"])

    if uploaded_file is not None:
        key = st.text_input('Enter a 16-byte key for encryption (e.g., "1234567890abcdef"):', key='enc_key')
        
        if key and len(key) == 16:
            key = key.encode('utf-8')
            image = Image.open(uploaded_file)
            image = image.convert("RGB")
            image_array = np.array(image)

            # Enkripsi gambar dengan pelacakan
            encrypted_image_array, round_results = encrypt_image_with_trace(image_array, key)
            encrypted_image_array = encrypted_image_array[:image_array.size].reshape(image_array.shape)
            encrypted_image = Image.fromarray(encrypted_image_array, "RGB")

            st.image(image, caption='Gambar Asli', use_column_width=True)
            st.image(encrypted_image, caption='Gambar Terenkripsi', use_column_width=True)
            
            # Tampilkan histogram
            plot_histogram(image_array, 'Histogram Gambar Asli')
            plot_histogram(encrypted_image_array, 'Histogram Gambar Terenkripsi')
            
            # Hitung dan tampilkan NPCR
            npcr_value = calculate_npcr(image_array, encrypted_image_array)
            st.write(f'NPCR: {npcr_value:.2f}%')
            
            original_entropy = calculate_entropy(image_array)
            encrypted_entropy = calculate_entropy(encrypted_image_array)
            st.write(f'Entropy of Original Image: {original_entropy:.2f}')
            st.write(f'Entropy of Encrypted Image: {encrypted_entropy:.2f}')
            
            # Tampilkan tabel hasil enkripsi
            st.subheader('Tabel Hasil Enkripsi AES')
            round_results_df = pd.DataFrame(round_results, columns=['Ronde', 'Variabel', 'Hasil Blok 1', 'Hasil Blok 2', 'Hasil Blok Terakhir'])
            st.dataframe(round_results_df)
            
            # Tombol untuk mengunduh gambar terenkripsi
            buffered = io.BytesIO()
            encrypted_image.save(buffered, format="PNG")
            st.download_button(
                label="Download Encrypted Image",
                data=buffered.getvalue(),
                file_name="encrypted_image.png",
                mime="image/png"
            )

with tab2:
    # Mengunggah gambar terenkripsi
    encrypted_file = st.file_uploader("Pilih gambar terenkripsi untuk diunggah", type=["png", "jpg", "jpeg"])

    if encrypted_file is not None:
        key = st.text_input('Enter a 16-byte key for encryption (e.g., "1234567890abcdef"):', key='dec_key')
        if key and len(key) == 16:
            key = key.encode('utf-8')
            # Baca gambar yang diunggah
            image2 = Image.open(encrypted_file)
            image2 = image2.convert("RGB")
            image2_array = np.array(image2)

            # Dekripsi gambar
            decrypted_image_array = decrypt_image(image2_array, key)
            decrypted_image_array = decrypted_image_array[:image2_array.size].reshape(image2_array.shape)
            decrypted_image = Image.fromarray(decrypted_image_array, "RGB")

            st.image(image2 , caption='Gambar Terenkripsi', use_column_width=True)
            st.image(decrypted_image, caption='Gambar Dekripsi', use_column_width=True)
            
            # Tampilkan histogram
            plot_histogram(image2_array, 'Histogram Gambar Terenkripsi')
            plot_histogram(decrypted_image_array, 'Histogram Gambar Dekripsi')
            
            # Hitung dan tampilkan NPCR
            npcr_value = calculate_npcr(image2_array, decrypted_image_array)
            st.write(f'NPCR: {npcr_value:.2f}%')
            
            encrypted_entropy = calculate_entropy(image2_array)
            decrypted_entropy = calculate_entropy(decrypted_image_array)
            st.write(f'Entropy of Encrypted Image: {encrypted_entropy:.2f}')
            st.write(f'Entropy of Decrypted Image: {decrypted_entropy:.2f}')
            
            # Tombol untuk mengunduh gambar dekripsi
            buffered = io.BytesIO()
            decrypted_image.save(buffered, format="PNG")
            st.download_button(
                label="Download Decrypted Image",
                data=buffered.getvalue(),
                file_name="decrypted_image.png",
                mime="image/png"
            )
