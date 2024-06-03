import streamlit as st
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import numpy as np
from PIL import Image
import matplotlib.pyplot as plt
from scipy.stats import entropy
import io

# Fungsi untuk mengenkripsi gambar
def encrypt_image(image_array, key):
    cipher = AES.new(key, AES.MODE_ECB)
    flat_image = image_array.flatten().tobytes()  # Ubah ke tipe data bytes
    padded_image = pad(flat_image, AES.block_size)
    encrypted_image = cipher.encrypt(padded_image)    
    return np.frombuffer(encrypted_image, dtype=np.uint8)

# Fungsi untuk mendekripsi gambar
def decrypt_image(encrypted_image_array, key):
    cipher = AES.new(key, AES.MODE_ECB)
    flat_image = encrypted_image_array.flatten().tobytes()
    padded_image = pad(flat_image, AES.block_size)
    decrypted_image = cipher.decrypt(padded_image)
    return np.frombuffer(decrypted_image, dtype=np.uint8)

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

            # Enkripsi gambar
            encrypted_image_array = encrypt_image(image_array, key)
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
            encrypted_image = Image.open(encrypted_file)
            encrypted_image = encrypted_image.convert("RGB")
            encrypted_image_array = np.array(encrypted_image)

            # Dekripsi gambar
            decrypted_image_array = decrypt_image(encrypted_image_array, key)
            decrypted_image_array = decrypted_image_array[:encrypted_image_array.size].reshape(encrypted_image_array.shape)
            decrypted_image = Image.fromarray(decrypted_image_array, "RGB")

            st.image(encrypted_image, caption='Gambar Terenkripsi', use_column_width=True)
            st.image(decrypted_image, caption='Gambar Dekripsi', use_column_width=True)
            
            # Tampilkan histogram
            plot_histogram(encrypted_image_array, 'Histogram Gambar Terenkripsi')
            plot_histogram(decrypted_image_array, 'Histogram Gambar Dekripsi')
            
            # Hitung dan tampilkan NPCR
            npcr_value = calculate_npcr(encrypted_image_array, decrypted_image_array)
            st.write(f'NPCR: {npcr_value:.2f}%')
            
            encrypted_entropy = calculate_entropy(encrypted_image_array)
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
