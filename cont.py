import streamlit as st
from PIL import Image, ImageDraw, ImageFont
import numpy as np
import io
import json
import hashlib
import datetime
import time

# --- KOD BAŞLANGICI: YARDIMCI FONKSİYONLAR ---

def initialize_session_state():
    """Streamlit oturum durumunu başlatır veya sıfırlar."""
    state_keys = [
        'decrypted_image', 'watermarked_image', 'hidden_message', 
        'is_message_visible', 'watermarked_image_active', 'original_image'
    ]
    for key in state_keys:
        if key not in st.session_state:
            st.session_state[key] = None if 'image' in key or 'message' in key else False

def generate_key_stream(img_shape, secret_key: str):
    """Görüntüyü şifrelemek/çözmek için Keystream (Anahtar Akışı) oluşturur."""
    if not secret_key:
        secret_key = "default_seed" 
    # Hash ile tohum oluşturma
    seed = int(hashlib.sha256(secret_key.encode('utf-8')).hexdigest(), 16) % (2**32 - 1)
    np.random.seed(seed)
    # Keystream oluşturma
    key_stream = np.random.randint(0, 256, size=img_shape, dtype=np.uint8)
    return key_stream

def xor_image(img_bytes, key_stream):
    """Görüntü verilerini Keystream ile XOR işlemine tabi tutar."""
    img_array = np.array(img_bytes, dtype=np.uint8)
    if img_array.shape != key_stream.shape:
        raise ValueError("Resim ve Anahtar Akışı boyutları eşleşmiyor!")

    encrypted_array = np.bitwise_xor(img_array, key_stream)
    return encrypted_array

# --- LED TABELA EFECTİ FONKSİYONU (Kaldı) ---

def draw_led_display(img: Image.Image, hidden_message: str) -> Image.Image:
    """Şifre çözülmüş görselin üzerine LED Tabela (Dot Matrix) efektiyle gizli mesajı ekler."""
    img_copy = img.copy().convert("RGBA")
    w, h = img_copy.size
    
    if not hidden_message.strip():
        return img 

    # 1. Tabela Alanını Belirleme (Üst %25)
    panel_height = int(h * 0.25)
    panel_margin = 30
    panel_rect = [
        panel_margin,
        panel_margin,
        w - panel_margin,
        panel_height + panel_margin
    ]
    
    panel = Image.new('RGBA', img_copy.size, (0, 0, 0, 0))
    panel_draw = ImageDraw.Draw(panel)
    panel_draw.rectangle(panel_rect, fill=(20, 20, 20, 200)) # Koyu yarı şeffaf arka plan
    
    # 2. Mesajı Pikselleştirme ve Çizme
    text_to_display = hidden_message.upper() 
    led_color = (255, 69, 0, 255) # Parlak Turuncu/Kırmızı
    led_radius = 2
    dot_spacing = 8
    
    try:
        font_size = 40
        font = ImageFont.load_default().font_variant(size=font_size) 
    except IOError:
        font_size = 30
        font = ImageFont.load_default()
        
    temp_draw = ImageDraw.Draw(Image.new('RGB', (1, 1)))
    try:
        bbox = temp_draw.textbbox((0, 0), text_to_display, font=font)
        text_w = bbox[2] - bbox[0]
        text_h = bbox[3] - bbox[1]
    except AttributeError:
        text_w = temp_draw.textlength(text_to_display, font=font)
        text_h = font_size
        
    start_x = panel_rect[0] + (panel_rect[2] - panel_rect[0] - text_w) // 2
    start_y = panel_rect[1] + (panel_height - text_h) // 2
    
    panel_draw.text((start_x, start_y), text_to_display, font=font, fill=(255, 255, 255, 255))
    
    # 3. Pikselleştirme (LED Efekti)
    panel_pixels = panel.load()
    
    for y in range(panel_rect[1], panel_rect[3], dot_spacing):
        for x in range(panel_rect[0], panel_rect[2], dot_spacing):
            
            if x >= w or y >= h:
                continue
            
            r, g, b, a = panel_pixels[x, y]
            
            if r > 200 and a > 0:
                panel_draw.ellipse(
                    (x - led_radius, y - led_radius, x + led_radius, y + led_radius),
                    fill=led_color,
                    outline=None
                )
            else:
                panel_draw.ellipse(
                    (x - led_radius, y - led_radius, x + led_radius, y + led_radius),
                    fill=(50, 50, 50, 50),
                    outline=None
                )
                
    # 4. Görüntüleri Birleştirme
    img_copy.paste(panel, (0, 0), panel)
    
    return img_copy.convert("RGB")

# --- ÖRNEK RESİM OLUŞTURMA FONKSİYONU ---
def create_sample_image():
    """Varsayılan bir örnek resim oluşturur."""
    if 'original_image' not in st.session_state or st.session_state.original_image is None:
        try:
            img = Image.new('RGB', (600, 400), color = 'lightblue')
            d = ImageDraw.Draw(img)
            try:
                # PIL'de varsayılan fontu yükle
                font = ImageFont.load_default().font_variant(size=40)
            except IOError:
                font = ImageFont.load_default()

            d.text((100, 180), "ÖRNEK GÖRSEL", fill=(50, 50, 50), font=font)
            st.session_state.original_image = img
        except Exception as e:
            st.error(f"Örnek görsel oluşturulurken hata oluştu: {e}")
            st.session_state.original_image = None
    return st.session_state.original_image

# --- ANA UYGULAMA YAPISI ---

st.set_page_config(layout="centered", page_title="Gizli Mesaj Şifreleyici")
initialize_session_state()

st.title("🔒 Görsel Üzerinde Gizli Mesaj Şifreleme")

tab_encrypt, tab_decrypt = st.tabs(["Şifreleme (Görseli Kilitle)", "Şifre Çözme (Mesajı Gör)"])

# --- ŞİFRELEME SEKME İÇERİĞİ ---
with tab_encrypt:
    st.header("Görseli Şifrele")
    
    # --- Örnek Resim Oluşturma Butonu ---
    if st.button("Örnek Resim Oluştur", key="create_sample_btn"):
        create_sample_image()
        
    uploaded_file = st.file_uploader("1. Şifrelenecek Görseli Yükle (.png, .jpg) VEYA Örnek Kullan", type=["png", "jpg", "jpeg"])

    if uploaded_file:
        original_img = Image.open(uploaded_file).convert("RGB")
        st.session_state.original_image = original_img
    
    if st.session_state.original_image:
        st.image(st.session_state.original_image, caption="Orijinal Görsel", use_column_width=True)
        
        with st.form("encryption_form"):
            
            # --- Sade Girdiler ---
            secret_key = st.text_input(
                "2. Şifreleme Anahtarı (Resim Şifresi)", 
                help="Görseli şifrelemek ve çözmek için kullanılacak anahtar.", 
                value="my_secret_key"
            )
            
            hidden_message = st.text_area(
                "3. Gizli Mesaj (Çözüldüğünde LED Panelde Görünür)", 
                max_chars=100,
                height=100,
                help="Şifre çözüldükten sonra resmin üzerinde gösterilecek mesaj."
            )
            
            encrypt_button = st.form_submit_button("Görseli Şifrele ve Dosyaları Oluştur", use_container_width=True)
        
        
        if encrypt_button:
            if not secret_key or not hidden_message:
                st.error("Lütfen Resim Şifresini ve Gizli Mesajı girin.")
            else:
                st.info("Şifreleme Başlatılıyor...")
                
                original_img = st.session_state.original_image
                img_array = np.array(original_img)
                key_stream = generate_key_stream(img_array.shape, secret_key)
                encrypted_array = xor_image(img_array, key_stream)
                encrypted_img = Image.fromarray(encrypted_array)
                
                # PNG Baytları
                png_bytes_io = io.BytesIO()
                encrypted_img.save(png_bytes_io, format='PNG')
                png_bytes = png_bytes_io.getvalue()
                
                # Orijinal Hash
                original_img_bytes = io.BytesIO()
                original_img.save(original_img_bytes, format='PNG')
                original_hash = hashlib.sha256(original_img_bytes.getvalue()).hexdigest()
                
                # Meta Dosyası (Sadece hash ve mesaj içeriyor)
                meta_data = {
                    "original_hash": original_hash,
                    "hidden_message": hidden_message,
                    # Kilit zamanı ve filigran şifresi kaldırıldı.
                }
                meta_bytes = json.dumps(meta_data, indent=4).encode('utf-8')
                
                
                st.success("Şifreleme Tamamlandı! Lütfen iki dosyayı da indirin.")
                st.markdown("### 📥 İndirilecek Dosyalar")
                
                st.download_button(
                    label="Şifreli Görsel İndir (.png)",
                    data=png_bytes,
                    file_name="encrypted_image.png",
                    mime="image/png",
                    use_
