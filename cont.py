import streamlit as st
from PIL import Image, ImageDraw, ImageFont
import numpy as np
import io
import json
import hashlib
import datetime
import time

# --- KOD BAŞLANGICI: YARDIMCI FONKSİYONLAR ---

def log(message):
    """Basit loglama fonksiyonu"""
    # st.toast(f"LOG: {message}")
    pass

def initialize_session_state():
    """Streamlit oturum durumunu (session state) başlatır veya sıfırlar."""
    state_keys = [
        'decrypted_image', 'watermarked_image', 'hidden_message', 
        'prompt_secret_key', 'is_message_visible', 'decryption_time_ok', 
        'show_decryption_error', 'watermarked_image_active'
    ]
    for key in state_keys:
        if key not in st.session_state:
            st.session_state[key] = None if 'image' in key or 'message' in key else False

def generate_key_stream(img_shape, secret_key: str):
    """Görüntüyü şifrelemek/çözmek için Keystream (Anahtar Akışı) oluşturur."""
    if not secret_key:
        secret_key = "default_seed" 
        
    seed = int(hashlib.sha256(secret_key.encode('utf-8')).hexdigest(), 16) % (2**32 - 1)
    np.random.seed(seed)
    
    key_stream = np.random.randint(0, 256, size=img_shape, dtype=np.uint8)
    return key_stream

def xor_image(img_bytes, key_stream):
    """Görüntü verilerini Keystream ile XOR işlemine tabi tutar."""
    img_array = np.array(img_bytes, dtype=np.uint8)
    
    if img_array.shape != key_stream.shape:
        raise ValueError("Resim ve Anahtar Akışı boyutları eşleşmiyor!")

    encrypted_array = np.bitwise_xor(img_array, key_stream)
    
    return encrypted_array

# --- LED TABELA EFECTİ FONKSİYONU ---

def draw_led_display(img: Image.Image, hidden_message: str) -> Image.Image:
    """Şifre çözülmüş görselin üzerine LED Tabela (Dot Matrix) efektiyle gizli mesajı ekler."""
    img_copy = img.copy().convert("RGBA")
    w, h = img_copy.size
    
    if not hidden_message.strip():
        return img 

    # 1. Tabela Alanını Belirleme (Üst %30)
    panel_height = int(h * 0.25) # Daha az yer kaplaması için %25 yapıldı
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
            
            # Eğer piksel parlaksa (Metin rengi), buraya parlak bir LED çiz.
            if r > 200 and a > 0:
                panel_draw.ellipse(
                    (x - led_radius, y - led_radius, x + led_radius, y + led_radius),
                    fill=led_color,
                    outline=None
                )
            else:
                # Mesaj olmayan yerleri kapalı LED renginde tut (Ekran parlaklığını simüle etmek için)
                panel_draw.ellipse(
                    (x - led_radius, y - led_radius, x + led_radius, y + led_radius),
                    fill=(50, 50, 50, 50),
                    outline=None
                )
                
    # 4. Görüntüleri Birleştirme
    img_copy.paste(panel, (0, 0), panel)
    
    return img_copy.convert("RGB")

# --- KOD BİTİŞİ: YARDIMCI FONKSİYONLAR ---


# --- ANA UYGULAMA YAPISI ---

# Basit, ortalanmış bir arayüz için 'centered' layout kullanılır.
st.set_page_config(layout="centered", page_title="Zaman Kilitli Görsel Şifreleme")
initialize_session_state()

st.title("🔒 Zaman Kilitli Görsel Şifreleme & LED Mesaj")

# Sekmeleri tanımlama
tab_encrypt, tab_decrypt = st.tabs(["Şifreleme (Kilit Ekle)", "Şifre Çözme (Kilit Aç)"])


# --- ŞİFRELEME SEKME İÇERİĞİ ---
with tab_encrypt:
    st.header("Görseli Şifrele ve Kilit Zamanı Ayarla")
    
    uploaded_file = st.file_uploader("1. Şifrelenecek Görseli Yükle (.png, .jpg)", type=["png", "jpg", "jpeg"])

    if uploaded_file:
        try:
            original_img = Image.open(uploaded_file).convert("RGB")
            st.image(original_img, caption="Orijinal Görsel", use_column_width=True)
            
            with st.form("encryption_form"):
                
                # --- Tüm Girdiler Alt Alta Yerleştirildi (Sade Arayüz) ---
                
                secret_key = st.text_input(
                    "2. Şifreleme Anahtarı (Keystream Tohumu)", 
                    help="Görseli şifrelemek ve çözmek için kullanılacak rastgele tohum.", 
                    value="my_secret_key"
                )
                
                decryption_time = st.date_input(
                    "3. Şifre Açma Tarihi", 
                    datetime.date.today() + datetime.timedelta(days=1),
                    min_value=datetime.date.today(),
                    help="Bu tarihten önce görsel çözülse bile mesaj gösterilemez."
                )
                
                hidden_message = st.text_area(
                    "4. Gizli Mesaj (Çözüldüğünde LED Panelde Görünür)", 
                    max_chars=100,
                    height=100,
                    help="Şifre çözüldükten sonra resmin üzerinde gösterilecek mesaj."
                )
                
                watermark_secret = st.text_input(
                    "5. Filigran Şifresi (Mesajı Göstermek İçin Ek Şifre)", 
                    help="Gizli mesajı göstermek için ekstra bir şifre. Boş bırakılabilir.",
                    value=""
                )
                
                encrypt_button = st.form_submit_button("Görseli Şifrele ve Dosyaları Oluştur")
            
            
            if encrypt_button:
                if not secret_key or not hidden_message:
                    st.error("Lütfen Şifreleme Anahtarı ve Gizli Mesajı girin.")
                else:
                    st.info("Şifreleme Başlatılıyor...")
                    
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
                    
                    # Meta Dosyası
                    meta_data = {
                        "decryption_time": decryption_time.isoformat(),
                        "original_hash": original_hash,
                        "hidden_message": hidden_message,
                        "watermark_secret_hash": hashlib.sha256(watermark_secret.encode('utf-8')).hexdigest() if watermark_secret else None
                    }
                    meta_bytes = json.dumps(meta_data, indent=4).encode('utf-8')
                    
                    
                    st.success("Şifreleme Tamamlandı! Lütfen iki dosyayı da indirin.")
                    
                    st.markdown("### 📥 İndirilecek Dosyalar")
                    
                    # Dosyaları indirme butonları alt alta
                    st.download_button(
                        label="Şifreli Görsel İndir (.png)",
                        data=png_bytes,
                        file_name="encrypted_image.png",
                        mime="image/png",
                        use_container_width=True
                    )
                    
                    st.download_button(
                        label="Kilit Meta Dosyası İndir (.meta)",
                        data=meta_bytes,
                        file_name="encrypted_image.meta",
                        mime="application/json",
                        use_container_width=True
                    )
                    
                    st.image(encrypted_img, caption="Şifreli Görsel (Bozulmuş)", use_column_width=True)
                        
        except Exception as e:
            st.error(f"Bir hata oluştu: {e}")
            log(f"Şifreleme Hatası: {e}")


# --- ŞİFRE ÇÖZME SEKME İÇERİĞİ ---
with tab_decrypt:
    st.header("Görseli Çöz ve Gizli Mesajı Gör")
    
    # Yükleyiciler alt alta
    uploaded_png = st.file_uploader("1. Şifreli .png Dosyasını Yükle", type=["png"], key="decrypt_png")
    uploaded_meta = st.file_uploader("2. .meta Dosyasını Yükle", type=["meta"], key="decrypt_meta")
        
    st.warning("Gizli mesajı görmek için **hem .png hem de .meta** dosyasını yüklemelisiniz.")

    # Oturum durumlarını temizleme (Yeni dosya yüklemede temizlik)
    if 'decrypt_png' in st.session_state and st.session_state.decrypt_png is None and st.session_state.decrypted_image is not None:
        initialize_session_state()
        st.rerun()

    
    if uploaded_png and uploaded_meta:
        
        # --- Şifre Çözme Formu ---
        with st.form("decryption_key_form", clear_on_submit=False):
            decrypt_secret_key = st.text_input(
                "3. Şifreleme Anahtarı (Şifreleme Sekmesinde Kullanılan)",
                value="my_secret_key",
                key="decrypt_key_input"
            )
            submit_key = st.form_submit_button("Görseli Çöz", use_container_width=True)
        
        # --- Şifre Çözme İşlemi ---
        if submit_key or st.session_state.decrypted_image is not None:
            
            try:
                # 1. Meta veriyi oku
                meta_data = json.loads(uploaded_meta.getvalue().decode('utf-8'))
                
                decryption_time_str = meta_data.get("decryption_time")
                original_hash = meta_data.get("original_hash")
                hidden_message = meta_data.get("hidden_message", "")
                watermark_secret_hash = meta_data.get("watermark_secret_hash")
                
                st.session_state.hidden_message = hidden_message 
                
                # 2. Şifreli resmi oku
                encrypted_img = Image.open(io.BytesIO(uploaded_png.getvalue())).convert("RGB")
                encrypted_array = np.array(encrypted_img)
                
                # 3. Şifre Çözme
                key_stream = generate_key_stream(encrypted_array.shape, decrypt_secret_key)
                decrypted_array = xor_image(encrypted_array, key_stream)
                decrypted_img = Image.fromarray(decrypted_array)
                
                st.session_state.decrypted_image = decrypted_img
                st.session_state.watermarked_image_active = False # Filigranı sıfırla

                
                # --- Zaman Kontrolü ---
                if decryption_time_str:
                    target_dt = datetime.datetime.fromisoformat(decryption_time_str).date()
                    current_dt = datetime.datetime.now().date()
                    
                    if current_dt < target_dt:
                        st.info(f"Gizli Mesaj Görüntüleme Kilidi: Mesaj, {target_dt.strftime('%d %B %Y')} tarihinden önce gösterilemez.")
                        st.session_state.decryption_time_ok = False
                    else:
                        st.session_state.decryption_time_ok = True
                        st.success(f"Zaman Kilidi Açıldı! ({target_dt.strftime('%d %B %Y')})")
                else:
                    st.session_state.decryption_time_ok = True
                    
                
                # --- Mesaj Gösterim Kontrolü ---
                
                if st.session_state.decryption_time_ok:
                    
                    if watermark_secret_hash:
                        # Filigran Şifresi Gerekli
                        with st.form("watermark_key_form"):
                            
                            if not st.session_state.is_message_visible or not st.session_state.watermarked_image_active:
                                wm_key = st.text_input(
                                    "4. Gizli Mesaj Şifresi (Filigran Şifresi)",
                                    type="password",
                                    key="wm_key_input"
                                )
                                wm_submit = st.form_submit_button("Mesajı LED Panelde Göster", use_container_width=True)
                            else:
                                wm_submit = False

                            
                            if wm_submit:
                                wm_current_hash = hashlib.sha256(wm_key.encode('utf-8')).hexdigest()
                                
                                if wm_current_hash == watermark_secret_hash:
                                    st.session_state.watermarked_image = draw_led_display(
                                        st.session_state.decrypted_image, 
                                        st.session_state.hidden_message
                                    )
                                    st.session_state.is_message_visible = True
                                    st.session_state.watermarked_image_active = True
                                    st.rerun()
                                else:
                                    st.error("Filigran Şifresi Yanlış!")
                                    st.session_state.is_message_visible = False
                                    
                    else:
                        # Filigran şifresi yoksa mesajı hemen LED panelde göster
                        if not st.session_state.is_message_visible or not st.session_state.watermarked_image_active:
                            st.session_state.watermarked_image = draw_led_display(
                                st.session_state.decrypted_image, 
                                st.session_state.hidden_message
                            )
                            st.session_state.is_message_visible = True
                            st.session_state.watermarked_image_active = True
                            st.rerun()
                            
                else:
                    st.session_state.is_message_visible = False
                
                
                # --- Çözülen Görseli Gösterme ---
                
                if st.session_state.watermarked_image_active and st.session_state.watermarked_image:
                    st.image(st.session_state.watermarked_image, caption="Çözülen Görsel (LED Mesaj Aktif)", use_column_width=True)
                elif st.session_state.decrypted_image:
                    st.image(st.session_state.decrypted_image, caption="Çözülen Görsel", use_column_width=True)
                    
            except json.JSONDecodeError:
                st.error("Hata: Meta dosyası bozuk veya geçerli bir JSON formatında değil.")
            except ValueError as e:
                st.error(f"Hata: Şifre Çözme Anahtarı geçersiz veya resim boyutu uyuşmuyor. ({e})")
            except Exception as e:
                st.error(f"Beklenmeyen bir hata oluştu: {e}")

# --- KOD SONU ---
