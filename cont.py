import streamlit as st
from PIL import Image, ImageDraw, ImageFont
import numpy as np
import io
import json
import hashlib
import datetime
import time # Gerekli time kütüphanesi

# --- KOD BAŞLANGICI: YARDIMCI FONKSİYONLAR ---

def log(message):
    """Basit loglama fonksiyonu (isteğe bağlı, kaldırılabilir)"""
    # st.toast(f"LOG: {message}")
    pass

def initialize_session_state():
    """Streamlit oturum durumunu (session state) başlatır."""
    if 'decrypted_image' not in st.session_state:
        st.session_state.decrypted_image = None
    if 'watermarked_image' not in st.session_state:
        st.session_state.watermarked_image = None
    if 'hidden_message' not in st.session_state:
        st.session_state.hidden_message = ""
    if 'prompt_secret_key' not in st.session_state:
        st.session_state.prompt_secret_key = False
    if 'is_message_visible' not in st.session_state:
        st.session_state.is_message_visible = False
    if 'decryption_time_ok' not in st.session_state:
        st.session_state.decryption_time_ok = False
    if 'show_decryption_error' not in st.session_state:
        st.session_state.show_decryption_error = False

# --- XOR ŞİFRELEME/ÇÖZME FONKSİYONLARI ---

def generate_key_stream(img_shape, secret_key: str):
    """
    Şifre çözme için Keystream (Anahtar Akışı) oluşturur.
    Gizli anahtarı kullanarak rastgele bir numpy dizisi üretir.
    """
    if not secret_key:
        secret_key = "default_seed" # Boş şifre için varsayılan tohum
        
    # Gizli anahtardan güvenilir bir tohum üretmek için hash kullan
    seed = int(hashlib.sha256(secret_key.encode('utf-8')).hexdigest(), 16) % (2**32 - 1)
    np.random.seed(seed)
    
    # Resim boyutuyla aynı, 0-255 arası rastgele değerler içeren numpy dizisi
    key_stream = np.random.randint(0, 256, size=img_shape, dtype=np.uint8)
    return key_stream

def xor_image(img_bytes, key_stream):
    """
    Görüntü verilerini Keystream ile XOR işlemine tabi tutar.
    Şifreleme ve şifre çözme için aynı fonksiyon kullanılır.
    """
    # Resmi numpy dizisine dönüştür
    img_array = np.array(img_bytes, dtype=np.uint8)
    
    # Boyutları kontrol et ve Keystream'i uydur (gerekliyse)
    if img_array.shape != key_stream.shape:
        # Genellikle boyutlar aynı olacaktır, ancak bir uyumsuzluk durumunda hata veririz.
        log(f"Boyut uyumsuzluğu: Resim {img_array.shape}, Keystream {key_stream.shape}")
        # Basitleştirmek için, burada boyut eşleşmediğinde hatayı yükseltiyoruz
        raise ValueError("Resim ve Anahtar Akışı boyutları eşleşmiyor!")

    # XOR işlemi
    encrypted_array = np.bitwise_xor(img_array, key_stream)
    
    return encrypted_array

# --- LED TABELA EFECTİ FONKSİYONU ---

def draw_led_display(img: Image.Image, hidden_message: str) -> Image.Image:
    """
    Şifre çözülmüş görselin üzerine LED Tabela (Dot Matrix) efektiyle gizli mesajı ekler.
    """
    img_copy = img.copy().convert("RGBA") # Şeffaflık için RGBA kopyası al
    w, h = img_copy.size
    
    if not hidden_message.strip():
        return img 

    # --- 1. Tabela Alanını Belirleme ---
    panel_height = int(h * 0.3)
    panel_margin = 40
    panel_rect = [
        panel_margin,
        panel_margin,
        w - panel_margin,
        panel_height + panel_margin
    ]
    
    # Şeffaf koyu panel oluşturma
    panel = Image.new('RGBA', img_copy.size, (0, 0, 0, 0))
    panel_draw = ImageDraw.Draw(panel)
    # Koyu gri, yarı şeffaf arka plan
    panel_draw.rectangle(panel_rect, fill=(20, 20, 20, 200))
    
    # --- 2. Mesajı Pikselleştirme ve Çizme ---

    # Ayarlar
    text_to_display = hidden_message.upper() 
    led_color = (255, 69, 0, 255) # Parlak Turuncu/Kırmızı
    led_radius = 2 # Her bir "led" dairesinin yarıçapı
    dot_spacing = 8 # İki merkez nokta arasındaki mesafe
    
    # Font yükleme (basitleştirmek için varsayılan font)
    try:
        font_size = 40
        font = ImageFont.load_default().font_variant(size=font_size) 
    except IOError:
        font_size = 30
        font = ImageFont.load_default()
        
    # Metin boyutunu hesapla
    temp_draw = ImageDraw.Draw(Image.new('RGB', (1, 1)))
    try:
        # Yeni PIL sürümleri için textbbox kullanılır
        bbox = temp_draw.textbbox((0, 0), text_to_display, font=font)
        text_w = bbox[2] - bbox[0]
        text_h = bbox[3] - bbox[1]
    except AttributeError:
        # Eski PIL sürümleri için textlength/font_size kullanılır
        text_w = temp_draw.textlength(text_to_display, font=font)
        text_h = font_size
        
    # Mesajı ortalamak için başlangıç koordinatları
    start_x = panel_rect[0] + (panel_rect[2] - panel_rect[0] - text_w) // 2
    start_y = panel_rect[1] + (panel_height - text_h) // 2
    
    # Metni panele beyaz renkte yaz (Pikselleştirme için)
    panel_draw.text((start_x, start_y), text_to_display, font=font, fill=(255, 255, 255, 255))
    
    # --- 3. Pikselleştirme (LED Efekti) ---

    panel_pixels = panel.load()
    
    # Paneli tarayarak mesajın olduğu yerleri parlak LED'lere dönüştür
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
                # Mesaj olmayan yerleri kapalı LED renginde tut
                panel_draw.ellipse(
                    (x - led_radius, y - led_radius, x + led_radius, y + led_radius),
                    fill=(50, 50, 50, 50),
                    outline=None
                )
                
    # --- 4. Görüntüleri Birleştirme ---
    img_copy.paste(panel, (0, 0), panel)
    
    return img_copy.convert("RGB")

# --- KOD BİTİŞİ: YARDIMCI FONKSİYONLAR ---


# --- ANA UYGULAMA YAPISI ---

st.set_page_config(layout="wide", page_title="Zaman Kilitli Görsel Şifreleme")
initialize_session_state()

st.title("🔒 Zaman Kilitli Görsel Şifreleme & LED Mesaj Paneli")

# Sekmeleri tanımlama
tab_encrypt, tab_decrypt = st.tabs(["Şifreleme (Kilit Ekle)", "Şifre Çözme (Kilit Aç)"])


# --- ŞİFRELEME SEKME İÇERİĞİ ---
with tab_encrypt:
    st.header("Görseli Şifrele ve Kilit Zamanı Ayarla")
    
    uploaded_file = st.file_uploader("1. Şifrelenecek Görseli Yükle (.png, .jpg)", type=["png", "jpg", "jpeg"])

    if uploaded_file:
        try:
            original_img = Image.open(uploaded_file).convert("RGB")
            st.image(original_img, caption="Orijinal Görsel", width=300)
            
            # Formu başlatma
            with st.form("encryption_form"):
                
                # --- Gerekli Veri Girişleri ---
                col1, col2 = st.columns(2)
                
                with col1:
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
                    
                with col2:
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
                
                # --- Şifreleme Butonu ---
                encrypt_button = st.form_submit_button("Görseli Şifrele ve Dosyaları Oluştur")
            
            
            if encrypt_button:
                if not secret_key:
                    st.error("Lütfen bir Şifreleme Anahtarı girin.")
                elif not hidden_message:
                    st.error("Lütfen bir Gizli Mesaj girin.")
                else:
                    st.info("Şifreleme Başlatılıyor...")
                    
                    # 1. Görüntüyü bayt dizisine çevirme
                    img_array = np.array(original_img)
                    
                    # 2. Keystream (Anahtar Akışı) oluşturma
                    key_stream = generate_key_stream(img_array.shape, secret_key)
                    
                    # 3. XOR Şifreleme işlemi
                    encrypted_array = xor_image(img_array, key_stream)
                    
                    # 4. Şifreli resmi PIL Image nesnesine çevirme
                    encrypted_img = Image.fromarray(encrypted_array)
                    
                    # 5. PNG dosyasını bayt olarak kaydetme
                    png_bytes_io = io.BytesIO()
                    encrypted_img.save(png_bytes_io, format='PNG')
                    png_bytes = png_bytes_io.getvalue()
                    
                    # 6. Orijinal resmin hash'ini hesaplama (Bütünlük Kontrolü)
                    original_img_bytes = io.BytesIO()
                    original_img.save(original_img_bytes, format='PNG')
                    original_hash = hashlib.sha256(original_img_bytes.getvalue()).hexdigest()
                    
                    # 7. Meta dosyasını oluşturma
                    meta_data = {
                        "decryption_time": decryption_time.isoformat(),
                        "original_hash": original_hash,
                        "hidden_message": hidden_message,
                        "watermark_secret_hash": hashlib.sha256(watermark_secret.encode('utf-8')).hexdigest() if watermark_secret else None
                    }
                    meta_bytes = json.dumps(meta_data, indent=4).encode('utf-8')
                    
                    
                    st.success("Şifreleme Tamamlandı! Lütfen iki dosyayı da indirin.")
                    
                    st.markdown("### 📥 İndirilecek Dosyalar")
                    
                    col_dl1, col_dl2 = st.columns(2)
                    
                    with col_dl1:
                        st.download_button(
                            label="Şifreli Görsel İndir (.png)",
                            data=png_bytes,
                            file_name="encrypted_image.png",
                            mime="image/png"
                        )
                        st.image(encrypted_img, caption="Şifreli Görsel (Bozulmuş)", width=250)
                        
                    with col_dl2:
                        st.download_button(
                            label="Kilit Meta Dosyası İndir (.meta)",
                            data=meta_bytes,
                            file_name="encrypted_image.meta",
                            mime="application/json"
                        )
                        st.code(json.dumps(meta_data, indent=2), language='json')
                        
        except Exception as e:
            st.error(f"Bir hata oluştu: {e}")
            log(f"Şifreleme Hatası: {e}")


# --- ŞİFRE ÇÖZME SEKME İÇERİĞİ ---
with tab_decrypt:
    st.header("Görseli Çöz ve Gizli Mesajı Gör")
    
    col_up1, col_up2 = st.columns(2)
    
    with col_up1:
        uploaded_png = st.file_uploader("1. Şifreli .png Dosyasını Yükle", type=["png"], key="decrypt_png")
    
    with col_up2:
        uploaded_meta = st.file_uploader("2. .meta Dosyasını Yükle", type=["meta"], key="decrypt_meta")
        
    st.warning("Gizli mesajı görmek için **hem .png hem de .meta** dosyasını yüklemelisiniz.")

    # Oturum durumlarını sıfırla
    if 'decrypt_png' in st.session_state and st.session_state.decrypt_png is None:
        initialize_session_state()
    
    if uploaded_png and uploaded_meta:
        
        # --- Şifre Çözme Butonu ---
        decrypt_btn = st.button("Şifre Çözme İşlemini Başlat")
        
        if decrypt_btn or st.session_state.decrypted_image is not None:
            
            try:
                # 1. Meta veriyi oku
                meta_bytes = uploaded_meta.getvalue()
                meta_data = json.loads(meta_bytes.decode('utf-8'))
                
                decryption_time_str = meta_data.get("decryption_time")
                original_hash = meta_data.get("original_hash")
                hidden_message = meta_data.get("hidden_message", "")
                watermark_secret_hash = meta_data.get("watermark_secret_hash")
                
                st.session_state.hidden_message = hidden_message # Mesajı state'e kaydet
                
                # 2. Şifreli resmi oku ve bayt dizisine çevir
                png_bytes_io = io.BytesIO(uploaded_png.getvalue())
                encrypted_img = Image.open(png_bytes_io).convert("RGB")
                encrypted_array = np.array(encrypted_img)
                
                # --- Şifre Çözme Formu ---
                with st.form("decryption_key_form", clear_on_submit=False):
                    decrypt_secret_key = st.text_input(
                        "3. Şifreleme Anahtarı (Şifreleme Sekmesinde Kullanılan)",
                        value="my_secret_key",
                        key="decrypt_key_input"
                    )
                    submit_key = st.form_submit_button("Görseli Çöz")
                
                
                if submit_key or st.session_state.decrypted_image is not None:
                    
                    # 4. Keystream oluşturma
                    key_stream = generate_key_stream(encrypted_array.shape, decrypt_secret_key)
                    
                    # 5. XOR Şifre Çözme
                    decrypted_array = xor_image(encrypted_array, key_stream)
                    
                    # 6. Çözülmüş resmi PIL Image nesnesine çevirme
                    decrypted_img = Image.fromarray(decrypted_array)
                    
                    st.session_state.decrypted_image = decrypted_img
                    st.session_state.show_decryption_error = False
                    
                    
                    # --- Bütünlük Kontrolü (Opsiyonel) ---
                    # Çözülen resmin hash'ini al ve meta verideki hash ile karşılaştır
                    decrypted_img_bytes = io.BytesIO()
                    decrypted_img.save(decrypted_img_bytes, format='PNG')
                    current_hash = hashlib.sha256(decrypted_img_bytes.getvalue()).hexdigest()
                    
                    if current_hash != original_hash:
                        st.warning("Çözülen görselin bütünlüğü bozulmuş olabilir (Hash uyuşmuyor).")
                    else:
                        st.success("Görsel Başarıyla Çözüldü ve Bütünlüğü Doğrulandı.")
                        

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
                        st.session_state.decryption_time_ok = True # Zaman kısıtlaması yoksa hemen açılır
                        
                    
                    # --- Mesaj Gösterimi ---
                    
                    if st.session_state.decryption_time_ok:
                        
                        if watermark_secret_hash:
                            st.session_state.prompt_secret_key = True
                            
                            # Filigran Şifresi Kontrolü
                            with st.form("watermark_key_form"):
                                
                                # Eğer filigran daha önce görünür yapıldıysa, formu gösterme
                                if not st.session_state.is_message_visible:
                                    wm_key = st.text_input(
                                        "4. Gizli Mesaj Şifresi (Filigran Şifresi)",
                                        type="password",
                                        key="wm_key_input"
                                    )
                                    wm_submit = st.form_submit_button("Mesajı Göster")
                                else:
                                    wm_submit = False

                                
                                if wm_submit:
                                    wm_current_hash = hashlib.sha256(wm_key.encode('utf-8')).hexdigest()
                                    
                                    if wm_current_hash == watermark_secret_hash:
                                        log("Filigran şifresi doğru. Mesaj gösteriliyor.")
                                        
                                        # YENİ LED Tabela Efekti eklendi
                                        st.session_state.watermarked_image = draw_led_display(
                                            st.session_state.decrypted_image, 
                                            st.session_state.hidden_message
                                        )
                                        st.session_state.is_message_visible = True
                                        st.session_state.prompt_secret_key = False
                                        st.rerun()
                                    else:
                                        st.error("Filigran Şifresi Yanlış!")
                                        st.session_state.is_message_visible = False
                                        
                        else:
                            # Filigran şifresi yoksa mesajı hemen göster
                            if not st.session_state.is_message_visible:
                                # YENİ LED Tabela Efekti eklendi
                                st.session_state.watermarked_image = draw_led_display(
                                    st.session_state.decrypted_image, 
                                    st.session_state.hidden_message
                                )
                                st.session_state.is_message_visible = True
                                st.session_state.prompt_secret_key = False
                                st.rerun()
                                
                    else:
                        st.session_state.is_message_visible = False # Zaman dolmadıysa mesaj görünmez
                
                
                # --- Çözülen Görseli Gösterme ---
                
                # Eğer filigran gösterilmesi gerekiyorsa (zaman geçtiyse ve/veya şifre doğruysa), filigranlı görseli göster
                if st.session_state.is_message_visible and st.session_state.watermarked_image:
                    st.image(st.session_state.watermarked_image, caption="Çözülen Görsel (LED Mesaj Aktif)", use_column_width=True)
                # Aksi halde, sadece çözülmüş resmi göster
                elif st.session_state.decrypted_image:
                    st.image(st.session_state.decrypted_image, caption="Çözülen Görsel", use_column_width=True)
                    
            except json.JSONDecodeError:
                st.session_state.show_decryption_error = True
                st.error("Hata: Meta dosyası bozuk veya geçerli bir JSON formatında değil.")
            except ValueError as e:
                st.session_state.show_decryption_error = True
                st.error(f"Hata: Şifre Çözme Anahtarı geçersiz veya resim boyutu uyuşmuyor. ({e})")
            except Exception as e:
                st.session_state.show_decryption_error = True
                st.error(f"Beklenmeyen bir hata oluştu: {e}")

# --- KOD SONU ---
