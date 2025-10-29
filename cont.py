import streamlit as st
from PIL import Image
import os
import time
from datetime import datetime
import io
# zoneinfo yerine, Python 3.8 ve altı sistemlerde uyumluluk için,
# time.mktime() ve datetime.fromtimestamp() gibi standart yöntemleri kullanacağız.

# --- Sayfa Yapılandırması ---
st.set_page_config(
    page_title="Zamanlı Görsel Şifreleme (🇹🇷)",
    page_icon="🖼️",
    layout="wide"
)

st.title("🖼️ Zamanlı Görsel Şifreleme Uygulaması")
st.markdown("---")

# --- Sabitler ---
# Şifreleme ve çözme için kullanılacak anahtar (Key)
SECRET_KEY = 123 
# (Bu sadece basit bir örnektir. Gerçek uygulamalarda çok daha karmaşık bir anahtar kullanılmalıdır.)

def apply_cipher(pixel_value, is_encrypt, offset_factor):
    """Piksel değerine şifreleme/çözme işlemini uygular."""
    
    # Şifreleme anahtarı, zaman ofseti ile birleştirilir.
    effective_key = SECRET_KEY + offset_factor
    
    if is_encrypt:
        # Şifreleme: Topla ve 256'ya göre mod al (0-255 aralığında tutmak için)
        return (pixel_value + effective_key) % 256
    else:
        # Çözme: Çıkar ve 256'ya göre mod al
        return (pixel_value - effective_key) % 256

def process_image(img, is_encrypt, timestamp_str):
    """Görüntüyü şifreler veya çözer ve sonucu döndürür."""
    try:
        # Zaman damgasını saniyeye çevir
        dt_object = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
        timestamp_seconds = time.mktime(dt_object.timetuple())
        
        # Zamanın saniyelik değerini şifreleme/çözme ofseti olarak kullan
        # Bu, şifreleme/çözme işleminin zamana bağlı olmasını sağlar
        offset_factor = int(timestamp_seconds) % 256
        
        img = img.convert("RGB")
        width, height = img.size
        
        new_img = Image.new("RGB", (width, height))
        
        # Görüntü üzerindeki her pikseli gez
        for y in range(height):
            for x in range(width):
                r, g, b = img.getpixel((x, y))
                
                # Her RGB bileşenine şifreleme/çözme işlemini uygula
                new_r = apply_cipher(r, is_encrypt, offset_factor)
                new_g = apply_cipher(g, is_encrypt, offset_factor)
                new_b = apply_cipher(b, is_encrypt, offset_factor)
                
                new_img.putpixel((x, y), (new_r, new_g, new_b))
                
        return new_img
        
    except ValueError:
        st.error("Hatalı zaman formatı! Lütfen 'YYYY-MM-DD HH:MM:SS' formatını kullanın.")
        return None
    except Exception as e:
        st.error(f"İşlem sırasında bir hata oluştu: {e}")
        return None

# --- Streamlit Arayüzü ---

# Sol sütun: Girişler
col1, col2 = st.columns([1, 1])

with col1:
    st.header("1. Girişler")
    
    operation = st.radio(
        "Yapılacak İşlemi Seçin:",
        ("Şifrele", "Çöz"),
        horizontal=True
    )

    uploaded_file = st.file_uploader(
        "Görüntü Dosyasını Yükleyin",
        type=['png', 'jpg', 'jpeg']
    )

    default_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    timestamp_input = st.text_input(
        f"Zaman Damgası (YYYY-MM-DD HH:MM:SS)",
        value=default_timestamp,
        help="Şifreleme/Çözme işleminin anahtarını oluşturmak için kullanılan tarih ve saat. Şifreyi çözmek için bu tarih/saatin tam olarak aynı olması gerekir."
    )

    if uploaded_file is not None:
        try:
            input_img = Image.open(uploaded_file)
            st.image(input_img, caption="Yüklenen Görüntü", use_column_width=True)
            
            # İşlem düğmesi
            if st.button(f"{operation} ve Görüntüle", type="primary"):
                is_encrypt = (operation == "Şifrele")
                processed_img = process_image(input_img, is_encrypt, timestamp_input)
                
                if processed_img:
                    st.session_state['processed_img'] = processed_img
                    st.session_state['operation'] = operation
                    st.session_state['processed'] = True
                    st.rerun() # Sağ sütunu güncellemek için yeniden çalıştır

        except Exception as e:
            st.error(f"Görüntü yüklenirken hata oluştu: {e}")

# Sağ sütun: Sonuçlar
with col2:
    st.header("2. Sonuç")
    
    if st.session_state.get('processed', False):
        processed_img = st.session_state['processed_img']
        operation = st.session_state['operation']
        
        if operation == "Şifrele":
            st.success("✅ Görüntü başarıyla şifrelendi!")
            output_caption = "Şifrelenmiş Görüntü"
        else:
            st.success("✅ Görüntü başarıyla çözüldü!")
            output_caption = "Çözülmüş Görüntü"
            
        st.image(processed_img, caption=output_caption, use_column_width=True)

        # İndirme düğmesi için görüntü bellekte tutulur
        buf = io.BytesIO()
        processed_img.save(buf, format="PNG")
        byte_im = buf.getvalue()

        st.download_button(
            label=f"{output_caption} İndir (PNG)",
            data=byte_im,
            file_name=f"{operation.lower()}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png",
            mime="image/png"
        )
    else:
        st.info("Lütfen sol panelde bir görüntü yükleyin ve işlemi başlatın.")

st.markdown("---")
st.caption("Geliştiren: Gemini")

