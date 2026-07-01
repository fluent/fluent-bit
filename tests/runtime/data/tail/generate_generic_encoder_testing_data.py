# -*- coding: utf-8 -*-

import os

# This script generates a set of text files for testing various character encodings.
# Each file contains a curated list of common, neutral words appropriate for the
# target language and encoding.
#
# The word lists specifically exclude:
# - Religious terminology
# - Names of capital cities
#
# To use this script:
# 1. Save it as a Python file (e.g., `generate_files.py`).
# 2. Run it from your terminal: `python generate_files.py`
# 3. The script will create several .txt files in the same directory.

# Dictionary of encodings and their corresponding test data.
# The keys are the encoding names (and will be used in the filenames).
# The values are lists of strings to be written to the files.
ENCODING_DATA = {
    # --- East Asian Encodings ---
    "sjis": [
        "こんにちは",  # Hello
        "ありがとう",  # Thank you
        "さようなら",  # Goodbye
        "日本",        # Japan
        "猫",          # Cat
        "犬",          # Dog
        "食べる",      # To eat
        "飲む",        # To drink
        "空",          # Sky
        "海",         # Sea
        "月",          # Moon
        "花",          # Flower
    ],
    "big5": [
        "你好",        # Hello
        "謝謝",        # Thank you
        "再見",        # Goodbye
        "貓",          # Cat
        "狗",          # Dog
        "吃",          # To eat
        "喝",          # To drink
        "天",          # Sky
        "海",          # Sea
        "月亮",        # Moon
        "花卉",        # Flower
    ],
    "gbk": [
        "你好",        # Hello
        "谢谢",        # Thank you
        "再见",        # Goodbye
        "中国",        # China
        "猫",          # Cat
        "狗",          # Dog
        "吃",          # To eat
        "喝",          # To drink
        "天",          # Sky
        "海",          # Sea
        "月亮",        # Moon
        "花",          # Flower
    ],
    "gb18030": [ # Superset of GBK, can include the same + more
        "你好", "谢谢", "再见", "中国", "猫", "狗", "吃", "喝", "天", "海",
        "欧元符号€", # Euro symbol to test expanded range
        "龘", "龍", # Complex characters
    ],
    "euc-kr": [ # Often used for Korean, UHC is a Microsoft equivalent
        "안녕하세요",  # Hello
        "감사합니다",  # Thank you
        "안녕히 가세요",# Goodbye
        "한국",        # Korea
        "고양이",      # Cat
        "개",          # Dog
        "먹다",        # To eat
        "마시다",      # To drink
        "하늘",        # Sky
        "바다",        # Sea
        "달",          # Moon
        "꽃",          # Flower
    ],

    # --- Windows Codepage Encodings ---
    "cp866": [ # Cyrillic (DOS)
        "Привет",      # Hello
        "Спасибо",      # Thank you
        "До свидания", # Goodbye
        "Компьютер",   # Computer
        "Информация",  # Information
        "Программа",   # Program
        "Файл",        # File
    ],
    "cp874": [ # Thai
        "สวัสดี",     # Hello
        "ขอบคุณ",     # Thank you
        "ลาก่อน",     # Goodbye
        "ภาษาไทย",   # Thai language
        "แมว",         # Cat
        "สุนัข",       # Dog
        "กิน",         # Eat
        "ดื่ม",        # Drink
    ],
    "cp1250": [ # Central European (Polish, Czech, etc.)
        "Cześć", "Dziękuję", # Polish
        "Ahoj", "Děkuji",     # Czech
        "Žluťoučký kůň",      # Czech phrase with diacritics
        "Gęślą jaźń",         # Polish phrase with diacritics
        "Árvíztűrő tükörfúrógép", # Hungarian
    ],
    "cp1251": [ # Cyrillic (Windows)
        "Привет", "Спасибо", "До свидания",
        "Кошка", "Собака", "Небо", "Море",
        "Български език", # Bulgarian
        "Українська мова",# Ukrainian
        "Беларуская мова",# Belarusian
    ],
    "cp1252": [ # Western European
        "Hello", "Thank you", "Goodbye", # English
        "Bonjour", "Merci", "Au revoir", # French
        "Hallo", "Danke", "Auf Wiedersehen", # German
        "Hola", "Gracias", "Adiós", # Spanish
        "Crème brûlée", "Piñata", "Fjord",
    ],
    "cp1253": [ # Greek
        "Γειά σου",    # Hello
        "Ευχαριστώ",   # Thank you
        "Αντίο",       # Goodbye
        "Ελληνικά",    # Greek
        "Γάτα",        # Cat
        "Σκύλος",      # Dog
        "Ουρανός",     # Sky
        "Θάλασσα",     # Sea
    ],
    "cp1254": [ # Turkish
        "Merhaba", "Teşekkür ederim", "Hoşça kal",
        "Türkiye", "Kedi", "Köpek",
        "Yemek", "İçmek", "Gök", "Deniz",
        "Öğrenci", "Işık", "Ağaç", # Words with specific Turkish chars
    ],
    "cp1255": [ # Hebrew
        "שלום",        # Hello/Peace
        "תודה",        # Thank you
        "להתראות",     # Goodbye
        "עברית",       # Hebrew
        "חתול",        # Cat
        "כלב",         # Dog
        "שמיים",       # Sky
        "ים",          # Sea
    ],
    "cp1256": [ # Arabic
        "مرحبا",       # Hello
        "شكرا",        # Thank you
        "مع السلامة",  # Goodbye
        "العربية",     # Arabic
        "قط",          # Cat
        "كلب",         # Dog
        "سماء",        # Sky
        "بحر",         # Sea
    ],
}

def generate_files():
    """
    Iterates through the ENCODING_DATA dictionary and creates a file for each entry.
    """
    # Get the directory where the script is running to save files there.
    output_dir = os.path.dirname(os.path.abspath(__file__))
    print(f"Files will be generated in: {output_dir}\n")

    for encoding, content_list in ENCODING_DATA.items():
        # Sanitize encoding name for use in filename, replacing cp with win
        # for clarity as requested. UHC is an alias for euc-kr in this context.
        if encoding.startswith("cp"):
            filename_prefix = encoding.replace("cp", "win")
        elif encoding == "euc-kr":
            filename_prefix = "uhc"
        else:
            filename_prefix = encoding

        file_path = os.path.join(output_dir, "log", f"generic_enc_{filename_prefix}.log")

        try:
            # Open the file with the specified encoding
            with open(file_path, 'w', encoding=encoding) as f:
                # Join the list of words with newline characters
                f.write('\n'.join(content_list))
                f.write('\n')
            print(f"Successfully created: {os.path.basename(file_path)} (Encoding: {encoding})")

        except UnicodeEncodeError as e:
            print(f"Error: Could not encode content for '{encoding}'.")
            print(f"  - File not created: {os.path.basename(file_path)}")
            print(f"  - Details: {e}")
        except Exception as e:
            print(f"An unexpected error occurred for '{encoding}': {e}")

if __name__ == "__main__":
    generate_files()
