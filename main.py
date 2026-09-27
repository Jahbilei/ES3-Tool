import os
import re
import json
import zipfile
import shutil
import string
import hashlib
import itertools
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor

from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.gridlayout import GridLayout
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.textinput import TextInput
from kivy.uix.filechooser import FileChooserListView
from kivy.uix.popup import Popup
from kivy.uix.progressbar import ProgressBar
from kivy.uix.slider import Slider
from kivy.uix.tabbedpanel import TabbedPanel, TabbedPanelItem
from kivy.clock import Clock
from kivy.core.window import Window
from kivy.utils import platform

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad

Window.softinput_mode = "below_target"

# ==========================================
# Core Cryptography & Worker Logic
# ==========================================
SALT = b"EasySave3Salt"
CHARSET = string.ascii_letters + string.digits

def derive_key(password: str) -> bytes:
    """Derives a 16-byte key using PBKDF2 HMAC SHA-1."""
    return hashlib.pbkdf2_hmac('sha1', password.encode('utf-8'), SALT, 1000, 16)

def check_password_worker(args):
    """Global worker function for ProcessPoolExecutor."""
    encrypted_data, prefix, suffix_tuple = args
    pwd = prefix + "".join(suffix_tuple)
    try:
        key = derive_key(pwd)
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
        res = json.loads(decrypted.decode('utf-8'))
        return pwd, res
    except Exception:
        return None

def encrypt_data(json_data: dict, password: str) -> bytes:
    """Encrypts a Python dictionary/JSON payload into ES3 byte format."""
    key = derive_key(password)
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    raw_str = json.dumps(json_data).encode('utf-8')
    ciphertext = cipher.encrypt(pad(raw_str, AES.block_size))
    return iv + ciphertext

# ==========================================
# Key & Settings Persistence Manager
# ==========================================
class ConfigManager:
    def __init__(self, base_dir="."):
        self.keys_file = Path(base_dir) / "saved_keys.json"
        self.settings_file = Path(base_dir) / "settings.json"
        self.keys = self.load_json(self.keys_file, {"LtR": "LtR49f"})
        self.settings = self.load_json(self.settings_file, {"workers": 4, "theme": "Dark"})

    def load_json(self, path, default):
        if path.exists():
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return default

    def save_keys(self):
        with open(self.keys_file, "w", encoding="utf-8") as f:
            json.dump(self.keys, f, indent=2)

    def save_settings(self):
        with open(self.settings_file, "w", encoding="utf-8") as f:
            json.dump(self.settings, f, indent=2)

# ==========================================
# UI Main Application Layout
# ==========================================
class CPMUtilityHub(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.orientation = 'vertical'
        self.padding = 8
        self.spacing = 8
        
        self.config = ConfigManager()
        self.target_file_b = None
        self.session_key_cache = None

        # Build Main Tabs
        self.tabs = TabbedPanel(do_default_tab=False)
        
        self.tab_decrypt = TabbedPanelItem(text='Decrypt')
        self.tab_encrypt = TabbedPanelItem(text='Encrypt')
        self.tab_keys = TabbedPanelItem(text='Key Library')
        self.tab_settings = TabbedPanelItem(text='Settings')

        self.setup_decrypt_tab()
        self.setup_encrypt_tab()
        self.setup_keys_tab()
        self.setup_settings_tab()

        self.tabs.add_widget(self.tab_decrypt)
        self.tabs.add_widget(self.tab_encrypt)
        self.tabs.add_widget(self.tab_keys)
        self.tabs.add_widget(self.tab_settings)

        self.add_widget(self.tabs)
        self.request_android_permissions()

    def request_android_permissions(self):
        if platform == "android":
            from android.permissions import request_permissions, Permission
            request_permissions([
                Permission.READ_EXTERNAL_STORAGE,
                Permission.WRITE_EXTERNAL_STORAGE
            ])

    # --------------------------------------
    # Decrypt Tab Setup & Logic
    # --------------------------------------
    def setup_decrypt_tab(self):
        layout = BoxLayout(orientation='vertical', spacing=8, padding=8)
        self.dec_status = Label(text="Select file, folder, or ZIP", size_hint_y=0.08)
        
        initial_path = "/sdcard/Download" if os.path.exists("/sdcard/Download") else os.path.expanduser("~")
        self.dec_chooser = FileChooserListView(path=initial_path, size_hint_y=0.75, dirselect=True)
        self.dec_chooser.bind(on_selection=self.on_dec_selected)

        btn = Button(text="Execute Decryption", size_hint_y=0.15, background_color=(0.2, 0.6, 1, 1))
        btn.bind(on_press=self.process_decryption)

        layout.add_widget(self.dec_status)
        layout.add_widget(self.dec_chooser)
        layout.add_widget(btn)
        self.tab_decrypt.add_widget(layout)

    def on_dec_selected(self, chooser, selection):
        if selection:
            self.dec_status.text = f"Selected: {Path(selection[0]).name}"

    def extract_prefix(self, file_path):
        """Extracts 3-char device prefix from binary signature or filename."""
        try:
            with open(file_path, "rb") as f:
                raw_bytes = f.read(128)
            matches = re.findall(rb"49f[A-Za-z0-9+/=]+", raw_bytes)
            if matches:
                import base64
                decoded = base64.b64decode(matches[0]).decode("utf-8", errors="ignore")
                if len(decoded) >= 3:
                    return decoded[:3]
        except Exception:
            pass

        try:
            filename = Path(file_path).stem
            filename = re.sub(r"\(.*?\)", "", filename)
            filename = re.sub(r"_[A-Za-z0-9]{6}\b", "", filename).strip()
            import base64
            clean_b64 = max(re.findall(r"[A-Za-z0-9+/=]+", filename), key=len)
            pad_len = 4 - (len(clean_b64) % 4)
            if pad_len != 4:
                clean_b64 += "=" * pad_len
            decoded = base64.b64decode(clean_b64).decode("utf-8")
            return decoded[:3]
        except Exception:
            return None

    def process_decryption(self, instance):
        selection = self.dec_chooser.selection
        if not selection:
            self.show_popup("Error", "No file or directory selected.")
            return

        target_path = Path(selection[0])

        # Smart Validation: Pre-check if text/JSON
        if target_path.is_file() and target_path.suffix.lower() in [".txt", ".json"]:
            try:
                with open(target_path, "r", encoding="utf-8") as f:
                    json.load(f)
                self.show_switch_prompt(target_path)
                return
            except Exception:
                pass

        if target_path.is_file() and target_path.suffix.lower() in [".zip"]:
            self.process_zip(target_path)
        elif target_path.is_dir():
            self.process_folder(target_path)
        else:
            self.process_single_file(target_path)

    def show_switch_prompt(self, target_path):
        layout = BoxLayout(orientation='vertical', padding=10, spacing=10)
        lbl = Label(text="This file is unencrypted text/JSON.\nSwitch to Encryption mode?", halign='center')
        
        btn_box = BoxLayout(spacing=10, size_hint_y=0.4)
        btn_yes = Button(text="Yes")
        btn_no = Button(text="Cancel")
        
        btn_box.add_widget(btn_yes)
        btn_box.add_widget(btn_no)
        layout.add_widget(lbl)
        layout.add_widget(btn_box)

        popup = Popup(title="Smart Intent Detection", content=layout, size_hint=(0.85, 0.35))

        def on_yes(inst):
            popup.dismiss()
            self.tabs.switch_to(self.tab_encrypt)
            self.enc_chooser.path = str(target_path.parent)
            self.enc_chooser.selection = [str(target_path)]
            self.enc_status.text = f"Selected File A: {target_path.name}"

        btn_yes.bind(on_press=on_yes)
        btn_no.bind(on_press=popup.dismiss)
        popup.open()

    def run_crack_engine(self, encrypted_bytes, prefix):
        # 1. Session Key Inheritance Check
        if self.session_key_cache and self.session_key_cache.startswith(prefix):
            try:
                key = derive_key(self.session_key_cache)
                cipher = AES.new(key, AES.MODE_CBC, encrypted_bytes[:16])
                dec = unpad(cipher.decrypt(encrypted_bytes[16:]), AES.block_size)
                return self.session_key_cache, json.loads(dec.decode('utf-8'))
            except Exception:
                pass

        # 2. Key Library Check
        if prefix in self.config.keys:
            known_pw = self.config.keys[prefix]
            try:
                key = derive_key(known_pw)
                cipher = AES.new(key, AES.MODE_CBC, encrypted_bytes[:16])
                dec = unpad(cipher.decrypt(encrypted_bytes[16:]), AES.block_size)
                return known_pw, json.loads(dec.decode('utf-8'))
            except Exception:
                pass

        # 3. Multiprocessing Brute-Force Fallback
        workers = int(self.config.settings.get("workers", 4))
        combos = list(itertools.product(CHARSET, repeat=3))
        args_generator = ((encrypted_bytes, prefix, c) for c in combos)

        with ProcessPoolExecutor(max_workers=workers) as executor:
            for result in executor.map(check_password_worker, args_generator, chunksize=1000):
                if result:
                    found_pw, dec_json = result
                    self.session_key_cache = found_pw
                    self.config.keys[prefix] = found_pw
                    self.config.save_keys()
                    return found_pw, dec_json

        return None, None

    def process_single_file(self, file_path):
        prefix = self.extract_prefix(file_path)
        if not prefix:
            self.show_popup("Error", "Could not resolve device prefix signature.")
            return

        with open(file_path, "rb") as f:
            data = f.read()

        pw, dec_json = self.run_crack_engine(data, prefix)
        if pw:
            out_name = f"{file_path.stem}_{pw}.txt"
            out_path = file_path.parent / out_name
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(dec_json, f, indent=2)
            self.show_popup("Success", f"Key Found: {pw}\nSaved to: {out_name}")
            self.refresh_keys_ui()
        else:
            self.show_popup("Failed", "Password not found.")

    def process_folder(self, folder_path):
        es3_files = list(folder_path.rglob("*.es3"))
        if not es3_files:
            self.show_popup("Notice", "No .es3 files found in folder.")
            return

        cracked_count = 0
        for f in es3_files:
            prefix = self.extract_prefix(f)
            if not prefix:
                continue
            with open(f, "rb") as stream:
                data = stream.read()
            pw, dec_json = self.run_crack_engine(data, prefix)
            if pw:
                out_path = f.parent / f"{f.stem}_{pw}.txt"
                with open(out_path, "w", encoding="utf-8") as out:
                    json.dump(dec_json, out, indent=2)
                cracked_count += 1

        self.show_popup("Batch Complete", f"Decrypted {cracked_count} / {len(es3_files)} files.")
        self.refresh_keys_ui()

    def process_zip(self, zip_path):
        tmp_dir = zip_path.parent / "_tmp_unpack"
        if tmp_dir.exists():
            shutil.rmtree(tmp_dir)
        os.makedirs(tmp_dir, exist_ok=True)

        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(tmp_dir)

        es3_files = list(tmp_dir.rglob("*.es3"))
        cracked = 0
        for f in es3_files:
            prefix = self.extract_prefix(f)
            if not prefix:
                continue
            with open(f, "rb") as stream:
                data = stream.read()
            pw, dec_json = self.run_crack_engine(data, prefix)
            if pw:
                out_txt = f.parent / f"{f.stem}_{pw}.txt"
                with open(out_txt, "w", encoding="utf-8") as out:
                    json.dump(dec_json, out, indent=2)
                f.unlink()
                cracked += 1

        out_zip = zip_path.parent / f"{zip_path.stem}_decrypted.zip"
        shutil.make_archive(str(out_zip.with_suffix('')), 'zip', tmp_dir)
        shutil.rmtree(tmp_dir)
        self.show_popup("Archive Complete", f"Decrypted {cracked} files into:\n{out_zip.name}")
        self.refresh_keys_ui()

    # --------------------------------------
    # Encrypt Tab Setup & Logic
    # --------------------------------------
    def setup_encrypt_tab(self):
        layout = BoxLayout(orientation='vertical', spacing=8, padding=8)
        self.enc_status = Label(text="Select File A (Payload .txt or .json)", size_hint_y=0.08)
        
        initial_path = "/sdcard/Download" if os.path.exists("/sdcard/Download") else os.path.expanduser("~")
        self.enc_chooser = FileChooserListView(path=initial_path, size_hint_y=0.55)
        self.enc_chooser.bind(on_selection=self.on_enc_selected)

        # File B / Key Config Controls
        ctrl_grid = GridLayout(cols=2, size_hint_y=0.22, spacing=5)
        ctrl_grid.add_widget(Label(text="Key (6-chars):"))
        self.txt_key = TextInput(multiline=False, text="LtR49f")
        ctrl_grid.add_widget(self.txt_key)

        ctrl_grid.add_widget(Label(text="File B (Target Name):"))
        self.btn_file_b = Button(text="Select Target File B")
        self.btn_file_b.bind(on_press=self.select_file_b)
        ctrl_grid.add_widget(self.btn_file_b)

        btn_enc = Button(text="Execute Encryption", size_hint_y=0.15, background_color=(0.2, 0.8, 0.2, 1))
        btn_enc.bind(on_press=self.process_encryption)

        layout.add_widget(self.enc_status)
        layout.add_widget(self.enc_chooser)
        layout.add_widget(ctrl_grid)
        layout.add_widget(btn_enc)
        self.tab_encrypt.add_widget(layout)

    def on_enc_selected(self, chooser, selection):
        if selection:
            self.enc_status.text = f"Selected File A: {Path(selection[0]).name}"

    def select_file_b(self, instance):
        selection = self.enc_chooser.selection
        if selection:
            self.target_file_b = Path(selection[0])
            self.btn_file_b.text = f"Target: {self.target_file_b.name}"
            prefix = self.extract_prefix(self.target_file_b)
            if prefix and prefix in self.config.keys:
                self.txt_key.text = self.config.keys[prefix]

    def process_encryption(self, instance):
        selection = self.enc_chooser.selection
        if not selection:
            self.show_popup("Error", "Select File A (JSON/Text input).")
            return

        file_a = Path(selection[0])
        password = self.txt_key.text.strip()
        if len(password) != 6:
            self.show_popup("Error", "Password key must be exactly 6 characters.")
            return

        try:
            with open(file_a, "r", encoding="utf-8") as f:
                payload = json.load(f)
        except Exception as e:
            self.show_popup("Error", f"Failed to parse File A JSON: {str(e)}")
            return

        encrypted_bytes = encrypt_data(payload, password)

        # Output Naming Clean-up System
        if self.target_file_b:
            raw_name = self.target_file_b.name
            clean_name = re.sub(r"\(.*?\)", "", raw_name)
            clean_name = re.sub(r"_[A-Za-z0-9]{6}\b", "", clean_name)
            clean_name = re.sub(r"\.(txt|json|es3)$", "", clean_name, flags=re.IGNORECASE).strip()
            out_file = file_a.parent / clean_name
        else:
            out_file = file_a.parent / f"{file_a.stem}_encrypted"

        with open(out_file, "wb") as f:
            f.write(encrypted_bytes)

        self.show_popup("Encryption Complete", f"Encrypted payload saved to:\n{out_file.name}")

    # --------------------------------------
    # Key Library Tab Setup & Logic
    # --------------------------------------
    def setup_keys_tab(self):
        layout = BoxLayout(orientation='vertical', padding=8, spacing=8)
        self.key_list_label = Label(text="", size_hint_y=0.8, halign="left", valign="top")
        self.key_list_label.bind(size=self.key_list_label.setter('text_size'))

        btn_refresh = Button(text="Refresh Library", size_hint_y=0.2)
        btn_refresh.bind(on_press=lambda i: self.refresh_keys_ui())

        layout.add_widget(self.key_list_label)
        layout.add_widget(btn_refresh)
        self.tab_keys.add_widget(layout)
        self.refresh_keys_ui()

    def refresh_keys_ui(self):
        text_lines = ["Saved Device Prefix Mappings:", "-" * 35]
        for prefix, key in self.config.keys.items():
            text_lines.append(f"Prefix: {prefix}  -->  Key: {key}")
        self.key_list_label.text = "\n".join(text_lines)

    # --------------------------------------
    # Settings Tab Setup & Logic
    # --------------------------------------
    def setup_settings_tab(self):
        layout = BoxLayout(orientation='vertical', padding=10, spacing=10)
        
        self.lbl_workers = Label(text=f"Process Workers: {self.config.settings.get('workers', 4)}")
        slider = Slider(min=1, max=16, value=int(self.config.settings.get('workers', 4)), step=1)
        
        def on_slider(inst, val):
            self.lbl_workers.text = f"Process Workers: {int(val)}"
            self.config.settings["workers"] = int(val)
            self.config.save_settings()

        slider.bind(value=on_slider)

        layout.add_widget(self.lbl_workers)
        layout.add_widget(slider)
        layout.add_widget(Label(text="App Version: 1.0.0 Alpha"))
        self.tab_settings.add_widget(layout)

    def show_popup(self, title, message):
        layout = BoxLayout(orientation='vertical', padding=10, spacing=10)
        lbl = Label(text=message, halign='center')
        close_btn = Button(text="OK", size_hint_y=0.3)
        layout.add_widget(lbl)
        layout.add_widget(close_btn)
        popup = Popup(title=title, content=layout, size_hint=(0.85, 0.4))
        close_btn.bind(on_release=popup.dismiss)
        popup.open()


class CPMApp(App):
    def build(self):
        return CPMUtilityHub()


if __name__ == "__main__":
    CPMApp().run()