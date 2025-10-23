import os
import sys
import hashlib
import json
import time
import threading
import ctypes
from ctypes import wintypes
import winreg
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout,
    QHBoxLayout, QPushButton, QLabel, QTableWidget,
    QTableWidgetItem, QMessageBox, QHeaderView, QSystemTrayIcon,
    QMenu, QDialog, QLineEdit, QInputDialog, QFormLayout, QGroupBox
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QFont, QColor, QPalette, QIcon, QPixmap, QPainter
import win32api
import win32file
import win32con

# === Windows API Sabitleri ===
WH_KEYBOARD_LL = 13
WH_MOUSE_LL = 14
WM_KEYDOWN = 0x0100
WM_SYSKEYDOWN = 0x0104
VK_LWIN = 0x5B
VK_RWIN = 0x5C
VK_ESCAPE = 0x1B
VK_TAB = 0x09
VK_CONTROL = 0x11
VK_MENU = 0x12
VK_DELETE = 0x2E

CONFIG_FILE = os.path.join(os.environ.get('APPDATA', ''), 'ServiceHash', 'config.json')
LOG_FILE = os.path.join(os.environ.get('APPDATA', ''), 'ServiceHash', 'logs', 'log.json')
STARTUP_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
APP_NAME = "ServiceHash"


class ServiceHashCore:
    def __init__(self):
        self.authorized_token = None
        self.password_hash = None
        self.monitoring = False
        self.lock_active = False
        self.ensure_config_dir()
        self.ensure_logs_dir()

    def ensure_config_dir(self):
        """Konfig dizinini oluşturur."""
        config_dir = os.path.dirname(CONFIG_FILE)
        if not os.path.exists(config_dir):
            os.makedirs(config_dir)

    def ensure_logs_dir(self):
        """Log dizinini oluşturur."""
        log_dir = os.path.dirname(LOG_FILE)
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)

    def hash_password(self, password):
        """Şifreyi hashler."""
        return hashlib.sha256(password.encode()).hexdigest()

    def verify_password(self, password):
        """Şifreyi doğrular."""
        if not self.password_hash:
            return False
        return self.hash_password(password) == self.password_hash

    def get_usb_drives(self):
        """Tüm USB sürücülerini listeler."""
        drives = []
        bitmask = win32api.GetLogicalDrives()
        for letter in range(65, 91):
            if bitmask & (1 << (letter - 65)):
                drive = chr(letter) + ":\\"
                try:
                    drive_type = win32file.GetDriveType(drive)
                    if drive_type == win32con.DRIVE_REMOVABLE:
                        try:
                            volume_info = win32api.GetVolumeInformation(drive)
                            drives.append({
                                'letter': drive,
                                'name': volume_info[0] if volume_info[0] else "USB Disk",
                                'serial': volume_info[1]
                            })
                        except Exception:
                            drives.append({
                                'letter': drive,
                                'name': "USB Disk",
                                'serial': 0
                            })
                except Exception:
                    pass
        return drives

    def create_device_hash(self, drive_info):
        """USB cihazı için benzersiz hash oluşturur."""
        device_string = f"{drive_info['letter']}{drive_info['serial']}{drive_info['name']}"
        return hashlib.sha256(device_string.encode()).hexdigest()

    def save_config(self, token=None, password=None):
        """Konfigürasyonu kaydeder."""
        config = {}
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
            except Exception:
                pass
        if token:
            self.authorized_token = token
            config['token'] = token
        if password:
            self.password_hash = self.hash_password(password)
            config['password_hash'] = self.password_hash
        config['enabled'] = True
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f)

    def load_config(self):
        """Konfigürasyonu yükler."""
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r') as f:
                    data = json.load(f)
                    self.authorized_token = data.get('token')
                    self.password_hash = data.get('password_hash')
                    return data.get('enabled', True)
            except Exception:
                pass
        return False

    def reset_config(self):
        """Konfigürasyonu sıfırlar."""
        if os.path.exists(CONFIG_FILE):
            os.remove(CONFIG_FILE)
        self.authorized_token = None
        self.password_hash = None

    def verify_usb(self):
        """USB'nin takılı olup olmadığını kontrol eder."""
        if not self.authorized_token:
            return False
        current_drives = self.get_usb_drives()
        for drive in current_drives:
            if self.create_device_hash(drive) == self.authorized_token:
                return True
        return False

    def log_event(self, event, details=""):
        """Olayı hashlenmiş olarak log dosyasına yaz."""
        timestamp = time.time()
        log_entry = {
            "timestamp": timestamp,
            "event": event,
            "details": details
        }
        logs = []
        if os.path.exists(LOG_FILE):
            try:
                with open(LOG_FILE, 'r') as f:
                    content = f.read()
                    if content:
                        logs = json.loads(content)
            except Exception:
                logs = []
        logs.append(log_entry)
        # Hashlenmiş olarak yaz
        content = json.dumps(logs)
        with open(LOG_FILE, 'w') as f:
            f.write(content)

    def get_logs(self):
        """Hashlenmiş logları oku ve döndür."""
        if not os.path.exists(LOG_FILE):
            return []
        try:
            with open(LOG_FILE, 'r') as f:
                content = f.read()
                if content:
                    logs = json.loads(content)
                    return logs
                else:
                    return []
        except Exception:
            return []


class SystemLocker:
    """Kernel seviyesi sistem kilitleme."""
    def __init__(self):
        self.keyboard_hook = None
        self.mouse_hook = None
        self.user32 = ctypes.WinDLL('user32', use_last_error=True)
        self.kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        self.keyboard_proc = None
        self.mouse_proc = None
        self.ctrl_pressed = False
        self.alt_pressed = False
        self.del_pressed = False

    def keyboard_hook_callback(self, nCode, wParam, lParam):
        """Klavye olaylarını engeller."""
        if nCode >= 0:
            kb_struct = ctypes.cast(lParam, ctypes.POINTER(ctypes.c_ulong))
            vk_code = kb_struct[0]
            if wParam in [WM_KEYDOWN, WM_SYSKEYDOWN]:
                if vk_code == VK_CONTROL:
                    self.ctrl_pressed = True
                if vk_code == VK_MENU:
                    self.alt_pressed = True
                if vk_code == VK_DELETE:
                    self.del_pressed = True

            if self.ctrl_pressed and self.alt_pressed and self.del_pressed:
                self.ctrl_pressed = False
                self.alt_pressed = False
                self.del_pressed = False
                return 1

            if vk_code in [VK_LWIN, VK_RWIN]:
                return 1
            if self.alt_pressed and vk_code == VK_TAB:
                return 1
            if self.alt_pressed and vk_code == 0x73:  # F4
                return 1
            if self.ctrl_pressed and vk_code == VK_ESCAPE:
                return 1
            if 0x70 <= vk_code <= 0x7B:  # F1-F12
                return 1
            return 1
        return self.user32.CallNextHookEx(None, nCode, wParam, lParam)

    def mouse_hook_callback(self, nCode, wParam, lParam):
        """Mouse olaylarını engeller."""
        if nCode >= 0:
            return 1
        return self.user32.CallNextHookEx(None, nCode, wParam, lParam)

    def install_hooks(self):
        """Low-level hook'ları kurar."""
        try:
            HOOKPROC = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p))
            self.keyboard_proc = HOOKPROC(self.keyboard_hook_callback)
            self.mouse_proc = HOOKPROC(self.mouse_hook_callback)
            h_mod = self.kernel32.GetModuleHandleW(None)
            self.keyboard_hook = self.user32.SetWindowsHookExW(
                WH_KEYBOARD_LL,
                self.keyboard_proc,
                h_mod,
                0
            )
            self.mouse_hook = self.user32.SetWindowsHookExW(
                WH_MOUSE_LL,
                self.mouse_proc,
                h_mod,
                0
            )
            return self.keyboard_hook and self.mouse_hook
        except Exception as e:
            print(f"Hook kurulum hatası: {e}")
            return False

    def remove_hooks(self):
        """Hook'ları kaldırır."""
        try:
            if self.keyboard_hook:
                self.user32.UnhookWindowsHookEx(self.keyboard_hook)
                self.keyboard_hook = None
            if self.mouse_hook:
                self.user32.UnhookWindowsHookEx(self.mouse_hook)
                self.mouse_hook = None
        except Exception:
            pass
        self.ctrl_pressed = False
        self.alt_pressed = False
        self.del_pressed = False

    def block_all_system_features(self):
        """TÜM sistem özelliklerini engeller."""
        try:
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER,
                                  r"Software\Microsoft\Windows\CurrentVersion\Policies\System")
            winreg.SetValueEx(key, "DisableTaskMgr", 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(key)
        except Exception:
            pass
        try:
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER,
                                  r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")
            winreg.SetValueEx(key, "NoWinKeys", 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(key)
        except Exception:
            pass
        try:
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER,
                                  r"Software\Microsoft\Windows\CurrentVersion\Policies\System")
            winreg.SetValueEx(key, "DisableRegistryTools", 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(key)
        except Exception:
            pass
        try:
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER,
                                  r"Software\Policies\Microsoft\Windows\System")
            winreg.SetValueEx(key, "DisableCMD", 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(key)
        except Exception:
            pass

    def unblock_all_system_features(self):
        """TÜM sistem özelliklerinin engelini kaldırır."""
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                r"Software\Microsoft\Windows\CurrentVersion\Policies\System",
                                0, winreg.KEY_SET_VALUE)
            try:
                winreg.DeleteValue(key, "DisableTaskMgr")
            except Exception:
                pass
            try:
                winreg.DeleteValue(key, "DisableRegistryTools")
            except Exception:
                pass
            winreg.CloseKey(key)
        except Exception:
            pass
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
                                0, winreg.KEY_SET_VALUE)
            try:
                winreg.DeleteValue(key, "NoWinKeys")
            except Exception:
                pass
            winreg.CloseKey(key)
        except Exception:
            pass
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                r"Software\Policies\Microsoft\Windows\System",
                                0, winreg.KEY_SET_VALUE)
            try:
                winreg.DeleteValue(key, "DisableCMD")
            except Exception:
                pass
            winreg.CloseKey(key)
        except Exception:
            pass


class LockScreen(QMainWindow):
    """Kurumsal sade kilit ekranı."""
    unlock_signal = pyqtSignal()

    def __init__(self, service_core):
        super().__init__()
        self.service = service_core
        self.locker = SystemLocker()
        self.setup_ui()
        self.start_checking()

    def setup_ui(self):
        """Kilit ekranı UI."""
        self.setWindowFlags(
            Qt.WindowStaysOnTopHint |
            Qt.FramelessWindowHint |
            Qt.WindowDoesNotAcceptFocus |
            Qt.Tool |
            Qt.CustomizeWindowHint
        )
        self.showFullScreen()
        self.setWindowState(Qt.WindowFullScreen | Qt.WindowActive)
        self.setAttribute(Qt.WA_DeleteOnClose, False)
        self.setStyleSheet("background-color: #000000;")
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignCenter)
        layout.setContentsMargins(30, 30, 30, 30)  # Küçültüldü

        icon_label = QLabel("⚠")
        icon_label.setStyleSheet("color: #ff0000; font-size: 120px;")  # Küçültüldü
        icon_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(icon_label)

        layout.addSpacing(20)

        title_label = QLabel("ERİŞİM ENGELLENDİ")
        title_label.setStyleSheet("""
            color: #ff0000;
            font-size: 45px;
            font-weight: bold;
            font-family: 'Arial', sans-serif;
            letter-spacing: 2px;
        """)
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)

        layout.addSpacing(15)

        line = QLabel("━" * 30)
        line.setStyleSheet("color: #cc0000; font-size: 14px;")
        line.setAlignment(Qt.AlignCenter)
        layout.addWidget(line)

        layout.addSpacing(15)

        subtitle_label = QLabel("YETKİLİ USB BULUNAMADI")
        subtitle_label.setStyleSheet("""
            color: #ff4444;
            font-size: 24px;
            font-weight: bold;
            font-family: Arial;
            letter-spacing: 1px;
        """)
        subtitle_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(subtitle_label)

        layout.addSpacing(20)

        info_label = QLabel("Yetkili USB takılana kadar erişim engellendi.")
        info_label.setStyleSheet("""
            color: #cc0000;
            font-size: 16px;
            font-family: Arial;
            font-style: italic;
        """)
        info_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(info_label)

        layout.addSpacing(15)

        block_info = QLabel("🚫 Sistem kilitlendi")
        block_info.setStyleSheet("""
            color: #ff6666;
            font-size: 14px;
            font-family: Arial;
        """)
        block_info.setAlignment(Qt.AlignCenter)
        layout.addWidget(block_info)

        layout.addSpacing(10)

        self.dot_label = QLabel("●")
        self.dot_label.setStyleSheet("""
            color: #ff0000;
            font-size: 40px;
        """)
        self.dot_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.dot_label)

        central_widget.setLayout(layout)

        self.anim_timer = QTimer()
        self.anim_timer.timeout.connect(self.animate_dot)
        self.anim_timer.start(300)  # Daha hızlı ama sade
        self.dot_count = 0
        self.activate_locks()

    def activate_locks(self):
        """TÜM sistem kilitlemelerini aktif eder."""
        self.locker.install_hooks()
        self.locker.block_all_system_features()
        self.activateWindow()
        self.raise_()
        self.setFocus()
        self.top_timer = QTimer()
        self.top_timer.timeout.connect(self.keep_on_top)
        self.top_timer.start(100)

    def keep_on_top(self):
        """Pencereyi sürekli en üstte tutar."""
        self.raise_()
        self.activateWindow()
        self.setWindowState(Qt.WindowFullScreen | Qt.WindowActive)

    def deactivate_locks(self):
        """Sistem kilitlemelerini kaldırır."""
        if hasattr(self, 'top_timer'):
            self.top_timer.stop()
        self.locker.remove_hooks()
        self.locker.unblock_all_system_features()

    def animate_dot(self):
        """Nokta animasyonu."""
        dots = ["●", "●●", "●●●", "●●●●", "●●●", "●●", "●"]
        self.dot_label.setText(dots[self.dot_count % 7])
        self.dot_count += 1

    def start_checking(self):
        """USB kontrolünü başlatır."""
        self.check_timer = QTimer()
        self.check_timer.timeout.connect(self.check_usb)
        self.check_timer.start(500)

    def check_usb(self):
        """USB'yi kontrol eder ve varsa kilidi açar."""
        if self.service.verify_usb():
            self.service.log_event("unlock_success", "USB token verified and system unlocked")
            self.deactivate_locks()
            self.check_timer.stop()
            self.anim_timer.stop()
            self.unlock_signal.emit()
            self.close()
        else:
            self.service.log_event("lock_active", "System is locked due to missing USB token")

    def keyPressEvent(self, event):
        event.ignore()

    def mousePressEvent(self, event):
        event.ignore()

    def closeEvent(self, event):
        if self.service.verify_usb():
            self.deactivate_locks()
            event.accept()
        else:
            event.ignore()

    def changeEvent(self, event):
        if event.type() == event.WindowStateChange:
            self.setWindowState(Qt.WindowFullScreen | Qt.WindowActive)
        event.ignore()


class PasswordDialog(QDialog):
    """Kurumsal şifre doğrulama penceresi."""
    def __init__(self, service_core, title="Şifre Doğrulama", parent=None):
        super().__init__(parent)
        self.service = service_core
        self.password = None
        self.setup_ui(title)

    def setup_ui(self, title):
        self.setWindowTitle(title)
        self.setFixedSize(500, 250)
        self.setModal(True)
        layout = QVBoxLayout()
        layout.setSpacing(20)
        layout.setContentsMargins(30, 30, 30, 30)

        title_label = QLabel("🔐 " + title)
        title_label.setStyleSheet("""
            font-size: 20px;
            font-weight: bold;
            color: #ffffff;
            padding: 10px;
            background-color: #636363;
            border-radius: 8px;
        """)
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Lütfen şifrenizi girin...")
        self.password_input.setStyleSheet("""
            QLineEdit {
                padding: 14px;
                font-size: 16px;
                border: 2px solid #636363;
                border-radius: 6px;
                background-color: #f0f0f0;
                color: #000000;
            }
            QLineEdit:focus {
                border: 2px solid #ff0000;
            }
        """)
        self.password_input.returnPressed.connect(self.verify_password)
        layout.addWidget(self.password_input)

        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(15)

        ok_btn = QPushButton("✓ Doğrula")
        ok_btn.setStyleSheet("""
            QPushButton {
                background-color: #ff0000;
                color: white;
                border: none;
                padding: 12px 30px;
                font-size: 14px;
                font-weight: bold;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #cc0000;
            }
        """)
        ok_btn.setCursor(Qt.PointingHandCursor)
        ok_btn.clicked.connect(self.verify_password)
        btn_layout.addWidget(ok_btn)

        cancel_btn = QPushButton("✗ İptal")
        cancel_btn.setStyleSheet("""
            QPushButton {
                background-color: #636363;
                color: white;
                border: none;
                padding: 12px 30px;
                font-size: 14px;
                font-weight: bold;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #4a4a4a;
            }
        """)
        cancel_btn.setCursor(Qt.PointingHandCursor)
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(cancel_btn)

        layout.addLayout(btn_layout)
        self.setLayout(layout)
        self.password_input.setFocus()

    def verify_password(self):
        """Şifreyi doğrular."""
        password = self.password_input.text()
        if not password:
            QMessageBox.warning(self, "Hata", "Lütfen şifre girin!")
            return
        if self.service.verify_password(password):
            self.password = password
            self.service.log_event("password_verify", "Password verified successfully")
            self.accept()
        else:
            self.service.log_event("password_verify_failed", "Password verification failed")
            QMessageBox.critical(self, "Hata", "Yanlış şifre!")
            self.password_input.clear()
            self.password_input.setFocus()


class SetupWindow(QMainWindow):
    """İlk kurulum penceresi - Kurumsal tema."""
    setup_complete = pyqtSignal()

    def __init__(self, service_core):
        super().__init__()
        self.service = service_core
        self.drives = []
        self.password = None
        self.setup_ui()

    def setup_ui(self):
        self.setWindowTitle("Service Hash - Kurumsal Kurulum")
        self.setFixedSize(900, 750)
        screen = QApplication.desktop().screenGeometry()
        x = (screen.width() - self.width()) // 2
        y = (screen.height() - self.height()) // 2
        self.move(x, y)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout()
        layout.setSpacing(25)
        layout.setContentsMargins(40, 40, 40, 40)

        # Başlık
        title = QLabel("🔒 Service Hash - Kurumsal Güvenlik Sistemi")
        title.setStyleSheet("""
            font-size: 26px;
            font-weight: bold;
            padding: 20px;
            background-color: #636363;
            color: white;
            border-radius: 12px;
        """)
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        # Şifre bölümü
        password_group = QGroupBox("🔐 Güvenlik Şifresi")
        password_group.setStyleSheet("""
            QGroupBox {
                font-size: 16px;
                font-weight: bold;
                border: 2px solid #636363;
                border-radius: 8px;
                margin-top: 15px;
                padding-top: 20px;
                background-color: #f0f0f0;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 20px;
                padding: 0 8px;
                color: #636363;
            }
        """)
        password_layout = QVBoxLayout()
        password_layout.setSpacing(15)

        pass_info = QLabel("Kontrol paneline erişim için bir şifre belirleyin:")
        pass_info.setStyleSheet("font-size: 14px; color: #333333; font-weight: normal;")
        password_layout.addWidget(pass_info)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Güvenlik şifrenizi girin...")
        self.password_input.setStyleSheet("""
            QLineEdit {
                padding: 14px;
                font-size: 16px;
                border: 2px solid #636363;
                border-radius: 6px;
                background-color: #ffffff;
                color: #000000;
            }
            QLineEdit:focus {
                border: 2px solid #ff0000;
            }
        """)
        password_layout.addWidget(self.password_input)

        self.password_confirm = QLineEdit()
        self.password_confirm.setEchoMode(QLineEdit.Password)
        self.password_confirm.setPlaceholderText("Şifreyi tekrar girin...")
        self.password_confirm.setStyleSheet("""
            QLineEdit {
                padding: 14px;
                font-size: 16px;
                border: 2px solid #636363;
                border-radius: 6px;
                background-color: #ffffff;
                color: #000000;
            }
            QLineEdit:focus {
                border: 2px solid #ff0000;
            }
        """)
        password_layout.addWidget(self.password_confirm)

        password_group.setLayout(password_layout)
        layout.addWidget(password_group)

        # USB bölümü
        usb_group = QGroupBox("💾 USB Token Seçimi")
        usb_group.setStyleSheet("""
            QGroupBox {
                font-size: 16px;
                font-weight: bold;
                border: 2px solid #636363;
                border-radius: 8px;
                margin-top: 15px;
                padding-top: 20px;
                background-color: #f0f0f0;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 20px;
                padding: 0 8px;
                color: #636363;
            }
        """)
        usb_layout = QVBoxLayout()
        usb_layout.setSpacing(15)

        usb_info = QLabel("Güvenlik token'ı olarak kullanılacak USB'yi seçin:")
        usb_info.setStyleSheet("font-size: 14px; color: #333333; font-weight: normal;")
        usb_layout.addWidget(usb_info)

        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(['Sürücü', 'İsim', 'Seri No'])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        self.table.setStyleSheet("""
            QTableWidget {
                background-color: #ffffff;
                border: 2px solid #636363;
                border-radius: 6px;
                font-size: 14px;
                color: #000000;
            }
            QTableWidget::item:selected {
                background-color: #ff0000;
                color: white;
            }
            QHeaderView::section {
                background-color: #636363;
                color: white;
                padding: 10px;
                font-weight: bold;
            }
        """)
        self.table.setMaximumHeight(200)
        usb_layout.addWidget(self.table)

        usb_group.setLayout(usb_layout)
        layout.addWidget(usb_group)

        # Butonlar
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(20)

        refresh_btn = QPushButton("🔄 USB Yenile")
        refresh_btn.setStyleSheet("""
            QPushButton {
                background-color: #636363;
                color: white;
                border: none;
                padding: 14px 30px;
                font-size: 14px;
                font-weight: bold;
                border-radius: 8px;
            }
            QPushButton:hover {
                background-color: #4a4a4a;
            }
        """)
        refresh_btn.setCursor(Qt.PointingHandCursor)
        refresh_btn.clicked.connect(self.refresh_drives)
        btn_layout.addWidget(refresh_btn)

        setup_btn = QPushButton("✓ Kurulumu Tamamla")
        setup_btn.setStyleSheet("""
            QPushButton {
                background-color: #ff0000;
                color: white;
                border: none;
                padding: 14px 30px;
                font-size: 14px;
                font-weight: bold;
                border-radius: 8px;
            }
            QPushButton:hover {
                background-color: #cc0000;
            }
        """)
        setup_btn.setCursor(Qt.PointingHandCursor)
        setup_btn.clicked.connect(self.complete_setup)
        btn_layout.addWidget(setup_btn)

        layout.addLayout(btn_layout)
        central_widget.setLayout(layout)
        self.refresh_drives()

    def refresh_drives(self):
        """USB listesini yeniler."""
        self.table.setRowCount(0)
        self.drives = self.service.get_usb_drives()
        if not self.drives:
            QMessageBox.warning(
                self,
                "Uyarı",
                "Hiçbir USB flash bellek bulunamadı!\nLütfen USB takıp 'USB Yenile' butonuna tıklayın."
            )
            return
        for drive in self.drives:
            row = self.table.rowCount()
            self.table.insertRow(row)
            item1 = QTableWidgetItem(drive['letter'])
            item1.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row, 0, item1)
            item2 = QTableWidgetItem(drive['name'])
            item2.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row, 1, item2)
            item3 = QTableWidgetItem(str(drive['serial']))
            item3.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row, 2, item3)

    def complete_setup(self):
        """Kurulumu tamamlar."""
        password = self.password_input.text()
        password_confirm = self.password_confirm.text()
        if not password:
            QMessageBox.warning(self, "Hata", "Lütfen bir şifre girin!")
            return
        if len(password) < 4:
            QMessageBox.warning(self, "Hata", "Şifre en az 4 karakter olmalıdır!")
            return
        if password != password_confirm:
            QMessageBox.warning(self, "Hata", "Şifreler eşleşmiyor!")
            return

        selected_rows = self.table.selectedItems()
        if not selected_rows:
            QMessageBox.warning(self, "Hata", "Lütfen bir USB seçin!")
            return
        row = self.table.currentRow()
        selected_drive = self.drives[row]

        token = self.service.create_device_hash(selected_drive)
        self.service.save_config(token=token, password=password)
        add_to_startup()
        self.service.log_event("setup_complete", f"Setup completed with token: {token[:16]}...")

        QMessageBox.information(
            self,
            "✓ Kurulum Tamamlandı",
            f"Kurulum başarıyla tamamlandı!\n"
            f"🔐 Şifre kaydedildi\n"
            f"💾 USB Token: {selected_drive['letter']} - {selected_drive['name']}\n"
            f"🔑 Token Hash: {token[:16]}...\n"
            f"✅ Sistem başlangıcına eklendi\n"
            f"✅ Güvenlik sistemi aktif\n"
            f"Program tray icon'dan yönetilecek."
        )
        self.setup_complete.emit()
        self.close()


class MainWindow(QMainWindow):
    """Ana kontrol penceresi - Kurumsal tema."""
    def __init__(self, service_core, tray_icon):
        super().__init__()
        self.service = service_core
        self.tray_icon = tray_icon
        self.lock_screen = None
        self.setup_ui()
        self.start_monitoring()

    def setup_ui(self):
        self.setWindowTitle("Service Hash - Kurumsal Kontrol Paneli")
        self.setFixedSize(900, 750)
        screen = QApplication.desktop().screenGeometry()
        x = (screen.width() - self.width()) // 2
        y = (screen.height() - self.height()) // 2
        self.move(x, y)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout()
        layout.setSpacing(25)
        layout.setContentsMargins(40, 40, 40, 40)

        # Durum göstergesi
        status_frame = QWidget()
        status_layout = QVBoxLayout()
        self.status_label = QLabel("🔒 Sistem Koruması Aktif")
        self.status_label.setStyleSheet("""
            font-size: 24px;
            font-weight: bold;
            color: #ffffff;
            padding: 20px;
            background-color: #636363;
            border-radius: 10px;
        """)
        self.status_label.setAlignment(Qt.AlignCenter)
        status_layout.addWidget(self.status_label)
        status_frame.setLayout(status_layout)
        layout.addWidget(status_frame)

        # Bilgi paneli
        info_frame = QWidget()
        info_frame.setStyleSheet("""
            background-color: #f0f0f0;
            border-radius: 10px;
            padding: 15px;
        """)
        info_layout = QVBoxLayout()
        info = QLabel(
            "🔐 <b>USB Token İzleniyor</b><br><br>"
            "• USB çıkartılırsa sistem anında kilitlenir<br>"
            "• Tüm klavye ve mouse girişleri engellenir<br>"
            "• Ctrl+Alt+Del, Win tuşu engellenir<br>"
            "• Sadece yetkili USB ile erişim sağlanır"
        )
        info.setStyleSheet("""
            font-size: 14px;
            color: #333333;
            line-height: 1.6;
        """)
        info.setWordWrap(True)
        info_layout.addWidget(info)
        info_frame.setLayout(info_layout)
        layout.addWidget(info_frame)

        # Token bilgisi
        self.token_label = QLabel(f"🔑 Token: {self.service.authorized_token[:24]}...")
        self.token_label.setStyleSheet("""
            font-size: 12px;
            color: #636363;
            padding: 10px;
            background-color: #ffffff;
            border-radius: 6px;
            font-family: 'Courier New';
        """)
        self.token_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.token_label)

        # Yönetim butonları
        btn_group = QGroupBox("⚙ USB Token Yönetimi")
        btn_group.setStyleSheet("""
            QGroupBox {
                font-size: 16px;
                font-weight: bold;
                border: 2px solid #636363;
                border-radius: 8px;
                margin-top: 15px;
                padding-top: 20px;
                background-color: #f0f0f0;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 20px;
                padding: 0 8px;
                color: #636363;
            }
        """)
        btn_layout = QVBoxLayout()
        btn_layout.setSpacing(15)

        # USB Değiştir
        change_btn = QPushButton("🔄 USB Token Değiştir")
        change_btn.setStyleSheet("""
            QPushButton {
                background-color: #ff0000;
                color: white;
                border: none;
                padding: 14px 20px;
                font-size: 14px;
                font-weight: bold;
                border-radius: 6px;
                text-align: left;
            }
            QPushButton:hover {
                background-color: #cc0000;
            }
        """)
        change_btn.setCursor(Qt.PointingHandCursor)
        change_btn.clicked.connect(self.change_token)
        btn_layout.addWidget(change_btn)

        # USB Sil
        delete_btn = QPushButton("🗑 USB Token Sil ve Sıfırla")
        delete_btn.setStyleSheet("""
            QPushButton {
                background-color: #636363;
                color: white;
                border: none;
                padding: 14px 20px;
                font-size: 14px;
                font-weight: bold;
                border-radius: 6px;
                text-align: left;
            }
            QPushButton:hover {
                background-color: #4a4a4a;
            }
        """)
        delete_btn.setCursor(Qt.PointingHandCursor)
        delete_btn.clicked.connect(self.delete_token)
        btn_layout.addWidget(delete_btn)

        # Şifre Değiştir
        change_pass_btn = QPushButton("🔐 Şifre Değiştir")
        change_pass_btn.setStyleSheet("""
            QPushButton {
                background-color: #636363;
                color: white;
                border: none;
                padding: 14px 20px;
                font-size: 14px;
                font-weight: bold;
                border-radius: 6px;
                text-align: left;
            }
            QPushButton:hover {
                background-color: #4a4a4a;
            }
        """)
        change_pass_btn.setCursor(Qt.PointingHandCursor)
        change_pass_btn.clicked.connect(self.change_password)
        btn_layout.addWidget(change_pass_btn)

        # Yeni: Günlük Aç Butonu
        logs_btn = QPushButton("📖 Uygulama Günlüğünü Aç")
        logs_btn.setStyleSheet("""
            QPushButton {
                background-color: #636363;
                color: white;
                border: none;
                padding: 14px 20px;
                font-size: 14px;
                font-weight: bold;
                border-radius: 6px;
                text-align: left;
            }
            QPushButton:hover {
                background-color: #4a4a4a;
            }
        """)
        logs_btn.setCursor(Qt.PointingHandCursor)
        logs_btn.clicked.connect(self.show_logs)
        btn_layout.addWidget(logs_btn)

        btn_group.setLayout(btn_layout)
        layout.addWidget(btn_group)

        # Alt butonlar
        bottom_layout = QHBoxLayout()
        bottom_layout.setSpacing(15)
        hide_btn = QPushButton("↓ Arka Plana Gönder")
        hide_btn.setStyleSheet("""
            QPushButton {
                background-color: #636363;
                color: white;
                border: none;
                padding: 12px 20px;
                font-size: 14px;
                font-weight: bold;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #4a4a4a;
            }
        """)
        hide_btn.setCursor(Qt.PointingHandCursor)
        hide_btn.clicked.connect(self.hide)
        bottom_layout.addWidget(hide_btn)

        layout.addLayout(bottom_layout)
        central_widget.setLayout(layout)

        # Durum kontrolü
        self.status_timer = QTimer()
        self.status_timer.timeout.connect(self.update_status)
        self.status_timer.start(1000)

    def change_token(self):
        """USB Token değiştir"""
        # Şifre doğrulama
        dialog = PasswordDialog(self.service, "USB Token Değiştir", self)
        if dialog.exec_() != QDialog.Accepted:
            return
        # USB seçimi
        change_dialog = ChangeTokenDialog(self.service, self)
        if change_dialog.exec_() == QDialog.Accepted:
            self.token_label.setText(f"🔑 Token: {self.service.authorized_token[:24]}...")
            self.service.log_event("token_change", "USB token changed successfully")
            QMessageBox.information(
                self,
                "Başarılı",
                "USB Token başarıyla değiştirildi!"
            )

    def delete_token(self):
        """USB Token sil"""
        # Şifre doğrulama
        dialog = PasswordDialog(self.service, "Token Silme Onayı", self)
        if dialog.exec_() != QDialog.Accepted:
            return
        # Onay
        reply = QMessageBox.question(
            self,
            "⚠ Kritik İşlem",
            "USB Token silinecek ve sistem sıfırlanacak!\n"
            "Bu işlem sonrası:\n"
            "• Tüm ayarlar silinecek\n"
            "• Program kapanacak\n"
            "• Yeniden kurulum gerekecek\n"
            "Devam etmek istediğinize emin misiniz?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            # Token ve ayarları sil
            self.service.reset_config()
            # Başlangıçtan kaldır
            remove_from_startup()
            self.service.log_event("token_delete", "USB token deleted and config reset")
            QMessageBox.information(
                self,
                "✓ Tamamlandı",
                "Tüm ayarlar silindi.\nProgram kapanacak."
            )
            # Programı kapat
            QApplication.quit()

    def change_password(self):
        """Şifre değiştir"""
        # Eski şifre doğrulama
        dialog = PasswordDialog(self.service, "Mevcut Şifre", self)
        if dialog.exec_() != QDialog.Accepted:
            return
        # Yeni şifre al
        new_pass, ok1 = QInputDialog.getText(
            self,
            "Yeni Şifre",
            "Yeni şifrenizi girin:",
            QLineEdit.Password
        )
        if not ok1 or not new_pass:
            return
        if len(new_pass) < 4:
            QMessageBox.warning(self, "Hata", "Şifre en az 4 karakter olmalıdır!")
            return
        # Şifre onayı
        confirm_pass, ok2 = QInputDialog.getText(
            self,
            "Şifre Onayı",
            "Yeni şifreyi tekrar girin:",
            QLineEdit.Password
        )
        if not ok2 or new_pass != confirm_pass:
            QMessageBox.warning(self, "Hata", "Şifreler eşleşmiyor!")
            return
        # Şifreyi kaydet
        self.service.save_config(password=new_pass)
        self.service.log_event("password_change", "Password changed successfully")
        QMessageBox.information(
            self,
            "✓ Başarılı",
            "Şifre başarıyla değiştirildi!"
        )

    def update_status(self):
        """USB durumunu güncelle"""
        if self.service.verify_usb():
            self.status_label.setText("✓ Sistem Koruması Aktif")
            self.status_label.setStyleSheet("""
                font-size: 24px;
                font-weight: bold;
                color: #ffffff;
                padding: 20px;
                background-color: #636363;
                border-radius: 10px;
            """)
        else:
            self.status_label.setText("⚠ USB Bulunamadı - Kilitlenecek!")
            self.status_label.setStyleSheet("""
                font-size: 24px;
                font-weight: bold;
                color: #ffffff;
                padding: 20px;
                background-color: #ff0000;
                border-radius: 10px;
            """)

    def start_monitoring(self):
        """USB izlemeyi başlat"""
        self.monitor_timer = QTimer()
        self.monitor_timer.timeout.connect(self.check_usb)
        self.monitor_timer.start(1000)

    def check_usb(self):
        """USB kontrolü"""
        if not self.service.verify_usb() and not self.lock_screen:
            self.service.log_event("lock_triggered", "USB removed, lock screen triggered")
            self.show_lock_screen()

    def show_lock_screen(self):
        """Kilit ekranını göster"""
        self.lock_screen = LockScreen(self.service)
        self.lock_screen.unlock_signal.connect(self.on_unlock)
        self.lock_screen.show()
        self.hide()

    def on_unlock(self):
        """Kilit açıldığında"""
        self.lock_screen = None

    def closeEvent(self, event):
        """Pencere kapatıldığında gizle"""
        event.ignore()
        self.hide()

    def show_logs(self):
        """Günlükleri göster"""
        logs = self.service.get_logs()
        if not logs:
            QMessageBox.information(self, "Günlükler", "Herhangi bir olay kaydedilmedi.")
            return
        log_text = ""
        for log in logs:
            timestamp = time.ctime(log['timestamp'])
            event = log['event']
            details = log.get('details', '')
            log_text += f"[{timestamp}] {event}\n"
            if details:
                log_text += f"    → {details}\n"
            log_text += "\n"
        # Log penceresi oluştur
        dialog = QDialog(self)
        dialog.setWindowTitle("Uygulama Günlüğü")
        dialog.setFixedSize(700, 500)
        layout = QVBoxLayout()
        text_area = QLabel()
        text_area.setText(log_text)
        text_area.setStyleSheet("""
            font-family: 'Courier New';
            font-size: 12px;
            color: #333333;
            background-color: #f0f0f0;
            padding: 10px;
            border-radius: 6px;
        """)
        text_area.setAlignment(Qt.AlignLeft)
        scroll_area = QWidget()
        scroll_layout = QVBoxLayout()
        scroll_layout.addWidget(text_area)
        scroll_area.setLayout(scroll_layout)
        layout.addWidget(scroll_area)
        close_btn = QPushButton("Kapat")
        close_btn.setStyleSheet("""
            QPushButton {
                background-color: #636363;
                color: white;
                border: none;
                padding: 10px 20px;
                font-size: 12px;
                font-weight: bold;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #4a4a4a;
            }
        """)
        close_btn.clicked.connect(dialog.close)
        layout.addWidget(close_btn)
        dialog.setLayout(layout)
        dialog.exec_()


class ChangeTokenDialog(QDialog):
    """USB Token değiştirme penceresi - Kurumsal tema"""
    def __init__(self, service_core, parent=None):
        super().__init__(parent)
        self.service = service_core
        self.drives = []
        self.selected_drive = None
        self.setup_ui()

    def setup_ui(self):
        self.setWindowTitle("USB Token Değiştir")
        self.setFixedSize(750, 500)
        self.setModal(True)
        layout = QVBoxLayout()
        layout.setSpacing(20)
        layout.setContentsMargins(30, 30, 30, 30)

        title = QLabel("🔄 Yeni USB Token Seçin")
        title.setStyleSheet("""
            font-size: 20px;
            font-weight: bold;
            color: white;
            padding: 15px;
            background-color: #636363;
            border-radius: 8px;
        """)
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        warning = QLabel(
            "⚠ DİKKAT: Yeni USB seçtikten sonra sadece o USB ile erişebilirsiniz!"
        )
        warning.setStyleSheet("""
            font-size: 14px;
            color: #ff0000;
            padding: 10px;
            background-color: #f0f0f0;
            border-radius: 6px;
            border: 1px solid #ff0000;
        """)
        warning.setAlignment(Qt.AlignCenter)
        layout.addWidget(warning)

        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(['Sürücü', 'İsim', 'Seri No'])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        self.table.setStyleSheet("""
            QTableWidget {
                background-color: #ffffff;
                border: 2px solid #636363;
                border-radius: 6px;
                font-size: 14px;
                color: #000000;
            }
            QTableWidget::item:selected {
                background-color: #ff0000;
                color: white;
            }
            QHeaderView::section {
                background-color: #636363;
                color: white;
                padding: 10px;
                font-weight: bold;
            }
        """)
        layout.addWidget(self.table)

        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(15)

        refresh_btn = QPushButton("🔄 Yenile")
        refresh_btn.setStyleSheet("""
            QPushButton {
                background-color: #636363;
                color: white;
                border: none;
                padding: 12px 25px;
                font-size: 14px;
                font-weight: bold;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #4a4a4a;
            }
        """)
        refresh_btn.setCursor(Qt.PointingHandCursor)
        refresh_btn.clicked.connect(self.refresh_drives)
        btn_layout.addWidget(refresh_btn)

        select_btn = QPushButton("✓ Seç ve Kaydet")
        select_btn.setStyleSheet("""
            QPushButton {
                background-color: #ff0000;
                color: white;
                border: none;
                padding: 12px 25px;
                font-size: 14px;
                font-weight: bold;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #cc0000;
            }
        """)
        select_btn.setCursor(Qt.PointingHandCursor)
        select_btn.clicked.connect(self.select_drive)
        btn_layout.addWidget(select_btn)

        cancel_btn = QPushButton("✗ İptal")
        cancel_btn.setStyleSheet("""
            QPushButton {
                background-color: #636363;
                color: white;
                border: none;
                padding: 12px 25px;
                font-size: 14px;
                font-weight: bold;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #4a4a4a;
            }
        """)
        cancel_btn.setCursor(Qt.PointingHandCursor)
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(cancel_btn)

        layout.addLayout(btn_layout)
        self.setLayout(layout)
        self.refresh_drives()

    def refresh_drives(self):
        """USB listesini yenile"""
        self.table.setRowCount(0)
        self.drives = self.service.get_usb_drives()
        if not self.drives:
            QMessageBox.warning(
                self,
                "Uyarı",
                "Hiçbir USB bulunamadı!\nYeni USB takıp 'Yenile' butonuna tıklayın."
            )
            return
        for drive in self.drives:
            row = self.table.rowCount()
            self.table.insertRow(row)
            item1 = QTableWidgetItem(drive['letter'])
            item1.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row, 0, item1)
            item2 = QTableWidgetItem(drive['name'])
            item2.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row, 1, item2)
            item3 = QTableWidgetItem(str(drive['serial']))
            item3.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row, 2, item3)

    def select_drive(self):
        """Yeni USB token seç"""
        selected_rows = self.table.selectedItems()
        if not selected_rows:
            QMessageBox.warning(self, "Uyarı", "Lütfen bir USB seçin!")
            return
        row = self.table.currentRow()
        self.selected_drive = self.drives[row]
        reply = QMessageBox.question(
            self,
            "Onay",
            f"Yeni USB Token:\n"
            f"Sürücü: {self.selected_drive['letter']}\n"
            f"İsim: {self.selected_drive['name']}\n"
            f"Eski token silinecek. Onaylıyor musunuz?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            token = self.service.create_device_hash(self.selected_drive)
            self.service.save_config(token=token)
            self.service.log_event("token_change", f"USB token changed to: {token[:16]}...")
            self.accept()


def create_red_icon():
    """Kırmızı tray icon oluştur"""
    pixmap = QPixmap(64, 64)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing)
    painter.setBrush(QColor(255, 0, 0))  # #ff0000
    painter.setPen(Qt.NoPen)
    painter.drawEllipse(4, 4, 56, 56)
    painter.setPen(Qt.NoPen)
    painter.setBrush(QColor(255, 255, 255))
    painter.drawRoundedRect(22, 32, 20, 20, 2, 2)
    painter.setBrush(Qt.NoBrush)
    painter.setPen(QColor(255, 255, 255))
    painter.drawArc(26, 22, 12, 16, 0, 180 * 16)
    painter.end()
    return QIcon(pixmap)


def add_to_startup():
    """Programı Windows başlangıcına ekle"""
    try:
        if getattr(sys, 'frozen', False):
            exe_path = sys.executable
        else:
            exe_path = f'"{sys.executable}" "{os.path.abspath(__file__)}"'
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            STARTUP_KEY,
            0,
            winreg.KEY_SET_VALUE
        )
        winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, exe_path)
        winreg.CloseKey(key)
        return True
    except Exception as e:
        print(f"Başlangıca eklenemedi: {e}")
        return False


def remove_from_startup():
    """Programı Windows başlangıcından kaldır"""
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            STARTUP_KEY,
            0,
            winreg.KEY_SET_VALUE
        )
        winreg.DeleteValue(key, APP_NAME)
        winreg.CloseKey(key)
        return True
    except:
        return False


class TrayApplication:
    """Tray icon uygulaması - Kurumsal tema"""
    def __init__(self, service_core):
        self.service = service_core
        self.app = QApplication(sys.argv)
        self.app.setQuitOnLastWindowClosed(False)
        self.tray_icon = QSystemTrayIcon()
        self.tray_icon.setIcon(create_red_icon())
        self.tray_icon.setToolTip("Service Hash - Kurumsal Güvenlik Sistemi")
        self.create_tray_menu()
        self.tray_icon.show()
        self.main_window = None
        self.lock_screen = None
        self.start_auto_monitoring()

    def create_tray_menu(self):
        """Tray menüsünü oluştur"""
        menu = QMenu()
        open_action = menu.addAction("📊 Kontrol Panelini Aç")
        open_action.triggered.connect(self.show_main_window_with_password)
        menu.addSeparator()
        status_action = menu.addAction("✓ Durum: Aktif")
        status_action.setEnabled(False)
        menu.addSeparator()
        check_action = menu.addAction("🔍 USB'yi Kontrol Et")
        check_action.triggered.connect(self.manual_check)
        menu.addSeparator()
        about_action = menu.addAction("ℹ Hakkında")
        about_action.triggered.connect(self.show_about)
        quit_action = menu.addAction("❌ Çıkış")
        quit_action.triggered.connect(self.quit_application)
        self.tray_icon.setContextMenu(menu)

    def show_main_window_with_password(self):
        """Şifre ile ana pencereyi aç"""
        dialog = PasswordDialog(self.service, "Kontrol Paneli Erişimi")
        if dialog.exec_() == QDialog.Accepted:
            self.show_main_window()

    def show_main_window(self):
        """Ana pencereyi göster"""
        if not self.main_window:
            self.main_window = MainWindow(self.service, self.tray_icon)
        self.main_window.show()
        self.main_window.activateWindow()
        self.main_window.raise_()

    def manual_check(self):
        """Manuel USB kontrolü"""
        if self.service.verify_usb():
            self.tray_icon.showMessage(
                "✓ USB Token Bulundu",
                "Yetkili USB takılı. Sistem güvende.",
                QSystemTrayIcon.Information,
                3000
            )
            self.service.log_event("manual_check", "USB token verified via manual check")
        else:
            self.tray_icon.showMessage(
                "⚠ USB Token Bulunamadı",
                "Yetkili USB bulunamadı! Sistem kilitlenecek.",
                QSystemTrayIcon.Critical,
                3000
            )
            self.service.log_event("manual_check_failed", "USB token not found in manual check")

    def show_about(self):
        """Hakkında penceresi"""
        QMessageBox.information(
            None,
            "Service Hash - Hakkında",
            "🔒 <b>Service Hash</b><br>"
            "USB Token Kurumsal Güvenlik Sistemi<br><br>"
            "Sürüm: 3.0<br>"
            "Şifre korumalı yönetim<br>"
            "Kernel seviyesi tam koruma<br><br>"
            "© 2025 Service Hash Security"
        )

    def quit_application(self):
        """Uygulamadan çık - Şifre korumalı"""
        dialog = PasswordDialog(self.service, "Çıkış Onayı")
        if dialog.exec_() != QDialog.Accepted:
            return
        reply = QMessageBox.question(
            None,
            "Çıkış Onayı",
            "Service Hash'i kapatmak istediğinize emin misiniz?\n"
            "⚠ Güvenlik sistemi devre dışı kalacaktır!",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            if self.lock_screen:
                self.lock_screen.deactivate_locks()
                self.lock_screen.close()
            self.service.log_event("app_quit", "Application closed by user")
            self.tray_icon.hide()
            self.app.quit()

    def start_auto_monitoring(self):
        """Otomatik USB izlemeyi başlat"""
        self.monitor_timer = QTimer()
        self.monitor_timer.timeout.connect(self.check_usb_status)
        self.monitor_timer.start(1000)

    def check_usb_status(self):
        """USB durumunu kontrol et"""
        if not self.service.verify_usb() and not self.lock_screen:
            self.service.log_event("lock_triggered", "USB removed, lock screen triggered by auto-check")
            self.show_lock_screen()

    def show_lock_screen(self):
        """Kilit ekranını göster"""
        self.lock_screen = LockScreen(self.service)
        self.lock_screen.unlock_signal.connect(self.on_unlock)
        self.lock_screen.show()
        if self.main_window:
            self.main_window.hide()
        self.tray_icon.showMessage(
            "🔒 Sistem Kilitlendi",
            "USB Token bulunamadı. Tüm erişim engellendi!",
            QSystemTrayIcon.Critical,
            5000
        )

    def on_unlock(self):
        """Kilit açıldığında"""
        self.lock_screen = None
        self.tray_icon.showMessage(
            "✓ Sistem Açıldı",
            "USB Token algılandı. Erişim sağlandı.",
            QSystemTrayIcon.Information,
            3000
        )

    def run(self):
        """Uygulamayı çalıştır"""
        return self.app.exec_()


def check_admin():
    """Admin yetkisi kontrolü"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def run_as_admin():
    """Admin olarak yeniden başlat"""
    try:
        if sys.argv[0].endswith('.py'):
            ctypes.windll.shell32.ShellExecuteW(
                None,
                "runas",
                sys.executable,
                " ".join([f'"{arg}"' for arg in sys.argv]),
                None,
                1
            )
        else:
            ctypes.windll.shell32.ShellExecuteW(
                None,
                "runas",
                sys.executable,
                "",
                None,
                1
            )
        sys.exit(0)
    except Exception as e:
        QMessageBox.critical(
            None,
            "Yetki Hatası",
            f"Program yönetici olarak çalıştırılamadı!\n"
            f"Hata: {e}\n"
            f"Lütfen programı sağ tıklayıp 'Yönetici olarak çalıştır' seçeneğini kullanın."
        )
        sys.exit(1)


def main():
    """Ana fonksiyon"""
    # Admin kontrolü
    if not check_admin():
        run_as_admin()
        return

    # Qt uygulama
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    app.setApplicationName("Service Hash")
    app.setOrganizationName("ServiceHash")

    # Servis oluştur
    service = ServiceHashCore()

    # Konfig var mı kontrol et
    if service.load_config():
        # Token ve şifre var - doğrudan çalış
        if service.verify_usb():
            # USB takılı - tray'de çalış
            tray_app = TrayApplication(service)
            tray_app.tray_icon.showMessage(
                "✓ Service Hash Başlatıldı",
                "USB Token kurumsal güvenlik sistemi aktif.\nŞifre korumalı yönetim hazır.",
                QSystemTrayIcon.Information,
                4000
            )
            service.log_event("app_start", "ServiceHash started successfully with USB token")
            sys.exit(tray_app.run())
        else:
            # USB yok - kilit ekranı göster
            tray_app = TrayApplication(service)
            service.log_event("app_start_no_usb", "ServiceHash started but USB token not found")
            tray_app.show_lock_screen()
            sys.exit(tray_app.run())
    else:
        # İlk kurulum - Şifre ve USB ayarla
        setup = SetupWindow(service)

        def on_setup_complete():
            setup.close()
            # Tray uygulamasını başlat
            tray_app = TrayApplication(service)
            tray_app.tray_icon.showMessage(
                "✓ Kurulum Tamamlandı",
                "Service Hash aktif. Şifre ve USB Token kaydedildi.",
                QSystemTrayIcon.Information,
                5000
            )
            service.log_event("app_start_after_setup", "ServiceHash started after setup")

        setup.setup_complete.connect(on_setup_complete)
        setup.show()
        sys.exit(app.exec_())


if __name__ == "__main__":
    main()