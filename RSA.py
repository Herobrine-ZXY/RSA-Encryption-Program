import sys
import os
import base64
import json
import random
import multiprocessing
import time
import math
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, QHBoxLayout,
    QTextEdit, QPushButton, QLabel, QMessageBox, QFileDialog,
    QComboBox, QGroupBox, QGridLayout, QTableWidget, QTableWidgetItem,
    QHeaderView, QCheckBox, QLineEdit, QStatusBar
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QPalette, QColor

# 支持的密钥大小
KEY_SIZES = ["128", "256", "512", "768", "1024", "2048", "3072", "4096"]
KEY_FORMATS = {"PEM (PKCS#1)": "pkcs1", "SSH": "ssh", "DER (Base64)": "der"}

# 字符编码选项
ENCODINGS = [
    "UTF-8", "UTF-16", "ASCII", "ISO-8859-1", "Windows-1252",
    "GBK", "Big5", "Shift_JIS"
]

# 默认数字映射表
DEFAULT_NUM_MAP = {
    'A': '41', 'B': '42', 'C': '43', 'D': '44', 'E': '45',
    'F': '46', 'G': '47', 'H': '48', 'I': '49', 'J': '50',
    'K': '51', 'L': '52', 'M': '53', 'N': '54', 'O': '55',
    'P': '56', 'Q': '57', 'R': '58', 'S': '59', 'T': '60',
    'U': '61', 'V': '62', 'W': '63', 'X': '64', 'Y': '65',
    'Z': '66',
    'a': '67', 'b': '68', 'c': '69', 'd': '70', 'e': '71',
    'f': '72', 'g': '73', 'h': '74', 'i': '75', 'j': '76',
    'k': '77', 'l': '78', 'm': '79', 'n': '80', 'o': '81',
    'p': '82', 'q': '83', 'r': '84', 's': '85', 't': '86',
    'u': '87', 'v': '88', 'w': '89', 'x': '90', 'y': '91',
    'z': '92',
    ' ': '93', '\n': '94', ',': '95', '.': '96', '?': '97',
    '!': '98', ':': '99'
}

# 固定前缀
PTZ_PREFIX = "PTZ"


def is_prime(n, k=5):
    """使用Miller-Rabin算法测试一个数是否为质数"""
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False

    # 将n-1写成 d * 2^r 的形式
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits):
    """生成指定位数的质数"""
    while True:
        # 生成随机数，确保最高位和最低位为1
        num = random.getrandbits(bits)
        num |= (1 << (bits - 1)) | 1

        # 确保最小大小
        if num < 2 ** (bits - 1):
            continue

        # 测试是否为质数
        if is_prime(num):
            return num


def extended_gcd(a, b):
    """扩展欧几里得算法计算模逆元"""
    if b == 0:
        return a, 1, 0
    else:
        gcd, x1, y1 = extended_gcd(b, a % b)
        x = y1
        y = x1 - (a // b) * y1
        return gcd, x, y


def mod_inverse(a, m):
    """计算模逆元"""
    gcd, x, y = extended_gcd(a, m)
    if gcd != 1:
        return None  # 模逆元不存在
    return x % m


class RSAKey:
    """RSA密钥类"""

    def __init__(self, n, e, d=None, p=None, q=None):
        self.n = n
        self.e = e
        self.d = d
        self.p = p
        self.q = q
        self.bits = n.bit_length()

    def public_key(self):
        """获取公钥部分"""
        return RSAKey(self.n, self.e)

    def encrypt(self, message):
        """使用公钥加密消息"""
        # 确保消息是整数且小于模数n
        if not isinstance(message, int):
            raise ValueError("消息必须是整数")
        if message >= self.n:
            raise ValueError("消息太大，无法加密")

        # RSA加密: c = m^e mod n
        return pow(message, self.e, self.n)

    def decrypt(self, ciphertext):
        """使用私钥解密密文"""
        # 确保密文是整数且小于模数n
        if not isinstance(ciphertext, int):
            raise ValueError("密文必须是整数")
        if ciphertext >= self.n:
            raise ValueError("密文太大，无法解密")

        # RSA解密: m = c^d mod n
        return pow(ciphertext, self.d, self.n)

    def save_pkcs1(self):
        """PKCS#1格式的公钥/私钥"""
        if self.d is None:
            # 公钥
            return f"-----BEGIN RSA PUBLIC KEY-----\n" \
                   f"N={hex(self.n)[2:]}\n" \
                   f"E={hex(self.e)[2:]}\n" \
                   f"-----END RSA PUBLIC KEY-----"
        else:
            # 私钥
            return f"-----BEGIN RSA PRIVATE KEY-----\n" \
                   f"N={hex(self.n)[2:]}\n" \
                   f"E={hex(self.e)[2:]}\n" \
                   f"D={hex(self.d)[2:]}\n" \
                   f"P={hex(self.p)[2:]}\n" \
                   f"Q={hex(self.q)[2:]}\n" \
                   f"-----END RSA PRIVATE KEY-----"

    def save_ssh(self):
        """SSH格式的公钥（仅支持公钥）"""
        if self.d is not None:
            return "SSH格式仅支持公钥"
        return f"ssh-rsa AAAAB3NzaC1yc2EAAAAADAQAB{base64.b64encode(f'{self.n}:{self.e}'.encode()).decode()}"

    def save_der(self):
        """DER格式的公钥（Base64编码）"""
        if self.d is not None:
            return "DER格式仅支持公钥"
        return base64.b64encode(f"N={hex(self.n)[2:]}\nE={hex(self.e)[2:]}".encode()).decode()


def generate_key_pair(bits):
    """生成RSA密钥对"""
    # 生成两个不同的质数
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)

    # 确保p和q不同
    while p == q:
        q = generate_prime(bits // 2)

    # 计算模数n和欧拉函数φ(n)
    n = p * q
    phi = (p - 1) * (q - 1)

    # 选择公钥指数e (通常为65537)
    e = 65537

    # 确保e和φ(n)互质
    if math.gcd(e, phi) != 1:
        # 尝试另一个e值
        e = 3
        while math.gcd(e, phi) != 1:
            e += 2

    # 计算私钥指数d
    d = mod_inverse(e, phi)

    # 创建密钥对象
    public_key = RSAKey(n, e)
    private_key = RSAKey(n, e, d, p, q)

    return public_key, private_key


class KeyGenerationThread(QThread):
    """用于后台生成密钥对的线程"""
    finished = pyqtSignal(object, object)  # 公钥和私钥
    progress = pyqtSignal(str)  # 进度信息
    error = pyqtSignal(str)  # 错误信息

    def __init__(self, bits):
        super().__init__()
        self.bits = bits

    def run(self):
        try:
            self.progress.emit(f"开始生成 {self.bits}-bit 密钥对...")
            start_time = time.time()

            public_key, private_key = generate_key_pair(self.bits)

            elapsed = time.time() - start_time
            self.progress.emit(f"{self.bits}-bit 密钥生成完成! 耗时: {elapsed:.2f}秒")
            self.finished.emit(public_key, private_key)

        except Exception as e:
            self.error.emit(f"密钥生成错误: {str(e)}")


class RSAChatApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("高级RSA安全通讯工具")
        self.setGeometry(100, 100, 900, 700)

        # 深色主题
        self.setup_dark_theme()

        # 初始化变量
        self.key_size = 1024
        self.key_format = "pkcs1"
        self.encoding = "UTF-8"
        self.enable_ptz_encryption = True
        self.num_map = DEFAULT_NUM_MAP.copy()
        self.reverse_num_map = {v: k for k, v in self.num_map.items()}
        self.config_file = "settings.json"
        self.key_gen_thread = None

        # 创建主布局
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # 创建配置工具栏
        self.create_config_toolbar()

        # 创建标签页
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)

        # 创建标签页
        self.create_key_tab()
        self.create_encrypt_tab()
        self.create_decrypt_tab()
        self.create_translation_tab()

        # 状态栏
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("就绪")

        # 初始加载配置
        self.load_config()

    def setup_dark_theme(self):
        """设置深色主题"""
        dark_palette = QPalette()
        dark_palette.setColor(QPalette.Window, QColor(45, 45, 45))
        dark_palette.setColor(QPalette.WindowText, Qt.white)
        dark_palette.setColor(QPalette.Base, QColor(25, 25, 25))
        dark_palette.setColor(QPalette.AlternateBase, QColor(45, 45, 45))
        dark_palette.setColor(QPalette.ToolTipBase, Qt.white)
        dark_palette.setColor(QPalette.ToolTipText, Qt.white)
        dark_palette.setColor(QPalette.Text, Qt.white)
        dark_palette.setColor(QPalette.Button, QColor(65, 65, 65))
        dark_palette.setColor(QPalette.ButtonText, Qt.white)
        dark_palette.setColor(QPalette.BrightText, Qt.red)
        dark_palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.HighlightedText, Qt.black)

        # 禁用颜色
        dark_palette.setColor(QPalette.Disabled, QPalette.Text, Qt.darkGray)
        dark_palette.setColor(QPalette.Disabled, QPalette.ButtonText, Qt.darkGray)

        # 应用主题
        app = QApplication.instance()
        app.setPalette(dark_palette)
        app.setStyle("Fusion")

        # 设置样式表
        app.setStyleSheet("""
            QWidget {
                font-size: 10pt;
            }
            QGroupBox {
                border: 1px solid #555;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 15px;
                font-weight: bold;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 5px;
                background-color: #333;
            }
            QTabWidget::pane {
                border-top: 2px solid #6B8E23;
            }
            QTabBar::tab {
                background: #555;
                color: white;
                padding: 8px;
                border: 1px solid #444;
                border-bottom-color: #222;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
                min-width: 100px;
            }
            QTabBar::tab:selected {
                background: #6B8E23;
                border-color: #9B9B9B;
                border-bottom-color: #6B8E23;
            }
            QTextEdit, QLineEdit, QComboBox {
                background-color: #1E1E1E;
                color: #E0E0E0;
                border: 1px solid #444;
                border-radius: 3px;
                padding: 5px;
                selection-background-color: #3A3A3A;
            }
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                                            stop:0 #6B8E23, stop:1 #556B2F);
                color: white;
                border: 1px solid #4A6572;
                border-radius: 4px;
                padding: 5px 10px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                                            stop:0 #7EA23D, stop:1 #6B8E23);
            }
            QPushButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, 
                                            stop:0 #4A6572, stop:1 #6B8E23);
            }
            QPushButton:disabled {
                background: #505050;
                color: #999;
            }
            QTableWidget {
                gridline-color: #444;
                background: #1E1E1E;
                alternate-background-color: #2A2A2A;
            }
            QHeaderView::section {
                background-color: #4A4A4A;
                color: white;
                padding: 4px;
                border: 1px solid #3A3A3A;
            }
        """)

    def create_config_toolbar(self):
        """创建配置工具栏"""
        toolbar = QWidget()
        toolbar_layout = QHBoxLayout(toolbar)
        toolbar_layout.setContentsMargins(5, 5, 5, 5)

        # 配置标签
        self.config_label = QLabel(f"当前配置: {self.config_file}")

        # 配置按钮
        save_btn = QPushButton("保存配置")
        save_btn.clicked.connect(self.save_config)

        save_as_btn = QPushButton("另存为...")
        save_as_btn.clicked.connect(self.save_config_as)

        load_btn = QPushButton("加载配置...")
        load_btn.clicked.connect(self.load_config_as)

        # 编码选择
        self.encoding_combo = QComboBox()
        self.encoding_combo.addItems(ENCODINGS)
        self.encoding_combo.setCurrentText(self.encoding)
        self.encoding_combo.currentTextChanged.connect(self.update_encoding)

        # 添加到工具栏
        toolbar_layout.addWidget(self.config_label)
        toolbar_layout.addStretch(1)
        toolbar_layout.addWidget(QLabel("编码:"))
        toolbar_layout.addWidget(self.encoding_combo, 1)
        toolbar_layout.addSpacing(10)
        toolbar_layout.addWidget(save_btn)
        toolbar_layout.addWidget(save_as_btn)
        toolbar_layout.addWidget(load_btn)

        # 添加到主布局
        self.centralWidget().layout().addWidget(toolbar)

    def create_key_tab(self):
        """创建密钥管理标签页"""
        key_tab = QWidget()
        layout = QVBoxLayout(key_tab)
        layout.setContentsMargins(10, 10, 10, 10)

        # 密钥生成选项
        key_group = QGroupBox("密钥生成选项")
        key_layout = QGridLayout(key_group)

        # 密钥大小选择
        key_layout.addWidget(QLabel("密钥大小:"), 0, 0)
        self.key_size_combo = QComboBox()
        self.key_size_combo.addItems(KEY_SIZES)
        self.key_size_combo.setCurrentText("1024")
        key_layout.addWidget(self.key_size_combo, 0, 1)

        # 密钥格式选择
        key_layout.addWidget(QLabel("密钥格式:"), 1, 0)
        self.key_format_combo = QComboBox()
        self.key_format_combo.addItems(list(KEY_FORMATS.keys()))
        self.key_format_combo.setCurrentText("PEM (PKCS#1)")
        key_layout.addWidget(self.key_format_combo, 1, 1)

        # 生成按钮
        self.generate_button = QPushButton("生成密钥对")
        self.generate_button.clicked.connect(self.generate_key_pair)
        key_layout.addWidget(self.generate_button, 0, 2, 2, 1)

        # 公钥/私钥显示区域
        keys_layout = QHBoxLayout()

        # 公钥显示
        pub_group = QGroupBox("公钥")
        pub_layout = QVBoxLayout(pub_group)
        self.public_key_display = QTextEdit()
        self.public_key_display.setPlaceholderText("公钥将显示在这里...")
        pub_layout.addWidget(self.public_key_display)

        # 私钥显示
        priv_group = QGroupBox("私钥")
        priv_layout = QVBoxLayout(priv_group)
        self.private_key_display = QTextEdit()
        self.private_key_display.setPlaceholderText("私钥将显示在这里...")
        priv_layout.addWidget(self.private_key_display)

        keys_layout.addWidget(pub_group)
        keys_layout.addWidget(priv_group)

        # 操作按钮
        btn_layout = QHBoxLayout()

        self.export_pub_btn = QPushButton("导出公钥")
        self.export_pub_btn.setEnabled(False)
        self.export_pub_btn.clicked.connect(self.export_public_key)

        self.export_priv_btn = QPushButton("导出私钥")
        self.export_priv_btn.setEnabled(False)
        self.export_priv_btn.clicked.connect(self.export_private_key)

        self.import_pub_btn = QPushButton("导入公钥")
        self.import_pub_btn.clicked.connect(self.import_public_key)

        self.import_priv_btn = QPushButton("导入私钥")
        self.import_priv_btn.clicked.connect(self.import_private_key)

        btn_layout.addWidget(self.export_pub_btn)
        btn_layout.addWidget(self.export_priv_btn)
        btn_layout.addWidget(self.import_pub_btn)
        btn_layout.addWidget(self.import_priv_btn)

        # 添加到主布局
        layout.addWidget(key_group)
        layout.addLayout(keys_layout, 1)
        layout.addLayout(btn_layout)

        # 添加标签页
        self.tabs.addTab(key_tab, "密钥管理")

    def create_encrypt_tab(self):
        """创建加密标签页"""
        encrypt_tab = QWidget()
        layout = QVBoxLayout(encrypt_tab)
        layout.setContentsMargins(10, 10, 10, 10)

        # 加密选项
        options_group = QGroupBox("加密选项")
        options_layout = QGridLayout(options_group)

        # 输出格式
        options_layout.addWidget(QLabel("输出格式:"), 0, 0)
        self.cipher_output_combo = QComboBox()
        self.cipher_output_combo.addItems(["十六进制", "Base64"])
        options_layout.addWidget(self.cipher_output_combo, 0, 1)

        # PTZ编码选项
        self.ptz_checkbox = QCheckBox("启用中文翻译和PTZ编码")
        self.ptz_checkbox.setChecked(True)
        options_layout.addWidget(self.ptz_checkbox, 1, 0, 1, 2)

        # 公钥输入
        pub_group = QGroupBox("公钥")
        pub_layout = QVBoxLayout(pub_group)
        self.encrypt_pub_key_edit = QTextEdit()
        self.encrypt_pub_key_edit.setPlaceholderText("在此粘贴公钥...")
        pub_layout.addWidget(self.encrypt极_pub_key_edit)

        # 明文输入
        plain_group = QGroupBox("明文")
        plain_layout = QVBoxLayout(plain_group)
        self.plain_text_edit = QTextEdit()
        self.plain_text_edit.setPlaceholderText("在此输入要加密的文本...")
        plain_layout.addWidget(self.plain_text_edit)

        # 加密按钮
        self.encrypt_button = QPushButton("加密")
        self.encrypt_button.clicked.connect(self.encrypt_message)

        # 密文输出
        cipher_group = QGroupBox("密文")
        cipher_layout = QVBoxLayout(cipher_group)
        self.cipher_text_edit = QTextEdit()
        self.cipher_text_edit.setReadOnly(True)
        self.cipher_text_edit.setPlaceholderText("加密结果将显示在这里...")
        cipher_layout.addWidget(self.cipher_text_edit)

        # 复制按钮
        self.copy_cipher_button = QPushButton("复制密文")
        self.copy_cipher_button.setEnabled(False)
        self.copy_cipher_button.clicked.connect(self.copy_cipher_text)

        # 添加到主布局
        layout.addWidget(options_group)
        layout.addWidget(pub_group)
        layout.addWidget(plain_group)
        layout.addWidget(self.encrypt_button)
        layout.addWidget(cipher_group)
        layout.addWidget(self.copy_cipher_button)

        # 添加标签页
        self.tabs.addTab(encrypt_tab, "加密")

    def create_decrypt_tab(self):
        """创建解密标签页"""
        decrypt_tab = QWidget()
        layout = QVBoxLayout(decrypt_tab)
        layout.setContentsMargins(10, 10, 10, 10)

        # 解密选项
        options_group = QGroupBox("解密选项")
        options_layout = QGridLayout(options_group)

        # 输入格式
        options_layout.addWidget(QLabel("输入格式:"), 0, 0)
        self.cipher_input_combo = QComboBox()
        self.cipher_input_combo.addItems(["十六进制", "Base64"])
        options_layout.addWidget(self.cipher_input_combo, 0, 1)

        # PTZ解码选项
        self.ptz_dec_checkbox = QCheckBox("启用中文翻译和PTZ解码")
        self.ptz_dec_checkbox.setChecked(True)
        options_layout.addWidget(self.ptz_dec_checkbox, 1, 0, 1, 2)

        # 私钥输入
        priv_group = QGroupBox("私钥")
        priv_layout = QVBoxLayout(priv_group)
        self.decrypt_priv_key_edit = QTextEdit()
        self.decrypt_priv_key_edit.setPlaceholderText("在此粘贴私钥...")
        priv_layout.addWidget(self.decrypt_priv_key_edit)

        # 密文输入
        cipher_group = QGroupBox("密文")
        cipher_layout = QVBoxLayout(cipher_group)
        self.cipher_input_edit = QTextEdit()
        self.cipher_input_edit.setPlaceholderText("在此输入要解密的密文...")
        cipher_layout.addWidget(self.cipher_input_edit)

        # 解密按钮
        self.decrypt_button = QPushButton("解密")
        self.decrypt_button.clicked.connect(self.decrypt_message)

        # 明文输出
        plain_group = QGroupBox("解密结果")
        plain_layout = QVBoxLayout(plain_group)
        self.decrypted_text_edit = QTextEdit()
        self.decrypted_text_edit.setReadOnly(True)
        self.decrypted_text_edit.setPlaceholderText("解密结果将显示在这里...")
        plain_layout.addWidget(self.decrypted_text_edit)

        # 添加到主布局
        layout.addWidget(options_group)
        layout.addWidget(priv_group)
        layout.addWidget(cipher_group)
        layout.addWidget(self.decrypt_button)
        layout.addWidget(plain_group)

        # 添加标签页
        self.tabs.addTab(decrypt_tab, "解密")

    def create_translation_tab(self):
        """创建翻译设置标签页"""
        translation_tab = QWidget()
        layout = QVBoxLayout(translation_tab)
        layout.setContentsMargins(10, 10, 10, 10)

        # PTZ设置
        ptz_group = QGroupBox("PTZ设置")
        ptz_layout = QVBoxLayout(ptz_group)

        # 前缀显示
        prefix_layout = QHBoxLayout()
        prefix_layout.addWidget(QLabel("固定前缀:"))
        prefix_layout.addWidget(QLabel(PTZ_PREFIX, styleSheet="font-weight: bold; font-size: 14px;"))
        prefix_layout.addStretch()

        # 映射表设置
        table_layout = QVBoxLayout()
        table_layout.addWidget(QLabel("字母-数字映射表:"))

        # 创建表格
        self.mapping_table = QTableWidget()
        self.mapping_table.setColumnCount(2)
        self.mapping_table.setHorizontalHeaderLabels(["字母", "数字代码"])
        self.mapping_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.mapping_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.populate_mapping_table()
        table_layout.addWidget(self.mapping_table)

        # 按钮布局
        button_layout = QHBoxLayout()

        save_mapping_btn = QPushButton("保存映射")
        save_mapping_btn.clicked.connect(self.save_mapping_table)

        random_mapping_btn = QPushButton("随机生成")
        random_mapping_btn.clicked.connect(self.generate_random_mapping)

        default_mapping_btn = QPushButton("恢复默认")
        default_mapping_btn.clicked.connect(self.restore_default_mapping)

        button_layout.addWidget(save_mapping_btn)
        button_layout.addWidget(random_mapping_btn)
        button_layout.addWidget(default_mapping_btn)

        # 添加PTZ注意事项
        note_label = QLabel(
            "<b>注意事项:</b><br>"
            "• 数字代码必须为两位数字且唯一<br>"
            "• 启用PTZ编码会增加加密文本长度<br>"
            "• 建议保持默认映射以确保兼容性"
        )
        note_label.setStyleSheet("color: #FF8888; font-size: 10pt;")

        # 翻译演示
        demo_group = QGroupBox("翻译演示")
        demo_layout = QVBoxLayout(demo_group)

        chinese_layout = QHBoxLayout()
        chinese_layout.addWidget(QLabel("中文文本:"))
        self.chinese_demo_edit = QLineEdit("你好世界")
        chinese_layout.addWidget(self.chinese_demo_edit)

        demo_btn = QPushButton("演示转换")
        demo_btn.clicked.connect(self.demo_ptz_conversion)

        self.demo_result_text = QTextEdit()
        self.demo_result_text.setReadOnly(True)

        demo_layout.addLayout(chinese_layout)
        demo_layout.addWidget(demo_btn)
        demo_layout.addWidget(self.demo_result_text)

        # 添加到布局
        ptz_layout.addLayout(prefix_layout)
        ptz_layout.addLayout(table_layout)
        ptz_layout.addLayout(button_layout)
        ptz_layout.addWidget(note_label)

        layout.addWidget(ptz_group)
        layout.addWidget(demo_group)

        # 添加标签页
        self.tabs.addTab(translation_tab, "翻译设置")

    def populate_mapping_table(self):
        """填充映射表格"""
        letters = sorted(self.num_map.keys())
        self.mapping_table.setRowCount(len(letters))

        for i, letter in enumerate(letters):
            # 字母列
            letter_item = QTableWidgetItem(letter)
            letter_item.setFlags(letter_item.flags() & ~Qt.ItemIsEditable)
            self.mapping_table.setItem(i, 0, letter_item)

            # 数字代码列
            code_item = QTableWidgetItem(self.num_map[letter])
            self.mapping_table.setItem(i, 1, code_item)

    def update_key_size(self):
        """更新密钥大小设置"""
        self.key_size = int(self.key_size_combo.currentText())

    def update_key_format(self):
        """更新密钥格式设置"""
        self.key_format = KEY_FORMATS[self.key_format_combo.currentText()]

    def update_encoding(self, encoding):
        """更新字符编码设置"""
        self.encoding = encoding

    def generate_key_pair(self):
        """生成RSA密钥对"""
        # 获取密钥大小
        bits = int(self.key_size_combo.currentText())

        # 更新UI状态
        self.status_bar.showMessage(f"正在生成 {bits}-bit RSA密钥，请稍候...")
        self.generate_button.setEnabled(False)
        self.generate_button.setText("生成中...")
        QApplication.setOverrideCursor(Qt.WaitCursor)
        QApplication.processEvents()

        # 创建并启动工作线程
        self.key_gen_thread = KeyGenerationThread(bits)
        self.key_gen_thread.finished.connect(self.handle_key_generation_finished)
        self.key_gen_thread.progress.connect(self.status_bar.showMessage)
        self.key_gen_thread.error.connect(self.handle_key_generation_error)
        self.key_gen_thread.start()

    def handle_key_generation_finished(self, public_key, private_key):
        """处理密钥生成完成"""
        try:
            # 根据选择的格式格式化密钥
            format_func = {
                "pkcs1": lambda k: k.save_pkcs1(),
                "ssh": lambda k: k.save_ssh(),
                "der": lambda k: k.save_der()
            }[self.key_format]

            # 显示公钥和私钥
            self.public_key_display.setPlainText(format_func(public_key))
            self.private_key_display.setPlainText(private_key.save_pkcs1())

            # 更新加密页面的公钥
            self.encrypt_pub_key_edit.setPlainText(format_func(public_key))

            # 更新解密页面的私钥
            self.decrypt_priv_key_edit.setPlainText(private_key.save_pkcs1())

            # 更新按钮状态
            self.export_pub_btn.setEnabled(True)
            self.export_priv_btn.setEnabled(True)

            self.status_bar.showMessage(f"成功生成 {self.key_size}-bit RSA密钥!")

        except Exception as e:
            self.status_bar.showMessage(f"密钥格式化错误: {str(e)}")
            QMessageBox.critical(self, "错误", f"无法格式化密钥: {str(e)}")

        finally:
            # 恢复UI状态
            self.generate_button.setEnabled(True)
            self.generate_button.setText("生成密钥对")
            QApplication.restoreOverrideCursor()

    def handle_key_generation_error(self, error_msg):
        """处理密钥生成错误"""
        self.generate_button.setEnabled(True)
        self.generate_button.setText("生成密钥对")
        QApplication.restoreOverrideCursor()

        self.status_bar.showMessage("密钥生成失败")
        QMessageBox.critical(self, "错误", error_msg)

    def export_public_key(self):
        """导出公钥到文件"""
        pub_key = self.public_key_display.toPlainText().strip()
        if not pub_key:
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "保存公钥文件", "", "所有文件 (*)"
        )

        if file_path:
            try:
                with open(file_path, "w") as f:
                    f.write(pub_key)
                self.status_bar.showMessage(f"公钥已导出到: {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "错误", f"导出公钥失败: {str(e)}")

    def export_private_key(self):
        """导出私钥到文件"""
        priv_key = self.private_key_display.toPlainText().strip()
        if not priv_key:
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "保存私钥文件", "", "所有文件 (*)"
        )

        if file_path:
            try:
                with open(file_path, "w") as f:
                    f.write(priv_key)
                self.status_bar.showMessage(f"私钥已导出到: {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "错误", f"导出私钥失败: {str(e)}")

    def import_public_key(self):
        """从文件导入公钥"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "打开公钥文件", "", "所有文件 (*)"
        )

        if file_path:
            try:
                with open(file_path, "r") as f:
                    pub_key = f.read()
                self.public_key_display.setPlainText(pub_key)
                self.encrypt_pub_key_edit.setPlainText(pub_key)
                self.export_pub_btn.setEnabled(True)
                self.status_bar.showMessage(f"已从 {file_path} 导入公钥")
            except Exception as e:
                QMessageBox.critical(self, "错误", f"导入公钥失败: {str(e)}")

    def import_private_key(self):
        """从文件导入私钥"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "打开私钥文件", "", "所有文件 (*)"
        )

        if file_path:
            try:
                with open(file_path, "r") as f:
                    priv_key = f.read()
                self.private_key_display.setPlainText(priv_key)
                self.decrypt_priv_key_edit.setPlainText(priv_key)
                self.export_priv_btn.setEnabled(True)
                self.status_bar.showMessage(f"已从 {file_path} 导入私钥")
            except Exception as e:
                QMessageBox.critical(self, "错误", f"导入私钥失败: {str(e)}")

    def load_key_from_text(self, key_text):
        """从文本加载RSAKey对象"""
        if not key_text:
            return None

        try:
            # 查找关键参数
            lines = key_text.split('\n')
            params = {}
            for line in lines:
                if '=' in line:
                    key, value = line.split('=', 1)
                    params[key.strip()] = value.strip()

            # 检查必要参数
            if 'N' not in params or 'E' not in params:
                return None

            # 解析参数
            n = int(params['N'], 16)
            e = int(params['E'], 16)

            # 检查是否有私钥参数
            if 'D' in params and 'P' in params and 'Q' in params:
                d = int(params['D'], 16)
                p = int(params['P'], 16)
                q = int(params['Q'], 16)
                return RSAKey(n, e, d, p, q)
            else:
                return RSAKey(n, e)

        except:
            return None

    def encrypt_message(self):
        """加密消息"""
        try:
            # 获取公钥文本
            pub_key_text = self.encrypt_pub_key_edit.toPlainText().strip()
            if not pub_key_text:
                QMessageBox.warning(self, "警告", "请输入公钥")
                return

            # 加载公钥
            pub_key = self.load_key_from_text(pub_key_text)
            if not pub_key or pub_key.d is not None:
                QMessageBox.warning(self, "错误", "无效的公钥")
                return

            # 获取明文
            plain_text = self.plain_text_edit.toPlainText().strip()
            if not plain_text:
                QMessageBox.warning(self, "警告", "请输入要加密的消息")
                return

            # 检查密钥大小限制
            if pub_key.bits < 128:
                QMessageBox.warning(self, "警告",
                                    f"密钥大小 ({pub_key.bits}位) 太小，最小为128位")
                return

            # 应用PTZ编码（如果启用）
            if self.ptz_checkbox.isChecked():
                plain_text, _ = self.text_to_ptz_encoded(plain_text)

            # 转换为字节并转换为整数
            plain_bytes = plain_text.encode(self.encoding)
            plain_int = int.from_bytes(plain_bytes, byteorder='big')

            # 检查消息长度
            max_msg_size = (pub_key.n.bit_length() // 8) - 11  # 留出空间
            if plain_int.bit_length() > max_msg_size * 8:
                QMessageBox.warning(self, "错误",
                                    f"消息太长 ({len(plain_bytes)}字节)，最大为 {max_msg_size}字节")
                return

            # 加密
            cipher_int = pub_key.encrypt(plain_int)
            cipher_bytes = cipher_int.to_bytes((cipher_int.bit_length() + 7) // 8, byteorder='big')

            # 根据选择的格式转换输出
            output_format = self.cipher_output_combo.currentText()
            if output_format == "Base64":
                cipher_text = base64.b64encode(cipher_bytes).decode()
            else:  # 十六进制
                cipher_text = cipher_bytes.hex()

            # 显示结果
            self.cipher_text_edit.setPlainText(cipher_text)
            self.copy_cipher_button.setEnabled(True)
            self.status_bar.showMessage("消息加密成功")

        except Exception as e:
            QMessageBox.critical(self, "错误", f"加密失败: {str(e)}")

    def decrypt_message(self):
        """解密消息"""
        try:
            # 获取私钥文本
            priv_key_text = self.decrypt_priv_key_edit.toPlainText().strip()
            if not priv_key_text:
                QMessageBox.warning(self, "警告", "请输入私钥")
                return

            # 加载私钥
            priv_key = self.load_key_from_text(priv_key_text)
            if not priv_key or priv_key.d is None:
                QMessageBox.warning(self, "错误", "无效的私钥")
                return

            # 获取密文
            cipher_text = self.cipher_input_edit.toPlainText().strip()
            if not cipher_text:
                QMessageBox.warning(self, "警告", "请输入要解密的密文")
                return

            # 根据输入格式解析密文
            input_format = self.cipher_input_combo.currentText()
            if input_format == "Base64":
                try:
                    cipher_bytes = base64.b64decode(cipher_text)
                except:
                    raise ValueError("无效的Base64格式")
            else:  # 十六进制
                try:
                    cipher_bytes = bytes.fromhex(cipher_text)
                except:
                    raise ValueError("无效的十六进制格式")

            # 转换为整数并解密
            cipher_int = int.from_bytes(cipher_bytes, byteorder='big')
            plain_int = priv_key.decrypt(cipher_int)

            # 将解密结果转换为字节
            bit_length = plain_int.bit_length()
            byte_length = (bit_length + 7) // 8
            plain_bytes = plain_int.to_bytes(byte_length, byteorder='big')

            # 尝试解码
            try:
                plain_text = plain_bytes.decode(self.encoding)
            except UnicodeDecodeError:
                # 尝试其他常见编码
                for enc in ['UTF-8', 'GBK', 'ISO-8859-1']:
                    try:
                        plain_text = plain_bytes.decode(enc)
                        break
                    except:
                        continue
                else:
                    plain_text = "无法解码内容，请检查编码设置"

            # 应用PTZ解码（如果启用）
            if self.ptz_dec_checkbox.isChecked():
                plain_text, _ = self.ptz_encoded_to_text(plain_text)

            # 显示结果
            self.decrypted_text_edit.setPlainText(plain_text)
            self.status_bar.showMessage("消息解密成功")

        except Exception as e:
            QMessageBox.critical(self, "错误", f"解密失败: {str(e)}")

    def text_to_ptz_encoded(self, text):
        """将文本转换为PTZ编码格式（简化版）"""
        # 简单的替换映射
        mapping = {
            '你': 'you', '好': 'hello', '世界': 'world', '加密': 'encrypt',
            '解密': 'decrypt', '消息': 'message', '安全': 'secure',
            '工具': 'tool', '中文': 'chinese', '测试': 'test'
        }

        # 简单翻译
        words = []
        for char in text:
            if char in mapping:
                words.append(mapping[char])
            else:
                words.append(char)
        english_text = ''.join(words)

        # 添加PTZ前缀
        encoded_text = PTZ_PREFIX

        # 字母转换为数字
        for char in english_text:
            if char in self.num_map:
                encoded_text += self.num_map[char]
            else:
                encoded_text += char

        return encoded_text, english_text

    def ptz_encoded_to_text(self, encoded_text):
        """将PTZ编码格式转换为文本（简化版）"""
        # 移除前缀
        if encoded_text.startswith(PTZ_PREFIX):
            encoded_text = encoded_text[len(PTZ_PREFIX):]

        # 解析数字代码
        chars = []
        i = 0
        while i < len(encoded_text):
            # 尝试解析两位数字
            if i + 2 <= len(encoded_text) and encoded_text[i:i + 2].isdigit():
                code = encoded_text[i:i + 2]
                if code in self.reverse_num_map:
                    chars.append(self.reverse_num_map[code])
                    i += 2
                    continue
            # 处理单个字符
            chars.append(encoded_text[i])
            i += 1

        english_text = ''.join(chars)

        # 简单反翻译
        mapping = {
            'you': '你', 'hello': '你好', 'world': '世界', 'encrypt': '加密',
            'decrypt': '解密', 'message': '消息', 'secure': '安全',
            'tool': '工具', 'chinese': '中文', 'test': '测试'
        }

        # 简单替换
        words = []
        for char in english_text:
            if char in mapping:
                words.append(mapping[char])
            else:
                words.append(char)

        chinese_text = ''.join(words)

        return chinese_text, english_text

    def copy_cipher_text(self):
        """复制密文到剪贴板"""
        cipher_text = self.cipher_text_edit.toPlainText()
        if cipher_text:
            clipboard = QApplication.clipboard()
            clipboard.setText(cipher_text)
            self.status_bar.showMessage("密文已复制到剪贴板")

    def save_mapping_table(self):
        """保存映射表到字典"""
        try:
            new_map = {}
            seen_codes = set()

            for i in range(self.mapping_table.rowCount()):
                letter = self.mapping_table.item(i, 0).text().strip()
                code = self.mapping_table.item(i, 1).text().strip()

                if not letter or not code:
                    continue

                # 验证代码格式
                if len(code) != 2 or not code.isdigit():
                    QMessageBox.warning(self, "错误", f"无效代码: '{code}'. 必须为2位数字")
                    return

                if code in seen_codes:
                    QMessageBox.warning(self, "错误", f"重复代码: '{code}'")
                    return

                seen_codes.add(code)
                new_map[letter] = code

            self.num_map = new_map
            self.reverse_num_map = {v: k for k, v in new_map.items()}

            # 重新填充表格
            self.populate_mapping_table()

            self.status_bar.showMessage("映射表已更新")
            QMessageBox.information(self, "成功", "映射表已保存")

        except Exception as e:
            QMessageBox.critical(self, "错误", f"保存映射表失败: {str(e)}")

    def generate_random_mapping(self):
        """随机生成新的映射表"""
        # 生成唯一的两位数代码池
        codes = [str(i).zfill(2) for i in range(10, 100)]
        random.shuffle(codes)

        # 更新表格
        for i in range(self.mapping_table.rowCount()):
            letter = self.mapping_table.item(i, 0).text()
            self.mapping_table.item(i, 1).setText(codes[i])

        self.status_bar.showMessage("已生成随机映射表")
        QMessageBox.information(self, "成功", "已生成随机映射表，请点击保存以应用")

    def restore_default_mapping(self):
        """恢复默认映射表"""
        self.num_map = DEFAULT_NUM_MAP.copy()
        self.reverse_num_map = {v: k for k, v in self.num_map.items()}
        self.populate_mapping_table()

        self.status_bar.showMessage("已恢复默认映射表")
        QMessageBox.information(self, "成功", "已恢复默认映射表")

    def demo_ptz_conversion(self):
        """演示PTZ转换过程"""
        text = self.chinese_demo_edit.text().strip()
        if not text:
            QMessageBox.warning(self, "警告", "请输入演示文本")
            return

        # 转换到PTZ
        ptz_encoded, english_text = self.text_to_ptz_encoded(text)

        # 转换回中文
        chinese_text, _ = self.ptz_encoded_to_text(ptz_encoded)

        # 显示结果
        result = f"原始文本: {text}\n"
        result += f"英文翻译: {english_text}\n"
        result += f"PTZ编码: {ptz_encoded}\n"
        result += f"解码文本: {chinese_text}"

        self.demo_result_text.setPlainText(result)
        self.status_bar.showMessage("PTZ转换演示完成")

    def save_config(self):
        """保存当前配置到文件"""
        config = {
            "key_size": self.key_size,
            "key_format": self.key_format,
            "encoding": self.encoding,
            "enable_ptz": self.enable_ptz_encryption,
            "num_map": self.num_map,
            "public_key": self.public_key_display.toPlainText(),
            "private_key": self.private_key_display.toPlainText()
        }

        try:
            with open(self.config_file, "w") as f:
                json.dump(config, f, indent=2)

            self.status_bar.showMessage(f"配置已保存到 {self.config_file}")

        except Exception as e:
            QMessageBox.critical(self, "错误", f"保存配置失败: {str(e)}")

    def save_config_as(self):
        """另存配置到新文件"""
        file_path, _ = QFileDialog.getSaveFileName(
            self, "保存配置文件", "", "JSON 文件 (*.json);;所有文件 (*)"
        )

        if file_path:
            if not file_path.lower().endswith('.json'):
                file_path += '.json'

            self.config_file = file_path
            self.config_label.setText(f"当前配置: {file_path}")
            self.save_config()

    def load_config(self):
        """从配置文件加载设置"""
        if not os.path.exists(self.config_file):
            return

        try:
            with open(self.config_file, "r") as f:
                config = json.load(f)

            # 应用配置
            self.key_size = config.get("key_size", 1024)
            self.key_format = config.get("key_format", "pkcs1")
            self.encoding = config.get("encoding", "UTF-8")
            self.enable_ptz_encryption = config.get("enable_ptz", True)
            self.num_map = config.get("num_map", DEFAULT_NUM_MAP.copy())

            # 更新UI元素
            self.key_size_combo.setCurrentText(str(self.key_size))

            # 找到对应的格式名称
            format_name = next((k for k, v in KEY_FORMATS.items() if v == self.key_format), "PEM (PKCS#1)")
            self.key_format_combo.setCurrentText(format_name)

            self.encoding_combo.setCurrentText(self.encoding)
            self.ptz_checkbox.setChecked(self.enable_ptz_encryption)
            self.ptz_dec_checkbox.setChecked(self.enable_ptz_encryption)
            self.populate_mapping_table()

            # 加载密钥
            public_key = config.get("public_key", "")
            private_key = config.get("private_key", "")

            self.public_key_display.setPlainText(public_key)
            self.private_key_display.setPlainText(private_key)
            self.encrypt_pub_key_edit.setPlainText(public_key)
            self.decrypt_priv_key_edit.setPlainText(private_key)

            # 更新导出按钮状态
            self.export_pub_btn.setEnabled(bool(public_key))
            self.export_priv_btn.setEnabled(bool(private_key))

            self.status_bar.showMessage(f"配置已从 {self.config_file} 加载")

        except Exception as e:
            QMessageBox.critical(self, "错误", f"加载配置失败: {str(e)}")

    def load_config_as(self):
        """从不同文件加载配置"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "打开配置文件", "", "JSON 文件 (*.json);;所有文件 (*)"
        )

        if file_path:
            self.config_file = file_path
            self.config_label.setText(f"当前配置: {file_path}")
            self.load_config()


if __name__ == "__main__":
    # 解决Windows多进程问题
    multiprocessing.freeze_support()

    app = QApplication(sys.argv)
    font = QFont("Arial", 9)
    app.setFont(font)

    window = RSAChatApp()
    window.show()
    sys.exit(app.exec_())