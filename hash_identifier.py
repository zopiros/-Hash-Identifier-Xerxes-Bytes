#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║       HASH IDENTIFIER — Xerxes Bytes (XBS)               ║
║   "We will find a way, or we will make a way."           ║
╚══════════════════════════════════════════════════════════╝

A PyQt5 GUI tool that identifies hash types by analyzing
length, character set, and structural patterns.
Supports 35+ hash algorithms.

Author  : Xerxes Bytes (XBS)
GitHub  : https://github.com/ZopIros
"""

import sys
import re
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QTextEdit, QPushButton, QTableWidget, QTableWidgetItem,
    QHeaderView, QFrame, QSplitter, QStatusBar
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QColor, QPalette, QTextCharFormat, QSyntaxHighlighter

# ─── Hash Signature Database ────────────────────────────────────────────────

HASH_SIGNATURES = [
    # (name, length, charset_regex, notes)
    ("MD5",             32,  r"^[a-f0-9]{32}$",              "Widely used, insecure"),
    ("MD5 (MySQL)",     16,  r"^[a-f0-9]{16}$",              "MySQL old password()"),
    ("MD4",             32,  r"^[a-f0-9]{32}$",              "Legacy Windows LM/NTLM"),
    ("SHA-1",           40,  r"^[a-f0-9]{40}$",              "Deprecated"),
    ("SHA-224",         56,  r"^[a-f0-9]{56}$",              "SHA-2 family"),
    ("SHA-256",         64,  r"^[a-f0-9]{64}$",              "SHA-2 family, common"),
    ("SHA-384",         96,  r"^[a-f0-9]{96}$",              "SHA-2 family"),
    ("SHA-512",        128,  r"^[a-f0-9]{128}$",             "SHA-2 family, strong"),
    ("SHA3-224",        56,  r"^[a-f0-9]{56}$",              "SHA-3 family"),
    ("SHA3-256",        64,  r"^[a-f0-9]{64}$",              "SHA-3 family"),
    ("SHA3-384",        96,  r"^[a-f0-9]{96}$",              "SHA-3 family"),
    ("SHA3-512",       128,  r"^[a-f0-9]{128}$",             "SHA-3 family"),
    ("NTLM",            32,  r"^[a-f0-9]{32}$",              "Windows authentication"),
    ("LM Hash",         32,  r"^[A-F0-9]{32}$",              "Legacy Windows, uppercase"),
    ("RIPEMD-128",      32,  r"^[a-f0-9]{32}$",              "Legacy"),
    ("RIPEMD-160",      40,  r"^[a-f0-9]{40}$",              "Bitcoin addresses"),
    ("RIPEMD-256",      64,  r"^[a-f0-9]{64}$",              "RIPEMD family"),
    ("RIPEMD-320",      80,  r"^[a-f0-9]{80}$",              "RIPEMD family"),
    ("Whirlpool",      128,  r"^[a-f0-9]{128}$",             "ISO standard"),
    ("Tiger-192",       48,  r"^[a-f0-9]{48}$",              "Fast algorithm"),
    ("BLAKE2b-512",    128,  r"^[a-f0-9]{128}$",             "Modern, fast"),
    ("BLAKE2s-256",     64,  r"^[a-f0-9]{64}$",              "Modern, fast"),
    ("Adler-32",         8,  r"^[a-f0-9]{8}$",               "Checksum, not crypto"),
    ("CRC32",            8,  r"^[a-f0-9]{8}$",               "Checksum, not crypto"),
    ("CRC32b",           8,  r"^[a-f0-9]{8}$",               "PHP crc32()"),
    ("MD5(WordPress)", 34,   r"^\$P\$[A-Za-z0-9./]{31}$",    "WordPress PHPass"),
    ("bcrypt",         60,   r"^\$2[ayb]\$\d{2}\$.{53}$",    "Adaptive, strong"),
    ("Argon2i",        None, r"^\$argon2i\$",                 "Memory-hard, very strong"),
    ("Argon2d",        None, r"^\$argon2d\$",                 "Memory-hard"),
    ("Argon2id",       None, r"^\$argon2id\$",                "Memory-hard, recommended"),
    ("scrypt",         None, r"^\$s0\$",                      "Memory-hard"),
    ("SHA-512 Crypt",  106,  r"^\$6\$[A-Za-z0-9./]{8,16}\$[A-Za-z0-9./]{86}$", "Unix shadow"),
    ("SHA-256 Crypt",  75,   r"^\$5\$[A-Za-z0-9./]{8,16}\$[A-Za-z0-9./]{43}$", "Unix shadow"),
    ("MD5 Crypt",      34,   r"^\$1\$[A-Za-z0-9./]{8}\$[A-Za-z0-9./]{22}$",    "Unix shadow"),
    ("DES Crypt",      13,   r"^[A-Za-z0-9./]{13}$",         "Old Unix, insecure"),
    ("PBKDF2-SHA256",  None, r"^\$pbkdf2-sha256\$",          "Django default"),
    ("PBKDF2-SHA1",    None, r"^\$pbkdf2-sha1\$",            "Common in apps"),
    ("MySQL 4.1+",     41,   r"^\*[A-F0-9]{40}$",            "MySQL SHA1 based"),
    ("Base64 (maybe)", None, r"^[A-Za-z0-9+/]+=*$",          "Encoded, not a hash"),
    ("Cisco IOS",      35,   r"^\$1\$[A-Za-z0-9./]{4}\$[A-Za-z0-9./]{22}$", "Cisco MD5"),
    ("Cisco Type 7",   None, r"^[0-9]{2}[0-9A-F]+$",         "Weak reversible"),
    ("HMAC-MD5",       32,   r"^[a-f0-9]{32}$",              "Keyed hash"),
    ("HMAC-SHA1",      40,   r"^[a-f0-9]{40}$",              "Keyed hash"),
    ("HMAC-SHA256",    64,   r"^[a-f0-9]{64}$",              "Keyed hash"),
]

CONFIDENCE_LABELS = {
    1:  ("Exact Match",  "#00FF88"),
    2:  ("Likely Match", "#FFD700"),
    3:  ("Possible",     "#FF8C00"),
}

def identify_hash(hashval: str) -> list[dict]:
    """Return a list of possible hash types sorted by confidence."""
    hashval = hashval.strip()
    if not hashval:
        return []

    results = []
    hlen = len(hashval)

    for name, length, pattern, notes in HASH_SIGNATURES:
        try:
            match = re.match(pattern, hashval, re.IGNORECASE)
        except re.error:
            continue
        if not match:
            continue

        confidence = 3
        if length is not None and hlen == length:
            confidence = 1
        elif length is None:
            confidence = 1  # pattern match is sufficient
        else:
            confidence = 2

        results.append({
            "name":       name,
            "length":     str(length) if length else "variable",
            "confidence": confidence,
            "notes":      notes,
        })

    results.sort(key=lambda x: x["confidence"])
    return results


# ─── Dark Theme ─────────────────────────────────────────────────────────────

def apply_dark_theme(app: QApplication):
    app.setStyle("Fusion")
    pal = QPalette()
    bg    = QColor("#0d0d0d")
    bg2   = QColor("#141414")
    bg3   = QColor("#1a1a2e")
    acc   = QColor("#7b2fff")
    acc2  = QColor("#00ffaa")
    text  = QColor("#e8e8e8")
    dim   = QColor("#666666")
    sel   = QColor("#2a2a4a")

    pal.setColor(QPalette.Window,          bg)
    pal.setColor(QPalette.WindowText,      text)
    pal.setColor(QPalette.Base,            bg2)
    pal.setColor(QPalette.AlternateBase,   bg3)
    pal.setColor(QPalette.Text,            text)
    pal.setColor(QPalette.ButtonText,      text)
    pal.setColor(QPalette.Button,          bg3)
    pal.setColor(QPalette.Highlight,       acc)
    pal.setColor(QPalette.HighlightedText, QColor("#ffffff"))
    pal.setColor(QPalette.PlaceholderText, dim)
    app.setPalette(pal)


# ─── Main Window ─────────────────────────────────────────────────────────────

class HashIdentifierWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Hash Identifier ⚔️ — Xerxes Bytes")
        self.setMinimumSize(860, 600)
        self._build_ui()
        self._apply_styles()

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(16, 12, 16, 12)
        root.setSpacing(10)

        # ── Header ────────────────────────────────────────────────────────
        header = QLabel(
            "🔍  HASH IDENTIFIER  ⚔️  <span style='color:#7b2fff;'>Xerxes Bytes</span>"
        )
        header.setTextFormat(Qt.RichText)
        header.setAlignment(Qt.AlignCenter)
        header.setFont(QFont("Consolas", 15, QFont.Bold))
        header.setStyleSheet("color:#e8e8e8; padding:6px 0;")
        root.addWidget(header)

        motto = QLabel('"We will find a way, or we will make a way."')
        motto.setAlignment(Qt.AlignCenter)
        motto.setStyleSheet("color:#555; font-size:11px; font-style:italic;")
        root.addWidget(motto)

        sep = QFrame(); sep.setFrameShape(QFrame.HLine)
        sep.setStyleSheet("color:#222;")
        root.addWidget(sep)

        # ── Input ─────────────────────────────────────────────────────────
        lbl_in = QLabel("  Paste hash value(s) below — one per line:")
        lbl_in.setStyleSheet("color:#aaa; font-size:12px; font-family:Consolas;")
        root.addWidget(lbl_in)

        self.input_box = QTextEdit()
        self.input_box.setPlaceholderText(
            "e.g.  5f4dcc3b5aa765d61d8327deb882cf99\n"
            "      $2y$10$...\n"
            "      $argon2id$..."
        )
        self.input_box.setFont(QFont("Consolas", 11))
        self.input_box.setMaximumHeight(120)
        root.addWidget(self.input_box)

        # ── Buttons ───────────────────────────────────────────────────────
        btn_row = QHBoxLayout()
        self.btn_identify = QPushButton("🔍  IDENTIFY")
        self.btn_clear    = QPushButton("✕  Clear")
        btn_row.addWidget(self.btn_identify)
        btn_row.addWidget(self.btn_clear)
        btn_row.addStretch()
        root.addLayout(btn_row)

        self.btn_identify.clicked.connect(self._identify)
        self.btn_clear.clicked.connect(self._clear)
        self.input_box.textChanged.connect(self._on_text_change)

        # ── Results Table ─────────────────────────────────────────────────
        lbl_out = QLabel("  Results:")
        lbl_out.setStyleSheet("color:#aaa; font-size:12px; font-family:Consolas;")
        root.addWidget(lbl_out)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels([
            "Hash (truncated)", "Algorithm", "Length", "Confidence", "Notes"
        ])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.horizontalHeader().setStyleSheet(
            "QHeaderView::section { background:#1a1a2e; color:#7b2fff; "
            "font-family:Consolas; font-size:11px; padding:4px; }"
        )
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setFont(QFont("Consolas", 10))
        root.addWidget(self.table)

        # ── Status Bar ────────────────────────────────────────────────────
        self.status = QStatusBar()
        self.setStatusBar(self.status)
        self.status.showMessage("Xerxes Bytes (XBS) — Hash Identifier ready.")

    def _apply_styles(self):
        self.setStyleSheet("""
            QMainWindow, QWidget { background:#0d0d0d; color:#e8e8e8; }
            QTextEdit {
                background:#141414; color:#00ffaa; border:1px solid #2a2a2a;
                border-radius:4px; padding:6px; font-family:Consolas;
            }
            QPushButton#identify {
                background:#7b2fff; color:#fff; border:none; border-radius:4px;
                font-family:Consolas; font-size:13px; font-weight:bold;
                padding:8px 20px;
            }
            QPushButton {
                background:#1a1a2e; color:#ccc; border:1px solid #333;
                border-radius:4px; font-family:Consolas; padding:7px 16px;
            }
            QPushButton:hover { background:#252545; color:#fff; }
            QTableWidget {
                background:#141414; color:#e0e0e0; gridline-color:#1e1e1e;
                border:1px solid #222; selection-background-color:#2a2a4a;
            }
            QTableWidget::item:alternate { background:#161626; }
            QStatusBar { background:#0d0d0d; color:#555; font-family:Consolas; font-size:10px; }
        """)
        self.btn_identify.setObjectName("identify")
        self.btn_identify.setStyleSheet(
            "QPushButton { background:#7b2fff; color:#fff; border:none; border-radius:4px;"
            " font-family:Consolas; font-size:13px; font-weight:bold; padding:8px 20px; }"
            "QPushButton:hover { background:#9b4fff; }"
        )

    def _on_text_change(self):
        # Live identification
        QTimer.singleShot(400, self._identify)

    def _identify(self):
        raw   = self.input_box.toPlainText().strip()
        lines = [l.strip() for l in raw.splitlines() if l.strip()]
        self.table.setRowCount(0)

        if not lines:
            self.status.showMessage("Enter a hash value to identify.")
            return

        total = 0
        for hashval in lines:
            matches = identify_hash(hashval)
            truncated = hashval[:24] + "…" if len(hashval) > 24 else hashval
            if not matches:
                row = self.table.rowCount()
                self.table.insertRow(row)
                self.table.setItem(row, 0, QTableWidgetItem(truncated))
                u = QTableWidgetItem("Unknown")
                u.setForeground(QColor("#ff4444"))
                self.table.setItem(row, 1, u)
                self.table.setItem(row, 2, QTableWidgetItem(str(len(hashval))))
                self.table.setItem(row, 3, QTableWidgetItem("—"))
                self.table.setItem(row, 4, QTableWidgetItem("No matching algorithm found"))
            else:
                for m in matches:
                    row = self.table.rowCount()
                    self.table.insertRow(row)
                    self.table.setItem(row, 0, QTableWidgetItem(truncated))
                    algo_item = QTableWidgetItem(m["name"])
                    conf_label, conf_color = CONFIDENCE_LABELS.get(m["confidence"], ("?", "#fff"))
                    algo_item.setForeground(QColor(conf_color))
                    self.table.setItem(row, 1, algo_item)
                    self.table.setItem(row, 2, QTableWidgetItem(m["length"]))
                    conf_item = QTableWidgetItem(conf_label)
                    conf_item.setForeground(QColor(conf_color))
                    self.table.setItem(row, 3, conf_item)
                    self.table.setItem(row, 4, QTableWidgetItem(m["notes"]))
                    total += 1

        self.status.showMessage(
            f"Identified {total} match(es) across {len(lines)} hash(es).  "
            f"— Xerxes Bytes (XBS)"
        )

    def _clear(self):
        self.input_box.clear()
        self.table.setRowCount(0)
        self.status.showMessage("Cleared.")


# ─── Entry Point ─────────────────────────────────────────────────────────────

def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Hash Identifier — Xerxes Bytes")
    apply_dark_theme(app)
    win = HashIdentifierWindow()
    win.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
