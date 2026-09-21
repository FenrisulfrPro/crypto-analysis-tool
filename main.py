# -*- coding: utf-8 -*-
"""密码算法分析工具 - PySide6 桌面版（浅蓝风格 UI）
模块：国密SM2/SM3 | 编码转换 | 协议分析(pcap) | 证书分析
"""
import sys
import base64
import html as _html
import warnings

warnings.filterwarnings("ignore", message=".*Diffie-Hellman over finite fields.*")
warnings.filterwarnings("ignore", message="scapy.*TLS.*")

from PySide6.QtCore import (Qt, QRect, QPoint, QSize as PY_QSIZE, Signal, QTimer,
                            QElapsedTimer, QEvent, QObject, QThread, Slot)
from PySide6.QtGui import (QFont, QPainter, QColor, QPen, QBrush, QPolygon,
                           QLinearGradient, QTextDocument, QFontMetrics)
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QTabWidget, QVBoxLayout, QHBoxLayout,
    QGridLayout, QLabel, QLineEdit, QPushButton, QPlainTextEdit, QComboBox,
    QTableWidget, QTableWidgetItem, QFileDialog, QGroupBox, QSplitter,
    QHeaderView, QMessageBox, QAbstractItemView, QSizePolicy, QTreeWidget,
    QTreeWidgetItem, QRadioButton, QButtonGroup, QFrame, QStackedWidget,
    QScrollArea, QDialog, QTextBrowser, QMenu,
)

sys.path.insert(0, '.')

from modules import sm2_sm3, codec, pcap_analysis, cert_analysis, packet_parser
from modules import sym_crypto, hash_tools, handshake_view, radix
TCP = packet_parser.TCP

APP_TITLE = "密码算法分析工具 v2.2"
MONO = "Consolas"

# ============================================================ 全局样式（浅蓝主题）
QSS = """
QWidget {
    font-family: "Microsoft YaHei UI", "Microsoft YaHei";
    font-size: 13px;
    color: #1f2430;
    background: #f3f6fb;
}
QSplitter::handle { background: #dde3ee; }
QSplitter::handle:hover { background: #93c5fd; }

QTabWidget::pane {
    border: 1px solid #dde3ee;
    border-radius: 8px;
    background: #ffffff;
    top: -1px;
}
QTabBar::tab {
    background: #eef1f7;
    color: #4b5563;
    padding: 8px 18px;
    margin-right: 2px;
    border: 1px solid #dde3ee;
    border-bottom: none;
    border-top-left-radius: 8px;
    border-top-right-radius: 8px;
    font-weight: 600;
}
QTabBar::tab:selected {
    background: #ffffff;
    color: #2563eb;
    border-top: 2px solid #2563eb;
}

QGroupBox {
    border: 1px solid #dde3ee;
    border-radius: 10px;
    margin-top: 14px;
    background: #ffffff;
    font-weight: 600;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 6px;
    color: #2563eb;
    background: #ffffff;
}

QLineEdit, QPlainTextEdit, QComboBox {
    border: 1px solid #d9dee8;
    border-radius: 6px;
    padding: 5px 8px;
    background: #ffffff;
    selection-background-color: #bfdbfe;
    selection-color: #1e3a8a;
}
QLineEdit:focus, QPlainTextEdit:focus, QComboBox:focus {
    border: 1px solid #3b82f6;
}

QPushButton {
    background: #eef2ff;
    color: #1d4ed8;
    border: 1px solid #c7d2fe;
    border-radius: 6px;
    padding: 6px 16px;
    font-weight: 600;
}
QPushButton:hover { background: #e0e7ff; }
QPushButton:pressed { background: #c7d2fe; }
QPushButton#primary {
    background: #2563eb; color: #ffffff; border: none; padding: 7px 20px;
}
QPushButton#primary:hover { background: #1d4ed8; }
QPushButton#success {
    background: #16a34a; color: #ffffff; border: none; padding: 7px 20px;
}
QPushButton#success:hover { background: #15803d; }
QPushButton#warn {
    background: #d97706; color: #ffffff; border: none; padding: 7px 16px;
}
QPushButton#warn:hover { background: #b45309; }
QPushButton#ghost {
    background: transparent; color: #6b7280; border: 1px solid #d9dee8;
}
QPushButton#ghost:hover { background: #f3f4f6; }

QRadioButton { spacing: 6px; padding: 2px 4px; }

QComboBox { min-width: 90px; }
QComboBox::drop-down { border: none; width: 20px; }

QFrame#modeCard {
    background: #ffffff;
    border: 1px solid #dde3ee;
    border-radius: 10px;
}

QLabel#stateLabel {
    font-size: 22px;
    font-weight: 800;
    padding: 10px 16px;
    border-radius: 8px;
}
QLabel#statePending { background: #f3f4f6; color: #6b7280; }
QLabel#stateOk  { background: #dcfce7; color: #15803d; }
QLabel#stateBad { background: #fee2e2; color: #b91c1c; }

/* ---- 细节美化（v2.2）：标签不再继承灰底、弹窗/浏览器/滚动条统一风格 ---- */
QLabel { background: transparent; }
QDialog { background: #f3f6fb; }
QTextBrowser, QTextEdit {
    background: #ffffff;
    border: 1px solid #dde3ee;
    border-radius: 8px;
    padding: 6px 8px;
}
QScrollBar:vertical { background: transparent; width: 10px; margin: 2px; }
QScrollBar::handle:vertical {
    background: #c7d2fe; border-radius: 5px; min-height: 24px;
}
QScrollBar::handle:vertical:hover { background: #a5b4fc; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar:horizontal { background: transparent; height: 10px; margin: 2px; }
QScrollBar::handle:horizontal {
    background: #c7d2fe; border-radius: 5px; min-width: 24px;
}
QScrollBar::handle:horizontal:hover { background: #a5b4fc; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }
QGroupBox {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                stop:0 #ffffff, stop:1 #fbfdff);
}
QToolTip {
    background: #1f2937; color: #f9fafb; border: none;
    padding: 4px 8px; border-radius: 4px;
}
"""


def _hex_nbytes(hex_str: str) -> int:
    """统计 HEX 字符串去除空白后的字节数"""
    s = ''.join(c for c in hex_str if c not in ' \t\n\r')
    if s.lower().startswith('0x'):
        s = s[2:]
    if len(s) % 2:
        s = '0' + s
    return len(s) // 2


# ============================================================ 文件加载动画（转圈遮罩 + 后台执行）
# 所有「上传/选择文件」入口统一使用：加载期间覆盖一层半透明遮罩 + 旋转指示器，
# 文件读取与解析放到后台线程执行，界面保持响应，处理完成后回到主线程刷新。

class BusyOverlay(QWidget):
    """半透明遮罩 + 旋转圆弧 + 文案（覆盖父控件区域，指示文件仍在处理中）。"""

    def __init__(self, parent, text="正在处理…"):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setStyleSheet("background: rgba(243, 246, 251, 0.78);")
        self._angle = 0
        self._text = text
        self._timer = QTimer(self)
        self._timer.setInterval(16)
        self._timer.timeout.connect(self._tick)
        self.hide()

    def _tick(self):
        self._angle = (self._angle + 14) % 360
        self.update()

    def start(self, text=None):
        if text:
            self._text = text
        pw = self.parentWidget()
        if pw is not None:
            self.setGeometry(pw.rect())
        self.raise_()
        self.show()
        self._timer.start()

    def stop(self):
        self._timer.stop()
        self.hide()

    def paintEvent(self, _ev):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        cx, cy = self.width() // 2, self.height() // 2 - 14
        r = 17
        pen = QPen(QColor("#DBEAFE"))
        pen.setWidth(4)
        p.setPen(pen)
        p.drawEllipse(cx - r, cy - r, 2 * r, 2 * r)
        pen = QPen(QColor("#3B82F6"))
        pen.setWidth(4)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        p.setPen(pen)
        p.drawArc(cx - r, cy - r, 2 * r, 2 * r, int(self._angle * 16), 260 * 16)
        p.setPen(QColor("#1F2937"))
        f = QFont("Microsoft YaHei UI", 10)
        p.setFont(f)
        p.drawText(self.rect().adjusted(0, 30, 0, 0),
                   Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop, self._text)


class _BusyWorker(QObject):
    """后台执行函数并发回结果（不创建任何 Qt 控件，仅发信号）。"""
    done = Signal(object)
    failed = Signal(str)

    def __init__(self, fn):
        super().__init__()
        self._fn = fn

    @Slot()
    def run(self):
        try:
            self.done.emit(self._fn())
        except Exception as e:  # 异常文本带回主线程展示
            self.failed.emit(str(e))


class _BusyController(QObject):
    """主线程侧回调接收器（保证 on_done / on_error 在 GUI 线程执行）。"""

    def __init__(self, on_done, on_error, owner=None):
        super().__init__(owner)
        self._on_done = on_done
        self._on_error = on_error

    @Slot(object)
    def handle_done(self, res):
        if self._on_done:
            self._on_done(res)

    @Slot(str)
    def handle_fail(self, msg):
        if self._on_error:
            self._on_error(msg)


def run_async(owner, work, on_done=None, on_error=None):
    """在后台线程执行 work()，完成后回主线程调用 on_done(result) / on_error(msg)。

    owner 用于持有 QThread / 工作对象引用，避免被回收。"""
    thread = QThread(owner)
    worker = _BusyWorker(work)
    state = {"t": thread, "w": None, "c": None}
    if not hasattr(owner, "_busy_jobs"):
        owner._busy_jobs = []
    owner._busy_jobs.append(state)

    def _finish():
        try:
            thread.quit()
            thread.wait(3000)
        except Exception:
            pass
        try:
            owner._busy_jobs.remove(state)
        except Exception:
            pass

    def _wrapped_done(res):
        try:
            if on_done:
                on_done(res)
        finally:
            _finish()

    def _wrapped_fail(msg):
        try:
            if on_error:
                on_error(msg)
        finally:
            _finish()

    # 控制器归属主线程，保证回调在 GUI 线程执行；回调结束后再收尾线程
    ctrl = _BusyController(_wrapped_done, _wrapped_fail, owner)
    state["w"], state["c"] = worker, ctrl
    worker.moveToThread(thread)
    thread.started.connect(worker.run)          # 在后台线程执行
    worker.done.connect(ctrl.handle_done)       # queued → 回主线程
    worker.failed.connect(ctrl.handle_fail)     # queued → 回主线程
    thread.start()
    return state


def busy_load(owner, text, work, on_done=None, on_error=None):
    """显示加载动画并在后台执行 work()：owner 需为 QWidget（遮罩覆盖在其上）。

    完成后自动隐藏动画；返回遮罩对象（owner._busy_overlay 同时记录，便于测试等待）。"""
    overlay = BusyOverlay(owner, text)
    owner._busy_overlay = overlay
    overlay.start()

    def _done(res):
        overlay.stop()
        owner._busy_overlay = None
        if on_done:
            on_done(res)

    def _fail(msg):
        overlay.stop()
        owner._busy_overlay = None
        if on_error:
            on_error(msg)

    run_async(owner, work, _done, _fail)
    return overlay


def wait_busy(owner, timeout_s=120.0):
    """（测试/脚本用）等待 owner 上的加载动画结束。"""
    import time as _time
    t0 = _time.time()
    app = QApplication.instance()
    while getattr(owner, "_busy_overlay", None) is not None and _time.time() - t0 < timeout_s:
        if app is not None:
            app.processEvents()
        _time.sleep(0.02)


# ============================================================ 国密 SM2 / SM3（重构）
# ---------------------------------------------------------- SM2 签名 / 验签 / 加解密（拆分子页）

class _Sm2MsgMixin:
    """SM2 子页公共：消息区构建、编码解析、文件拖拽。"""

    def _build_msg_box(self, allow_za, placeholder):
        box = QGroupBox("消息")
        mv = QVBoxLayout(box)
        row1 = QHBoxLayout()
        row1.addWidget(QLabel("消息方式"))
        self.rb_msg = QRadioButton("消息M")
        self.rb_msg.setChecked(True)
        bm = QButtonGroup(self)
        bm.addButton(self.rb_msg)
        row1.addWidget(self.rb_msg)
        self.rb_za = None
        if allow_za:
            self.rb_za = QRadioButton("Hash(Za||M)")
            bm.addButton(self.rb_za)
            self.rb_za.toggled.connect(self._refresh_msg_info)
            row1.addWidget(self.rb_za)
        row1.addSpacing(18)
        row1.addWidget(QLabel("编码"))
        self.rb_hex = QRadioButton("HEX")
        self.rb_hex.setChecked(True)
        self.rb_utf8 = QRadioButton("UTF-8")
        self.rb_b64 = QRadioButton("Base64")
        be = QButtonGroup(self)
        be.addButton(self.rb_hex)
        be.addButton(self.rb_utf8)
        be.addButton(self.rb_b64)
        for rb in (self.rb_hex, self.rb_utf8, self.rb_b64):
            row1.addWidget(rb)
        row1.addStretch(1)
        self.btn_open_file = QPushButton("选择文件 / 拖拽导入…")
        self.btn_open_file.clicked.connect(self._pick_msg_file)
        row1.addWidget(self.btn_open_file)
        mv.addLayout(row1)

        self.msg_edit = QPlainTextEdit()
        self.msg_edit.setMaximumHeight(110)
        self.msg_edit.setAcceptDrops(False)
        self.msg_edit.installEventFilter(self)
        self.msg_edit.setPlaceholderText(placeholder)
        mv.addWidget(self.msg_edit)

        row_info = QHBoxLayout()
        self.msg_info = QLabel("字节数: 0")
        self.msg_info.setStyleSheet("color:#6b7280;")
        row_info.addWidget(self.msg_info)
        row_info.addStretch(1)
        mv.addLayout(row_info)
        self.msg_edit.textChanged.connect(self._refresh_msg_info)
        return box

    def _current_msg_bytes(self):
        text = self.msg_edit.toPlainText().strip()
        if not text:
            raise ValueError("消息为空")
        if self.rb_za is not None and self.rb_za.isChecked():
            clean = ''.join(text.split())
            if len(clean) != 64 or not all(c in '0123456789abcdefABCDEF' for c in clean):
                raise ValueError("Hash(Za||M) 模式需输入 64 位十六进制 e 值（32 字节）")
            return bytes.fromhex(clean)
        if self.rb_hex.isChecked():
            clean = ''.join(text.split())
            if len(clean) % 2 != 0 or not all(c in '0123456789abcdefABCDEF' for c in clean):
                raise ValueError("HEX 模式输入不是合法十六进制")
            return bytes.fromhex(clean)
        if self.rb_b64.isChecked():
            try:
                return base64.b64decode(text)
            except Exception:
                raise ValueError("Base64 解码失败")
        return text.encode('utf-8')

    def _refresh_msg_info(self):
        try:
            data = self._current_msg_bytes()
            mode = "Hash(Za||M)" if (self.rb_za is not None and self.rb_za.isChecked()) else "消息M"
            self.msg_info.setText("%s | 字节数: %d | 开头 HEX: %s…" % (mode, len(data), data[:8].hex()))
        except Exception as e:
            self.msg_info.setText("字节数: -  (%s)" % e)

    def _pick_msg_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "选择消息文件", "",
                                              "所有文件 (*.*);;文本 (*.txt *.json *.log)")
        if path:
            self._load_msg_file(path)

    def _load_msg_file(self, path):
        """导入消息文件：显示加载动画，读取在后台线程执行后填入消息区。"""
        def work():
            with open(path, 'rb') as f:
                return f.read()

        def done(raw):
            self.rb_msg.setChecked(True)
            self.rb_hex.setChecked(True)
            self.msg_edit.setPlainText(raw.hex())
            self._append_res("[文件] %s\n已载入 %d 字节并转为 HEX" % (path, len(raw)))

        def failed(msg):
            QMessageBox.critical(self, "读取失败", msg)

        busy_load(self, "正在读取文件…", work, done, failed)

    # ---------------------------------------------------------- 消息文件拖拽
    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()
        else:
            e.ignore()

    def dragMoveEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()
        else:
            e.ignore()

    def dropEvent(self, e):
        urls = e.mimeData().urls()
        if urls:
            self._load_msg_file(urls[0].toLocalFile())

    def eventFilter(self, obj, ev):
        if obj is self.msg_edit:
            t = ev.type()
            if t == QEvent.Type.DragEnter or t == QEvent.Type.DragMove:
                if ev.mimeData().hasUrls():
                    ev.acceptProposedAction()
                    return True
            elif t == QEvent.Type.Drop:
                urls = ev.mimeData().urls()
                if urls:
                    ev.acceptProposedAction()
                    self._load_msg_file(urls[0].toLocalFile())
                    return True
            elif t == QEvent.Type.DragLeave:
                return True
        return super().eventFilter(obj, ev)


class _Sm2SignPanel(_Sm2MsgMixin, QWidget):
    """SM2 签名：私钥 + 公钥 + 消息 → r||s / DER 签名。"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 12, 16, 12)
        root.setSpacing(12)

        key_box = QGroupBox("SM2 密钥（签名需同时提供私钥与公钥）")
        key_grid = QGridLayout(key_box)
        # 比例：标签列固定宽、输入列占满剩余（避免标签灰底过宽挤压输入框）
        key_grid.setColumnMinimumWidth(0, 96)
        key_grid.setColumnStretch(0, 0)
        key_grid.setColumnStretch(1, 1)
        key_grid.setColumnStretch(2, 0)
        key_grid.setHorizontalSpacing(10)
        key_grid.setVerticalSpacing(8)
        key_grid.addWidget(QLabel("私钥 d"), 0, 0)
        self.priv_edit = QLineEdit()
        key_grid.addWidget(self.priv_edit, 0, 1)
        self.btn_gen = QPushButton("生成新密钥对")
        self.btn_gen.clicked.connect(self._gen_keypair)
        key_grid.addWidget(self.btn_gen, 0, 2, 1, 1)
        key_grid.addWidget(QLabel("公钥 P"), 1, 0)
        self.pub_edit = QLineEdit()
        self.pub_edit.setFont(QFont(MONO, 10))
        self.pub_edit.setPlaceholderText("x||y 或 04||X||Y（hex / base64 / PEM 证书均可自动识别）")
        key_grid.addWidget(self.pub_edit, 1, 1, 1, 2)
        root.addWidget(key_box)

        root.addWidget(self._build_msg_box(
            allow_za=False,
            placeholder="消息M：粘贴 HEX / UTF-8 / Base64 内容，或拖入文件（自动转 HEX）"))

        sig_box = QGroupBox("签名值（输出）")
        sv = QVBoxLayout(sig_box)
        self.sig_edit = QPlainTextEdit()
        self.sig_edit.setFont(QFont(MONO, 10))
        self.sig_edit.setMaximumHeight(110)
        self.sig_edit.setPlaceholderText("生成签名后显示 r||s（DER 形式见下方运行日志）")
        sv.addWidget(self.sig_edit)
        root.addWidget(sig_box)

        op = QHBoxLayout()
        self.btn_sign = QPushButton("生成签名")
        self.btn_sign.setObjectName("primary")
        self.btn_sign.clicked.connect(self._do_sign)
        self.btn_sm3 = QPushButton("SM3 摘要")
        self.btn_sm3.clicked.connect(self._do_sm3)
        op.addWidget(self.btn_sign)
        op.addWidget(self.btn_sm3)
        op.addStretch(1)
        self.btn_demo = QPushButton("载入演示数据")
        self.btn_demo.clicked.connect(self._load_demo)
        self.btn_clear = QPushButton("清空")
        self.btn_clear.setObjectName("ghost")
        self.btn_clear.clicked.connect(self._clear_all)
        op.addWidget(self.btn_demo)
        op.addWidget(self.btn_clear)
        root.addLayout(op)

        res_box = QGroupBox("运行日志")
        rv = QVBoxLayout(res_box)
        self.res_edit = QPlainTextEdit()
        self.res_edit.setReadOnly(True)
        self.res_edit.setFont(QFont(MONO, 10))
        self.res_edit.setMaximumHeight(150)
        rv.addWidget(self.res_edit)
        root.addWidget(res_box, 1)

    def _append_res(self, text):
        self.res_edit.appendPlainText(text)

    def _gen_keypair(self):
        priv, pub = sm2_sm3.generate_sm2_keypair()
        self.priv_edit.setText(priv)
        self.pub_edit.setText(pub)
        self._append_res("已生成 SM2 密钥对（公钥为 x||y，无 04 前缀）")

    def _do_sm3(self):
        try:
            data = self._current_msg_bytes()
        except ValueError as e:
            QMessageBox.warning(self, "提示", str(e))
            return
        self._append_res("\n[SM3 摘要] 消息 %d 字节 ->\n%s" % (len(data), sm2_sm3.sm3_hex(data)))

    def _do_sign(self):
        try:
            data = self._current_msg_bytes()
        except ValueError as e:
            QMessageBox.warning(self, "提示", str(e))
            return
        priv = self.priv_edit.text().strip()
        pub = self.pub_edit.text().strip()
        if not priv or not pub:
            QMessageBox.warning(self, "提示", "请填写（或生成）私钥与公钥")
            return
        try:
            sig = sm2_sm3.sm2_sign(data, priv, pub)
        except ValueError as e:
            QMessageBox.critical(self, "签名失败", str(e))
            return
        self.sig_edit.setPlainText(sig)
        self._append_res("\n[SM2 签名] 消息 %d 字节 | 公钥: %s…" % (len(data), pub[:20]))
        self._append_res("签名 r||s (128 hex):\n%s" % sig)
        self._append_res("签名 DER (hex):\n%s" % sm2_sm3.rs_to_der(sig).hex())

    def _load_demo(self):
        msg = b'{"random":"123456","op":"login","role":"admin"}'
        priv, pub = sm2_sm3.generate_sm2_keypair()
        self.priv_edit.setText(priv)
        self.pub_edit.setText("04" + pub)
        self.msg_edit.setPlainText(msg.hex())
        self.rb_hex.setChecked(True)
        sig = sm2_sm3.sm2_sign(msg, priv, pub)
        self.sig_edit.setPlainText(sm2_sm3.rs_to_der(sig).hex())
        self._append_res("已载入演示数据（公钥 04||X||Y、签名 DER hex）；可点「生成签名」重新生成。")

    def _clear_all(self):
        self.priv_edit.clear()
        self.pub_edit.clear()
        self.msg_edit.clear()
        self.sig_edit.clear()
        self.res_edit.clear()
        self._refresh_msg_info()


class _Sm2VerifyPanel(_Sm2MsgMixin, QWidget):
    """SM2 验签：公钥 + 签名者ID + 消息 + 签名值 → 通过 / 不通过。"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 12, 16, 12)
        root.setSpacing(12)

        cfg_box = QGroupBox("验签参数")
        cfg = QGridLayout(cfg_box)
        # 比例：标签列固定宽（灰底已透明），输入框占满剩余宽度
        cfg.setColumnMinimumWidth(0, 96)
        cfg.setColumnStretch(0, 0)
        cfg.setColumnStretch(1, 1)
        cfg.setColumnStretch(2, 0)
        cfg.setHorizontalSpacing(10)
        cfg.setVerticalSpacing(8)
        cfg.addWidget(QLabel("公钥 P"), 0, 0)
        self.pub_edit = QLineEdit()
        self.pub_edit.setFont(QFont(MONO, 10))
        self.pub_edit.setPlaceholderText("x||y 或 04||X||Y（hex / base64 / PEM 证书均可自动识别）")
        cfg.addWidget(self.pub_edit, 0, 1, 1, 2)
        cfg.addWidget(QLabel("签名者 ID"), 1, 0)
        self.id_edit = QLineEdit("1234567812345678")
        self.id_edit.setPlaceholderText("默认 1234567812345678")
        cfg.addWidget(self.id_edit, 1, 1, 1, 2)
        root.addWidget(cfg_box)

        root.addWidget(self._build_msg_box(
            allow_za=True,
            placeholder="消息M：粘贴 HEX / UTF-8 / Base64 内容，或拖入文件（自动转 HEX）\n"
                        "Hash(Za||M)：粘贴 64 位十六进制 e 值（跳过哈希计算直接验签）"))

        sig_box = QGroupBox("签名值")
        sv = QVBoxLayout(sig_box)
        self.sig_edit = QPlainTextEdit()
        self.sig_edit.setFont(QFont(MONO, 10))
        self.sig_edit.setMaximumHeight(110)
        self.sig_edit.setPlaceholderText("r||s 或 DER（hex / base64）均可，例如\n3046022100D75789…")
        sv.addWidget(self.sig_edit)
        svh = QLabel("自动识别 r||s / ASN.1 DER（hex 或 base64）格式")
        svh.setStyleSheet("color:#6b7280; font-size:11px;")
        sv.addWidget(svh)
        root.addWidget(sig_box)

        op = QHBoxLayout()
        self.btn_verify = QPushButton("验  签")
        self.btn_verify.setObjectName("success")
        self.btn_verify.clicked.connect(self._do_verify)
        op.addWidget(self.btn_verify)
        op.addStretch(1)
        self.btn_demo = QPushButton("载入演示数据")
        self.btn_demo.clicked.connect(self._load_demo)
        self.btn_clear = QPushButton("清空")
        self.btn_clear.setObjectName("ghost")
        self.btn_clear.clicked.connect(self._clear_all)
        op.addWidget(self.btn_demo)
        op.addWidget(self.btn_clear)
        root.addLayout(op)

        res_box = QGroupBox("验签结果")
        rv = QVBoxLayout(res_box)
        self.state_label = QLabel("待验证")
        self.state_label.setObjectName("stateLabel")
        self.state_label.setProperty("stateClass", "statePending")
        self.state_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._apply_state_style("pending")
        rv.addWidget(self.state_label)
        self.res_edit = QPlainTextEdit()
        self.res_edit.setReadOnly(True)
        self.res_edit.setFont(QFont(MONO, 10))
        self.res_edit.setMinimumHeight(150)
        rv.addWidget(self.res_edit)
        root.addWidget(res_box, 1)

    def _append_res(self, text):
        self.res_edit.appendPlainText(text)

    def _apply_state_style(self, state):
        if state == "ok":
            self.state_label.setProperty("stateClass", "stateOk")
            self.state_label.setText("✓  验签成功")
        elif state == "bad":
            self.state_label.setProperty("stateClass", "stateBad")
            self.state_label.setText("✗  验签失败")
        else:
            self.state_label.setProperty("stateClass", "statePending")
            self.state_label.setText("待验证")
        self.state_label.setObjectName("stateLabel")
        self.state_label.setStyleSheet("")
        self.state_label.style().unpolish(self.state_label)
        self.state_label.style().polish(self.state_label)

    def _do_verify(self):
        try:
            msg = self._current_msg_bytes()
        except ValueError as e:
            QMessageBox.warning(self, "提示", str(e))
            return
        sig = self.sig_edit.toPlainText().strip()
        pub = self.pub_edit.text().strip()
        if not sig or not pub:
            QMessageBox.warning(self, "提示", "请填写签名值和公钥（支持多种格式）")
            return
        is_za = self.rb_za is not None and self.rb_za.isChecked()
        sm2_id = self.id_edit.text().strip() or None
        try:
            ok, log = sm2_sm3.sm2_verify_ex(msg, sig, pub, sm2_id=sm2_id, msg_is_za_m=is_za)
        except Exception as e:
            QMessageBox.critical(self, "验签失败", str(e))
            return
        self._apply_state_style("ok" if ok else "bad")
        self._append_res("\n[SM2 验签] 模式: %s | 输入公钥: %s…" %
                         ("Hash(Za||M)" if is_za else "消息M", pub[:20]))
        self._append_res(log)

    def _load_demo(self):
        msg = b'{"random":"123456","op":"login","role":"admin"}'
        priv, pub = sm2_sm3.generate_sm2_keypair()
        sig = sm2_sm3.sm2_sign(msg, priv, pub)
        der = sm2_sm3.rs_to_der(sig).hex()
        self.pub_edit.setText("04" + pub)
        self.id_edit.setText("1234567812345678")
        self.msg_edit.setPlainText(msg.hex())
        self.rb_hex.setChecked(True)
        self.sig_edit.setPlainText(der)
        self._append_res("已载入演示数据（程序自生成）；下方自动验签一次作为示例。")
        ok, log = sm2_sm3.sm2_verify_ex(msg, der, "04" + pub, sm2_id="1234567812345678")
        self._apply_state_style("ok" if ok else "bad")
        self._append_res(log)

    def _clear_all(self):
        self.pub_edit.clear()
        self.msg_edit.clear()
        self.sig_edit.clear()
        self.state_label.setText("待验证")
        self.res_edit.clear()
        self._refresh_msg_info()


class _Sm2EncDecPanel(_Sm2MsgMixin, QWidget):
    """SM2 加解密：公钥加密 / 私钥解密（GM/T 0003.4，C1C3C2 密文格式）。"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 12, 16, 12)
        root.setSpacing(12)

        key_box = QGroupBox("SM2 密钥")
        key_grid = QGridLayout(key_box)
        # 比例：标签列固定宽（灰底已透明），输入框占满剩余宽度
        key_grid.setColumnMinimumWidth(0, 96)
        key_grid.setColumnStretch(0, 0)
        key_grid.setColumnStretch(1, 1)
        key_grid.setColumnStretch(2, 0)
        key_grid.setHorizontalSpacing(10)
        key_grid.setVerticalSpacing(8)
        key_grid.addWidget(QLabel("公钥 P（加密用）"), 0, 0)
        self.pub_edit = QLineEdit()
        self.pub_edit.setFont(QFont(MONO, 10))
        key_grid.addWidget(self.pub_edit, 0, 1, 1, 2)
        key_grid.addWidget(QLabel("私钥 d（解密用）"), 1, 0)
        self.priv_edit = QLineEdit()
        key_grid.addWidget(self.priv_edit, 1, 1, 1, 2)
        root.addWidget(key_box)

        root.addWidget(self._build_msg_box(
            allow_za=False,
            placeholder="消息M：加密=明文 / 解密=密文(C1C3C2 hex)。粘贴 HEX / UTF-8 / Base64，或拖入文件"))

        out_box = QGroupBox("结果输出")
        ov = QVBoxLayout(out_box)
        self.out_edit = QPlainTextEdit()
        self.out_edit.setFont(QFont(MONO, 10))
        self.out_edit.setMaximumHeight(110)
        self.out_edit.setPlaceholderText("加密后的密文(C1C3C2 hex) 或 解密后的明文显示在这里（可选中复制）")
        ov.addWidget(self.out_edit)
        root.addWidget(out_box)

        op = QHBoxLayout()
        self.btn_encrypt = QPushButton("公钥加密")
        self.btn_encrypt.clicked.connect(self._do_encrypt)
        self.btn_decrypt = QPushButton("私钥解密")
        self.btn_decrypt.clicked.connect(self._do_decrypt)
        op.addWidget(self.btn_encrypt)
        op.addWidget(self.btn_decrypt)
        op.addStretch(1)
        self.btn_demo = QPushButton("载入演示数据")
        self.btn_demo.clicked.connect(self._load_demo)
        self.btn_clear = QPushButton("清空")
        self.btn_clear.setObjectName("ghost")
        self.btn_clear.clicked.connect(self._clear_all)
        op.addWidget(self.btn_demo)
        op.addWidget(self.btn_clear)
        root.addLayout(op)

        res_box = QGroupBox("运行日志")
        rv = QVBoxLayout(res_box)
        self.res_edit = QPlainTextEdit()
        self.res_edit.setReadOnly(True)
        self.res_edit.setFont(QFont(MONO, 10))
        self.res_edit.setMinimumHeight(120)
        rv.addWidget(self.res_edit)
        root.addWidget(res_box, 1)

    def _append_res(self, text):
        self.res_edit.appendPlainText(text)

    def _do_encrypt(self):
        try:
            data = self._current_msg_bytes()
        except ValueError as e:
            QMessageBox.warning(self, "提示", str(e))
            return
        pub = self.pub_edit.text().strip()
        if not pub:
            QMessageBox.warning(self, "提示", "请填写公钥（加密用）")
            return
        try:
            ct = sm2_sm3.sm2_encrypt(data, pub)
        except Exception as e:
            QMessageBox.critical(self, "加密失败", str(e))
            return
        self.out_edit.setPlainText(ct)
        self._append_res("\n[SM2 公钥加密] 明文 %d 字节 → 密文(C1C3C2 hex, %d 字节):\n%s"
                         % (len(data), len(ct) // 2, ct))

    def _do_decrypt(self):
        try:
            ct_txt = self._current_msg_bytes()
        except ValueError as e:
            QMessageBox.warning(self, "提示", str(e))
            return
        priv = self.priv_edit.text().strip()
        if not priv:
            QMessageBox.warning(self, "提示", "请填写私钥（解密用）")
            return
        try:
            pt = sm2_sm3.sm2_decrypt(ct_txt.hex(), priv)
        except Exception as e:
            QMessageBox.critical(self, "解密失败", str(e))
            return
        try:
            shown = pt.decode('utf-8')
        except Exception:
            shown = "(非 UTF-8 明文) HEX: %s" % pt.hex()
        self.out_edit.setPlainText(shown)
        self._append_res("\n[SM2 私钥解密] 密文 %d 字节 → 明文 %d 字节:\n%s" % (len(ct_txt), len(pt), shown))

    def _load_demo(self):
        msg = b'{"random":"123456","op":"login","role":"admin"}'
        priv, pub = sm2_sm3.generate_sm2_keypair()
        self.priv_edit.setText(priv)
        self.pub_edit.setText("04" + pub)
        self.msg_edit.setPlainText(msg.hex())
        self.rb_hex.setChecked(True)
        ct = sm2_sm3.sm2_encrypt(msg, "04" + pub)
        self.out_edit.setPlainText(ct)
        self._append_res("已载入演示数据：公钥 04||X||Y、明文为消息区 hex。\n密文(C1C3C2) 已生成在「结果输出」；"
                         "把密文粘贴回消息区后可「私钥解密」还原。")
        try:
            pt = sm2_sm3.sm2_decrypt(ct, priv)
            self._append_res("自检解密成功，明文: %s" % pt.decode('utf-8', 'replace'))
        except Exception as ex:
            self._append_res("自检解密失败: %s" % ex)

    def _clear_all(self):
        self.pub_edit.clear()
        self.priv_edit.clear()
        self.msg_edit.clear()
        self.out_edit.clear()
        self.res_edit.clear()
        self._refresh_msg_info()


class Sm2Sm3Tab(QWidget):
    """国密 SM2 / SM3：签名、验签、加解密拆成三个子页，避免所有功能堆在一屏。"""

    def __init__(self, parent=None):
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        self.inner = QTabWidget()
        self.inner.addTab(_Sm2SignPanel(), "SM2 签名")
        self.inner.addTab(_Sm2VerifyPanel(), "SM2 验签")
        self.inner.addTab(_Sm2EncDecPanel(), "SM2 加解密")
        root.addWidget(self.inner)


# ============================================================ 编码转换
class CodecTab(QWidget):
    """常用编码转换：Base64 / Base64URL / HEX / UTF-8 / URL 多格式互转"""
    _IN_FORMATS = [
        ("auto", "自动识别"),
        ("base64", "Base64"),
        ("base64url", "Base64URL（URL 安全）"),
        ("hex", "HEX（十六进制）"),
        ("utf8", "UTF-8 文本"),
        ("url", "URL 编码"),
    ]
    _OUT_FORMATS = [
        ("base64", "Base64"),
        ("base64url", "Base64URL（URL 安全）"),
        ("hex_upper", "HEX 大写"),
        ("hex_lower", "HEX 小写"),
        ("utf8", "UTF-8 文本"),
        ("url", "URL 编码"),
    ]

    def __init__(self, parent=None):
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.addWidget(QLabel("输入文本 / 编码串："))

        self.in_edit = QPlainTextEdit()
        self.in_edit.setMaximumHeight(110)
        root.addWidget(self.in_edit)

        # 转换设置区
        cfg = QGroupBox("转换设置")
        g = QGridLayout(cfg)
        g.addWidget(QLabel("输入格式："), 0, 0)
        self.in_combo = QComboBox()
        for val, label in self._IN_FORMATS:
            self.in_combo.addItem(label, val)
        g.addWidget(self.in_combo, 0, 1)
        g.addWidget(QLabel("输出格式："), 0, 2)
        self.out_combo = QComboBox()
        for val, label in self._OUT_FORMATS:
            self.out_combo.addItem(label, val)
        self.out_combo.setCurrentIndex(self._OUT_FORMATS.index(("hex_upper", "HEX 大写")))
        g.addWidget(self.out_combo, 0, 3)

        self.btn_convert = QPushButton("转换")
        self.btn_convert.clicked.connect(lambda: self._convert_from_cfg())
        g.addWidget(self.btn_convert, 0, 4)

        self.btn_clear = QPushButton("清空")
        self.btn_clear.clicked.connect(self._clear)
        g.addWidget(self.btn_clear, 0, 5)

        # 快捷转换按钮
        quick = QHBoxLayout()
        for label, src, dst in (
                ("Base64 → HEX", "base64", "hex_upper"),
                ("Base64URL → HEX", "base64url", "hex_upper"),
                ("UTF-8 → HEX", "utf8", "hex_upper"),
                ("HEX → Base64", "hex", "base64"),
                ("HEX → Base64URL", "hex", "base64url"),
                ("HEX → UTF-8", "hex", "utf8"),
                ("Base64 → UTF-8", "base64", "utf8"),
        ):
            b = QPushButton(label)
            b.clicked.connect(lambda _=False, s=src, d=dst: self._quick(s, d))
            quick.addWidget(b)
        g.addLayout(quick, 1, 0, 1, 5)
        root.addWidget(cfg)

        root.addWidget(QLabel("输出："))
        self.out_edit = QPlainTextEdit()
        self.out_edit.setReadOnly(True)
        self.out_edit.setFont(QFont(MONO, 10))
        root.addWidget(self.out_edit)

    def _do_convert(self, src, dst):
        text = self.in_edit.toPlainText()
        if not text.strip():
            self.out_edit.setPlainText("")
            return
        try:
            out = codec.convert(src, dst, text)
            extra = ""
            if dst.startswith("hex"):
                extra = "\n\n[HEX] 共 %d 字节" % _hex_nbytes(out)
            self.out_edit.setPlainText(out + extra)
        except Exception as e:
            self.out_edit.setPlainText("[转换失败] %s：%s" % (src + "→" + dst, e))

    def _convert_from_cfg(self):
        src = self.in_combo.currentData()
        dst = self.out_combo.currentData()
        self._do_convert(src, dst)

    def _quick(self, src, dst):
        self._do_convert(src, dst)

    def _clear(self):
        """清空输入与输出（保留格式选择）。"""
        self.in_edit.clear()
        self.out_edit.clear()


# ============================================================ 协议分析
# ============================================================ 握手时序图视图（模式 ②）
# 客户端在左、服务端在右，虚线生命线 + 带箭头斜线表示报文的发送方向，
# 仿 TCP 三次握手示意图；每条消息左侧圆圈标注序号（时间顺序）。
class HandshakeView(QWidget):
    """密钥协商过程视图（模仿 「协商过程详情」样式）：
    - 白 → #EFF6FF 纵向渐变背景
    - 左右两侧全高彩色生命线：客户端天蓝 #93C5FD / 服务端淡红 #FCA5A5，端点标签 + 设备图标
    - 中央灰色时间轴；消息按发送方左右交替排布
    - 报文卡：客户端淡蓝 #EFF6FF / 服务端淡红 #FEF2F2 圆角卡 + 同色系外缘箭头
      （卡内嵌白底分节箱：协议版本名（TLCP 1.0 / TLS 1.2）高亮、随机数按普通文本显示、
       「支持的密码套件：点击查看详情」提示）
    - 交错淡入上浮动画（framer-motion 风格，相邻卡延迟 STAGGER_MS）
    - 点击报文卡仍在下方「关键参数」面板展开完整字段（保持 eventClicked 信号）"""
    eventClicked = Signal(object)
    certClicked = Signal(int, object)   # (证书序号, 该张证书关键字段 dict)，按钮点击弹出详情

    LANE_X = 22         # 生命线距窗口边缘距离
    LANE_W = 128        # 生命线宽（加宽以容纳完整 IP : 端口）
    LANE_GAP = 18       # 生命线与卡片之间隙（窄窗口兜底）
    AXIS_GAP = 56       # 红蓝两列固定贴近中央时间轴的轴距（不随窗口拉宽）
    CARD_MIN_W = 220
    CARD_MAX_W = 560
    CARD_PAD = 9        # 卡片内边距
    CARD_GAP = 8        # 相邻卡片纵向间距
    CARD_RADIUS = 12    # 卡片圆角
    MAX_LINES = 4       # 卡内分节箱最多显示行数
    STAGGER_MS = 130    # 相邻卡片动画启动延迟
    ANIM_MS = 240       # 单张卡片动画时长

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMouseTracking(True)
        self._events = []
        self._cards = []            # [(QRect, index, meta)]
        self._headers = []          # [(QRect, meta)] 阶段横幅（kind='phase'，全宽，不可点击）
        self._sel = -1
        self._hover = -1
        self._hover_cert = (-1, -1)  # (事件序, 证书序号) 悬停中的证书按钮
        self._hover_btn = -1         # 悬停中的「关键参数」按钮（事件序）
        self._cli_sub = ""
        self._srv_sub = ""
        self._content_h = 320
        # 动画
        self._prog = []
        self._anim_on = False
        self._t0 = QElapsedTimer()
        self._timer = QTimer(self)
        self._timer.setInterval(16)
        self._timer.timeout.connect(self._tick)

    # ------------------------------------------------------------ 数据
    def set_sequence(self, client_sub, server_sub, events):
        self._cli_sub = client_sub or ""
        self._srv_sub = server_sub or ""
        self._events = list(events)
        self._sel = -1
        self._hover = -1
        self._hover_cert = (-1, -1)
        self._hover_btn = -1
        self._relayout()
        self._start_anim()
        self.updateGeometry()
        self.update()

    def sizeHint(self):
        return PY_QSIZE(self.width() if self.width() else 900, self._content_h)

    def resizeEvent(self, ev):
        super().resizeEvent(ev)
        self._relayout()

    # ------------------------------------------------------------ 动画
    @staticmethod
    def _ease(t):
        t = max(0.0, min(1.0, t))
        return 1 - (1 - t) ** 3

    def _start_anim(self):
        n = len(self._cards)
        self._prog = [0.0] * n
        if n:
            self._t0.restart()
            self._anim_on = True
            self._timer.start()
            self.update()

    def _tick(self):
        now = self._t0.elapsed()
        done = True
        for i in range(len(self._prog)):
            st = i * self.STAGGER_MS
            if now <= st:
                self._prog[i] = 0.0
                done = False
            else:
                t = (now - st) / float(self.ANIM_MS)
                if t < 1.0:
                    done = False
                self._prog[i] = self._ease(t)
        if done:
            self._timer.stop()
            self._anim_on = False
        self.update()

    # ------------------------------------------------------------ 交互
    def _hit(self, pos):
        for rect, i, _m in self._cards:
            if rect.adjusted(-8, -2, 8, 2).contains(pos):
                return i
        return -1

    def _hit_cert(self, pos):
        """命中证书按钮 → 返回 (事件序, 证书序号)；未命中返回 (-1, -1)。

        注意：返回的是事件的索引（元组里存的 _i），不是卡片在列表中的位置——
        阶段横幅（kind='phase'）不占卡片位，卡片位与事件序在 TLCP 双向鉴别时会错位。"""
        for _ci, (_rect, _i, meta) in enumerate(self._cards):
            for br, cert_i, _label in meta.get("btn_rects") or []:
                if br.adjusted(-2, -2, 2, 2).contains(pos):
                    return (_i, cert_i)
        return (-1, -1)

    def _hit_main(self, pos):
        """命中「关键参数」按钮 → 返回该卡片对应的事件序；未命中返回 -1。"""
        for _ci, (_rect, _i, meta) in enumerate(self._cards):
            bm = meta.get("btn_main")
            if bm is not None and bm.adjusted(-3, -3, 3, 3).contains(pos):
                return _i
        return -1

    def mouseMoveEvent(self, ev):
        pos = ev.position().toPoint()
        hc = self._hit_cert(pos)
        i = self._hit(pos)
        mi = self._hit_main(pos)
        mark = (i, hc, mi)
        if mark != (self._hover, self._hover_cert, self._hover_btn):
            self._hover, self._hover_cert, self._hover_btn = i, hc, mi
            over = (i >= 0) or (hc[0] >= 0) or (mi >= 0)
            self.setCursor(Qt.CursorShape.PointingHandCursor if over else Qt.CursorShape.ArrowCursor)
            self.update()
        super().mouseMoveEvent(ev)

    def leaveEvent(self, ev):
        self._hover = -1
        self._hover_cert = (-1, -1)
        self._hover_btn = -1
        self.setCursor(Qt.CursorShape.ArrowCursor)
        self.update()
        super().leaveEvent(ev)

    def mousePressEvent(self, ev):
        if ev.button() == Qt.MouseButton.LeftButton:
            pos = ev.position().toPoint()
            ci, cert_i = self._hit_cert(pos)
            if ci >= 0:
                ev.accept()
                if 0 <= ci < len(self._events):
                    # ci 已是事件序：直接取该事件的 fields（TLCP 双向有阶段横幅时卡片位≠事件序）
                    fields = dict((k, v) for k, v in ((self._events[ci].get("fields")) or []))
                    d = self._cert_fields_for(fields, cert_i)
                    self.certClicked.emit(cert_i, d)
                return
            mi = self._hit_main(pos)
            i = self._hit(pos)
            if mi >= 0 or i >= 0:
                self._sel = i if i >= 0 else mi
                self.update()
                self.eventClicked.emit(self._events[i if i >= 0 else mi])
                ev.accept()
                return
        super().mousePressEvent(ev)

    @classmethod
    def _cert_fields_for(cls, fields, cn):
        """从 Certificate 事件的全部字段中取出第 cn 张证书的字段（去掉 certN_ 前缀）。"""
        pre = "cert%d_" % cn
        return {k[len(pre):]: v for k, v in fields.items() if k.startswith(pre)}

    # ------------------------------------------------------------ 卡片内容构建
    @staticmethod
    def _note_text(e):
        parts = ["客户端发送" if e.get("dir") == "c->s" else "服务端发送"]
        if e.get("no") is not None:
            parts.append("包 #%s" % e["no"])
        if e.get("ts") is not None:
            parts.append("%.3fs" % e["ts"])
        return " · ".join(parts)

    @staticmethod
    def _field_label(k):
        if k == "cipher_suites_full":
            return "密码套件"
        if k == "selected_cipher_suite":
            return "最终选定密码套件"
        name = str(k)
        if "random" in name.lower() or "随机" in name:
            return "随机数"
        return name

    @staticmethod
    def _cert_label(k):
        name = str(k)
        return {"cert_chain_count": "证书链数"}.get(name, name)

    @staticmethod
    def _value_html(k, disp, s):
        import re
        short = s.replace("\n", " ").strip()
        if len(short) > 96:
            short = short[:96] + "…"
        es = _html.escape(short)
        el = _html.escape(disp)
        if "version" in str(k).lower() or "版本" in disp:
            # 协议版本名（如 TLCP 1.0 / TLS 1.2）高亮，括号中的十六进制代码保持普通
            m = re.match(r"^(.*?)(?=\s*\(|\s*（|$)", short)
            name = m.group(1) if m else short
            rest = short[len(name):]
            inner = ("<b><span style='color:#2563eb'>%s</span></b>%s"
                     % (_html.escape(name), _html.escape(rest)))
        elif "随机数" in disp:
            inner = es
        elif "最终选定密码套件" in disp or "选定" in disp:
            inner = "<b><span style='color:#2563eb'>%s</span></b>" % es
        elif "算法" in disp or "套件" in disp:
            inner = "<b>%s</b>" % es
        else:
            inner = es
        return "<span style='color:#374151'>%s：</span>%s" % (el, inner)

    def _content_html(self, e):
        divs = []
        fields = e.get("fields") or []
        title = e.get("title") or ""
        if title in ("ServerKeyExchange", "CertificateVerify", "ServerHello") and fields:
            self._append_verify_badge(divs, dict(fields))
        if not fields:
            d = (e.get("detail") or "").strip()
            if d:
                divs.append("<div style='color:#6b7280;font-style:italic'>%s</div>" % _html.escape(d))
            return "\n".join(divs)
        if e.get("title") == "Certificate":
            return self._cert_html(fields)
        if e.get("title") == "KEX_REPLY":
            return self._kex_reply_html(fields)
        total = len(fields)
        shown = 0
        for k, v in fields:
            disp = self._field_label(k)
            s = str(v)
            if " | " in s:
                parts = [x for x in (p.strip() for p in s.split(" | ")) if x]
                n = len(parts)
                if k == "cipher_suites_full":
                    divs.append("<div><span style='color:#1677ff;text-decoration:underline'>"
                                "支持的密码套件（%d 项）：点击查看详情</span></div>" % n)
                else:
                    first = parts[0]
                    divs.append("<div><span style='color:#374151'>%s：</span>%s "
                                "<span style='color:#9ca3af'>… 等 %d 项</span></div>"
                                % (_html.escape(disp), _html.escape(first), n))
                shown += 1
            else:
                divs.append("<div>%s</div>" % self._value_html(k, disp, s))
                shown += 1
            if shown >= self.MAX_LINES and shown < total:
                divs.append("<div style='color:#9ca3af'>… 其余 %d 项，点击下方展开查看全部</div>"
                            % (total - shown))
                break
        return "\n".join(divs)

    @staticmethod
    def _clip(s, n):
        return s if len(s) <= n else s[:n] + "…"

    @staticmethod
    def _append_verify_badge(divs, fd):
        """在消息卡片首页追加验签徽标（TLS / TLCP 的 ServerKeyExchange / CertificateVerify）。"""
        ok = fd.get("验签结果")
        if not ok:
            return
        if ok == "通过":
            badge = ("<span style='background:#DCFCE7;color:#15803D;border-radius:3px;"
                     "padding:0 5px;font-weight:bold'>验签通过 ✓</span>")
        elif ok == "失败":
            badge = ("<span style='background:#FEE2E2;color:#B91C1C;border-radius:3px;"
                     "padding:0 5px;font-weight:bold'>验签失败 ✗</span>")
        else:
            badge = ("<span style='background:#FEF3C7;color:#92400E;border-radius:3px;"
                     "padding:0 5px;font-weight:bold'>未能验签 ⚠</span>")
        alg = fd.get("签名算法") or "签名验证"
        divs.append("<div><span style='color:#374151'>身份鉴别（%s）：</span>%s</div>"
                    % (_html.escape(str(alg)), badge))
        detail = fd.get("验签详情")
        if detail:
            divs.append("<div style='color:#6b7280'>%s</div>" % _html.escape(str(detail)))

    def _cert_html(self, fields):
        """Certificate 卡首页展示：证书值（公钥 / 算法 / 签名值 / 指纹等）直接放在视图里。"""
        f = {}
        for k, v in fields:
            f[k] = v

        def get(cn, key):
            v = f.get("cert%d_%s" % (cn, key))
            return "" if v is None else str(v)

        divs = []
        n = f.get("cert_chain_count")
        if n:
            divs.append("<div style='color:#374151'><b>证书链</b>：%d 张（点击下方「证书 N」按钮查看每张详情）</div>" % n)
        for i in range(1, 2):  # 首页详列第 1 张，其余点击展开
            pre = ("<b>第 %d 张</b>·" % i) if (n or 1) > 1 else "<b>证书</b>·"
            sub = get(i, "subject")
            pub = get(i, "pubkey")
            alg = get(i, "sig_algorithm")
            sig = get(i, "sig_value")
            thb = get(i, "sha256_thumb")
            if sub:
                divs.append("<div>%s主体：%s</div>" % (pre, _html.escape(self._clip(sub, 60))))
            if pub:
                divs.append("<div>%s公钥算法：%s</div>" % (pre, _html.escape(self._clip(pub, 40))))
            if alg:
                divs.append("<div>%s签名算法：%s</div>" % (pre, _html.escape(self._clip(alg, 40))))
            cu = get(i, "ext_key_usage")
            ku = get(i, "key_usage")
            if cu:
                divs.append("<div>%s证书用途：%s</div>" % (pre, _html.escape(self._clip(cu, 44))))
            if ku:
                divs.append("<div>%s密钥用途：%s</div>" % (pre, _html.escape(self._clip(ku, 40))))
            if sig:
                divs.append("<div>%s签名值：<span style='font-family:Consolas'>%s</span></div>"
                            % (pre, _html.escape(self._clip(sig, 24))))
            if thb:
                divs.append("<div>%s指纹SHA256：<span style='font-family:Consolas'>%s</span></div>"
                            % (pre, _html.escape(self._clip(thb, 14))))
        if (n or 1) > 1:
            divs.append("<div style='color:#9ca3af'>… 其余 %d 张证书，点击下方「证书 N」按钮查看详情</div>"
                        % ((n or 1) - 1))
        return "\n".join(divs)

    def _kex_reply_html(self, fields):
        """CSSH KEX_REPLY 卡首页：双证书（签名∥加密）+ random-server + SM2 签名值 + 验签。"""
        f = {}
        for k, v in fields:
            f[k] = v
        divs = [self.__class__._cert_html_inner(f, 1, 2)]
        if f.get("random-server"):
            divs.append("<div><span style='color:#374151'>random-server：</span>"
                        "<span style='font-family:Consolas'>%s</span></div>"
                        % _html.escape(self._clip(str(f["random-server"]), 24)))
        if f.get("签名值 (DER)"):
            divs.append("<div><span style='color:#374151'>签名值 (DER，GB/T 35276)：</span>"
                        "<span style='font-family:Consolas'>%s…</span></div>"
                        % _html.escape(self._clip(str(f["签名值 (DER)"]), 30)))
        if f.get("验签结果"):
            ok = f["验签结果"]
            if ok == "通过":
                badge = "<span style='background:#DCFCE7;color:#15803D;border-radius:3px;padding:0 5px;font-weight:bold'>验签通过 ✓</span>"
            elif ok == "失败":
                badge = "<span style='background:#FEE2E2;color:#B91C1C;border-radius:3px;padding:0 5px;font-weight:bold'>验签失败 ✗</span>"
            else:
                badge = "<span style='background:#FEF3C7;color:#92400E;border-radius:3px;padding:0 5px;font-weight:bold'>未能验签 ⚠</span>"
            divs.append("<div><span style='color:#374151'>SM2 验签（M=rc∥rs）：</span>%s</div>" % badge)
        return "\n".join(divs)

    @staticmethod
    def _cert_html_inner(f, n_first=1, n_total=1):
        """证书区行渲染（供 Certificate / KEX_REPLY 卡复用）。"""
        html_out = HandshakeView._cert_html_shared(f, n_first, n_total)
        return html_out

    @staticmethod
    def _cert_html_shared(f, n_first, n_total):
        divs = []
        divs.append("<div style='color:#374151'><b>证书链</b>：%d 张（点击下方「证书 N」按钮查看每张详情）</div>" % n_total)
        for i in range(1, n_first + 1):
            pre = ("<b>第 %d 张</b>·" % i) if n_total > 1 else "<b>证书</b>·"
            ku = f.get("cert%d_key_usage" % i)
            if ku:
                divs.append("<div>%s密钥用途：%s</div>" % (pre, _html.escape(HandshakeView._clip(str(ku), 40))))
            if ku and i == 1 and "数字签名" not in str(ku):
                divs.append("<div style='color:#B45309'>　↳ 签名证书 keyUsage 未声明数字签名（GB/T 38540 加密证书格式如实解析，实际仍承担 SM2 签名）</div>")
            sub = f.get("cert%d_subject" % i)
            if sub:
                divs.append("<div>%s主体：%s</div>" % (pre, _html.escape(HandshakeView._clip(str(sub), 60))))
        return "\n".join(divs)

    def _card_meta(self, e, side, cw):
        fm_n = QFontMetrics(QFont("Microsoft YaHei UI", 7.5))
        note = self._note_text(e)
        title = e.get("title") or ("握手消息" if side == "server" else "消息")
        title_h = 18
        note_h = fm_n.height()
        doc = QTextDocument()
        doc.setDefaultFont(QFont("Microsoft YaHei UI", 8))
        doc.setHtml(self._content_html(e))
        doc.setTextWidth(cw - self.CARD_PAD * 2)
        box_h = 6 + int(doc.size().height()) + 6
        meta = {"title": title, "note": note, "doc": doc, "side": side,
                "title_h": title_h, "note_h": note_h, "box_h": box_h,
                "certs": 0, "btn_h": 0, "btn_rects": [], "rect": QRect()}
        if title in ("Certificate", "KEX_REPLY"):
            f = dict((k, v) for k, v in (e.get("fields") or []))
            n = f.get("cert_chain_count") or 0
            for idx in range(1, 64):
                if f.get("cert%d_subject" % idx) is None:
                    break
                n = max(n, idx)
            meta["certs"] = n
            meta["btn_h"] = 30 if n else 0
        return meta

    def _build(self):
        W = max(self.width(), 880)
        lane_right = self.LANE_X + self.LANE_W + self.LANE_GAP
        max_usable = W - lane_right * 2
        cw = (max_usable - self.AXIS_GAP) // 2
        cw = max(self.CARD_MIN_W, min(self.CARD_MAX_W, cw))
        # 两列对称地贴近中央时间轴：中间轴距固定，大窗口也不再留白
        total = 2 * cw + self.AXIS_GAP
        start_x = max(lane_right, (W - total) // 2)
        client_x = start_x
        server_x = W - start_x - cw
        y = 10
        cards = []
        headers = []
        for i, e in enumerate(self._events):
            if e.get("kind") == "phase":
                # 阶段横幅：横贯左右生命线之间的全宽标题条，不进卡片区
                bh = 32
                hw = max(W - (self.LANE_X + self.LANE_W + self.LANE_GAP) * 2, 240)
                rect = QRect((W - hw) // 2, y, hw, bh)
                headers.append((QRect(rect), e))
                y += bh + 10
                continue
            side = "client" if e.get("dir") == "c->s" else "server"
            meta = self._card_meta(e, side, cw)
            h = (self.CARD_PAD * 2 + meta["title_h"] + meta["note_h"] + 6 + meta["box_h"]
                 + meta["btn_h"])
            x = client_x if side == "client" else server_x
            rect = QRect(x, y, cw, h)
            meta["rect"] = QRect(rect)
            # 「关键参数」按钮（常驻每张卡片右上角，点击弹出该包详情）
            fm3 = QFontMetrics(QFont("Microsoft YaHei UI", 7.5))
            lab = "关键参数"
            cw3 = fm3.horizontalAdvance(lab) + 15
            meta["btn_main"] = QRect(rect.right() - self.CARD_PAD - cw3, rect.y() + 4, cw3, 18)
            if meta["certs"]:
                meta["btn_rects"] = self._build_cert_btns(rect, meta)
            cards.append((rect, i, meta))
            y += h + self.CARD_GAP
        self._cards = cards
        self._headers = headers
        self._content_h = y + 14

    def _build_cert_btns(self, rect, meta):
        """在证书卡底部生成一排「证书 1 / 证书 2 …」按钮区域。"""
        fm = QFontMetrics(QFont("Microsoft YaHei UI", 8))
        pad = self.CARD_PAD
        chh = 20
        by = rect.bottom() - meta["btn_h"] + (meta["btn_h"] - chh) // 2
        bx = rect.x() + pad
        rects = []
        for i in range(1, int(meta["certs"]) + 1):
            label = "证书 %d" % i
            cw = fm.horizontalAdvance(label) + 18
            rects.append((QRect(bx, by, cw, chh), i, label))
            bx += cw + 8
        return rects

    def _relayout(self):
        self._build()
        self.setMinimumHeight(self._content_h)
        self.updateGeometry()
        old = len(self._prog)
        new = len(self._cards)
        if old != new:
            self._prog = self._prog[:new] + [1.0] * (new - old)

    # ------------------------------------------------------------ 辅助绘制
    def _lane_rect(self, side):
        W = max(self.width(), 1)
        H = max(self.height(), 1)
        if side == "client":
            return QRect(self.LANE_X, 0, self.LANE_W, H), QColor("#93C5FD")
        return QRect(W - self.LANE_X - self.LANE_W, 0, self.LANE_W, H), QColor("#FCA5A5")

    @staticmethod
    def _draw_device_icon(p, side, cx, y):
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QBrush(QColor("#334155")))
        if side == "client":   # 手机
            p.drawRoundedRect(QRect(cx - 7, y, 14, 22), 4, 4)
            p.drawRect(QRect(cx - 3, y - 2, 6, 2))
            p.setBrush(QBrush(QColor("#93C5FD")))
            p.drawRoundedRect(QRect(cx - 4, y + 3, 8, 13), 2, 2)
        else:                  # 服务器
            for k in range(3):
                p.drawRoundedRect(QRect(cx - 13, y + k * 7, 26, 6), 2, 2)

    def _draw_lane(self, p, side):
        rect, col = self._lane_rect(side)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QBrush(col))
        p.drawRect(rect)
        H = rect.height()
        cx = rect.center().x()
        if side == "client":
            tcol = "#2563EB"
            sdt = "客户端"
            sub = self._cli_sub
        else:
            tcol = "#DC2626"
            sdt = "服务端"
            sub = self._srv_sub
        self._draw_device_icon(p, side, cx, H // 2 - 34)
        box_w = rect.width() - 6
        p.setFont(QFont("Microsoft YaHei UI", 8, QFont.Weight.Bold))
        p.setPen(QColor(tcol))
        p.drawText(QRect(rect.x() + 2, H // 2 - 14, box_w, 16), Qt.AlignmentFlag.AlignHCenter, sdt)
        p.setFont(QFont("Consolas", 7))
        p.setPen(QColor("#4b5563"))
        fm = p.fontMetrics()
        ty = H // 2 + 6
        if fm.horizontalAdvance(sub) <= box_w:
            p.drawText(QRect(rect.x() + 2, ty, box_w, 14), Qt.AlignmentFlag.AlignHCenter, sub)
        else:
            p.drawText(QRect(rect.x() + 2, ty, box_w, 30),
                       Qt.AlignmentFlag.AlignHCenter | Qt.TextFlag.TextWordWrap, sub)

    def _draw_arrow(self, p, side, cx, cy):
        col = QColor("#3B82F6") if side == "client" else QColor("#EF4444")
        if side == "client":
            x0, x1 = cx - 4, cx + 13
        else:
            x0, x1 = cx + 4, cx - 13
        p.setPen(QPen(col, 2))
        p.drawLine(x0, cy, x1, cy)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QBrush(col))
        if side == "client":
            p.drawPolygon(QPolygon([QPoint(x1, cy), QPoint(x1 - 8, cy - 5), QPoint(x1 - 8, cy + 5)]))
        else:
            p.drawPolygon(QPolygon([QPoint(x1, cy), QPoint(x1 + 8, cy - 5), QPoint(x1 + 8, cy + 5)]))

    # ------------------------------------------------------------ 卡片绘制
    def _draw_card(self, p, rect, meta, i):
        sel = (i == self._sel)
        hover = (i == self._hover)
        side = meta["side"]
        if side == "client":
            bc, bgc, ac = QColor("#60A5FA"), QColor("#EFF6FF"), QColor("#3B82F6")
        else:
            bc, bgc, ac = QColor("#F87171"), QColor("#FEF2F2"), QColor("#EF4444")
        R = self.CARD_RADIUS

        # 投影
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QBrush(QColor(15, 35, 60, 22)))
        p.drawRoundedRect(QRect(rect.x() + 2, rect.y() + 3, rect.width(), rect.height()), R, R)
        # 底色 + 边框
        bw = 3 if sel else (2 if hover else 1.5)
        p.setBrush(QBrush(bgc))
        p.setPen(QPen(bc, bw))
        p.drawRoundedRect(rect, R, R)
        if sel:
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QBrush(QColor(bc.red(), bc.green(), bc.blue(), 26)))
            p.drawRoundedRect(rect, R, R)

        # 外缘箭头（指向对端）
        cy = rect.center().y()
        if side == "client":
            self._draw_arrow(p, side, rect.right() + 7, cy)
        else:
            self._draw_arrow(p, side, rect.left() - 7, cy)

        pad = self.CARD_PAD
        x = rect.x() + pad
        tw = rect.width() - pad * 2
        # 卡片标题
        p.setFont(QFont("Microsoft YaHei UI", 10.5, QFont.Weight.Bold))
        p.setPen(QColor("#1F2937"))
        p.drawText(QRect(x, rect.y() + 4, tw, meta["title_h"]),
                   Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, meta["title"])
        y = rect.y() + 4 + meta["title_h"]
        # 方向 / 时间注释（斜体）
        f_n = QFont("Microsoft YaHei UI", 7.5)
        f_n.setItalic(True)
        p.setFont(f_n)
        p.setPen(QColor("#6B7280"))
        p.drawText(QRect(x, y, tw, meta["note_h"]),
                   Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, meta["note"])
        # 白底分节箱（关键参数摘要）
        box_top = y + meta["note_h"] + 5
        box_h = rect.y() + rect.height() - pad - box_top - meta["btn_h"]
        box = QRect(x, box_top, tw, box_h)
        p.setBrush(QBrush(QColor("#FFFFFF")))
        p.setPen(QPen(QColor("#E5E7EB"), 1))
        p.drawRoundedRect(box, 6, 6)
        p.save()
        p.translate(x + 5, box_top + 6)
        meta["doc"].drawContents(p)
        p.restore()

        # 证书按钮排（证书 1 / 证书 2 …，点击弹出单张证书详情）
        for br, ci, label in meta["btn_rects"]:
            sel_b = (ci == self._hover_cert[1] and self._hover_cert[0] == i)
            p.setPen(QPen(QColor("#2563EB"), 2 if sel_b else 1))
            p.setBrush(QBrush(QColor(255, 255, 255, 235)))
            p.drawRoundedRect(br, 10, 10)
            p.setFont(QFont("Microsoft YaHei UI", 8))
            p.setPen(QColor("#2563EB"))
            p.drawText(br, Qt.AlignmentFlag.AlignCenter, label)

        # 「关键参数」按钮（常驻每卡右上角，点击弹出该包详情）
        bm = meta.get("btn_main")
        if bm is not None:
            bm_hover = (self._hover_btn == i)
            p.setPen(QPen(QColor("#2563EB"), 2 if bm_hover else 1))
            p.setBrush(QBrush(QColor(255, 255, 255, 240)))
            p.drawRoundedRect(bm, 9, 9)
            p.setFont(QFont("Microsoft YaHei UI", 7.5, QFont.Weight.DemiBold))
            p.setPen(QColor("#2563EB"))
            p.drawText(bm, Qt.AlignmentFlag.AlignCenter, "关键参数")

    def _draw_phase(self, p, rect, ev):
        """阶段横幅：TLCP 双向鉴别时区分「①服务端鉴别 / ②客户端鉴别」的标题条。"""
        g = QLinearGradient(rect.topLeft(), rect.bottomLeft())
        g.setColorAt(0.0, QColor("#E0E7FF"))
        g.setColorAt(1.0, QColor("#F5F7FF"))
        p.setPen(QPen(QColor("#C7D2FE"), 1))
        p.setBrush(QBrush(g))
        p.drawRoundedRect(rect, 9, 9)
        p.setFont(QFont("Microsoft YaHei UI", 10, QFont.Weight.DemiBold))
        p.setPen(QColor("#3730A3"))
        p.drawText(QRect(rect.x() + 10, rect.y(), rect.width() - 20, rect.height()),
                   Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                   ev.get("title") or "")
        p.setFont(QFont("Consolas", 7.5))
        p.setPen(QColor("#6D28D9"))
        p.drawText(QRect(rect.x() + 10, rect.y(), rect.width() - 20, rect.height()),
                   Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                   ev.get("detail") or "")

    # ------------------------------------------------------------ 绘制
    def paintEvent(self, ev):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        W = max(self.width(), 1)
        H = max(self.height(), 1)

        # 白 → #EFF6FF 纵向渐变背景
        g = QLinearGradient(0, 0, 0, H)
        g.setColorAt(0.0, QColor("#FFFFFF"))
        g.setColorAt(1.0, QColor("#EFF6FF"))
        p.fillRect(QRect(0, 0, W, H), QBrush(g))

        # 左右全高彩色生命线 + 端点标签
        self._draw_lane(p, "client")
        self._draw_lane(p, "server")

        # 中央时间轴
        p.setPen(QPen(QColor(209, 213, 219, 170), 2))
        p.drawLine(W // 2, 0, W // 2, H)

        # 阶段横幅（TLCP 双向鉴别）
        for rect, ev in self._headers:
            self._draw_phase(p, rect, ev)

        # 报文卡（交错淡入上浮动画）
        for idx, (rect, i, meta) in enumerate(self._cards):
            prog = self._prog[idx] if idx < len(self._prog) else 1.0
            if prog <= 0.0:
                continue
            p.save()
            p.translate(0, int((1.0 - prog) * 16))
            p.setOpacity(prog)
            self._draw_card(p, rect, meta, i)
            p.restore()

        p.end()


# ============================================================ 详情弹窗（包 / 证书）
_CERT_LABELS = {
    "version": "证书版本",
    "serial": "序列号",
    "subject": "使用者",
    "issuer": "颁发者",
    "not_before": "有效期起",
    "not_after": "有效期止",
    "pubkey": "公钥算法",
    "pubkey_curve": "公钥曲线",
    "sig_algorithm": "签名算法",
    "basic_constraints": "CA 约束 (BasicConstraints)",
    "ext_key_usage": "证书用途 (EKU)",
    "key_usage": "密钥用途 (KeyUsage)",
    "sha256_thumb": "SHA256 指纹",
    "sig_sha256": "签名值 SHA256",
    "sig_value": "完整签名值 (HEX)",
    "error": "解析提示",
}


class PacketDetailDialog(QDialog):
    """单个通信消息的关键参数弹窗（时序图每卡「关键参数」按钮 / 点击消息框弹出，可多开）。

    内容按「块状卡片」展示：每部分参数一个卡片，长数据（HEX/签名值等）用等宽代码块
    折行显示，完整不省略，便于阅读与手动核对。"""
    def __init__(self, title, html, parent=None, plain_text=""):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(760, 620)
        lay = QVBoxLayout(self)
        browse = QTextBrowser()
        browse.setOpenExternalLinks(False)
        browse.setFont(QFont("Microsoft YaHei UI", 9))
        if html:
            browse.setHtml(html)
        else:
            browse.setPlainText(plain_text or "")
        lay.addWidget(browse, 1)
        btn = QPushButton("关闭")
        btn.clicked.connect(self.accept)
        lay.addWidget(btn, 0, Qt.AlignmentFlag.AlignHCenter)
        self.browser = browse
        self.edit = browse


class SummaryDialog(QDialog):
    """「协商过程总结」弹窗：富文本展示最终密码套件 / 证书链 / 双向身份鉴别信息。

    主视图时序图右上角的「查看协商总结」按钮点击弹出，以免横幅占用主界面篇幅。"""
    def __init__(self, title, html, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title or "协商过程总结")
        self.resize(800, 560)
        lay = QVBoxLayout(self)
        browse = QTextBrowser()
        browse.setOpenExternalLinks(False)
        browse.setHtml(html or "")
        lay.addWidget(browse, 1)
        btn = QPushButton("关闭")
        btn.clicked.connect(self.accept)
        lay.addWidget(btn, 0, Qt.AlignmentFlag.AlignHCenter)
        self.browser = browse


class CertDetailDialog(QDialog):
    """证书详情窗口：展示单张证书的全部关键字段（点击时序图「证书 N」按钮弹出），
    并提供「导出证书 (.cer)」按钮把原始 DER 证书存到本地。

    版式：块状卡片 + 高亮签名算法 / 有效期 / 密钥用途；有效期与当前系统时间比对，
    给出「有效 ✓（绿）/ 已过期 ✗（红）」标志。"""
    def __init__(self, cert_index, fields, parent=None):
        super().__init__(parent)
        self.setWindowTitle("证书详情 · 第 %d 张" % cert_index)
        self.resize(780, 640)
        lay = QVBoxLayout(self)
        head = QLabel("服务端证书 · 第 %d 张" % cert_index)
        head.setStyleSheet("font-size:13px; font-weight:bold; color:#1F2937;")
        lay.addWidget(head)
        hint = QLabel("该窗口由时序图卡片上的「证书 %d」按钮弹出，字段与报文中携带的证书一致，可作留存核验。"
                      % cert_index)
        hint.setWordWrap(True)
        hint.setStyleSheet("color:#78909C; font-size:11px;")
        lay.addWidget(hint)

        btnrow = QHBoxLayout()
        btn_export = QPushButton("导出证书 (.cer)")
        btn_export.setToolTip("把该证书按原始 DER 编码保存到本机（如 .cer 文件）")
        btn_export.clicked.connect(lambda: self._export(fields))
        btn_close = QPushButton("关闭")
        btn_close.clicked.connect(self.accept)
        btnrow.addWidget(btn_export)
        btnrow.addStretch(1)
        btnrow.addWidget(btn_close)
        lay.addLayout(btnrow)

        browse = QTextBrowser()
        browse.setOpenExternalLinks(False)
        browse.setFont(QFont("Microsoft YaHei UI", 9))
        browse.setHtml(self._detail_html(fields, cert_index))
        lay.addWidget(browse, 1)
        self.browser = browse
        self.edit = browse

    # ------------------------------------------------------------ 版式（块状 + 高亮）

    @staticmethod
    def _parse_cert_time(s):
        """'YYYY/M/D H:M:S'（无前导零）→ datetime；失败返回 None。"""
        from datetime import datetime
        try:
            d, t = str(s).strip().split(" ")
            y, mo, dd = d.split("/")
            hh, mi, ss = t.split(":")
            return datetime(int(y), int(mo), int(dd), int(hh), int(mi), int(ss))
        except Exception:
            return None

    @classmethod
    def _validity_badge(cls, fields):
        """有效期与当前系统时间比对：有效（绿）/ 已过期（红）/ 未生效（红）。"""
        nb = cls._parse_cert_time(fields.get("not_before"))
        na = cls._parse_cert_time(fields.get("not_after"))
        if not nb or not na:
            return "", None
        from datetime import datetime
        now = datetime.now()
        if nb <= now <= na:
            return handshake_view._badge("有效 ✓", "#DCFCE7", "#15803D", "#BBF7D0"), "ok"
        if now > na:
            return handshake_view._badge("已过期 ✗", "#FEE2E2", "#B91C1C", "#FECACA"), "expired"
        return handshake_view._badge("未生效 ✗", "#FEE2E2", "#B91C1C", "#FECACA"), "notyet"

    @classmethod
    def _detail_html(cls, fields, cert_index):
        from html import escape
        hv = handshake_view
        out = []
        subj = fields.get("subject") or "(未知)"
        out.append(hv._card("<b style='font-size:13px;color:#1F2937'>%s</b>"
                            "<span style='color:%s;font-size:11px'>　第 %d 张证书</span>"
                            % (escape(str(subj)), hv.LABEL_COLOR, cert_index),
                            accent=hv.ACCENT_BLUE))
        if fields.get("issuer"):
            out.append(hv._kv_block("颁发者", "<span style='%s'>%s</span>"
                                    % (hv.VAL_CSS, escape(str(fields["issuer"])))))
        # 有效期（高亮 + 有效/过期标志，标志放在本块内）
        nb, na = fields.get("not_before"), fields.get("not_after")
        if nb or na:
            badge, _state = cls._validity_badge(fields)
            val = ("%s<br><span style='%s'>%s</span>　→　<span style='%s'>%s</span>"
                   % (badge,
                      hv.VAL_CSS, escape(str(nb or "?")),
                      hv.VAL_CSS, escape(str(na or "?"))))
            out.append(hv._kv_block("有效期", val, color="#B45309",
                                    accent=("#22C55E" if _state == "ok" else "#EF4444")))
        # 签名算法（高亮）
        if fields.get("sig_algorithm"):
            chip = hv._badge(escape(str(fields["sig_algorithm"])), "#EFF6FF", "#1D4ED8", "#BFDBFE")
            out.append(hv._kv_block("签名算法", chip, color="#1D4ED8", accent=hv.ACCENT_BLUE))
        # 密钥用途 / 证书用途（高亮）
        if fields.get("key_usage"):
            chip = hv._badge(escape(str(fields["key_usage"])), "#FEF3C7", "#92400E", "#FDE68A")
            out.append(hv._kv_block("密钥用途 (KeyUsage)", chip, color="#B45309",
                                    accent=hv.ACCENT_AMBER))
        if fields.get("ext_key_usage"):
            chip = hv._badge(escape(str(fields["ext_key_usage"])), "#FEF3C7", "#92400E", "#FDE68A")
            out.append(hv._kv_block("证书用途 (EKU)", chip, color="#B45309",
                                    accent=hv.ACCENT_AMBER))
        # 其余字段
        for key in ("version", "serial", "pubkey", "pubkey_curve", "basic_constraints",
                    "sha256_thumb", "sig_sha256", "error"):
            if fields.get(key) not in (None, ""):
                out.append(hv._kv_block(_CERT_LABELS.get(key, key),
                                        "<span style='%s'>%s</span>"
                                        % (hv.VAL_CSS, escape(str(fields[key])))))
        # 长数据代码块
        sv = str(fields.get("sig_value") or "")
        if sv:
            out.append(hv._code_block("完整签名值（%d 字节，HEX）" % (len(sv) // 2), sv))
        der = str(fields.get("der_hex") or "")
        if der:
            out.append(hv._code_block("完整证书 DER（%d 字节，HEX）" % (len(der) // 2), der,
                                      accent=hv.ACCENT_AMBER))
        # 未在常用映射中的额外字段
        known = {"version", "serial", "subject", "issuer", "not_before", "not_after",
                 "sig_algorithm", "pubkey", "pubkey_curve", "key_usage", "ext_key_usage",
                 "basic_constraints", "sha256_thumb", "sig_sha256", "sig_value", "der_hex",
                 "error"}
        for k, v in fields.items():
            if k in known:
                continue
            out.append(hv._kv_block(_CERT_LABELS.get(k, k),
                                    "<span style='%s'>%s</span>" % (hv.VAL_CSS, escape(str(v)))))
        return ("<div style='font-family:\"Microsoft YaHei UI\",\"Microsoft YaHei\";"
                "font-size:12px;color:#374151'>%s</div>" % "".join(out))

    @staticmethod
    def _export(fields):
        der_hex = fields.get("der_hex")
        if not der_hex:
            QMessageBox.information(None, "导出证书", "该证书未保留原始 DER 数据，无法导出")
            return
        from datetime import datetime
        default = "cert_%s.cer" % (fields.get("serial") or
                                   datetime.now().strftime("%Y%m%d%H%M%S"))
        path, _ = QFileDialog.getSaveFileName(None, "保存证书", default,
                                              "证书 (*.cer);;PEM (*.pem);;所有文件 (*)")
        if not path:
            return
        try:
            with open(path, "wb") as f:
                f.write(bytes.fromhex(der_hex))
            QMessageBox.information(None, "导出证书", "已导出到：\n%s" % path)
        except Exception as e:
            QMessageBox.critical(None, "导出证书", "导出失败：%s" % e)

    @staticmethod
    def _format(fields):
        lines = []
        for k in ("version", "serial", "subject", "issuer"):
            if k in fields:
                lines.append("%s：%s" % (_CERT_LABELS.get(k, k), fields[k]))
        nb, na = fields.get("not_before"), fields.get("not_after")
        if nb and na:
            lines.append("有效期：%s - %s" % (nb, na))
        for k in ("sig_algorithm", "pubkey", "pubkey_curve", "key_usage",
                  "ext_key_usage", "basic_constraints",
                  "sig_sha256", "sha256_thumb", "sig_value"):
            if k in fields:
                lines.append("%s：%s" % (_CERT_LABELS.get(k, k), fields[k]))
        seen = {"version", "serial", "subject", "issuer", "not_before", "not_after",
                "sig_algorithm", "pubkey", "pubkey_curve", "key_usage",
                "ext_key_usage", "basic_constraints", "sig_sha256", "sha256_thumb",
                "sig_value", "der_hex"}
        for k, v in fields.items():
            if k in seen:
                continue
            if k == "der_hex":
                continue
            lines.append("%s：%s" % (_CERT_LABELS.get(k, k), v))
        return "\n".join(lines)


class PcapTab(QWidget):
    """协议分析 (pcap)：表格总览 + 点击行查看单包协议字段树，
    并可一键查看该 TCP 流的完整消息交互（支持 TLS / TLCP / SSH / CSSH）。"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self._pkts = []
        self._row_pkt = []          # 表格每行对应的 packet
        self._detail_map = {}       # id(QTreeWidgetItem) -> [(字段, 值)]
        self._all_rows = []
        self._all_pkts = []
        self._streams = None
        self._row_flow = []         # 表格每行对应的 TCP 流 key（或 None）
        self._file_summary = ""     # 文件概述（单行，供 info_label）
        self._summary_html = ""     # 当前「协商过程总结」HTML（供弹窗显示）
        self._summary_title = "协商过程总结"
        root = QVBoxLayout(self)
        self.setAcceptDrops(True)   # 支持把 pcap / pcapng 直接拖到本页加载

        top = QHBoxLayout()
        self.btn_open = QPushButton("选择 pcap / pcapng 文件…")
        self.btn_open.clicked.connect(self._open)
        self.btn_export = QPushButton("导出 CSV")
        self.btn_export.setEnabled(False)
        self.btn_export.clicked.connect(self._export_csv)
        self.btn_clear = QPushButton("清空")
        self.btn_clear.clicked.connect(self._clear)
        self.mode_combo = QComboBox()
        self.mode_combo.setFixedWidth(240)
        self.mode_combo.addItem("① 密钥协商过程（客户端 ⇄ 服务端）", 2)
        self.mode_combo.addItem("② 报文列表（Wireshark 式）", 1)
        self.path_label = QLabel("未加载文件（点击「选择文件」或直接拖拽 pcap/pcapng 到本页）")
        self.path_label.setStyleSheet("color:#666;")
        top.addWidget(self.btn_open)
        top.addWidget(self.btn_export)
        top.addWidget(self.btn_clear)
        top.addStretch(1)
        top.addWidget(QLabel("视图模式"))
        top.addWidget(self.mode_combo)
        top.addWidget(self.path_label, 1)
        root.addLayout(top)

        # ---- 过滤 / 搜索 / 流查看工具条（模式 ① 使用）----
        bar = QHBoxLayout()
        bar.addWidget(QLabel("显示过滤"))
        self.cmb_proto = QComboBox()
        self.cmb_proto.addItem("全部协议", None)
        for p in ("TLS", "TLCP", "SSH", "HTTP", "DNS", "TCP", "UDP", "ARP", "ICMP", "其他"):
            self.cmb_proto.addItem(p, p)
        self.cmb_proto.currentIndexChanged.connect(lambda _i: self._apply_filter())
        bar.addWidget(self.cmb_proto)
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("过滤：协议名(如 tls/ssh) 或 报文概要(如 server hello / client hello)…")
        self.search_edit.setClearButtonEnabled(True)
        self.search_edit.textChanged.connect(lambda _t: self._apply_filter())
        bar.addWidget(self.search_edit, 1)
        self.btn_flow = QPushButton("查看该 TCP 流")
        self.btn_flow.setEnabled(False)
        self.btn_flow.clicked.connect(self._show_selected_flow)
        bar.addWidget(self.btn_flow)
        self.btn_flow_raw = QPushButton("流原文(Hex+ASCII)")
        self.btn_flow_raw.setEnabled(False)
        self.btn_flow_raw.clicked.connect(self._show_flow_raw)
        bar.addWidget(self.btn_flow_raw)
        root.addLayout(bar)

        self.info_label = QLabel("")
        self.info_label.setStyleSheet("color:#546E7A; padding:3px 6px; background:#FAFBFC;"
                                      " border:1px solid #E5E7EB; border-radius:4px;")
        self.info_label.setWordWrap(True)
        root.addWidget(self.info_label)

        self.stack = QStackedWidget()

        # ---- 页面 1：Wireshark 式报文列表 + 字段树 ----
        page1 = QWidget()
        p1 = QVBoxLayout(page1)
        p1.setContentsMargins(0, 0, 0, 0)
        dsplit = QSplitter(Qt.Orientation.Vertical)

        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(["No", "时间(s)", "来源", "目的", "协议", "长度", "概要"])
        self.table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.cellClicked.connect(self._on_cell_clicked)
        dsplit.addWidget(self.table)

        # 详情区：协议字段树（左）+ 字段明细 / Hex（右）
        dsp = QSplitter(Qt.Orientation.Horizontal)
        self.detail_tree = QTreeWidget()
        self.detail_tree.setColumnCount(3)
        self.detail_tree.setHeaderLabels(["项目", "方向/协议", "值"])
        self.detail_tree.setColumnWidth(0, 280)
        self.detail_tree.setColumnWidth(1, 90)
        self.detail_tree.header().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.detail_tree.currentItemChanged.connect(self._show_detail)
        dsp.addWidget(self.detail_tree)
        self.detail_edit = QPlainTextEdit()
        self.detail_edit.setReadOnly(True)
        self.detail_edit.setFont(QFont(MONO, 9))
        dsp.addWidget(self.detail_edit)
        dsp.setSizes([560, 320])
        dsplit.addWidget(dsp)
        dsplit.setSizes([360, 300])
        p1.addWidget(dsplit, 1)
        self.stack.addWidget(page1)

        # ---- 页面 2：握手时序图（客户端 ⇄ 服务端）----
        page2 = QWidget()
        p2 = QVBoxLayout(page2)
        p2.setContentsMargins(0, 0, 0, 0)
        p2.setSpacing(2)
        row = QHBoxLayout()
        row.setSpacing(6)
        self.btn_summary = QPushButton("查看「协商总结」")
        self.btn_summary.setEnabled(False)
        self.btn_summary.setToolTip("弹出本次密钥协商总结：版本 / 最终密码套件 / 服务端与客户端证书等（可多开）")
        self.btn_summary.clicked.connect(self._on_summary_click)
        row.addWidget(self.btn_summary)
        lab = QLabel("选择会话")
        lab.setStyleSheet("font-size:11px; color:#37474F;")
        row.addWidget(lab)
        self.flow_combo = QComboBox()
        self.flow_combo.setFont(QFont("Microsoft YaHei UI", 10))
        self.flow_combo.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.flow_combo.currentIndexChanged.connect(self._on_flow_selected)
        row.addWidget(self.flow_combo, 1)
        self.hs_hint = QLabel("② 仅展示 ClientHello → Server Finished 关键协商包；点消息框或「关键参数」按钮查看详情")
        self.hs_hint.setStyleSheet("color:#78909C; font-size:11px;")
        self.hs_hint.setTextFormat(Qt.TextFormat.RichText)
        row.addWidget(self.hs_hint)
        p2.addLayout(row)

        self.diagram_scroll = QScrollArea()
        self.diagram_scroll.setWidgetResizable(True)
        self.diagram_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.handshake_view = HandshakeView()
        self.handshake_view.eventClicked.connect(self._on_packet_detail)
        self.handshake_view.certClicked.connect(self._on_cert_detail)
        self.diagram_scroll.setWidget(self.handshake_view)
        self._open_dialogs = []   # 保留所有已打开的详情弹窗引用（支持多开/并排比对）
        p2.addWidget(self.diagram_scroll, 1)
        self.stack.addWidget(page2)

        root.addWidget(self.stack, 1)

        # 默认视图 = ① 密钥协商过程（时序图），Wireshark 式报文列表为次选
        self.mode_combo.currentIndexChanged.connect(self._on_mode_changed)
        self.stack.setCurrentIndex(1)
        if not self._all_rows:
            self.handshake_view.set_sequence("", "", [{"seq": 1, "dir": "c->s", "kind": "…",
                "title": "点击「选择 pcap / pcapng 文件…」加载抓包", "detail": "将自动绘制客户端 ⇄ 服务端密钥协商过程",
                "no": None, "ts": None, "fields": []}])

    # ------------------------------------------------------------ 关键参数 → 独立弹窗（可多开）
    def _open_dlg(self, dlg):
        dlg.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self._open_dialogs.append(dlg)
        dlg.destroyed.connect(lambda: self._open_dialogs.remove(dlg) if dlg in self._open_dialogs else None)
        dlg.show()

    def _on_packet_detail(self, ev):
        title = "关键参数 — 〔#%s〕 %s" % (ev.get("seq", ""), ev.get("title", ""))
        self._open_dlg(PacketDetailDialog(
            title,
            handshake_view.event_detail_html(ev),
            self,
            plain_text=handshake_view.event_detail_text(ev)))

    # ------------------------------------------------------------ 证书「N」按钮 → 详情弹窗（可多开）
    def _on_cert_detail(self, cert_index, fields):
        self._open_dlg(CertDetailDialog(cert_index, fields, self))

    # ------------------------------------------------------------ 文件加载
    def _open(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "选择抓包文件", "", "抓包文件 (*.pcap *.pcapng *.cap);;所有文件 (*.*)")
        if not path:
            return
        self.analyze_file(path)

    def _clear(self):
        """清空已加载抓包与全部解析结果（报文列表 / 详情 / 时序图 / 协商总结复位）。"""
        self._pkts = []
        self._all_rows = []
        self._all_pkts = []
        self._streams = None
        self._row_flow = []
        self._row_pkt = []
        self._detail_map = {}
        self._file_summary = ""
        self._summary_html = ""
        self._summary_title = "协商过程总结"
        self.flow_combo.blockSignals(True)
        self.flow_combo.clear()
        self.flow_combo.blockSignals(False)
        self.flow_combo.setEnabled(False)
        self.btn_summary.setEnabled(False)
        self.btn_flow.setEnabled(False)
        self.btn_flow_raw.setEnabled(False)
        self.btn_export.setEnabled(False)
        self.cmb_proto.setCurrentIndex(0)
        self.search_edit.clear()
        self.table.setRowCount(0)
        self.detail_tree.clear()
        self.detail_edit.clear()
        self.path_label.setText("未加载文件（点击「选择文件」或直接拖拽 pcap/pcapng 到本页）")
        self.info_label.setText("")
        self.handshake_view.set_sequence("", "", [{"seq": 1, "dir": "c->s", "kind": "…",
            "title": "点击「选择 pcap / pcapng 文件…」加载抓包",
            "detail": "将自动绘制客户端 ⇄ 服务端密钥协商过程",
            "no": None, "ts": None, "fields": []}])

    # ---------------------------------------------------------- 拖拽加载 pcap
    @staticmethod
    def _drop_url(e):
        if e.mimeData().hasUrls():
            urls = e.mimeData().urls()
            if urls:
                return urls[0].toLocalFile()
        return None

    def dragEnterEvent(self, e):
        p = self._drop_url(e)
        if p and p.lower().endswith((".pcap", ".pcapng", ".cap")):
            e.acceptProposedAction()
        else:
            e.ignore()

    def dragMoveEvent(self, e):
        p = self._drop_url(e)
        if p and p.lower().endswith((".pcap", ".pcapng", ".cap")):
            e.acceptProposedAction()
        else:
            e.ignore()

    def dropEvent(self, e):
        p = self._drop_url(e)
        if not p:
            return
        if not p.lower().endswith((".pcap", ".pcapng", ".cap")):
            QMessageBox.information(self, "提示", "请拖入 pcap / pcapng 抓包文件")
            return
        self.analyze_file(p)

    def analyze_file(self, path):
        """加载抓包：显示加载动画，解析在后台线程执行，完成后刷新界面。"""
        want_diagram = self.mode_combo.currentData() == 2

        def work():
            a = pcap_analysis.analyze_pcap(path, max_rows=200000)
            try:
                from scapy.all import rdpcap
                pkts = rdpcap(path)
            except Exception:
                pkts = []
            streams = None
            if want_diagram and pkts:
                # 时序图模式：顺带在后台完成流解析（较耗时）
                try:
                    streams = packet_parser.analyze_streams(pkts)
                except Exception:
                    streams = {}
            return a, pkts, streams

        def done(res):
            a, self._pkts, pre_streams = res
            try:
                self.path_label.setText(path)
                s = a['summary']
                self._file_summary = "共 %s 个数据包 | %s → %s | 时长 %.1f 秒" % (
                    s['文件包数'], s['起始时间'], s['结束时间'], s['时长(秒)'])
                self.info_label.setText(self._file_summary)

                self._all_rows = a['rows']
                self._all_pkts = self._pkts[:len(self._all_rows)]
                self._streams = pre_streams
                self._row_flow = []
                self.flow_combo.clear()
                self.cmb_proto.setCurrentIndex(0)
                self.search_edit.clear()
                self.btn_export.setEnabled(True)
                self._apply_filter()
                self.detail_tree.clear()
                self.detail_edit.clear()
                self.btn_flow.setEnabled(True)
                self.btn_flow_raw.setEnabled(True)

                self._summary_html = ""
                self._summary_title = "协商过程总结"
                self.btn_summary.setEnabled(False)

                # 默认视图为 ① 密钥协商过程：加载后立即渲染
                if self.mode_combo.currentData() == 2:
                    self.stack.setCurrentIndex(1)
                    self._ensure_streams()
                    self._populate_flow_combo(select_key=None)
            except Exception as e:
                QMessageBox.critical(self, "解析失败", str(e))

        def failed(msg):
            QMessageBox.critical(self, "解析失败", msg)

        busy_load(self, "正在解析抓包文件…", work, done, failed)

    PROTO_BG = {  # Wireshark 风格协议配色
        "TLS": "#FDF3D8", "TLCP": "#FDF3D8", "SSH": "#E7F5E7", "HTTP": "#E7F5E7",
        "DNS": "#F1E6F8", "TCP": "#E3F0FD", "UDP": "#EDEBF5", "ARP": "#FCE7E9",
        "ICMP": "#FDEBD8",
    }

    def _fill_table(self, rows):
        self.table.setRowCount(len(rows))
        self.table.setUpdatesEnabled(False)
        align_right = Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
        for r, row in enumerate(rows):
            no, delta, src, dst, proto, length, info = row
            bg = QColor(self.PROTO_BG.get(proto, "#FFFFFF"))
            for c, val in enumerate((no, "%.4f" % delta, src, dst, proto, length, info)):
                it = QTableWidgetItem(str(val))
                it.setBackground(QBrush(bg))
                if c == 5:
                    it.setTextAlignment(align_right)
                self.table.setItem(r, c, it)
        self.table.setUpdatesEnabled(True)
        self.table.scrollToTop()

    # ------------------------------------------------------------ 时序图模式（模式 ②）
    def _ensure_streams(self):
        """惰性计算全文件 TCP 流解析结果并缓存（含 TLS / TLCP / SSH / CSSH 握手消息）。"""
        if self._streams is None and self._pkts:
            try:
                self._streams = packet_parser.analyze_streams(self._pkts)
            except Exception as e:
                self._streams = {}
                QMessageBox.warning(self, "流解析失败", str(e))
        if not self._row_flow and self._all_pkts:
            self._row_flow = []
            for pkt in self._all_pkts:
                try:
                    key = packet_parser.flow_key_of(pkt)
                    self._row_flow.append(key if key and self._streams and key in self._streams else None)
                except Exception:
                    self._row_flow.append(None)
        return self._streams or {}

    def _populate_flow_combo(self, select_key=None):
        self.flow_combo.blockSignals(True)
        self.flow_combo.clear()
        streams = self._streams or {}
        sets_ = handshake_view.negotiation_sets(streams)
        if not sets_:
            sets_ = handshake_view.fallback_sets(streams)
        sel = -1
        for i, st in enumerate(sets_):
            self.flow_combo.addItem(st["label"], i)
            if select_key is not None and st.get("phases") and st["phases"][0].get("key") == select_key:
                sel = i
        self.flow_combo.setEnabled(len(sets_) > 0)
        self.flow_combo.blockSignals(False)
        bidir = any(len(s.get("phases") or []) > 1 for s in sets_)
        nflow = len(streams)
        if bidir:
            self.hs_hint.setText("② 检测到 TLCP <b>双向身份鉴别</b>：①服务端鉴别 → ②客户端鉴别（客户端出示自身证书）"
                                 "；TLS 仅取首次协商。点消息框或「关键参数」查看详情")
        elif nflow > 1:
            self.hs_hint.setText("② 按包序仅展示<b>首个完成密钥协商</b>的会话（其余 %d 个会话忽略）；"
                                 "TLCP 若检测到客户端出示自身证书则展示双向两段协商" % (nflow - 1))
        else:
            self.hs_hint.setText("② 仅展示 ClientHello → Server Finished 关键协商包；点消息框或「关键参数」按钮查看详情")
        if len(sets_) == 0:
            self.handshake_view.set_sequence("", "", [{"seq": 1, "dir": "c->s", "kind": "…",
                "title": "未识别到握手消息会话", "detail": "本pcap未解析出 TLS / TLCP / SSH / CSSH 会话",
                "no": None, "ts": None}])
            return
        idx = sel if sel >= 0 else (self.flow_combo.currentIndex() if self.flow_combo.count() else 0)
        self.flow_combo.setCurrentIndex(idx)
        self._on_flow_selected(idx)

    def _on_mode_changed(self, _idx):
        if self.mode_combo.currentData() == 2:
            self.stack.setCurrentIndex(1)
            if not self._all_rows:
                self.flow_combo.clear()
                self.flow_combo.setEnabled(False)
                self.handshake_view.set_sequence("", "", [{"seq": 1, "dir": "c->s", "kind": "…",
                    "title": "请先加载 pcap / pcapng 文件", "detail": "点击左上角「选择 pcap / pcapng 文件…」",
                    "no": None, "ts": None, "fields": []}])
                return
            key = self._flow_key_of_current_row()
            self._ensure_streams()
            self._populate_flow_combo(select_key=key)
        else:
            self.stack.setCurrentIndex(0)

    def _flow_key_of_current_row(self):
        row = self.table.currentRow()
        if row < 0 or row >= len(self._row_flow):
            return None
        return self._row_flow[row]

    def _on_flow_selected(self, idx):
        if idx < 0:
            return
        sidx = self.flow_combo.itemData(idx)
        if sidx is None:
            return
        self._render_diagram(sidx)

    def _sets_of(self):
        streams = self._streams or {}
        sets_ = handshake_view.negotiation_sets(streams)
        if not sets_:
            sets_ = handshake_view.fallback_sets(streams)
        return sets_

    def _on_summary_click(self):
        if not self._summary_html:
            QMessageBox.information(self, "协商总结", "暂未生成协商总结\n（请先加载抓包文件并选择会话）")
            return
        self._open_dlg(SummaryDialog(self._summary_title, self._summary_html, self))

    def _render_diagram(self, sidx):
        try:
            sets_ = self._sets_of()
            st = sets_[sidx] if 0 <= sidx < len(sets_) else (sets_[0] if sets_ else None)
            if not st:
                self._summary_html = "<span style='color:#B71C1C'>未解析出协商消息，无法生成总结。</span>"
                self._summary_title = "协商过程总结"
                self.btn_summary.setEnabled(True)
                self.handshake_view.set_sequence("", "", [{"seq": 1, "dir": "c->s", "kind": "…",
                    "title": "未识别到协商会话", "detail": "本pcap未解析出完成密钥协商的会话",
                    "no": None, "ts": None}])
                return
            client = st.get("client", "客户端")
            server = st.get("server", "服务端")
            evs = handshake_view.set_to_events(self._streams or {}, st)
            self._summary_html = handshake_view.negotiation_set_html(
                self._streams or {}, st, st.get("proto", ""))
            self._summary_title = "协商过程总结 · %s" % st.get("label", "")
            self.btn_summary.setEnabled(bool(self._summary_html))
            self.handshake_view.set_sequence(client, server, evs)
        except Exception as e:
            self._summary_html = "<span style='color:#B71C1C'>协商总结生成失败：%s</span>" % _html.escape(str(e))
            self._summary_title = "协商过程总结"
            self.btn_summary.setEnabled(True)
            self.handshake_view.set_sequence("", "", [{"seq": 1, "dir": "c->s", "kind": "…",
                "title": "时序图生成失败", "detail": str(e), "no": None, "ts": None}])

    # ------------------------------------------------------------ 点击行 → 单包协议字段树
    def _on_cell_clicked(self, row, _col):
        if row < 0 or row >= len(self._row_pkt):
            return
        pkt = self._row_pkt[row]
        if pkt is None:
            self.detail_edit.setPlainText("（该行无对应数据包）")
            return
        try:
            tree = packet_parser.build_packet_tree(pkt)
        except Exception as e:
            self.detail_edit.setPlainText("单包解析失败：%s" % e)
            return
        self._fill_detail_tree(tree, "包 #%d" % (row + 1))
        # 右侧：先展示协议关键字段解析文本，再附完整 Hex（签名值等单独成行）
        text_parts = []
        for grp, fields in tree.items():
            text_parts.append("== %s ==" % grp)
        for k, v in fields.items():
            sv = str(v)
            text_parts.append("%s: %s" % (k, sv))
        body = "\n".join(text_parts)
        try:
            raw = bytes(pkt)
        except Exception:
            raw = b""
        body += "\n\n==== Hex Dump（完整 %d 字节） ====\n" % len(raw)
        body += raw.hex()
        self.detail_edit.setPlainText(body)

    def _fill_detail_tree(self, tree, caption):
        self.detail_tree.clear()
        self._detail_map = {}
        cap = QTreeWidgetItem([caption, "", ""])
        cap.setExpanded(True)
        for grp, fields in tree.items():
            it = QTreeWidgetItem(["%s" % grp, "", ""])
            for k, v in fields.items():
                sv = str(v)
                shown = sv
                child = QTreeWidgetItem([k, "", shown])
                it.addChild(child)
                self._detail_map[id(child)] = [(k, sv)]
            cap.addChild(it)
            self._detail_map[id(it)] = list(fields.items())
            it.setExpanded(True)
        self.detail_tree.addTopLevelItem(cap)

    def _show_detail(self, cur, _prev):
        if cur is None:
            return
        fields = self._detail_map.get(id(cur))
        if fields is None:
            return
        lines = []
        for k, v in fields:
            sv = str(v)
            lines.append("%s:\n  %s\n" % (k, sv))
        self.detail_edit.setPlainText("\n".join(lines))

    # ------------------------------------------------------------ 查看该 TCP 流
    def _show_selected_flow(self):
        row = self.table.currentRow()
        if row < 0 or row >= len(self._row_pkt):
            QMessageBox.information(self, "提示", "请先在表格中选中一个数据包")
            return
        pkt = self._row_pkt[row]
        if not pkt or not pkt.haslayer(TCP):
            QMessageBox.information(self, "提示", "该包不是 TCP 包，无法查看流")
            return
        try:
            key = packet_parser.flow_key_of(pkt)
            if self._streams is None:
                self._streams = packet_parser.analyze_streams(self._pkts)
            fl = self._streams.get(key)
        except Exception as e:
            QMessageBox.critical(self, "流解析失败", str(e))
            return
        if not fl:
            QMessageBox.information(self, "提示", "未在该文件中解析到这条 TCP 流的应用层消息")
            return
        self.detail_tree.clear()
        self._detail_map = {}
        top = QTreeWidgetItem(["TCP 流  %s ⇄ %s   [%s]" % (fl["client"], fl["server"], fl["proto"]), "", ""])
        top.setExpanded(True)
        lines = ["TCP 流 %s ⇄ %s  协议: %s" % (fl["client"], fl["server"], fl["proto"]),
                 "共 %d 条应用层消息：\n" % len(fl["messages"])]
        for m in fl["messages"]:
            it = QTreeWidgetItem([m["type"], "%s %s" % (m["proto"], m["dir"]), m["summary"]])
            fields = m.get("fields") or {}
            flds = list(fields.items()) if fields else [("摘要", m["summary"])]
            self._detail_map[id(it)] = flds
            top.addChild(it)
            lines.append("· [%s] %s  |  %s" % (m["dir"], m["type"], m["summary"]))
        self.detail_tree.addTopLevelItem(top)
        self.detail_edit.setPlainText("\n".join(lines))

    # ------------------------------------------------------------ 过滤 / 搜索
    def _apply_filter(self):
        if not self._all_rows:
            return
        proto = self.cmb_proto.currentData()
        tokens = [t for t in self.search_edit.text().strip().lower().split() if t]
        vis_rows, vis_pkts = [], []
        for row, pkt in zip(self._all_rows, self._all_pkts):
            rproto = row[4]
            if proto is not None:
                if proto == "其他":
                    if rproto in ("TLS", "TLCP", "SSH", "HTTP", "DNS", "TCP", "UDP", "ARP", "ICMP"):
                        continue
                elif rproto != proto:
                    continue
            if tokens:
                if not self._row_matches(row, tokens):
                    continue
            vis_rows.append(row)
            vis_pkts.append(pkt)
        self._row_pkt = vis_pkts
        self._fill_table(vis_rows)
        txt = self._file_summary
        if len(vis_rows) != len(self._all_rows):
            txt += " ｜ 当前显示 %d / %d 行（已过滤）" % (len(vis_rows), len(self._all_rows))
        self.info_label.setText(txt)

    @staticmethod
    def _row_matches(row, tokens):
        """Wireshark 式：多关键字以空格分隔，均需在 No/地址/协议/概要 任一字段命中。"""
        hay = "\t".join(str(x) for x in row).lower()
        return all(t in hay for t in tokens)

    # ------------------------------------------------------------ 导出 CSV
    def _export_csv(self):
        if not self._all_rows:
            return
        path, _ = QFileDialog.getSaveFileName(self, "导出 CSV", "pcap_export.csv",
                                              "CSV 文件 (*.csv);;所有文件 (*.*)")
        if not path:
            return
        import csv
        try:
            with open(path, 'w', newline='', encoding='utf-8-sig') as f:
                w = csv.writer(f)
                w.writerow(["No", "时间(s)", "来源", "目的", "协议", "长度", "概要"])
                for row in self._all_rows:
                    w.writerow(list(row))
        except Exception as e:
            QMessageBox.critical(self, "导出失败", str(e))
            return
        QMessageBox.information(self, "导出成功",
                                "已导出 %d 行到：\n%s" % (len(self._all_rows), path))

    # ------------------------------------------------------------ TCP 流原文视图
    def _show_flow_raw(self):
        row = self.table.currentRow()
        if row < 0 or row >= len(self._row_pkt):
            QMessageBox.information(self, "提示", "请先在表格中选中一个数据包")
            return
        pkt = self._row_pkt[row]
        if not pkt or not pkt.haslayer(TCP):
            QMessageBox.information(self, "提示", "该包不是 TCP 包，无法查看流原文")
            return
        try:
            key = packet_parser.flow_key_of(pkt)
            flows = packet_parser.reassemble_flows(self._pkts)
        except Exception as e:
            QMessageBox.critical(self, "流重组失败", str(e))
            return
        f = flows.get(key)
        if not f:
            QMessageBox.information(self, "提示", "未找到该 TCP 流原文数据")
            return
        a, ap, b, bp = key
        ab, ba = f["ab"], f["ba"]
        head = "TCP 流  %s:%d ⇄ %s:%d   |  A→B %d 字节 | B→A %d 字节\n" % (a, ap, b, bp, len(ab), len(ba))
        if ab:
            head += "\n====== 方向 A→B（%s:%d → %s:%d） ======\n" % (a, ap, b, bp)
            head += packet_parser.hexdump(ab)
        if ba:
            head += "\n\n====== 方向 B→A（%s:%d → %s:%d） ======\n" % (b, bp, a, ap)
            head += packet_parser.hexdump(ba)
        self.detail_tree.clear()
        self._detail_map = {}
        self.detail_edit.setPlainText(head)


# ============================================================ 证书分析
class CertTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._cert_path = None
        self._last_fields = None
        root = QVBoxLayout(self)
        self.setAcceptDrops(True)

        top = QHBoxLayout()
        self.btn_file = QPushButton("选择证书文件 (PEM/DER)…")
        self.btn_file.clicked.connect(self._pick_file)
        self.btn_parse = QPushButton("分析")
        self.btn_parse.clicked.connect(self._parse)
        self.btn_demo = QPushButton("载入演示证书")
        self.btn_demo.clicked.connect(self._load_demo)
        self.btn_export = QPushButton("导出结果")
        self.btn_export.clicked.connect(self._export)
        self.btn_clear = QPushButton("清空")
        self.btn_clear.clicked.connect(self._clear)
        top.addWidget(self.btn_file)
        top.addWidget(self.btn_parse)
        top.addWidget(self.btn_demo)
        top.addWidget(self.btn_export)
        top.addWidget(self.btn_clear)
        top.addStretch(1)
        root.addLayout(top)

        root.addWidget(QLabel("粘贴 PEM 证书文本，或直接把证书文件(.crt/.cer/.pem/.der)拖到下方文本框："))
        self.pem_edit = QPlainTextEdit()
        self.pem_edit.setMaximumHeight(160)
        self.pem_edit.setAcceptDrops(False)
        self.pem_edit.installEventFilter(self)
        root.addWidget(self.pem_edit)

        self.table = QTableWidget(0, 2)
        self.table.setHorizontalHeaderLabels(["属性", "值"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        h = self.table.verticalHeader()
        h.setVisible(False)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._table_menu)
        root.addWidget(self.table, 1)

    def _pick_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "选择证书文件", "", "证书 (*.crt *.cer *.pem *.der);;所有文件 (*.*)")
        if path:
            self._load_file(path)

    def _load_file(self, path):
        """加载证书文件：显示加载动画，读取与分析在后台线程执行。"""
        def work():
            with open(path, 'rb') as f:
                raw = f.read()
            text = raw.decode('utf-8', 'replace')
            pem = text if '-----BEGIN' in text else None
            fields = cert_analysis.analyze_cert(text=pem, path=path if pem is None else None)
            return raw, text, fields

        def done(res):
            raw, text, fields = res
            self._cert_path = path
            if '-----BEGIN' in text:
                self.pem_edit.setPlainText(text)
            else:
                # DER：直接按文件解析
                self.pem_edit.setPlainText("（DER 二进制证书，已按文件加载）")
            self._show_fields(fields)

        def failed(msg):
            QMessageBox.critical(self, "读取/解析失败", msg)

        busy_load(self, "正在读取并分析证书…", work, done, failed)

    # ---------------------------------------------------------- 拖拽加载证书文件
    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()
        else:
            e.ignore()

    def dragMoveEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()
        else:
            e.ignore()

    def dropEvent(self, e):
        urls = e.mimeData().urls()
        if urls:
            self._load_file(urls[0].toLocalFile())

    def eventFilter(self, obj, ev):
        if obj is self.pem_edit:
            if ev.type() == QEvent.Type.DragEnter or ev.type() == QEvent.Type.DragMove:
                if ev.mimeData().hasUrls():
                    ev.acceptProposedAction()
                    return True
            elif ev.type() == QEvent.Type.Drop:
                urls = ev.mimeData().urls()
                if urls:
                    ev.acceptProposedAction()
                    self._load_file(urls[0].toLocalFile())
                    return True
            elif ev.type() == QEvent.Type.DragLeave:
                return True
        return super().eventFilter(obj, ev)

    def _parse(self):
        path = self._cert_path
        text = self.pem_edit.toPlainText()
        try:
            fields = cert_analysis.analyze_cert(text=text if text and '-----BEGIN' in text else None,
                                                path=path)
        except Exception as e:
            QMessageBox.critical(self, "解析失败", str(e))
            return
        self._show_fields(fields)

    def _show_fields(self, fields):
        """把解析结果填入表格（有效期合并为一行 + 关键参数高亮）。"""
        self._last_fields = fields
        rows = self._build_rows(fields)
        self.table.setRowCount(len(rows))
        for r, (k, v, style) in enumerate(rows):
            it0 = QTableWidgetItem(k)
            it1 = QTableWidgetItem(str(v))
            self._apply_row_style(it0, it1, style)
            self.table.setItem(r, 0, it0)
            self.table.setItem(r, 1, it1)
        self.table.resizeRowsToContents()

    # ---------------------------------------------------------- 关键参数高亮 / 有效期标识

    # 关键参数高亮配色（标签底色/字色 + 值底色/字色）
    _HL_STYLES = {
        "sig": {"lb": "#EFF6FF", "lf": "#1D4ED8", "vb": "#EFF6FF", "vf": "#1D4ED8"},
        "ku": {"lb": "#FEF3C7", "lf": "#92400E", "vb": "#FFFBEB", "vf": "#92400E"},
        "pub": {"lb": "#F0F9FF", "lf": "#0369A1", "vb": "#F0F9FF", "vf": "#0369A1"},
        "valid_ok": {"lb": "#FEF3C7", "lf": "#B45309", "vb": "#ECFDF5", "vf": "#15803D"},
        "valid_bad": {"lb": "#FEF3C7", "lf": "#B45309", "vb": "#FEF2F2", "vf": "#B91C1C"},
    }

    @staticmethod
    def _validity_state(nb, na):
        """有效期与当前系统时间比对：ok / expired / notyet / unknown。"""
        import datetime as _dt
        try:
            b = _dt.datetime.strptime(str(nb), "%Y-%m-%d %H:%M:%S")
            a = _dt.datetime.strptime(str(na), "%Y-%m-%d %H:%M:%S")
        except Exception:
            return "unknown"
        now = _dt.datetime.now()
        if b <= now <= a:
            return "ok"
        return "expired" if now > a else "notyet"

    @classmethod
    def _row_style(cls, key):
        if key.startswith("签名算法"):
            return "sig"
        if key.startswith("密钥用途") or key.startswith("扩展密钥用途"):
            return "ku"
        if key.startswith("公钥算法"):
            return "pub"
        return ""

    def _build_rows(self, fields):
        """整理表格行：① 合并有效期为一行（起-止 + 有效/过期标识）；② 标记关键参数高亮。"""
        rows = []
        nb = fields.get("有效期从 notBefore")
        na = fields.get("有效期至 notAfter")
        validity_added = False
        for k, v in fields.items():
            if k in ("有效期从 notBefore", "有效期至 notAfter"):
                if validity_added:
                    continue
                validity_added = True
                state = self._validity_state(nb, na)
                mark = {"ok": "有效 ✓", "expired": "已过期 ✗", "notyet": "未生效 ✗"}.get(state, "")
                line = "%s-%s" % (nb or "?", na or "?")
                if mark:
                    line += "　%s" % mark
                rows.append(("有效期", line, "valid_ok" if state == "ok" else
                             ("valid_bad" if state in ("expired", "notyet") else "")))
                continue
            rows.append((k, str(v), self._row_style(k)))
        return rows

    def _apply_row_style(self, it0, it1, style):
        st = self._HL_STYLES.get(style)
        if not st:
            return
        it0.setBackground(QColor(st["lb"]))
        it0.setForeground(QColor(st["lf"]))
        it1.setBackground(QColor(st["vb"]))
        it1.setForeground(QColor(st["vf"]))
        for it in (it0, it1):
            f = it.font()
            f.setBold(True)
            it.setFont(f)

    def _clear(self):
        """清空 PEM 输入、解析结果与已加载证书状态。"""
        self._cert_path = None
        self._last_fields = None
        self.pem_edit.clear()
        self.table.setRowCount(0)

    def _table_menu(self, pos):
        """证书解析结果右键菜单：复制该值 / 复制该行 / 复制全部。"""
        idx = self.table.indexAt(pos)
        menu = QMenu(self)
        act_cell = act_row = None
        if idx.isValid():
            act_cell = menu.addAction("复制该值")
            act_row = menu.addAction("复制该行")
        act_all = menu.addAction("复制全部结果")
        act = menu.exec(self.table.viewport().mapToGlobal(pos))
        if act is act_cell:
            self._copy_cell(idx.row(), idx.column())
        elif act is act_row:
            self._copy_row(idx.row())
        elif act is act_all:
            self._copy_all()

    def _copy_cell(self, row, col):
        it = self.table.item(row, col)
        QApplication.clipboard().setText(it.text() if it else "")

    def _copy_row(self, row):
        c0 = self.table.item(row, 0)
        c1 = self.table.item(row, 1)
        QApplication.clipboard().setText("%s\t%s" % (c0.text() if c0 else "", c1.text() if c1 else ""))

    def _copy_all(self):
        lines = []
        for r in range(self.table.rowCount()):
            c0 = self.table.item(r, 0)
            c1 = self.table.item(r, 1)
            lines.append("%s: %s" % (c0.text() if c0 else "", c1.text() if c1 else ""))
        QApplication.clipboard().setText("\n".join(lines))

    def _load_demo(self):
        """生成一张 RSA 自签名演示证书并自动分析（用于快速体验界面；SM2 证书可直接选择文件加载）。"""
        import datetime
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        try:
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "demo.local-crypto-tool.cn")])
            now = datetime.datetime.now(datetime.timezone.utc)
            cert = (x509.CertificateBuilder()
                    .subject_name(name).issuer_name(name)
                    .public_key(key.public_key())
                    .serial_number(x509.random_serial_number())
                    .not_valid_before(now - datetime.timedelta(days=1))
                    .not_valid_after(now + datetime.timedelta(days=365))
                    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                    .add_extension(x509.SubjectAlternativeName([x509.DNSName("demo.local-crypto-tool.cn")]), critical=False)
                    .sign(key, hashes.SHA256()))
            pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        except Exception as e:
            QMessageBox.critical(self, "生成演示证书失败", str(e))
            return
        self._cert_path = None
        self.pem_edit.setPlainText(pem)
        self._parse()

    def _export(self):
        if not self._last_fields:
            QMessageBox.information(self, "提示", "请先分析一张证书")
            return
        path, _ = QFileDialog.getSaveFileName(self, "导出证书分析结果",
                                              "cert_analysis.txt", "文本文件 (*.txt);;所有文件 (*.*)")
        if not path:
            return
        lines = ["证书分析结果"]
        lines.append("=" * 56)
        for k, v, _style in self._build_rows(self._last_fields):
            lines.append("%s：" % k)
            lines.append(str(v))
            lines.append("")
        try:
            with open(path, 'w', encoding='utf-8-sig') as f:
                f.write("\n".join(lines))
        except Exception as e:
            QMessageBox.critical(self, "导出失败", str(e))
            return
        QMessageBox.information(self, "导出成功", "已导出到：\n%s" % path)


# ============================================================ 对称加解密（SM4 / AES）
class SymCryptoTab(QWidget):
    """SM4 / AES 对称加解密：ECB / CBC / CFB / OFB / CTR / GCM，PKCS7 填充。"""
    _MODES = ("ECB", "CBC", "CFB", "OFB", "CTR", "GCM")

    def __init__(self, parent=None):
        super().__init__(parent)
        self._file_data = None
        self.setAcceptDrops(True)

        root = QVBoxLayout(self)
        root.setContentsMargins(16, 12, 16, 12)
        root.setSpacing(10)

        # ---- 算法 / 模式 / 输入编码 ----
        cfg = QGroupBox("算法与模式")
        g = QGridLayout(cfg)
        g.addWidget(QLabel("算法"), 0, 0)
        self.cmb_alg = QComboBox()
        self.cmb_alg.addItem("SM4")
        self.cmb_alg.addItem("AES")
        self.cmb_alg.currentTextChanged.connect(self._on_alg_changed)
        g.addWidget(self.cmb_alg, 0, 1)
        g.addWidget(QLabel("密钥位长"), 0, 2)
        self.cmb_bits = QComboBox()
        for b in (16, 24, 32):
            self.cmb_bits.addItem("%d 位" % (b * 8), b * 8)
        self.cmb_bits.setCurrentIndex(0)
        g.addWidget(self.cmb_bits, 0, 3)
        g.addWidget(QLabel("模式"), 0, 4)
        self.cmb_mode = QComboBox()
        for m in self._MODES:
            self.cmb_mode.addItem(m)
        self.cmb_mode.currentTextChanged.connect(self._on_mode_changed)
        g.addWidget(self.cmb_mode, 0, 5)
        g.addWidget(QLabel("输入编码"), 0, 6)
        bg = QButtonGroup(self)
        self.rb_hex = QRadioButton("HEX")
        self.rb_utf8 = QRadioButton("UTF-8")
        self.rb_b64 = QRadioButton("Base64")
        self.rb_utf8.setChecked(True)
        for r in (self.rb_hex, self.rb_utf8, self.rb_b64):
            bg.addButton(r)
        g.addWidget(self.rb_hex, 0, 7)
        g.addWidget(self.rb_utf8, 0, 8)
        g.addWidget(self.rb_b64, 0, 9)
        root.addWidget(cfg)

        # ---- 密钥 / IV / Tag / AAD ----
        keybox = QGroupBox("密钥 · IV/Nonce · 认证")
        kg = QGridLayout(keybox)
        kg.addWidget(QLabel("密钥 K"), 0, 0)
        self.key_edit = QLineEdit()
        self.key_edit.setPlaceholderText("SM4 为 16 字节；AES 按密钥位长 16/24/32 字节（HEX / Base64 / UTF-8）")
        kg.addWidget(self.key_edit, 0, 1, 1, 2)
        self.btn_key = QPushButton("随机生成")
        self.btn_key.clicked.connect(self._gen_key)
        kg.addWidget(self.btn_key, 0, 3)
        kg.addWidget(QLabel("IV / Nonce"), 1, 0)
        self.iv_edit = QLineEdit()
        self.iv_edit.setPlaceholderText("CBC/CFB/OFB/CTR 需 16 字节；GCM 建议 12 字节 Nonce；ECB 不需要")
        kg.addWidget(self.iv_edit, 1, 1, 1, 2)
        self.btn_iv = QPushButton("随机生成")
        self.btn_iv.clicked.connect(self._gen_iv)
        kg.addWidget(self.btn_iv, 1, 3)
        kg.addWidget(QLabel("GCM Tag"), 2, 0)
        self.tag_edit = QLineEdit()
        self.tag_edit.setPlaceholderText("GCM 认证标签（加密后自动填入；解密时必填）")
        kg.addWidget(self.tag_edit, 2, 1, 1, 2)
        kg.addWidget(QLabel("AAD"), 2, 3)
        self.aad_edit = QLineEdit()
        self.aad_edit.setPlaceholderText("关联数据（可选）")
        kg.addWidget(self.aad_edit, 2, 4)
        root.addWidget(keybox)

        # ---- 输入 / 输出 ----
        split = QSplitter(Qt.Orientation.Horizontal)
        left = QGroupBox("输入（加密=明文 / 解密=密文）")
        lv = QVBoxLayout(left)
        self.in_edit = QPlainTextEdit()
        self.in_edit.setMaximumHeight(160)
        lv.addWidget(self.in_edit)
        lr = QHBoxLayout()
        lr.addStretch(1)
        self.btn_file = QPushButton("选择文件 / 拖拽导入…")
        self.btn_file.clicked.connect(self._pick_file)
        lr.addWidget(self.btn_file)
        lv.addLayout(lr)

        right = QGroupBox("输出 / 结果")
        rv = QVBoxLayout(right)
        self.out_edit = QPlainTextEdit()
        self.out_edit.setReadOnly(True)
        rv.addWidget(self.out_edit)
        rh = QHBoxLayout()
        rh.addWidget(QLabel("输出编码"))
        bg = QButtonGroup(self)
        self.rb_out_hex = QRadioButton("HEX")
        self.rb_out_utf8 = QRadioButton("UTF-8")
        self.rb_out_b64 = QRadioButton("Base64")
        self.rb_out_hex.setChecked(True)
        for r in (self.rb_out_hex, self.rb_out_utf8, self.rb_out_b64):
            bg.addButton(r)
        rh.addWidget(self.rb_out_hex)
        rh.addWidget(self.rb_out_utf8)
        rh.addWidget(self.rb_out_b64)
        rh.addStretch(1)
        rv.addLayout(rh)
        split.addWidget(left)
        split.addWidget(right)
        split.setSizes([520, 400])
        root.addWidget(split, 1)

        # ---- 操作 ----
        op = QHBoxLayout()
        self.btn_enc = QPushButton("加  密")
        self.btn_enc.setObjectName("primary")
        self.btn_enc.clicked.connect(self._do_encrypt)
        self.btn_dec = QPushButton("解  密")
        self.btn_dec.setObjectName("success")
        self.btn_dec.clicked.connect(self._do_decrypt)
        self.btn_demo = QPushButton("载入演示数据")
        self.btn_demo.clicked.connect(self._load_demo)
        op.addWidget(self.btn_enc)
        op.addWidget(self.btn_dec)
        op.addStretch(1)
        op.addWidget(self.btn_demo)
        root.addLayout(op)

        # ---- 日志 ----
        lb = QGroupBox("运行日志")
        lbv = QVBoxLayout(lb)
        self.log_edit = QPlainTextEdit()
        self.log_edit.setReadOnly(True)
        self.log_edit.setMaximumHeight(130)
        lbv.addWidget(self.log_edit)
        root.addWidget(lb)

        self._on_alg_changed()
        self._on_mode_changed()

    # ---------------------------------------------------------- 状态联动
    def _on_alg_changed(self):
        n = self.cmb_bits.count()
        for i in range(n):
            self.cmb_bits.setItemText(i, "%d 位" % (self.cmb_bits.itemData(i) * 8))
        if self.cmb_alg.currentText() == "SM4":
            self.cmb_bits.setEnabled(False)
            self.cmb_bits.setCurrentIndex(0)
        else:
            self.cmb_bits.setEnabled(True)

    def _on_mode_changed(self):
        mode = self.cmb_mode.currentText()
        is_ecb = mode == "ECB"
        is_gcm = mode == "GCM"
        self.iv_edit.setEnabled(not is_ecb)
        self.btn_iv.setEnabled(not is_ecb)
        self.tag_edit.setEnabled(is_gcm)
        self.aad_edit.setEnabled(is_gcm)
        if is_ecb:
            self.iv_edit.clear()
            self.iv_edit.setPlaceholderText("ECB 模式不需要 IV")
        else:
            self.iv_edit.setPlaceholderText(
                "GCM 建议 12 字节 Nonce；其余模式需 16 字节 IV")

    # ---------------------------------------------------------- 随机生成
    def _gen_key(self):
        key_len = self.cmb_bits.currentData()
        if self.cmb_alg.currentText() == "SM4":
            key_len = 16
        self.key_edit.setText(sym_crypto.secure_random_hex(key_len))
        self._append_log("已生成 %s 密钥（%d 字节）" % (self.cmb_alg.currentText(), key_len))

    def _gen_iv(self):
        n = 12 if self.cmb_mode.currentText() == "GCM" else 16
        self.iv_edit.setText(sym_crypto.secure_random_hex(n))
        self._append_log("已生成 %s（%d 字节）" % ("Nonce" if n == 12 else "IV", n))

    def _append_log(self, text):
        self.log_edit.appendPlainText(text)

    # ---------------------------------------------------------- 输入解析
    def _current_input_bytes(self):
        text = self.in_edit.toPlainText().strip()
        if not text:
            raise ValueError("输入为空")
        if self.rb_hex.isChecked():
            clean = ''.join(text.split())
            if len(clean) % 2 != 0 or not all(c in '0123456789abcdefABCDEF' for c in clean):
                raise ValueError("HEX 输入不是合法十六进制")
            return bytes.fromhex(clean)
        if self.rb_b64.isChecked():
            try:
                return base64.b64decode(''.join(text.split()))
            except Exception:
                raise ValueError("Base64 解码失败")
        return text.encode('utf-8')

    def _fmt_output(self, data: bytes) -> str:
        if self.rb_out_hex.isChecked():
            return data.hex()
        if self.rb_out_b64.isChecked():
            return base64.b64encode(data).decode('ascii')
        try:
            return data.decode('utf-8')
        except Exception:
            return "(非 UTF-8 可打印，已按 HEX 显示)\n" + data.hex()

    # ---------------------------------------------------------- 文件拖拽
    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()
        else:
            e.ignore()

    def dropEvent(self, e):
        urls = e.mimeData().urls()
        if urls:
            self._load_file(urls[0].toLocalFile())

    def _pick_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "选择文件", "", "所有文件 (*.*)")
        if path:
            self._load_file(path)

    def _load_file(self, path):
        """导入文件：显示加载动画，读取在后台线程执行后填入输入区。"""
        def work():
            with open(path, 'rb') as f:
                return f.read()

        def done(raw):
            self._file_data = raw
            self.rb_hex.setChecked(True)
            self.in_edit.setPlainText(raw.hex())
            self._append_log("[文件] 已载入 %d 字节并转为 HEX：%s" % (len(raw), path))

        def failed(msg):
            QMessageBox.critical(self, "读取失败", msg)

        busy_load(self, "正在读取文件…", work, done, failed)

    # ---------------------------------------------------------- 加解密
    def _do_encrypt(self):
        try:
            mode = self.cmb_mode.currentText()
            alg = self.cmb_alg.currentText()
            bits = self.cmb_bits.currentData()
            data = self._current_input_bytes()
            key = sym_crypto.normalize_key(alg, bits, self.key_edit.text())
            iv = None
            if mode != "ECB":
                iv = sym_crypto.normalize_iv(mode, self.iv_edit.text())
            aad = sym_crypto.parse_bytes(self.aad_edit.text()) if \
                (mode == "GCM" and self.aad_edit.text().strip()) else b""
        except ValueError as e:
            QMessageBox.warning(self, "提示", str(e))
            return
        try:
            r = sym_crypto.encrypt(alg, mode, key, iv, data, aad)
        except Exception as e:
            QMessageBox.critical(self, "加密失败", str(e))
            return
        if mode == "GCM":
            self.tag_edit.setText(r["tag_hex"])
        self.out_edit.setPlainText(self._fmt_output(bytes.fromhex(r["cipher_hex"])))
        self._append_log("[加密] %s-%d | %s | 明文 %d 字节 → 密文 %d 字节%s"
                         % (alg, bits or 128, mode, len(data), len(r["cipher_hex"]) // 2,
                            " | Tag=%s" % r["tag_hex"] if mode == "GCM" else ""))

    def _do_decrypt(self):
        try:
            mode = self.cmb_mode.currentText()
            alg = self.cmb_alg.currentText()
            bits = self.cmb_bits.currentData()
            ct = self._current_input_bytes()
            key = sym_crypto.normalize_key(alg, bits, self.key_edit.text())
            iv = None
            if mode != "ECB":
                iv = sym_crypto.normalize_iv(mode, self.iv_edit.text())
            tag = None
            aad = b""
            if mode == "GCM":
                tag = sym_crypto.parse_bytes(self.tag_edit.text())
                if self.aad_edit.text().strip():
                    aad = sym_crypto.parse_bytes(self.aad_edit.text())
        except ValueError as e:
            QMessageBox.warning(self, "提示", str(e))
            return
        try:
            pt = sym_crypto.decrypt(alg, mode, key, iv, ct, tag, aad)
        except Exception as e:
            if mode == "GCM":
                QMessageBox.critical(self, "解密失败",
                                     "GCM 认证失败：认证标签不匹配（密钥 / Nonce / AAD / 密文 / Tag 任一有误或数据被篡改）")
            else:
                QMessageBox.critical(self, "解密失败", str(e) or "解密失败")
            return
        self.out_edit.setPlainText(self._fmt_output(pt))
        self._append_log("[解密] %s-%d | %s | 密文 %d 字节 → 明文 %d 字节"
                         % (alg, bits or 128, mode, len(ct), len(pt)))

    def _load_demo(self):
        """载入一组自洽演示数据并自动执行一次加解密。"""
        alg = "SM4"
        mode = "CBC"
        iv = sym_crypto.secure_random_hex(16)
        key = sym_crypto.secure_random_hex(16)
        self.cmb_alg.setCurrentText(alg)
        self.cmb_mode.setCurrentText(mode)
        self.key_edit.setText(key)
        self.iv_edit.setText(iv)
        plain = "演示数据：对称加密 SM4-CBC 自检 OK".encode('utf-8')
        self.rb_hex.setChecked(True)
        self.rb_out_hex.setChecked(True)
        self.in_edit.setPlainText(plain.hex())
        r = sym_crypto.encrypt(alg, mode, bytes.fromhex(key), bytes.fromhex(iv), plain)
        self.out_edit.setPlainText(r["cipher_hex"])
        back = sym_crypto.decrypt(alg, mode, bytes.fromhex(key), bytes.fromhex(iv), bytes.fromhex(r["cipher_hex"]))
        self._append_log("[演示] SM4-CBC 自检：加密→解密 往返% s" % ("成功 ✓" if back == plain else "失败 ✗"))


# ============================================================ 摘要 / HMAC
class HashTab(QWidget):
    """摘要计算（SM3 / MD5 / SHA 族）与 HMAC 消息认证码。"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self._file_data = None
        self.setAcceptDrops(True)

        root = QVBoxLayout(self)
        root.setContentsMargins(16, 12, 16, 12)
        root.setSpacing(10)

        # ---- 数据来源 + 输入 ----
        src = QHBoxLayout()
        src.addWidget(QLabel("数据来源"))
        self.rb_text = QRadioButton("文本（HEX/Base64/UTF-8 自动识别）")
        self.rb_file = QRadioButton("文件（原始字节）")
        self.rb_text.setChecked(True)
        bg = QButtonGroup(self)
        bg.addButton(self.rb_text)
        bg.addButton(self.rb_file)
        self.rb_file.toggled.connect(self._on_src_changed)
        src.addWidget(self.rb_text)
        src.addWidget(self.rb_file)
        src.addStretch(1)
        self.btn_file = QPushButton("选择文件 / 拖拽导入…")
        self.btn_file.clicked.connect(self._pick_file)
        src.addWidget(self.btn_file)
        self.file_label = QLabel("")
        self.file_label.setStyleSheet("color:#666;")
        root.addLayout(src)

        self.in_edit = QPlainTextEdit()
        self.in_edit.setMaximumHeight(120)
        self.in_edit.setPlaceholderText("粘贴文本 / HEX / Base64 内容（例如：SM3/SHA 摘要的对象）")
        root.addWidget(self.in_edit)

        # ---- 摘要按钮 ----
        op = QHBoxLayout()
        self.btn_hash = QPushButton("计算全部摘要")
        self.btn_hash.setObjectName("primary")
        self.btn_hash.clicked.connect(self._do_hash)
        op.addWidget(self.btn_hash)
        self.btn_clear = QPushButton("清空")
        self.btn_clear.clicked.connect(self._clear)
        op.addWidget(self.btn_clear)
        op.addStretch(1)
        root.addLayout(op)

        self.table = QTableWidget(0, 2)
        self.table.setHorizontalHeaderLabels(["算法", "摘要值"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._table_menu)
        root.addWidget(self.table, 1)

        # ---- HMAC ----
        hb = QGroupBox("HMAC 消息认证码（密钥 + 同一数据源）")
        hg = QHBoxLayout(hb)
        hg.addWidget(QLabel("算法"))
        self.cmb_hmac = QComboBox()
        for name in hash_tools.HMAC_ALGOS:
            self.cmb_hmac.addItem(name)
        hg.addWidget(self.cmb_hmac)
        hg.addWidget(QLabel("密钥"))
        self.key_edit = QLineEdit()
        self.key_edit.setPlaceholderText("HMAC 密钥（HEX / Base64 / UTF-8）")
        hg.addWidget(self.key_edit, 1)
        self.btn_hmac = QPushButton("计算 HMAC")
        self.btn_hmac.setObjectName("success")
        self.btn_hmac.clicked.connect(self._do_hmac)
        hg.addWidget(self.btn_hmac)
        root.addWidget(hb)

        self.hmac_label = QLabel("HMAC 结果：—")
        self.hmac_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.hmac_label.setStyleSheet("font-family:Consolas; font-size:12px; color:#1d4ed8; padding:4px;")
        self.hmac_label.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.hmac_label.customContextMenuRequested.connect(self._hmac_label_menu)
        root.addWidget(self.hmac_label)

    # ---------------------------------------------------------- 数据
    def _on_src_changed(self):
        use_file = self.rb_file.isChecked()
        self.in_edit.setEnabled(not use_file)
        if use_file and not self._file_data:
            self._pick_file()

    def _current_data(self) -> bytes:
        if self.rb_file.isChecked():
            if not self._file_data:
                raise ValueError("请先选择文件")
            return self._file_data
        return hash_tools.parse_bytes(self.in_edit.toPlainText())

    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()
        else:
            e.ignore()

    def dropEvent(self, e):
        urls = e.mimeData().urls()
        if urls:
            self._load_file(urls[0].toLocalFile())

    def _pick_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "选择文件", "", "所有文件 (*.*)")
        if path:
            self._load_file(path)

    def _load_file(self, path):
        """导入文件：显示加载动画，读取在后台线程执行后选中「文件」输入。"""
        def work():
            with open(path, 'rb') as f:
                return f.read()

        def done(raw):
            self._file_data = raw
            self.rb_file.setChecked(True)
            self.file_label.setText("已选文件：%s（%d 字节）" % (path, len(raw)))

        def failed(msg):
            QMessageBox.critical(self, "读取失败", msg)

        busy_load(self, "正在读取文件…", work, done, failed)

    # ---------------------------------------------------------- 计算
    def _do_hash(self):
        try:
            data = self._current_data()
        except ValueError as e:
            QMessageBox.warning(self, "提示", str(e))
            return
        res = hash_tools.hash_all(data)
        self.table.setRowCount(len(res))
        for r, (name, h) in enumerate(res.items()):
            self.table.setItem(r, 0, QTableWidgetItem(name))
            self.table.setItem(r, 1, QTableWidgetItem(h))
        self.table.resizeRowsToContents()
        self.table.verticalHeader().setDefaultSectionSize(22)

    def _do_hmac(self):
        try:
            data = self._current_data()
            algo = self.cmb_hmac.currentText()
            key = hash_tools.parse_bytes(self.key_edit.text())
        except ValueError as e:
            QMessageBox.warning(self, "提示", str(e))
            return
        try:
            h = hash_tools.hmac_bytes(algo, key, data)
        except Exception as e:
            QMessageBox.critical(self, "HMAC 失败", str(e))
            return
        self.hmac_label.setText("HMAC-%s 结果：%s" % (algo, h))
        self.hmac_label.setToolTip(h)

    # ---------------------------------------------------------- 右键复制摘要结果
    def _table_menu(self, pos):
        """摘要结果表格右键菜单：复制该值 / 复制该行 / 复制全部。"""
        idx = self.table.indexAt(pos)
        menu = QMenu(self)
        act_cell = act_row = None
        if idx.isValid():
            act_cell = menu.addAction("复制该值")
            act_row = menu.addAction("复制该行")
        act_all = menu.addAction("复制全部摘要")
        if self.hmac_label.text() and "结果：—" not in self.hmac_label.text():
            act_hmac = menu.addAction("复制 HMAC 结果")
        else:
            act_hmac = None
        act = menu.exec(self.table.viewport().mapToGlobal(pos))
        if act is act_cell:
            self._copy_cell(idx.row(), idx.column())
        elif act is act_row:
            self._copy_row(idx.row())
        elif act is act_all:
            self._copy_all()
        elif act is act_hmac:
            self._copy_hmac()

    def _copy_cell(self, row, col):
        it = self.table.item(row, col)
        QApplication.clipboard().setText(it.text() if it else "")

    def _copy_row(self, row):
        c0 = self.table.item(row, 0)
        c1 = self.table.item(row, 1)
        QApplication.clipboard().setText("%s\t%s" % (c0.text() if c0 else "", c1.text() if c1 else ""))

    def _copy_all(self):
        lines = []
        for r in range(self.table.rowCount()):
            c0 = self.table.item(r, 0)
            c1 = self.table.item(r, 1)
            lines.append("%s: %s" % (c0.text() if c0 else "", c1.text() if c1 else ""))
        QApplication.clipboard().setText("\n".join(lines))

    def _copy_hmac(self):
        text = self.hmac_label.text()
        val = text.split("结果：", 1)[-1] if "结果：" in text else text
        QApplication.clipboard().setText(val)
        self.hmac_label.setToolTip(val)

    def _hmac_label_menu(self, pos):
        """HMAC 结果标签右键菜单：复制 HMAC 值。"""
        text = self.hmac_label.text()
        if not text or "结果：—" in text:
            return
        menu = QMenu(self)
        act = menu.addAction("复制 HMAC 结果")
        if menu.exec(self.hmac_label.mapToGlobal(pos)) is act:
            self._copy_hmac()

    def _clear(self):
        """清空数据来源、输入、摘要结果、HMAC 区域，并回到文本模式。"""
        self._file_data = None
        self.in_edit.clear()
        self.file_label.setText("")
        self.key_edit.clear()
        self.table.setRowCount(0)
        self.hmac_label.setText("HMAC 结果：—")
        if self.rb_file.isChecked():
            self.rb_text.setChecked(True)



# ============================================================ 进制转换
class RadixTab(QWidget):
    """进制转换：二进制 / 八进制 / 十进制 / 十六进制 互转（默认 十进制 → 十六进制）"""
    _BASE_ITEMS = [
        ("bin", "二进制"),
        ("oct", "八进制"),
        ("dec", "十进制"),
        ("hex", "十六进制"),
    ]

    def __init__(self, parent=None):
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.addWidget(QLabel("输入整数值："))

        self.in_edit = QPlainTextEdit()
        self.in_edit.setMaximumHeight(110)
        root.addWidget(self.in_edit)

        # 进制设置区
        cfg = QGroupBox("进制设置")
        g = QGridLayout(cfg)
        g.addWidget(QLabel("源进制："), 0, 0)
        self.src_combo = QComboBox()
        for val, label in self._BASE_ITEMS:
            self.src_combo.addItem(label, val)
        self.src_combo.setCurrentIndex(self._BASE_ITEMS.index(("dec", "十进制")))
        g.addWidget(self.src_combo, 0, 1)
        g.addWidget(QLabel("目标进制："), 0, 2)
        self.dst_combo = QComboBox()
        for val, label in self._BASE_ITEMS:
            self.dst_combo.addItem(label, val)
        self.dst_combo.setCurrentIndex(self._BASE_ITEMS.index(("hex", "十六进制")))
        g.addWidget(self.dst_combo, 0, 3)

        self.btn_convert = QPushButton("转换")
        self.btn_convert.clicked.connect(self._convert_from_cfg)
        g.addWidget(self.btn_convert, 0, 4)

        self.btn_clear = QPushButton("清空")
        self.btn_clear.clicked.connect(self._clear)
        g.addWidget(self.btn_clear, 0, 5)
        root.addWidget(cfg)

        root.addWidget(QLabel("结果（目标进制置顶，四种进制全景）："))
        self.out_edit = QPlainTextEdit()
        self.out_edit.setReadOnly(True)
        self.out_edit.setFont(QFont(MONO, 10))
        root.addWidget(self.out_edit)

        act = QHBoxLayout()
        self.btn_copy = QPushButton("复制结果")
        self.btn_copy.clicked.connect(self._copy)
        act.addWidget(self.btn_copy)
        act.addStretch(1)
        root.addLayout(act)

    def _convert_from_cfg(self):
        src = self.src_combo.currentData()
        dst = self.dst_combo.currentData()
        text = self.in_edit.toPlainText()
        if not text.strip():
            self.out_edit.setPlainText("")
            return
        try:
            n = radix.parse_int(text, src)
            lines = ["【%s】%s" % (radix.out_label(dst), radix.format_in(n, dst))]
            for key, label, val in radix.all_bases(n):
                if key != dst:
                    lines.append("%s：%s" % (label, val))
            self.out_edit.setPlainText("\n".join(lines))
        except Exception as e:
            self.out_edit.setPlainText("[转换失败] %s：%s" % (src + "→" + dst, e))

    def _copy(self):
        """复制结果区文本到剪贴板。"""
        text = self.out_edit.toPlainText()
        if text:
            QApplication.clipboard().setText(text)

    def _clear(self):
        """清空输入与输出（保留进制选择）。"""
        self.in_edit.clear()
        self.out_edit.clear()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_TITLE)
        self.resize(1220, 860)

        tabs = QTabWidget()
        tabs.addTab(Sm2Sm3Tab(), "① 国密 SM2 / SM3（签名 / 验签 / 加解密）")
        tabs.addTab(CodecTab(), "② 常用编码转换")
        tabs.addTab(PcapTab(), "③ 协议分析 (pcap)")
        tabs.addTab(CertTab(), "④ 证书分析")
        tabs.addTab(SymCryptoTab(), "⑤ 对称加解密 SM4/AES")
        tabs.addTab(HashTab(), "⑥ 摘要 / HMAC")
        tabs.addTab(RadixTab(), "⑦ 进制转换")
        self.setCentralWidget(tabs)
        self.statusBar().showMessage("就绪 — 国密 SM2/SM3/SM4、TLS/TLCP 抓包与证书分析")


def _place_window_on_screen(w):
    """把主窗口放回主屏可用区域。

    多显示器且排列异常（或系统记忆了旧位置）时，窗口可能被放到可视区域之外，
    表现为「进程已启动但看不到窗口」；启动时统一校正到主屏，并在 show 之后再
    校验一次标题栏是否可见（部分窗口管理器会把窗口再挪走）。
    """
    try:
        from PySide6.QtCore import QTimer
        from PySide6.QtGui import QGuiApplication
    except Exception:
        return
    screen = QGuiApplication.primaryScreen() or next(iter(QGuiApplication.screens()), None)
    if screen is None:
        return
    avail = screen.availableGeometry()
    ww = min(max(w.width(), 800), avail.width())
    hh = min(max(w.height(), 600), avail.height())
    x = avail.left() + max(0, (avail.width() - ww) // 2)
    y = avail.top() + max(0, (avail.height() - hh) // 2)
    w.setGeometry(x, y, ww, hh)

    def _ensure_visible():
        a = screen.availableGeometry()
        fg = w.frameGeometry()
        if fg.top() < a.top():
            w.move(w.x(), w.y() + (a.top() - fg.top()))
            fg = w.frameGeometry()
        if fg.left() < a.left():
            w.move(w.x() + (a.left() - fg.left()), w.y())
            fg = w.frameGeometry()
        if (fg.top() < a.top() or fg.left() < a.left()
                or fg.bottom() > a.bottom() or fg.right() > a.right()):
            # 仍不可见（例如窗口大于屏幕）：退化为最大化，保证能用
            w.showMaximized()

    QTimer.singleShot(0, _ensure_visible)


def main():
    app = QApplication(sys.argv)
    app.setApplicationName(APP_TITLE)
    app.setStyleSheet(QSS)
    w = MainWindow()
    _place_window_on_screen(w)
    w.show()
    w.raise_()
    w.activateWindow()
    print("[OK] 密码算法分析工具 v2.2 已启动，主界面窗口已打开（请勿关闭此控制台）", flush=True)
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
