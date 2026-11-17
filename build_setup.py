# -*- coding: utf-8 -*-
"""REA Studio 安装程序构建脚本

流程：publish ReaSetup（单文件 WPF 安装向导）-> 复制到 output\\REASetup.exe
      -> 把 output\\REAStudio.exe（已内含 node / llama / model 载荷）附加到安装器尾部
      -> 写 24 字节尾标 REASET01 + offset + length
安装器运行时会从自身尾部读出该 REAStudio.exe 并释放到安装目录，因此模型随安装包一起分发。
"""
import os
import shutil
import struct
import subprocess
import sys
import time

ROOT = r"F:\REA-Inverse"
SETUP_PROJ = os.path.join(ROOT, "installer", "ReaSetup")
PUBLISH = os.path.join(ROOT, "build", "setup_publish")
OUTPUT = os.path.join(ROOT, "output")
PAYLOAD_EXE = os.path.join(OUTPUT, "REAStudio.exe")
PAYLOAD_LITE = os.path.join(OUTPUT, "REA Studio(no model).exe")
SETUP_EXE = os.path.join(OUTPUT, "REASetup.exe")
SETUP_LITE = os.path.join(OUTPUT, "REA Setup(no model).exe")
MAGIC = b"REASET01"        # 载荷含本地大模型
MAGIC_LITE = b"REASET02"   # 载荷不含本地大模型（安装后在线下载）


def log(msg):
    print("[setup] " + msg, flush=True)


def publish():
    if os.path.isdir(PUBLISH):
        shutil.rmtree(PUBLISH, ignore_errors=True)
    cmd = [
        "dotnet", "publish", "ReaSetup.csproj",
        "-c", "Release", "-r", "win-x64", "--self-contained", "true",
        "-p:PublishSingleFile=true",
        "-p:IncludeNativeLibrariesForSelfExtract=true",
        "-o", PUBLISH,
    ]
    log("publish: " + " ".join(cmd))
    r = subprocess.run(cmd, cwd=SETUP_PROJ, capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    if r.returncode != 0:
        print((r.stdout or "")[-2000:] + (r.stderr or "")[-2000:])
        raise SystemExit("ReaSetup publish 失败")
    exe = os.path.join(PUBLISH, "REASetup.exe")
    if not os.path.isfile(exe):
        raise SystemExit("未生成 REASetup.exe")
    os.makedirs(OUTPUT, exist_ok=True)
    log("安装器骨架 %.1f MB" % (os.path.getsize(exe) / 1048576.0))
    return exe


def emit(skeleton, dst, payload, magic, tag):
    """把 payload exe 附加到安装器骨架末尾，写出安装程序。"""
    if not os.path.isfile(payload):
        log("跳过 %s：缺少 %s（请先运行 build.py）" % (os.path.basename(dst), os.path.basename(payload)))
        return
    if os.path.exists(dst):
        os.remove(dst)
    shutil.copy2(skeleton, dst)
    base = os.path.getsize(dst)
    length = os.path.getsize(payload)
    log("附加载荷 [%s] %.1f MB -> %s" % (tag, length / 1048576.0, os.path.basename(dst)))
    t0 = time.time()
    with open(dst, "ab") as out:
        with open(payload, "rb") as src:
            shutil.copyfileobj(src, out, 16 * 1024 * 1024)
        out.write(struct.pack("<8sqq", magic, base, length))
    log("安装程序完成: %s (%.1f MB, %.1fs)" % (dst, os.path.getsize(dst) / 1048576.0, time.time() - t0))


if __name__ == "__main__":
    skeleton = publish()
    if "nopayload" not in sys.argv:
        emit(skeleton, SETUP_EXE, PAYLOAD_EXE, MAGIC, "含模型")
        emit(skeleton, SETUP_LITE, PAYLOAD_LITE, MAGIC_LITE, "不含模型")
    log("完成")
