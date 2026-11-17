# -*- coding: utf-8 -*-
"""REA Studio 打包脚本

流程：assemble（组装 node / rea-agents / llama / model）-> make_zip
      -> dotnet publish 单文件自包含 -> 把 payload.zip 追加到 EXE 尾部（24 字节尾标 REAPAY01）

产物（output 目录）：
  REAStudio.exe       带模型版：载荷含 node + llama + model.gguf
  REA Studio(no model).exe  不带模型版：载荷只含 node + llama，模型由用户在软件内「下载模型」获取

用法：
  python build.py                # 产出两版
  python build.py skipzip        # 不重打载荷（仅重发布程序本体，沿用已有 payload.zip）
  python build.py nomodel        # 只产出不带模型版
"""
import os
import shutil
import struct
import subprocess
import sys
import time
import zipfile

ROOT = r"F:\REA-Inverse"
PAYLOAD = os.path.join(ROOT, "build", "payload")
NODE_SRC = os.path.join(PAYLOAD, "node", "node.exe")
REA_SRC = os.path.join(ROOT, "build", "rea-agents")
PROJ = os.path.join(ROOT, "src", "ReaStudio")
TEMP = os.path.join(ROOT, "build", "temp")
ZIP_FULL = os.path.join(TEMP, "payload.zip")
ZIP_LITE = os.path.join(TEMP, "payload-lite.zip")
PART_DIR = os.path.join(ROOT, "build", "payload")
CHUNK_MB = 700
PUBLISH = os.path.join(ROOT, "build", "publish-out")
OUTPUT = os.path.join(ROOT, "output")
EXE_FULL = "REAStudio.exe"
EXE_LITE = "REA Studio(no model).exe"
MAGIC = b"REAPAY01"


def log(msg):
    print("[build] " + msg, flush=True)


def copy_tree(src, dst):
    if os.path.isdir(dst):
        shutil.rmtree(dst, ignore_errors=True)
    shutil.copytree(src, dst)
    n = sum(len(f) for _, _, f in os.walk(dst))
    size = sum(os.path.getsize(os.path.join(r, f)) for r, _, fs in os.walk(dst) for f in fs)
    log("copied %s -> %s (%d files, %.1f MB)" % (src, dst, n, size / 1048576.0))


def assemble():
    node_dir = os.path.join(PAYLOAD, "node")
    os.makedirs(os.path.join(node_dir, "modules"), exist_ok=True)
    if not os.path.isfile(NODE_SRC):
        raise SystemExit("缺少 node.exe: " + NODE_SRC)
    dst = os.path.join(node_dir, "modules", "rea-agents")
    if not os.path.isfile(os.path.join(dst, "scripts", "rea.mjs")):
        copy_tree(REA_SRC, dst)
    else:
        log("rea-agents already present, skip copy")
    if not os.path.isfile(os.path.join(dst, "scripts", "rea.mjs")):
        raise SystemExit("rea-agents 入口缺失")

    for need, name in [
        (os.path.join(PAYLOAD, "llama", "llama-server.exe"), "llama-server.exe"),
        (os.path.join(PAYLOAD, "model", "model.gguf"), "model.gguf"),
    ]:
        if os.path.isfile(need):
            log("%s ready (%.1f MB)" % (name, os.path.getsize(need) / 1048576.0))
        else:
            log("警告: 缺少 " + name + "，本地 AI 推理将不可用")


def _walk_zip(z, base, arc):
    if not os.path.isdir(base):
        log("警告: 载荷目录不存在，跳过 " + base)
        return
    for r, _, files in os.walk(base):
        for f in files:
            full = os.path.join(r, f)
            rel = os.path.relpath(full, base).replace("\\", "/")
            arcname = arc + "/" + rel
            if f.lower().endswith(".gguf"):
                zi = zipfile.ZipInfo.from_file(full, arcname)
                zi.compress_type = zipfile.ZIP_STORED
                with open(full, "rb") as fh, z.open(zi, "w") as out:
                    shutil.copyfileobj(fh, out, 1024 * 1024 * 4)
            else:
                z.write(full, arcname, zipfile.ZIP_DEFLATED)


def make_zip(lite=False):
    """lite=True 时不打包 model 目录（不带模型版）。"""
    dst = ZIP_LITE if lite else ZIP_FULL
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    if os.path.exists(dst):
        os.remove(dst)
    dirs = ("llama", "node") if lite else ("llama", "model", "node")
    t0 = time.time()
    with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for name in dirs:
            _walk_zip(z, os.path.join(PAYLOAD, name), name)
    log("%s = %.1f MB (%.1fs)  [%s]" % (
        os.path.basename(dst), os.path.getsize(dst) / 1048576.0, time.time() - t0,
        "不含模型" if lite else "含模型"))


def split_payload():
    """把 payload.zip 切成 <= 700MB 分卷内嵌（单资源过大时 CSC 会报 CS1566）。
    已有旧分卷不删除，整体归档到 build\\temp\\old-parts-<时间戳>\\。"""
    if not os.path.isfile(ZIP_FULL):
        log("警告: 无 payload.zip，跳过分卷")
        return
    os.makedirs(PART_DIR, exist_ok=True)
    stale = [f for f in os.listdir(PART_DIR) if f.startswith("payload.zip")]
    if stale:
        arch = os.path.join(TEMP, "old-parts-%s" % time.strftime("%Y%m%d%H%M%S"))
        os.makedirs(arch, exist_ok=True)
        for f in stale:
            shutil.move(os.path.join(PART_DIR, f), os.path.join(arch, f))
        log("旧分卷已归档到 " + arch + "（%d 个）" % len(stale))
    chunk = CHUNK_MB * 1024 * 1024
    idx = 1
    with open(ZIP_FULL, "rb") as src:
        while True:
            buf = src.read(chunk)
            if not buf:
                break
            dst = os.path.join(PART_DIR, "payload.zip.%03d" % idx)
            with open(dst, "wb") as out:
                out.write(buf)
            log("part %s = %.1f MB" % (os.path.basename(dst), len(buf) / 1048576.0))
            idx += 1
    log("分卷完成，共 %d 卷" % (idx - 1))


def dotnet_publish():
    if os.path.isdir(PUBLISH):
        shutil.rmtree(PUBLISH, ignore_errors=True)
    cmd = [
        "dotnet", "publish", "ReaStudio.csproj",
        "-c", "Release", "-r", "win-x64", "--self-contained", "true",
        "-p:PublishSingleFile=true",
        "-p:IncludeNativeLibrariesForSelfExtract=true",
        "-o", PUBLISH,
    ]
    log("publish: " + " ".join(cmd))
    r = subprocess.run(cmd, cwd=PROJ, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if r.returncode != 0:
        print((r.stdout or "")[-1500:] + (r.stderr or "")[-1500:])
        raise SystemExit("publish 失败")
    exe = os.path.join(PUBLISH, "REAStudio.exe")
    if not os.path.isfile(exe):
        raise SystemExit("未生成 REAStudio.exe")
    return exe


def attach_payload(exe, src):
    """把 payload.zip 追加到 EXE 尾部，并写 24 字节尾标（magic + 偏移 + 长度）。"""
    if not os.path.isfile(src):
        log("警告: 缺少 %s，跳过附加" % src)
        return
    base = os.path.getsize(exe)
    length = os.path.getsize(src)
    with open(exe, "ab") as out:
        with open(src, "rb") as z:
            shutil.copyfileobj(z, out, 8 * 1024 * 1024)
        out.write(struct.pack("<8sqq", MAGIC, base, length))
    log("载荷已附加: %s offset=%d length=%.1f MB" % (os.path.basename(src), base, length / 1048576.0))


def emit(skeleton, name, zip_src):
    dst = os.path.join(OUTPUT, name)
    if os.path.exists(dst):
        os.remove(dst)
    shutil.copy2(skeleton, dst)
    attach_payload(dst, zip_src)
    log("产物: %s  (%.1f MB)" % (dst, os.path.getsize(dst) / 1048576.0))


if __name__ == "__main__":
    args = sys.argv[1:]
    lite_only = "nomodel" in args
    os.makedirs(OUTPUT, exist_ok=True)
    assemble()
    if "skipzip" not in args:
        if not lite_only:
            make_zip(lite=False)
        make_zip(lite=True)
    skeleton = dotnet_publish()
    if not lite_only:
        emit(skeleton, EXE_FULL, ZIP_FULL)
    emit(skeleton, EXE_LITE, ZIP_LITE)
    log("完成")
