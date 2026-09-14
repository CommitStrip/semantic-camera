#!/usr/bin/env python3
"""index.html 内联脚本护栏：语法检查（node --check）+ 顶层 TDZ 静态扫描。

CI 此前只对独立 JS 文件做 node --check，<script> 内联块零覆盖；而接线层
P0（页面加载即崩类）恰好全部出在内联块——TDZ 又是运行时错误，语法检查必绿。
本脚本补两道静态闸门：

1. 每个无 src 的 <script> 块过 node --check（源码走 stdin，命令全字面量）；
2. 顶层 use-before-declaration 扫描：const/let/class 不提升，顶层提前引用
   即 ReferenceError。先剥离注释与字符串（保位映射），再按花括号深度定位
   顶层——函数体/对象字面量在深度 >0，其内部前向引用合法，不误报。

保守边界（已知不报，宁漏勿误）：解构声明、多声明符的后续名字、function
声明（提升，合法）不参与判定。
"""
import argparse
import glob
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCAN_DIR = os.path.join(ROOT, "web")

IDENT = re.compile(r'[A-Za-z_$][A-Za-z0-9_$]*')
INLINE_SCRIPT = re.compile(r'<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>', re.S)

RESERVED = {
    'break', 'case', 'catch', 'class', 'const', 'continue', 'debugger',
    'default', 'delete', 'do', 'else', 'export', 'extends', 'false', 'finally',
    'for', 'function', 'if', 'import', 'in', 'instanceof', 'new', 'null',
    'return', 'super', 'switch', 'this', 'throw', 'true', 'try', 'typeof',
    'var', 'void', 'while', 'with', 'let', 'static', 'yield', 'await', 'of',
}


def under_root(path):
    """规范化并校验路径必须落在仓库根内，防目录逃逸。"""
    real = os.path.realpath(path)
    if os.path.commonpath([real, ROOT]) != ROOT:
        raise ValueError("path escapes repo root: %s" % path)
    return real


def strip_comments_strings(src):
    """剥离注释与字符串字面量；被剥字符替换为空格（换行保留）以保持位置映射。"""
    out = list(src)
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ''
        if c == '/' and nxt == '/':
            while i < n and src[i] != '\n':
                out[i] = ' '
                i += 1
        elif c == '/' and nxt == '*':
            out[i] = out[i + 1] = ' '
            i += 2
            while i < n and not (src[i] == '*' and i + 1 < n and src[i + 1] == '/'):
                out[i] = '\n' if src[i] == '\n' else ' '
                i += 1
            if i < n:
                out[i] = out[i + 1] = ' '
                i += 2
        elif c in ('"', "'"):
            q = c
            out[i] = ' '
            i += 1
            while i < n:
                if src[i] == '\\':
                    out[i] = ' '
                    if i + 1 < n:
                        out[i + 1] = ' '
                    i += 2
                    continue
                out[i] = '\n' if src[i] == '\n' else ' '
                i += 1
                if src[i - 1] == q:
                    break
        elif c == '`':
            out[i] = ' '
            i += 1
            while i < n:
                if src[i] == '\\':
                    out[i] = ' '
                    if i + 1 < n:
                        out[i + 1] = ' '
                    i += 2
                    continue
                out[i] = '\n' if src[i] == '\n' else ' '
                i += 1
                if src[i - 1] == '`':
                    break
        else:
            i += 1
    return ''.join(out)


def scan_tdz(code):
    """返回 [(line, name, decl_line)]：顶层引用了同块后面才声明的 const/let/class。"""
    stripped = strip_comments_strings(code)
    depth = [0] * (len(stripped) + 1)
    for i, ch in enumerate(stripped):
        depth[i + 1] = depth[i] + (1 if ch == '{' else -1 if ch == '}' else 0)

    declarations = {}
    uses = []
    last_ident = None
    for m in IDENT.finditer(stripped):
        name, pos = m.group(), m.start()
        if depth[pos] != 0:
            continue
        prev = stripped[:pos].rstrip()
        prev_ch = prev[-1] if prev else ''
        if prev_ch in ('.', '?'):      # 属性访问 a.b / a?.b（元组判定：空串 in 字符串恒真）
            last_ident = None
            continue
        if last_ident in ('const', 'let', 'class'):
            declarations.setdefault(name, pos)
            last_ident = name
            continue
        if last_ident == 'function':   # 函数声明提升，合法
            last_ident = name
            continue
        if name not in RESERVED:
            uses.append((name, pos))
        last_ident = name

    def line_of(p):
        return stripped.count('\n', 0, p) + 1

    return [(line_of(pos), name, line_of(declarations[name]))
            for name, pos in uses
            if name in declarations and pos < declarations[name]]


def syntax_check(js, tag):
    # node --check 从 stdin 读源码：命令列表保持全字面量，不经由磁盘临时文件
    r = subprocess.run(['node', '--check'], input=js, capture_output=True, text=True)
    if r.returncode != 0:
        print(f'[syntax] {tag}: FAIL\n{(r.stderr or r.stdout).strip()[:600]}')
        return False
    return True


SELF_TEST_CASES = [
    # (源码, 期望 TDZ 命中数, 说明)
    ('A.open();\nconst A = {};', 1, '顶层提前引用 const（原 P0-1 形态）'),
    ('function f() { return B.x; }\nconst B = {x: 1};', 0, '函数体内前向引用合法'),
    ('const C = { m() { return D; } };\nconst D = 1;', 0, '对象字面量方法内前向引用合法'),
    ('fn();\nfunction fn() {}', 0, 'function 声明提升合法'),
    ('const s = "A.open();";\nconst A = {};', 0, '字符串内引用不算'),
    ('// A.open();\nconst A = {};', 0, '注释内引用不算'),
    ('if (x) { g(); }\nconst g = () => {};', 0, '块内引用不算（引用处在深度>0）'),
    ('h();\nlet h = () => {};', 1, 'let 同样不提升'),
]


def self_test():
    ok = True
    for src, want, desc in SELF_TEST_CASES:
        got = scan_tdz(src)
        if len(got) != want:
            print(f'[self-test] FAIL: {desc} —— 期望 {want} 处，实得 {len(got)}: {got}')
            ok = False
        else:
            print(f'[self-test] ok: {desc}')
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--self-test', action='store_true', help='只跑内置用例')
    args = ap.parse_args()
    if args.self_test:
        return 0 if self_test() else 1

    files = [under_root(p) for p in glob.glob(os.path.join(SCAN_DIR, '*.html'))]
    if not files:
        print('[inline-guard] web/ 下无 HTML')
        return 1
    files.sort()
    failed = False
    for path in files:
        with open(path, encoding='utf-8') as f:
            html = f.read()
        for bi, block in enumerate(INLINE_SCRIPT.findall(html)):
            tag = f'{os.path.basename(path)}#block{bi}'
            if not syntax_check(block, tag):
                failed = True
            for line, name, decl_line in scan_tdz(block):
                print(f'[tdz] {tag}:{line} 引用了第 {decl_line} 行才声明的 '
                      f'const/let/class「{name}」——顶层提前引用即 ReferenceError')
                failed = True
    print('[inline-guard] ' + ('FAIL' if failed else 'PASS'))
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
