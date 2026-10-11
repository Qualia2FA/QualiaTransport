# fuzz 使用说明

本目录是本仓库的 libFuzzer 目标（基于 `cargo-fuzz`）。

## 为什么需要 nightly

`cargo-fuzz` 依赖 `-Zsanitizer`，这是 nightly 专属特性。稳定版无法运行 fuzz。

```powershell
rustup toolchain install nightly --component rust-src
cargo install cargo-fuzz --locked
```

## ⚠️ Windows 上必须先修 PATH（否则 fuzz 跑不起来）

在 Windows + MSVC 上，Rust 的 `-Zsanitizer=address` 链接**动态** ASan 运行时，
所以运行时需要 `clang_rt.asan_dynamic-x86_64.dll` 在 `PATH` 上。它随 Visual Studio
分发，但**不在**默认 `PATH` 中，因此默认会看到：

```
error: process didn't exit successfully: ... (exit code: 0xc0000135, STATUS_DLL_NOT_FOUND)
```

加上 DLL 所在目录即可。**注意版本必须匹配**：先用 VS **2022** 的，VS 2019 那份会报
`0xc0000139 STATUS_ENTRYPOINT_NOT_FOUND`（DLL 找到了但符号对不上）。

```powershell
# 找出本机所有候选（版本不同，报错也不同）
Get-ChildItem 'C:\Program Files\Microsoft Visual Studio','C:\Program Files (x86)\Microsoft Visual Studio' `
  -Recurse -Filter 'clang_rt.asan_dynamic-x86_64.dll' -ErrorAction SilentlyContinue |
  Select-Object FullName, LastWriteTime, Length

# 把可用的那一份加到 PATH 前面（路径按上一步结果替换）
$asanDir = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\<版本>\bin\Hostx64\x64'
$env:PATH = "$asanDir;$env:PATH"
```

该路径与 VS 版本号绑死，**无法写死在仓库里**，所以必须每次手动设置（或在自己的
shell profile 里固化）。替代方案：在 **WSL / Linux** 上跑 fuzz 不需要这一步，
CI 的 fuzz job 就跑在 Linux 上。

## 运行

```powershell
cd fuzz

# 列出所有目标
cargo +nightly fuzz list

# 限时跑（**务必带限时**：libFuzzer 不会因为 -runs=N 就退出，
# 不带 -max_total_time 会一直跑下去）
cargo +nightly fuzz run envelope_decode -- -max_total_time=300

# 复现某个崩溃
cargo +nightly fuzz run envelope_decode artifacts/envelope_decode/<crash-file>
```

`corpus/`、`artifacts/`、`coverage/` 均不入库（见 `.gitignore`）。值得长期保留的样本
放进 `regressions/<目标>/`，那个目录是入库的，且 CI 会在跑 fuzz 前先喂进语料库。

## 现有目标

| 目标 | 覆盖的输入面 | 检查的性质 |
|---|---|---|
| `envelope_decode` | 二维码承载的文本（任何拍到码的人都能构造） | 不 panic、解得开就必须是规范写法、膨胀有界、整串落在二维码的字母数字模式里 |
| `qr_scan` | 图像解码（用户导入的图片可能是别人给的） | 不 panic、尺寸任意（1×1 到 48×48）、尺寸构造不吞内存、解得开的载荷能重新编码再读回来 |

## 为什么图像目标要把边长压到 48

二维码定位是**逐像素**的：图一大，单次执行就从微秒变成毫秒，覆盖速度掉几个数量级，
而 fuzz 的价值全在「每秒能试多少次」。真正需要担心的越界与整数溢出都发生在小尺寸的
边界上（1×1、21×21、极端长宽比），大图并不会带来新的分支。

## 写断言时的陷阱

**不要做全局子串搜索。** 断言「输出里含某个串」时，fuzzer 会构造出把该串放进**别的
字段**的输入，于是断言命中了一个无关的位置——上游仓库已经因此误报过两次。判据是
「断言有没有绑定到具体字段的结构」。

**`prop_assert!` 会把表达式当格式串。** `matches!(x, Err(E::V { .. }))` 里的花括号会被
当成占位符，报的是 `invalid format string`。先绑到一个 `bool` 再断言。

**断言失败时先问「这条性质本身对不对」。** 「任意输入都必须被拒绝」这类断言经常是
错的：合法的边界输入本来就该被接受。写新性质时先想清楚反例会是什么。
