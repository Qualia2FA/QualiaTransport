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
| `frame_reassemble` | 动态二维码的**状态机**（输入被切成若干段，逐段喂同一个拼装器） | 不 panic、报错时状态不变、拼装按帧号而不是按到达顺序、自己拆出来的帧必定拼得回去 |
| `qr_scan` | 图像解码（用户导入的图片可能是别人给的） | 不 panic、尺寸任意（1×1 到 48×48）、尺寸构造不吞内存、解得开的载荷能重新编码再读回来 |
| `lan_datagram` | UDP 组播报文与二维码里的连接信息（同网段任何人都能灌） | 不 panic、解析出来的一定能原样编回去、重复与乱序不改变视图、压力下视图有界 |

`frame_reassemble` 是唯一一个**跨输入有状态**的目标：像 `envelope_decode` 那样「一条
文本进去、一份字节出来」的形态永远走不到「先扫了 A 的第 1 帧、再扫 B 的第 2 帧」这类
序列，而状态机正是拼装器的全部内容。它的输入按字节切成若干段，段与段之间共享同一个
拼装器。

## 为什么图像目标要把边长压到 48

二维码定位是**逐像素**的：图一大，单次执行就从微秒变成毫秒，覆盖速度掉几个数量级，
而 fuzz 的价值全在「每秒能试多少次」。真正需要担心的越界与整数溢出都发生在小尺寸的
边界上（1×1、21×21、极端长宽比），大图并不会带来新的分支。

## 写断言时的陷阱

**`libfuzzer-sys` 的 panic hook 在展开之前就 `abort`。** 因此**库里的 `catch_unwind`
在 fuzz 目标里形同虚设**：panic 还没开始展开，进程就被 hook 结束了。这个坑在给
`qr_scan` 加收敛时才暴露出来（见 `Error::QrDecoderPanicked`）——库里的收敛是对的、
`cargo test` 里的回归测试是绿的，而 fuzzer 仍然报同一份输入崩溃。目标要覆盖一条
**已知会 panic** 的路径，就得先把这个 hook 换掉（`qr_scan.rs` 的 `loosen_panic_hook`）。
代价是丢掉展开前的调用栈，而输入样本仍在，复现一次就有栈。

**换掉 hook 也修不好 Windows。** Rust 的 panic 在 Windows 上以 SEH 异常的形式抛出，
而 libFuzzer 自己有一个进程级的异常处理器，它会把这次抛出直接当成崩溃——`catch_unwind`
一样没机会。因此**本机（Windows）跑 `qr_scan` 时，一个已经被库收敛的 panic 仍会报成
崩溃**；CI 的 fuzz job 在 Linux 上，那里 panic 不发信号，收敛照常生效。要在本机确认
收敛有效，看 `cargo test`，不要看这个目标。

**一条已知的上游缺陷不该让关卡长期红着。** `rqrr` 0.11.0 里有一处断言会被退化图像
触发（几十字节的周期性噪声就够），而本 crate 已经把它收敛成错误。若 fuzz 目标把这个
错误重新抛成断言，这一关就会在上游修复之前一直红——而**长期红的关卡只会被无视**。
因此 `qr_scan` 把它当成允许的结果：可见性由应用侧的日志与那条定长回归测试提供。

**不要做全局子串搜索。** 断言「输出里含某个串」时，fuzzer 会构造出把该串放进**别的
字段**的输入，于是断言命中了一个无关的位置——上游仓库已经因此误报过两次。判据是
「断言有没有绑定到具体字段的结构」。

**`prop_assert!` 会把表达式当格式串。** `matches!(x, Err(E::V { .. }))` 里的花括号会被
当成占位符，报的是 `invalid format string`。先绑到一个 `bool` 再断言。

**断言失败时先问「这条性质本身对不对」。** 「任意输入都必须被拒绝」这类断言经常是
错的：合法的边界输入本来就该被接受。写新性质时先想清楚反例会是什么。
