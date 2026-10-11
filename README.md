# QualiaTransport

把一段字节放进**二维码**，再从二维码（或一张图片）里读回来。

这是一个独立可复用的库：任何需要「让两台设备通过二维码交换一小段字节」的项目都能用它，
不需要接受 Qualia2FA 的保险库格式、账号模型或同步协议。

```rust
use qualia_transport::qr::{EcLevel, QrProfile};

// 声明这条通道的能力：M 级纠错、最多显示到第 20 版（97×97 模块）。
let profile = QrProfile::new(EcLevel::Medium, 20)?;

// 装不下会在**这里**就报出来（带上「需要多少、上限多少」），而不是等到用户扫码。
let symbol = profile.encode_payload(payload)?;
println!("第 {} 版，{}×{} 模块", symbol.version(), symbol.size(), symbol.size());

// 端侧按 modules() 把矩阵画到界面上；要一份像素用 render()。
let image = symbol.render(4, 4)?;

// 反过来：从摄像头或用户导入的图片里把载荷读回来。
let payload = qualia_transport::qr::scan::decode_payload(&image)?;
```

## 它解决的两个问题

**一、容量必须在使用之前就知道。** 二维码装不下就是装不下，没有重试余地——而用户
已经举着手机在扫的时候才发现，是最坏的时机。因此本库给出这条通道的**精确上限**，
并且那个数字是**对编码器实时二分出来的**，不是从规范里抄来的一张表：抄错不会编译
报错，而一旦编码器换了实现，抄来的表就开始与真实行为各自漂移。超限时报出的错误带着
`needed` 与 `limit`，调用方据此才能告诉用户「差多少」，并顺势引导改用别的通道。

**二、平台相机交回的是文本，不是字节。** Android 的 ML Kit、iOS 的 AVFoundation、
剪贴板、以及人眼抄下来的一串字符——全都只能承载文本。因此载荷先经过一层文本信封
（`Q2FA1:<帧号>/<帧数>:<BASE32>`），再用二维码的**字母数字模式**编码：整串只落在
二维码那 45 个字符的表内，代价约 10% 容量，换来的是「任何扫码器读出来的都是同一串
文本」。选 Base32 而不是 Base64 正是为此——Base64 的小写字母不在那张表里。

## 接入你自己的项目

```toml
[dependencies]
qualia-transport = "0.1"
```

移动端走平台相机、不需要从图片里解码时，关掉默认 feature 可以甩掉整条图像解码链
（它也是本库依赖树里唯一带 `unsafe` 的地方，来自缓存 crate）：

```toml
[dependencies]
qualia-transport = { version = "0.1", default-features = false }
```

## 接口约定

- **装不下是一个错误，不是一个近似。** 超过上限就返回错误，绝不产出「差一点」的码。
- **线格式是 `Q2FA1:<帧号>/<帧数>:<BASE32>`。** 前缀让别人的二维码能被一眼认出来
  （报「这不是本应用的码」而不是「载荷坏了」）；帧号/帧数写在载荷之前，是为了将来做
  动态二维码时，扫描方不必解开任何一帧就知道还差哪几帧。
- **同一个载荷只有一种文本表示。** 大小写、填充、非零尾比特都被规范化或拒绝——否则
  「这两张码是不是同一张」就没有答案，而去重与重放记账都要靠它。
- **输入是像素，不是图片文件。** 图像格式的解码归平台（JVM 的 `ImageIO`、Android 的
  `BitmapFactory`、iOS 的 `UIImage`）：格式解码器是历史漏洞的重灾区，而这个库只认像素。
- **纯逻辑。** 不碰文件系统、网络、时钟与环境变量，全部输入都是参数；`#![forbid(unsafe_code)]`，
  且任何输入都不得导致 panic——唯一的失败方式是返回错误。
- **本库不生成随机数，也不接触任何密钥材料。** 二维码编码是确定性的；载荷里的随机数
  与密钥由调用方负责。

## 状态

已实现：二维码的容量模型、编码、渲染、文本信封、以及从图像里解码（`scan-image`，
默认开启）。

尚未实现：**局域网通道**——UDP 组播发现、离线传输、以及各平台的局域网权限流程。
它与二维码的区别只是「字节怎么过去」，上层的合并与裁决逻辑完全共用。

## 参与贡献

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo clippy --all-targets --no-default-features -- -D warnings   # feature 组合也要干净
cargo test --no-default-features --all-targets
cargo doc --no-deps            # 不得有警告（配 RUSTDOCFLAGS="-D warnings"）
cargo +1.89 check --all-targets
cargo deny check
```

fuzz 目标在 `fuzz/`（需要 nightly 与 cargo-fuzz，Windows 上还要先修 `PATH`，见
`fuzz/README.md`）：

```bash
cd fuzz
cargo +nightly fuzz list
cargo +nightly fuzz run envelope_decode -- -max_total_time=60
cargo +nightly fuzz run qr_scan -- -max_total_time=60
```

### MSRV 策略

最低支持 Rust **1.89**。MSRV 会随依赖的实际需要提升，但每次提升都要在 CI 里用真实
工具链验证过（`cargo +1.89 check --all-targets`）。

## 许可

LGPL-3.0-or-later，见 [LICENSE](LICENSE) 与 [COPYING.LESSER](COPYING.LESSER)。

选择 LGPL 而非 MIT/Apache 是刻意的：本库解析的是攻击者可控的输入（扫到的文本、导入
的图片），任何修改都应当以源码形式回馈，以便被审计。
