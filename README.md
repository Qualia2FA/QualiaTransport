# QualiaTransport

两台设备之间把一段字节送过去的几条通道：**二维码**（含从一张图片里读回来）与
**局域网**（在同一网段上互相发现，再把字节送过去）。

这是一个独立可复用的库：任何需要「让两台设备交换一小段字节」的项目都能用它，不需要
接受 Qualia2FA 的保险库格式、账号模型或同步协议。

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

局域网那一半（组播发现不需要额外 feature）：

```rust
use qualia_transport::lan::lobby::Lobby;
use qualia_transport::lan::LanAddress;

// 打开大厅：往一个组播组里周期性地报「我在这里、我的端点公钥与端口是这个」，
// 同时听别人报。
let mut lobby = Lobby::open(my_device_id, my_endpoint_key, my_port)?;

// 界面每次刷新时把积压的事件取完。
while let Some(event) = lobby.try_poll() {
    println!("{:?} 现在 {:?}", event.peer.device, event.peer.status);
}

// 跨网段（组播到不了）时，把连接信息放进二维码带外传过去。
let bytes = LanAddress::new(my_endpoint_key, my_port).encode();
```

## 它解决的三个问题

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

**三、局域网里「谁在」这一问不该每次都靠扫码。** 同一个 WiFi 下的设备本来就在一个
广播域里，因此局域网那半用 **UDP 组播**做发现：每台设备周期性地报一次自己的设备
标识、端点公钥与端口，各方累积出一份「这个网段上有谁」的名单。发现**不做认证**——
公告只是提示，真正的身份由建立连接时的握手证明（见下）；跨网段或组播被禁时，退回
二维码把连接信息带外传过去。

## 局域网通道的两点约定

**发现可以无认证，凭据必须来自信道。** 组播组是共享介质：同网段上任何一台机器都能
往组里灌任意字节，包括「我是设备 X」这种伪造公告。因此公告**不签名**，它只用来回答
「这个网段上大概有谁、去哪里找他」；「他真的是那台设备吗」由连接建立时的握手回答，
而「这条载荷该不该收」由上层按设备标识做白名单。给公告签名的代价是每个公告周期都
唤醒一次硬件密钥库，而收益是零——伪造公告换来的只是让对端发起一次连不上的连接。

**在线格式里带上发送方的设备标识。** 传输层只认端点公钥（握手证明的那个），而上层
要的是设备标识（用户看得见的那个）。两者之间的映射来自无认证的公告，因此**不能信**：
每条消息由发送方自己报一次设备标识，接收方用它去套已有的白名单。这个字段不是用来
**建立**信任的，而是用来让接收方**应用**信任。

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

需要局域网的数据面（QUIC 传输）时打开 `iroh-lan`：

```toml
[dependencies]
qualia-transport = { version = "0.1", features = ["iroh-lan"] }
```

组播发现与二维码**不**需要这个 feature——它只带进 QUIC 传输层。注意三点：它会显著
增大依赖树与构建时间；它的最低 Rust 版本是 **1.91**（iroh 1.3.0 的要求），高于本
crate 的 1.89；**「不联网」目前只到「不构建 relay、不注册 DNS/pkarr、关掉 HTTPS
探测」这一层，抓包实证尚未完成**，因此不要把「本通道已证明不联网」写进对外说明。

## 接口约定

- **装不下是一个错误，不是一个近似。** 超过上限就返回错误，绝不产出「差一点」的码。
- **线格式是 `Q2FA1:<帧号>/<帧数>:<BASE32>`。** 前缀让别人的二维码能被一眼认出来
  （报「这不是本应用的码」而不是「载荷坏了」）；帧号/帧数写在载荷之前，是为了将来做
  动态二维码时，扫描方不必解开任何一帧就知道还差哪几帧。
- **同一个载荷只有一种文本表示。** 大小写、填充、非零尾比特都被规范化或拒绝——否则
  「这两张码是不是同一张」就没有答案，而去重与重放记账都要靠它。
- **输入是像素，不是图片文件。** 图像格式的解码归平台（JVM 的 `ImageIO`、Android 的
  `BitmapFactory`、iOS 的 `UIImage`）：格式解码器是历史漏洞的重灾区，而这个库只认像素。
- **局域网公告是定长 84 字节的 UDP 报文，连接信息是定长 42 字节。** 定长让解析器的
  形状就是「长度不对就拒绝」，没有一处可以被输入牵着走的变长解析。组播 TTL 固定为 1：
  公告飘到别的网段，会让「设备列表里出现隔壁办公室的机器」这种无法解释的现象成真。
- **列表与收件箱都有界。** 设备标识是公开信息，同网段的任何一台机器都能凭空造出无数
  个「新设备」发公告（每条 84 字节）。因此对端名单有上限、超出时丢掉最不活跃的那些，
  而收件箱满了丢最旧的——上限是安全性质，不是性能调优。
- **收件人是显式的。** 定向发送不得退化成广播——一条本该只给 B 的载荷出现在 C 手里，
  用户看不到任何异常。
- **纯逻辑，除了一处。** 二维码那一半与局域网的线格式不碰文件系统、网络、时钟与环境
  变量，全部输入都是参数；只有组播大厅会开 socket、起一个后台线程、读时钟，而那里的
  判断被压到最小——所有推理都在纯逻辑那一层，因此「三台设备收敛到同一份名单」这类
  性质可以在一个进程里、不需要网络地验证。`#![forbid(unsafe_code)]` 全程成立，且任何
  输入都不得导致 panic——唯一的失败方式是返回错误。
- **本库不生成密钥材料。** 二维码编码是确定性的；组播大厅只读取调用方给的端点公钥与
  端口。载荷里的随机数与密钥由调用方负责。

## 状态

已实现：二维码的容量模型、编码、渲染、文本信封、从图像里解码（`scan-image`，默认
开启）；局域网 UDP 组播发现与连接信息；局域网数据面（`iroh-lan`，默认关闭）。

尚未实现：动态二维码（多帧，格式里已经留好帧号/帧数），以及各平台的局域网权限流程
——Android 17（targetSdk 37+）需要在运行时申请 `ACCESS_LOCAL_NETWORK`，iOS 需要
`NSLocalNetworkUsageDescription` 与组播 entitlement。

## 参与贡献

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo clippy --all-targets --no-default-features -- -D warnings   # feature 组合也要干净
cargo test --no-default-features --all-targets
cargo clippy --all-targets --features iroh-lan -- -D warnings     # 局域网数据面
cargo test --features iroh-lan
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
cargo +nightly fuzz run lan_datagram -- -max_total_time=60
```

### MSRV 策略

最低支持 Rust **1.89**，但「所有 feature 组合都在 1.89 上成立」这句话**不成立**：
`iroh-lan` 要求 **1.91**（iroh 1.3.0 声明的 `rust-version`）。因此 CI 的 MSRV 那一关
测的是不带 `iroh-lan` 的两种组合，带它的组合由 stable 工具链覆盖。MSRV 会随依赖的
实际需要提升，但每次提升都要在 CI 里用真实工具链验证过。

## 许可

LGPL-3.0-or-later，见 [LICENSE](LICENSE) 与 [COPYING.LESSER](COPYING.LESSER)。

选择 LGPL 而非 MIT/Apache 是刻意的：本库解析的是攻击者可控的输入（扫到的文本、导入
的图片、同网段上任何人发来的报文），任何修改都应当以源码形式回馈，以便被审计。
