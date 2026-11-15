# Hướng dẫn cấp License Key (tiếng Việt)

Tài liệu vận hành cho **nhà cung cấp** (bạn). Platform bị **khoá** cho tới khi có
license key hợp lệ: chưa có key thì mọi thao tác ghi (tạo task, chạy workflow,
agent) bị từ chối `402`, chỉ đọc là mở. Bạn phát một mã đã ký và gửi khách; khách
dán vào **System → License**. Việc xác thực **hoàn toàn offline** — không cần
internet, không server kích hoạt.

---

## 1. Cơ chế (hiểu nhanh)

- **Chữ ký số Ed25519.** Bạn giữ *private key* (con dấu). Binary chỉ nhúng
  *public key* (`licensing/pubkey.go`) để verify.
- Một mã (code) = `base64(payload).base64(chữ_ký)`. Trong payload có: khách hàng,
  tier, hạn dùng, giới hạn, danh sách tính năng, và **khoá máy (tuỳ chọn)**.
- Không có private key thì **không ai forge được mã** → an toàn kể cả khi mã nằm
  công khai trong DB của khách.

---

## 2. Chuẩn bị (làm 1 lần)

Private key của bạn nằm ở `scripts/license-private-key.b64` (đã **gitignore**,
không bao giờ lên GitHub).

> ⚠️ **Giữ kín & backup offline.** Đây là con dấu tạo *mọi* key. Lộ = người khác
> tự phát key VIP. Mất = phải đổi khoá và phát lại toàn bộ key cũ.

Tất cả lệnh chạy từ thư mục gốc project:

```bash
cd /mnt/c/Users/kin/Downloads/hainguyen0207-go
```

---

## 3. Tạo key — các kịch bản

Lệnh phát key in phần tóm tắt ra màn hình (stderr) và **dòng mã dài cuối cùng**
(stdout) — đó là thứ gửi cho khách.

### 3.1. Key VIP nhất (bạn tự dùng) — mọi máy, vĩnh viễn, không giới hạn

```bash
go run ./cmd/gen-license -key scripts/license-private-key.b64 \
    -customer "VIP" -tier enterprise
```

Không `-expires` = vĩnh viễn · không `-machine` = mọi máy · không
`-targets/-tasks/-tokens` = không giới hạn · không `-features` = mở tất cả.

### 3.2. Key VIP khoá máy (để BÁN — chống chia sẻ) ⭐ khuyến nghị

Full quyền enterprise nhưng chỉ chạy đúng 1 máy của khách:

```bash
go run ./cmd/gen-license -key scripts/license-private-key.b64 \
    -customer "Tên khách" -tier enterprise -machine <Machine-ID-khách>
```

Quy trình 4 bước:

1. Khách cài đặt → mở **System → License** → thấy **Machine ID** → bấm copy, gửi bạn.
2. Bạn chạy lệnh trên với `-machine <Machine-ID-khách>`.
3. Gửi khách dòng mã dài.
4. Khách dán vào ô **Activate** → mở khoá. Copy mã sang máy khác sẽ **báo lỗi**.

### 3.3. Cho thuê theo thời hạn

```bash
go run ./cmd/gen-license -key scripts/license-private-key.b64 \
    -customer "Tên khách" -tier pro -expires 2026-12-31
```

Hết ngày `-expires` (tính theo UTC) thì tự khoá lại. Có chống **quay ngược đồng
hồ**: server lưu mốc thời gian cao nhất, chỉnh lùi clock không hồi sinh được key
hết hạn.

### 3.4. Giới hạn quy mô (gói nhỏ)

```bash
go run ./cmd/gen-license -key scripts/license-private-key.b64 \
    -customer "Tên khách" -tier pro -expires 2026-12-31 \
    -targets 10 -tasks 5
```

`-targets 10` tối đa 10 target · `-tasks 5` tối đa 5 task chạy song song.
(0 hoặc bỏ cờ = không giới hạn.)

---

## 4. Bảng cờ đầy đủ

| Cờ | Ý nghĩa | Mặc định |
|----|---------|----------|
| `-key` | file private key (hoặc đặt env `LICENSE_PRIVATE_KEY`) | — |
| `-customer` | tên khách — **bắt buộc** | — |
| `-tier` | `community` / `pro` / `enterprise` | `pro` |
| `-expires` | `YYYY-MM-DD`, bỏ trống = vĩnh viễn | vĩnh viễn |
| `-machine` | khoá 1 máy theo Machine ID, bỏ trống = mọi máy | mọi máy |
| `-targets` | số target tối đa (0 = ∞) | 0 |
| `-tasks` | số task song song tối đa (0 = ∞) | 0 |
| `-tokens` | số token LLM tối đa (0 = ∞) | 0 |
| `-features` | danh sách tính năng cho phép, cách nhau dấu phẩy; bỏ trống = **TẤT CẢ** | tất cả |

---

## 5. Khách kích hoạt thế nào

1. Deploy build có sẵn endpoint license (từ commit `bff9a2c` trở đi).
2. Đăng nhập → **System → License**.
3. Dán mã vào ô **Activate** → bấm **Activate**.
   - Hợp lệ → hiện "Licensed — all features unlocked", mở khoá toàn bộ.
   - Sai/hết hạn/sai máy → báo lý do, **không** kích hoạt.
4. Muốn gỡ → bấm **Deactivate** (quay về trạng thái khoá read-only).

---

## 6. Quản lý

### Thu hồi 1 khách (revoke)
Scheme offline **không** có revoke từ xa. Cách xử lý:
- Phát key có `-expires` ngắn (vd 1 năm) → tự hết hạn, muốn gia hạn thì phát mã mới.
- Trường hợp khẩn: **đổi khoá ký** (mục dưới) — nhưng thao tác này vô hiệu *mọi*
  key cũ, phải phát lại cho tất cả khách.

### Đổi khoá ký (khi private key bị lộ)
```bash
go run ./cmd/gen-license keygen
```
→ Copy **PUBLIC KEY** in ra, dán vào `licensing/pubkey.go` (`publicKeyB64`), build
lại và ship binary mới. Giữ **PRIVATE KEY** mới offline. Mọi key cũ ngừng verify.

### Backup
Sao lưu `scripts/license-private-key.b64` ra nơi an toàn offline (USB/mã hoá).

---

## 7. Lỗi thường gặp

| Triệu chứng | Nguyên nhân | Cách xử lý |
|-------------|-------------|------------|
| Khách dán mã báo "bound to a different machine" | mã khoá máy, dán sai máy | phát lại mã với đúng Machine ID của khách |
| Báo "expired" | quá hạn `-expires` | phát mã mới gia hạn |
| Báo "invalid license code" | mã bị cắt/sửa, hoặc binary dùng public key khác | copy nguyên vẹn; đảm bảo build khớp khoá ký |
| Không thấy trang License / 404 `/api/license` | binary cũ chưa có tính năng | deploy lại build `bff9a2c`+ |
| Mọi thao tác trả `402` | chưa kích hoạt key | dán key hợp lệ ở System → License |

---

## 8. Bảo mật — nói thẳng

Đây là license **offline/trust-based**: người có binary và biết reverse-engineer
*có thể* patch bỏ kiểm tra hoặc thay public key rồi tự ký. Các lớp đã làm để nâng
rào (đủ cho khách thường):

- Chặn mọi route ghi, kể cả `/api/v1/*` của runner (đã bịt lỗ bypass).
- Khoá máy (machine-bound) chống chia sẻ mã.
- Chống quay ngược đồng hồ (mốc thời gian cao nhất).
- Binary strip symbol (`-s -w -trimpath`) khó patch.

Muốn tuyệt đối → cần thêm **online revocation / attestation** (bổ sung sau).

---

## 9. Tham khảo nhanh

```bash
# VIP mọi máy, vĩnh viễn, unlimited (bạn tự dùng)
go run ./cmd/gen-license -key scripts/license-private-key.b64 -customer "VIP" -tier enterprise

# VIP khoá máy (bán cho khách)
go run ./cmd/gen-license -key scripts/license-private-key.b64 -customer "ACME" -tier enterprise -machine <machine-id>

# Pro có hạn + giới hạn
go run ./cmd/gen-license -key scripts/license-private-key.b64 -customer "ACME" -tier pro -expires 2026-12-31 -targets 10 -tasks 5

# Đổi khoá ký
go run ./cmd/gen-license keygen
```

> Bản tiếng Anh ngắn gọn: `scripts/LICENSING.md`.
