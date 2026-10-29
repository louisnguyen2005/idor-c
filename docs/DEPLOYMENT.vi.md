# Hướng dẫn triển khai NOVA MART Attack–Defense trên CyberRangeCZ

Tài liệu này dành cho ban vận hành: chuẩn bị source, tạo pool, kết nối SSH qua gateway, chạy checker và bàn giao scoreboard/monitor. Các lệnh ví dụ dùng PowerShell trên máy Windows có Python 3 và OpenSSH Client.

## 1. Kiến trúc và luật thi mặc định

Một sandbox gồm bốn VM đội, một VM server dùng chung và router. Mỗi VM đội chạy hai instance NOVA MART tách source/config/SQLite: `shop01` ở port 8080 cho round 1 và `shop02` ở port 8081 cho round 2. Gateway Windows chuyển tiếp bốn cổng mỗi round: 8011–8014 đến port 8080 của các đội; 8021–8024 đến port 8081. Người tổ chức có thể chọn local mode để chỉ kiểm tra từ máy gateway hoặc LAN mode để người thi truy cập.

Cuộc thi dài 60 phút: hai round, mỗi round 30 phút; mỗi tick 120 giây; 15 tick/round, 30 tick. Checker lấy trạng thái service đầu mỗi tick. Luồng checker đăng ký khách, giải CAPTCHA bình thường, đăng nhập, tạo đơn có flag trong ghi chú riêng, đọc lại đơn và xác nhận các flag còn hạn. UP được 1 SLA; DOWN/MUMBLE/ERROR hoặc thiếu kết quả được 0 SLA cho tick. Capture flag địch được +100, đội sở hữu bị −100. Flag sống ba tick và hết hạn khi round chuyển service. Capture ghi một lần.

Lỗ hổng trong source NOVA MART: SQL injection catalog search, CAPTCHA bypass, stored XSS review, CSRF ở chức năng chia sẻ đơn, và brute force trên login merchant với mật khẩu mẫu trong không gian `market00`–`market31`. Đây là hành vi chủ ý của challenge. Từng switch trong `deployment.json` có thể tắt để đội phòng thủ kiểm tra bản vá.

## 2. Sửa cấu hình trước khi upload source

Mở `deployment.json` và kiểm tra:

- `network`, IP router/server và IP từng VM nằm trong cùng CIDR, không trùng.
- Image/flavor tồn tại trên CyberRangeCZ.
- Mỗi đội có ID, node, IP và password SSH riêng. Đổi password mẫu trước giải; giữ repository chỉ cho ban tổ chức.
- Hai service có ID/cổng/gateway ports khác nhau. `vulnerability_count` phải bằng 5; giữ đủ năm khóa boolean `vulnerabilities`.
- `round_seconds=1800`, `max_rounds=2`, `tick_seconds=120`; `scoring=attack_defense`.

Generate file CyberRangeCZ và kiểm tra source trên Windows:

```powershell
Set-Location "D:\path\to\LVTN-merged"
py -3 -m pip install -r requirements-dev.txt
py -3 -m gameserver.definition --write
py -3 -m gameserver.definition
py -3 -m unittest discover -s tests -v
```

Đóng source ZIP sạch:

```powershell
py -3 -m gameserver.package --output ..\LVTN-shop-attack-defense.zip
```

Builder loại `.git`, khóa riêng, file `config.json` theo allocation, SQLite runtime, log, token và kết quả checker; bên cạnh ZIP có checksum SHA-256. Giải nén ZIP vào thư mục mới và xác nhận `topology.yml`, `deployment.json`, `provisioning/` nằm ngay gốc source trước khi đưa vào Git repository mà Sandbox Definition dùng.

## 3. Tạo hoặc cập nhật pool

Đẩy revision ZIP đã kiểm thử lên repository riêng của bạn; trên CyberRangeCZ chọn revision đó trong Sandbox Definition và tạo/reprovision pool size 1. Kiểm tra image/flavor và địa chỉ sau khi Allocate thành công. Việc sửa source local không tự cập nhật pool cũ. Khi thay đổi topology, service, IP hoặc luật, cần deploy revision và cấp sandbox mới.

Provisioning tạo tài khoản `user-access` riêng cho mỗi VM, dùng password SSH theo đội, cài hai service instances và systemd units, rồi kiểm tra health identity. Web app chạy không phải root. Mỗi service có SQLite riêng dưới `/var/lib/idor-free-lab/<service-id>/service.sqlite`; thao tác restart được giới hạn theo instance.

## 4. Lấy SSH access ZIP và cấu hình allocation trên Windows

Tải **user SSH access ZIP** của allocation mới từ CyberRangeCZ; giải nén các file user-config và user-key vào:

```text
%USERPROFILE%\.ssh
```

Giữ private key riêng, không gửi cho đội thi. `management-config` thuộc luồng truy cập quản trị; gateway checker ở đây dùng user config. Mở PowerShell tại gốc source và chạy:

```powershell
.\Configure-Deployment.ps1 `
  -SshConfig "$env:USERPROFILE\.ssh\<CURRENT-ALLOCATION-user-config>" `
  -Access local -EventId nova-demo-01
```

Thay placeholder bằng đúng tên file có `pool-id-…-sandbox-id-…-user-config`. Script kiểm tra UUID trong tên file, tạo config gateway/checker, sinh alias đội và tạo runtime mới trong `gameserver/runtime-sla-nova-demo-01`. Event ở trạng thái READY, chưa chạy đồng hồ. `local` phù hợp khi checker và người thi dùng cùng máy; listener chỉ ở `127.0.0.1`.

## 5. Xác minh SSH và gateway

Trong PowerShell, xác nhận host key/fingerprint theo hướng dẫn quản trị CyberRangeCZ, sau đó:

```powershell
Set-Location .\CyberRangeCZ-Windows-Gateway
.\Test-CTFGateway.ps1
.\Test-CTFGateway.ps1 -CheckSsh
```

Preflight `-CheckSsh` phải báo SSH forwarding thành công cho các backend của cả `shop01`, `shop02` và shared organizer service. Cảnh báo chưa có listener trước khi bật gateway là bình thường. Sau khi trust đúng fingerprint, mở gateway:

```powershell
.\Start-CTFGateway.ps1
```

Giữ cửa sổ này mở. Cửa sổ thứ hai có thể kiểm tra cổng local theo các dòng `gatewayIp` và `gatewayPort` trong file `config.json` sinh sau allocation. Đừng bật listener công khai khi đang dùng `local`.

## 6. Mạng dành cho đội thi

Để đội truy cập gateway, cấu hình lại allocation trước khi start event với CIDR thực của mạng đội thi:

```powershell
Set-Location "D:\path\to\LVTN-merged"
.\Configure-Deployment.ps1 `
  -SshConfig "$env:USERPROFILE\.ssh\<CURRENT-ALLOCATION-user-config>" `
  -Access lan -GatewayIp auto -ClientCidr "<CIDR-DA-XAC-NHAN>" -EventId nova-lan-01
```

Auto chọn IP interface theo route đến SSH landing host. CIDR phải được quản trị viên xác nhận. Trong PowerShell Administrator, tạo firewall rule đã giới hạn nguồn:

```powershell
.\Apply-GatewayFirewall.ps1
```

Chạy lại gateway preflight. Từ mạng người thi, thử mở `/health` trên cổng gateway của từng đội/service. URL theo mẫu `http://<gateway-ip>:8011/health` tới team01 round1, `8012` tới team02, tiếp tục tới `8014`; round2 dùng `8021`–`8024`. Chỉ công bố URL sau khi mọi forward phản hồi đúng sandbox/service.

## 7. Preflight checker và bắt đầu event

Chạy preflight không tính điểm:

```powershell
Set-Location "D:\path\to\LVTN-merged"
py -3 -m gameserver.worker --preflight
```

Kết quả mong đợi là 4 dòng `UP` cho service round 1. Nếu `DOWN`, kiểm tra SSH/gateway, listener và service systemd trên từng VM. `MUMBLE` thường là identity sai, CAPTCHA/order workflow lỗi hoặc ứng dụng bị vá làm hỏng đường đi hợp lệ.

Sau khi thống nhất giờ bắt đầu, chạy:

```powershell
.\gameserver\Start-Stack.ps1
```

Script tự khởi động/reuse gateway, bật backend, preflight lại, bật checker rồi gọi start event. Chỉ khi event bắt đầu, tick 1 mới chạy. Giữ terminal điều phối mở. Scoreboard công khai ở `http://127.0.0.1:9000/` (thay port theo runtime). Nếu dùng LAN mode, mở scoreboard từ IP gateway/cổng backend đã cấu hình.

## 8. Scoreboard, team tokens và monitor

Scoreboard hiển thị round/tick/service còn bao lâu, SLA mỗi đội, trạng thái checker, điểm attack/defense, lịch sử và capture. Nộp flag từ form **Submit captured flag**: mỗi đội cần Bearer token riêng. Token nằm trong file riêng `gameserver/runtime-sla-<event>/teams/teamXX.json`, khóa ở runtime ban tổ chức; phát đúng token cho đội tương ứng qua kênh bảo mật. Không đưa `config.json`, `worker.json`, `operator.json`, `monitor.json` hay database cho người thi.

Trang monitor ban tổ chức: `http://<backend-host>:<port>/monitor`. Lấy `monitor_token` từ `gameserver/runtime-sla-<event>/monitor.json`, nhập trong trang. Trang này chỉ đọc phase, tick hiện tại, heartbeat checker, thời điểm kết quả gần nhất, lỗi scheduler và số bản ghi database; nó không chứa flag. Bắt đầu/kết thúc cuộc thi bằng stack hoặc `gameserver.control`; monitor token không thay thế admin token.

### Chia sẻ scoreboard của event local đang chạy

Backend và checker tiếp tục chạy ở `127.0.0.1:9000`. Trên máy điều phối, mở **PowerShell Administrator** thứ ba tại gốc source và chạy:

```powershell
.\Start-PublicScoreboard.ps1 -ListenIp "<IP-MAY-DIEU-PHOI>" -ClientCidr "<IP-MAY-BAN>/32"
```

Ví dụ địa chỉ truy cập là `http://<IP-MAY-DIEU-PHOI>:9000/#score`. Bạn thi phải có đường mạng tới IP máy điều phối. Script chỉ mở scoreboard, các API bảng điểm và API nộp flag; API quản trị, checker và monitor không đi qua địa chỉ chia sẻ. Mỗi đội vẫn cần token riêng để nộp flag. Firewall chỉ cho phép IP/CIDR đã truyền vào `-ClientCidr`. Giữ cửa sổ này mở; `Ctrl+C` dừng điểm truy cập và xóa rule firewall do script tạo. IP `10.x.x.x` là IP nội bộ; để truy cập từ Internet cần cấu hình mạng ngoài (định tuyến/NAT hoặc reverse proxy HTTPS) riêng.

## 9. SQLite, backup và khôi phục

Database cuộc thi: `gameserver/runtime-sla-<event>/competition.sqlite`, SQLite WAL. Backend là tiến trình duy nhất mở database; worker báo kết quả qua API. `tick_checks` có khóa `(tick,team)`, `tick_flags` giữ flag/password riêng và mã đơn xác nhận, `tick_captures` giới hạn capture mỗi flag, `tick_submissions` chỉ lưu hash đầu vào cùng verdict. Monitor API không trả giá trị flag. Runtime ACL chỉ dành cho ban tổ chức.

Backup online nhất quán:

```powershell
py -3 -m gameserver.control backup --destination "D:\CTF-backups\nova-demo-01.sqlite"
```

Đích phải là file chưa tồn tại trong thư mục backup đã tạo trước. Kết thúc sự kiện:

```powershell
py -3 -m gameserver.control finish
```

Chỉ restore database cùng `config.json`/event gốc. Mỗi service VM có database sản phẩm riêng; không gộp các DB này vào database điểm.

## 10. Demo offline, kiểm tra mã và giới hạn

Demo không cần pool; chế độ nhanh dùng 5 giây/tick để checker nhiều bước kịp chạy:

```powershell
py -3 -m gameserver.demo --fast
```

Mở `http://127.0.0.1:19000/`. Demo dựng service shop và backend local; 30 tick chạy nhanh khoảng 150 giây, tick 3 mô phỏng service của đội thứ hai DOWN, tick 4 hồi phục. Nó kiểm tra đặt flag, ghi SLA/capture và giao diện mà không kết nối allocation CyberRangeCZ.

Source tests kiểm tra đủ năm hành vi bật/tắt, luồng checker tạo/đọc đơn, scoring/dedupe/TTL, token monitor, lịch 30 tick, file generated và firewall/gateway config. GitHub workflow còn chạy Ansible syntax check trên Linux. Local test không thay thế việc xác nhận allocation thật. Trước giải, kiểm tra trên pool mới: image/flavor, cổng gateway, SSH password từng đội, checker preflight, bảng điểm từ mạng đội và monitor từ mạng ban tổ chức.

## 11. Tham khảo kỹ thuật

- SQLite WAL: https://sqlite.org/wal.html
- SQLite online backup API: https://docs.python.org/3/library/sqlite3.html#sqlite3.Connection.backup
- Ansible include_tasks loops: https://docs.ansible.com/projects/ansible/latest/collections/ansible/builtin/include_tasks_module.html
- CyberRangeCZ Sandbox Definition: theo tài liệu/vùng triển khai của instance CyberRangeCZ mà ban tổ chức đang dùng.
