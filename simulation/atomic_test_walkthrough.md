# 🧪 Nhật ký Kiểm thử Mô phỏng Tấn công (Atomic Red Team Walkthrough)

Tài liệu này ghi lại quy trình cài đặt, kiểm tra điều kiện tiên quyết và thực thi mô phỏng đối kháng bằng **Invoke-AtomicRedTeam** trên máy trạm Windows 11 (`baclev`) nhằm tạo telemetry tấn công thực tế và kiểm chứng năng lực phát hiện của Wazuh SIEM.

> [!CAUTION]
> **CẢNH BÁO AN TOÀN:**
> Kịch bản kiểm thử này chỉ được thực hiện trên môi trường máy ảo cô lập (Isolated Lab Environment). KHÔNG chạy các kịch bản kiểm thử tấn công trên hệ thống sản xuất (Production).

---

## 1. Môi trường Thực thi & Điều kiện Tiên quyết

* **Mục tiêu thử nghiệm:** Endpoint `baclev` (Windows 11 Pro 64-bit, IP: `10.10.10.100` / `10.10.20.x`).
* **Quyền hạn yêu cầu:** Quyền Quản trị viên cục bộ (Local Administrator) trên Windows PowerShell.
* **Kênh Telemetry kích hoạt:**
  * Windows Security Event Log (Audit Process Creation - Event ID 4688, Logon Failure - Event ID 4625).
  * Microsoft-Windows-Sysmon/Operational (Event ID 1 - Process Creation với Command Line đầy đủ).
  * Microsoft-Windows-PowerShell/Operational (Event ID 4104 - Script Block Logging).

### Lệnh cài đặt Framework trên Windows 11:
```powershell
# Chạy với quyền Administrator
Set-ExecutionPolicy Bypass -Scope Process -Force
Install-Module -Name invoke-atomicredteam,powershell-yaml -Scope CurrentUser -Force
Import-Module invoke-atomicredteam
```

---

## 2. Kiểm tra Điều kiện Tiên quyết (Prerequisites Check: T1059.001)

Kỹ thuật: **MITRE ATT&CK T1059.001** (*Command and Scripting Interpreter: PowerShell*).

Trước khi kích hoạt tấn công, chạy lệnh kiểm tra các module phụ thuộc:
```powershell
Invoke-AtomicTest T1059.001 -GetPrereqs
```

### Bằng chứng trích xuất thực tế từ Terminal (Khớp với `evidence/atomic-powershell.png`):
```plaintext
exported in the module.
  GetPrereq's for: T1059.001-14 ATHPowerShellCommandLineParameter -Command parameter variations with encoded arguments
  Attempting to satisfy prereq: The AtomicTestHarnesses module must be installed and Out-ATHPowerShellCommandLineParameter must be exported in the module.
    Prereq already met: The AtomicTestHarnesses module must be installed and Out-ATHPowerShellCommandLineParameter must be exported in the module.
  GetPrereq's for: T1059.001-15 ATHPowerShellCommandLineParameter -EncodedCommand parameter variations
  Attempting to satisfy prereq: The AtomicTestHarnesses module must be installed and Out-ATHPowerShellCommandLineParameter must be exported in the module.
    Prereq already met: The AtomicTestHarnesses module must be installed and Out-ATHPowerShellCommandLineParameter must be exported in the module.
  GetPrereq's for: T1059.001-16 ATHPowerShellCommandLineParameter -EncodedCommand parameter variations with encoded arguments
  Attempting to satisfy prereq: The AtomicTestHarnesses module must be installed and Out-ATHPowerShellCommandLineParameter must be exported in the module.
    Prereq already met: The AtomicTestHarnesses module must be installed and Out-ATHPowerShellCommandLineParameter must be exported in the module.
GetPrereq's for: T1059.001-17 PowerShell Command Execution
No Preqs Defined
GetPrereq's for: T1059.001-18 PowerShell Invoke Known Malicious Cmdlets
No Preqs Defined
GetPrereq's for: T1059.001-19 PowerUp Invoke-AllChecks
No Preqs Defined
GetPrereq's for: T1059.001-20 Abuse Nslookup with DNS Records
No Preqs Defined
GetPrereq's for: T1059.001-21 SOAPHound - Dump BloodHound Data
No Preqs Defined
GetPrereq's for: T1059.001-22 SOAPHound - Build Cache
```

> **Đánh giá của SOC Analyst:**
> Các bài test **T1059.001-15** và **T1059.001-16** đặc biệt quan trọng vì chúng tạo ra các chuỗi tham số mã hóa Base64 (`-EncodedCommand`, `-enc`, `-e`), là mục tiêu phát hiện trực tiếp của **Wazuh Rule 100710**.

---

## 3. Thực thi Kịch bản Kiểm thử (Adversary Emulation)

### Test 1: Mô phỏng thực thi PowerShell cơ bản (T1059.001 Test 1 & 2)
```powershell
Invoke-AtomicTest T1059.001 -TestNumbers 1,2
```

### Test 2: Mô phỏng thực thi tham số mã hóa Base64 (T1059.001 Test 15)
```powershell
Invoke-AtomicTest T1059.001 -TestNumbers 15
```

### Test 3: Mô phỏng xác thực thất bại / RDP Password Guessing (T1110)
```powershell
# Thực hiện tạo nhiều phiên xác thực thất bại qua net use / RDP để kích hoạt Event 4625
1..5 | ForEach-Object {
    cmd.exe /c "net use \\127.0.0.1\c$ /user:invaliduser wrongpassword$($_) 2>&1"
}
```

### Dọn dẹp sau kiểm thử (Cleanup Phase):
```powershell
Invoke-AtomicTest T1059.001 -Cleanup
```

---

## 4. Quy trình Đối chiếu Telemetry & Kết quả Kiểm thử

### 4.1. Quy trình đối chiếu (Triangulation Workflow)
1. **Timestamp:** Ghi nhận mốc thời gian chạy lệnh tại Endpoint (`baclev`).
2. **Endpoint Telemetry:**
   * Mở Event Viewer $\rightarrow$ `Microsoft-Windows-Sysmon/Operational`: Tìm Event ID 1 có Image `powershell.exe` và trường CommandLine chứa tham số `-enc` hoặc kịch bản Atomic.
   * Mở `Microsoft-Windows-PowerShell/Operational`: Tìm Event ID 4104 bóc tách ScriptBlock thực tế.
3. **Wazuh SIEM Ingestion:**
   * Agent đẩy log qua encrypted TCP 1514 về Manager.
   * Kiểm tra `/var/ossec/logs/alerts/alerts.json` trên Wazuh Manager xem rule nào được kích hoạt.

### 4.2. Kết quả Dự kiến (Expected Results)
* Lệnh `netsh.exe` thay đổi firewall kích hoạt Sysmon Event 1 và nổ **Rule 100602** (Level 10).
* Lệnh `powershell.exe -EncodedCommand` kích hoạt Sysmon Event 1 và nổ **Rule 100710** (Level 12).
* Lệnh xác thực sai kích hoạt Windows Security Event 4625 và nổ **Rule 100500** (Level 10). Nếu lặp lại $\ge 5$ lần, kích hoạt tương quan **Rule 100501** (Level 12).

### 4.3. Kết quả Thực tế Quan sát (Actual Observed Results trên Wazuh SIEM)
*(Đối chiếu từ giao diện Threat Hunting thực tế tại `evidence/wazuh-threat-hunting-dashboard.png`)*

* **Tổng telemetry ghi nhận (24h):** **2,960** sự kiện.
* **Cảnh báo mức độ nghiêm trọng cao (Level 12+):** **367** cảnh báo.
* **Phân bổ xác thực:** **5** Authentication failures, **11** Authentication successes.
* **Kỹ thuật MITRE ghi nhận trên Top 10 ATT&CK:**
  * *Windows Command Scripting*
  * *Ingress Tool Transfer*
  * *Command and Scripting Interpreter*
  * *Account Discovery*
  * *PowerShell*
  * *Valid Accounts*
  * *Password Guessing*
