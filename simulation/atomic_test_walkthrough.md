# 🧪 Nhật ký Kiểm thử Mô phỏng Tấn công (Atomic Red Team)

Tài liệu này ghi lại quy trình cài đặt và sử dụng **Invoke-AtomicRedTeam** trên máy trạm Windows 11 (`baclev`) nhằm tạo dữ liệu tấn công thực tế và kiểm chứng khả năng phát hiện của Wazuh SIEM.

---

## 1. Cài đặt Môi trường Kiểm thử trên Endpoint
Thực thi trên PowerShell với quyền Quản trị viên (Run as Administrator):

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
Install-Module -Name invoke-atomicredteam,powershell-yaml -Scope CurrentUser -Force
Import-Module invoke-atomicredteam
```

---

## 2. Kiểm tra Điều kiện Tiên quyết (Prerequisites Check) cho Kỹ thuật T1059.001
Thực hiện kiểm tra các điều kiện tiên quyết của gói kỹ thuật T1059.001 (Command and Scripting Interpreter: PowerShell):

```powershell
Invoke-AtomicTest T1059.001 -GetPrereqs
```

**Kết quả trích xuất thực tế từ Terminal trên máy baclev:**
```plaintext
Prereq successfully met: SharpHound.ps1 must be located at "C:\AtomicRedTeam\atomics\..\ExternalPayloads\SharpHound.ps1"
GetPrereq's for: T1059.001-3 Run Bloodhound from Memory using Download Cradle
No Preqs Defined
GetPrereq's for: T1059.001-4 Mimikatz - Cradlecraft PsSendKeys
No Preqs Defined
GetPrereq's for: T1059.001-5 Invoke-AppPathBypass
No Preqs Defined
GetPrereq's for: T1059.001-6 Powershell MsXml COM object - with prompt
No Preqs Defined
GetPrereq's for: T1059.001-7 Powershell XML requests
No Preqs Defined
GetPrereq's for: T1059.001-8 Powershell invoke mshta.exe download
No Preqs Defined
GetPrereq's for: T1059.001-10 PowerShell Fileless Script Execution
No Preqs Defined
GetPrereq's for: T1059.001-11 NTFS Alternate Data Stream Access
Attempting to satisfy prereq: Homedrive must be an NTFS drive
Prereq already met: Homedrive must be an NTFS drive
GetPrereq's for: T1059.001-12 PowerShell Session Creation and Use
Attempting to satisfy prereq: PSRemoting must be enabled
```

---

## 3. Kích hoạt Mô phỏng Tấn công (Test Execution)
Chạy kịch bản kiểm thử của T1059.001:

```powershell
Invoke-AtomicTest T1059.001 -TestNumbers 1
```

---

## 4. Kết quả Quan sát trên Wazuh SIEM
Các hành vi tải công cụ (*Ingress Tool Transfer*), thực thi kịch bản (*PowerShell*, *Windows Command Scripting*) và dò mật khẩu (*Password Guessing*) ngay lập tức sinh ra **328 cảnh báo mức độ nghiêm trọng cao (Level 12+)** trên tổng số **2,218 sự kiện** được đẩy về Wazuh Manager từ agent `baclev`.
