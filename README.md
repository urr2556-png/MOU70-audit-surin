# MOU70-audit-surin
ระบบติดตามงานตามข้อตกลงการปฏิบัติราชการ ปีงบประมาณ พ.ศ. 2570 ของสำนักตรวจเงินแผ่นดินจังหวัดสุรินทร์ แสดงแผนและผลของกลุ่มตรวจสอบ 1–5 จาก Google Sheets

ไฟล์ในโครงการ

ไฟล์

หน้าที่

index.html

หน้าเมนูเข้าสู่ระบบ ลงทะเบียน และแอดมินบน GitHub Pages

server.mjs

เซิร์ฟเวอร์ Node.js สำหรับจัดการบัญชีและตรวจสิทธิ์

dashboard.html

แดชบอร์ดที่เซิร์ฟเวอร์แสดงหลังเข้าสู่ระบบ

footer.html

ส่วนท้ายและช่องทางติดต่อ

ทดสอบบน Windows

เปิด PowerShell ในโฟลเดอร์ที่มีไฟล์ทั้งสี่และใช้ Node.js 24

node --version

สร้างบัญชีแอดมินครั้งแรกโดยใช้ข้อมูลทดสอบ หรือข้อมูลแอดมินที่กำหนดบนเครื่องของหน่วยงาน รหัสผ่านให้กรอกใน PowerShell และอย่าใส่ในโค้ดหรือ GitHub

$env:MOU_ADMIN_NAME = Read-Host 'ชื่อแอดมิน'
$env:MOU_ADMIN_PHONE = Read-Host 'เบอร์โทรศัพท์แอดมิน'
$env:MOU_ADMIN_CODE = Read-Host 'รหัสข้าราชการแอดมิน'
$secret = Read-Host 'รหัสผ่านอย่างน้อย 12 ตัวอักษร' -AsSecureString
$ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret)
try {
    [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) | node server.mjs init-admin
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
    $secret.Dispose()
    Remove-Item Env:MOU_ADMIN_NAME, Env:MOU_ADMIN_PHONE, Env:MOU_ADMIN_CODE
}

เมื่อขึ้นข้อความว่าสร้างบัญชีแอดมินแล้ว ให้เริ่มเซิร์ฟเวอร์

node server.mjs

เปิด หน้าทดสอบบนเครื่อง แล้วเข้าสู่ระบบด้วยบัญชีแอดมิน เจ้าหน้าที่ลงทะเบียนด้วยชื่อ เบอร์โทรศัพท์ รหัสข้าราชการ สตง. และรหัสผ่าน จากนั้นรออนุมัติก่อนเข้าแดชบอร์ด

เชื่อม Google Sheets

เปิด Google Sheets API ในโครงการ Google Cloud ของหน่วยงาน

ตั้ง OAuth Client ID สำหรับเว็บ เพิ่ม origin ที่เปิดระบบจริง เช่น http://127.0.0.1:8080 สำหรับทดสอบ

ตั้งค่าใน PowerShell ก่อนเริ่มเซิร์ฟเวอร์

$env:MOU_GOOGLE_CLIENT_ID = 'ใส่ OAuth Client ID ของหน่วยงาน'
node server.mjs

หลังเข้าสู่ระบบ กด เชื่อมบัญชี Google ด้วยบัญชีที่มีสิทธิ์อ่านชีต ระบบอ่านแผนและผลทุก 30 วินาทีขณะเปิดหน้า การเชื่อมจริงต้องทดสอบด้วยบัญชีที่ได้รับสิทธิ์

เปิดให้ใช้งานจริง

รัน server.mjs บนเซิร์ฟเวอร์ Node.js 24 ที่เข้าถึงผ่าน HTTPS และตั้ง MOU_ORIGIN ให้ตรงกับ origin ของเว็บ

ตั้ง MOU_DB เป็นพาธฐานข้อมูล SQLite บนพื้นที่จัดเก็บถาวรที่จำกัดสิทธิ์ และสำรองข้อมูลตามรอบ เก็บไฟล์ฐานข้อมูลและไฟล์ประกอบ SQLite ไว้นอก GitHub

ตั้ง MOU_GOOGLE_CLIENT_ID และเพิ่ม origin จริงใน Google Cloud

ใส่ URL แบบ HTTPS ของเซิร์ฟเวอร์ใน ACCOUNT_SERVER ของ index.html หน้า GitHub Pages

GitHub Pages แสดงหน้าเมนูทางเข้า ระบบเข้าสู่ระบบ การอนุมัติบัญชี และฐานข้อมูลทำงานบนเซิร์ฟเวอร์ Node.js
