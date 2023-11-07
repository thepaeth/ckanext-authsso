
# ckanext-authsso

CKAN Extesion  สำหรับทำ Authen ผ่าน API Authen ของหน่วยงาน


## Installation

Activate CKAN environment ก่อน
```
source /usr/lib/ckan/default/bin/activate
cd /usr/lib/ckan/default
```

ติดตั้ง ckanext-authsso
```
pip install -e git+https://github.com/thepaeth/ckanext-authsso.git#egg=ckanext-authsso
```

เพิ่ม ckanext-authsso เข้าไปใน plugins ของ ckan.ini
```
ckan.plugins = authsso ... 
```

## Configuration

การตั้งค่า config สำหรับ ckanext-authsso
```
# host/server สำหรับทำ authen
authsso.authen_host = http://examp.com
# หน้าสำหรับที่ให้ผู้ใช้ redirect ไป login
authsso.authen_page = /user/login
# path สำหรับดึงข้อมูลของผู้ใช้ที่ login ผ่านแล้ว
authsso.authen_path = /auth/user/getinfo

# ชื่อ parameter สำหรับรับค่า token key ของผู้ใช้
authsso.token_params = token
```

restart CKAN service 
```
sudo supervisorctl reload
```
