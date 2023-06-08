import requests
import xlrd
import sys
import time
import json
import xlwt
from xlwt import Workbook

# Open Input Excel Workbook
wb = xlrd.open_workbook(sys.argv[1])
sheet = wb.sheet_by_index(0)

# Extracting the first row
sheet.cell_value(0, 0)

# New Workbook for output
wbwrite = Workbook()
sheet1 = wbwrite.add_sheet('Hashes')
sheet1.write(0, 0, 'MD5')
sheet1.write(0, 1, 'SHA1')
sheet1.write(0, 2, 'SHA256')

# VT API data, Do not Change or Share
url = 'https://www.virustotal.com/api/v3/files/'
API_KEY = '<API KEY GOES HERE>'
HASH = ''

# Moving row by row down
for i in range(sheet.nrows):
    HASH = (sheet.cell_value(i, 0))
    vt_url = url + HASH
    header = {'x-apikey': API_KEY}
    response = requests.get(vt_url, headers=header)
    data = response.json()
    attr = data.get("data").get("attributes")
    MD5 = attr.get("md5")
    SHA1 = attr.get("sha1")
    SHA256 = attr.get("sha256")
    print(SHA1)
    # Writing Data to new Excel sheet
    sheet1.write(i + 1, 0, MD5)
    sheet1.write(i + 1, 1, SHA1)
    sheet1.write(i + 1, 2, SHA256)
    print(i + 1, " of ", sheet.nrows, " Completed with response ",response)
    time.sleep(1)  # VirusTotal Public API allows only 4 requests per minute, Do not change the sleep duration.


wbwrite.save('HashConvertedOutput.xls')

# Written by Ashan Harindu Weerasuriya
# zp4rR0w
