#!/usr/bin/env python3
import cgi
import smtplib
import hashlib
from random import *

import psycopg2
conn = psycopg2.connect(dbname='testdb', user='postgres',
                        password='1111', host='localhost')
cur = conn.cursor()

form = cgi.FieldStorage()
text1 = form.getfirst("TEXT_1", "не задано")
text2 = form.getfirst("TEXT_2", "не задано")

print("Content-type: text/html\n")
print("""<!DOCTYPE HTML>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Обработка данных форм</title>
        </head>
        <body>""")

print("<h1>Обработка данных форм!</h1>")

print("""</body>
        </html>""")

code = ''
for i in range(0, 6):
    d = randint(0, 9)
    code += str(d)

cur.execute("SELECT password FROM Users_info WHERE login = '" + text1 + "';")
get_pass = cur.fetchone()
if not get_pass:
    print("Пользователь с таким логином не найден")
    exit()
if get_pass[0] != text2:
    print("Неверный пароль")
    exit()
cur.execute("UPDATE Users_info SET hash = '" + hashlib.md5(code.encode()).hexdigest() + "' WHERE login = '" + text1 + "';")
conn.commit()
cur.close()
conn.close()

HOST = "smtp.yandex.ru"
SUBJECT = "Verification code"
TO = "fohnsmith2@yandex.ru"
FROM = "fohnsmith1@yandex.ru"
password = 'asswecan1'
text = "Your verification code: " + code
BODY = "\r\n".join((
    "From: %s" % FROM,
    "To: %s" % TO,
    "Subject: %s" % SUBJECT,
    "",
    text
))
server = smtplib.SMTP(HOST)
server.starttls()
server.login(FROM, password)
server.sendmail(FROM, [TO], BODY)
server.quit()


with open('/home/user/Documents/verify.html', 'r') as verify:
    print(verify.read())