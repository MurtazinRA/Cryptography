#!/usr/bin/env python3
import cgi
import psycopg2
import hashlib

form = cgi.FieldStorage()
text1 = form.getfirst("TEXT_1", "не задано")

conn = psycopg2.connect(dbname='testdb', user='postgres', password='1111', host='localhost')
cur = conn.cursor()
cur.execute("SELECT * FROM Users_info WHERE hash = '" + hashlib.md5(text1.encode()).hexdigest() + "';")
if not cur.fetchone():
    output = "Неверный код! Аутентификация не пройдена"
else:
    output = "Аутентификация пройдена! Всем спасибо, все свободны"
conn.commit()
cur.close()
conn.close()

print("Content-type: text/html\n")
print("""<!DOCTYPE HTML>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Обработка данных форм</title>
        </head>
        <body>""")

print("<h1>Обработка данных форм!</h1>")
print(output)

print("""</body>
        </html>""")
