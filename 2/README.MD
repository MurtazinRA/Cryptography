Руководство по запуску программы на Ubuntu 20.04  
  
Устанавливаем pip и библиотеку psycopg2  
sudo apt install python3-pip  
pip3 install psycopg2  
  
Устанавливаем СУБД PostgreSQL:  
sudo apt install postgresql  
sudo -i -u postgres  
  
Создаем базу данных и устанавливаем пароль пользователю postgres:  
psql  
create database testdb;  
alter user postgres with encrypted password '1111';  
  
Создаем таблицу и заполняем таблицу несколькими строками(приведен код для Python):    
cur.execute("CREATE TABLE Users_info (id SERIAL PRIMARY KEY, login VARCHAR(32), email VARCHAR(32), password VARCHAR(32), hash TEXT);")  
cur.execute("INSERT INTO Users_info (login, email, password, hash) VALUES (%s, %s, %s, %s);", ('ivanpetrov', 'fohnsmith2@yandex.ru', 'vanya007', '0'))  
cur.execute("INSERT INTO Users_info (login, email, password, hash) VALUES (%s, %s, %s, %s);", ('vasyaivanov', 'fohnsmith1@yandex.ru', 'supervasya', '0'))  
cur.execute("INSERT INTO Users_info (login, email, password, hash) VALUES (%s, %s, %s, %s);", ('grisha', 'ilovemysweater@yandex.ru', 'slave', '0'))  
conn.commit()  
  
Меняем настройки в почтовом аккаунте отправителя (для почтового аккаунта на yandex.ru) - разрешаем доступ со стороны почтовых клиентов для протоколов IMAP и POP3  
  
Помещаем файл index.html на рабочий стол (/home/user/Desktop), также на рабочий стол добавляем и папку cgi-bin  
  
Для того, чтобы нельзя было получить файл verify.html по прямой ссылке (страница с запросом кода подтверждения), помещаем его в /home/user/Documents  
  
