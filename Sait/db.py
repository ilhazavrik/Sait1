import os
from app import app, db

# Удаляем старую базу данных, если она существует
if os.path.exists('database.db'):
    os.remove('database.db')

# Пересоздаем таблицы
with app.app_context():
    db.create_all()
    print("База данных и таблицы успешно пересозданы!")
