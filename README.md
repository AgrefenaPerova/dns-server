# DNS-сервер с кэшированием

Этот проект реализует простой кэширующий DNS-сервер на Python.

## 📦 Зависимости

- Python 3.13 (или совместимая версия Python 3.8+)
- [dnslib](https://pypi.org/project/dnslib/)

### Установка зависимостей

Если используешь Python 3.13, сначала установи `pip`, если он не установлен:

```bash
sudo apt install python3.13-venv python3.13-distutils -y
curl -sS https://bootstrap.pypa.io/get-pip.py | sudo python3.13
```

Затем установи библиотеку `dnslib`:

```bash
sudo python3.13 -m pip install dnslib
```

Если используешь другую версию Python:

```bash
pip install dnslib
```

---

## 🚀 Запуск сервера

```bash
sudo python3.13 dns_server.py
```

Сервер слушает DNS-запросы на порту 53 и кэширует результаты, чтобы сократить количество обращений к внешним DNS.

Пример запуска с логами:

```bash
$ sudo python3.13 dns_server.py
Starting DNS server on 0.0.0.0:53...
Cached response for google.com: 142.250.191.14
Serving cached response for google.com
```

---

## 🧪 Тестирование клиента

```bash
python3.13 dns_client.py
```

Пример вывода:

```bash
$ python3.13 dns_client.py
Ответ от сервера: 142.250.180.14
```

Скрипт клиента отправляет DNS-запросы серверу и выводит полученные ответы.

---

## 🗂️ Структура проекта

- `dns_server.py` — основной сервер
- `dns_client.py` — тестовый DNS-клиент
- `Resource.py` — реализация хранения и управления кэшом

---

## 📎 Примечания

- Для прослушивания 53 порта требуются root-права (`sudo`)
- Кэш реализован в памяти и не сохраняется между запусками
- Только A-записи (IPv4) поддерживаются в текущей версии

---
