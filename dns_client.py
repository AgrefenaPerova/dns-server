import socket
import struct

# Стандартный A-запрос для www.google.com
def build_dns_query():
    transaction_id = b'\xaa\xaa'
    flags = b'\x01\x00'
    questions = b'\x00\x01'
    answer_rrs = b'\x00\x00'
    authority_rrs = b'\x00\x00'
    additional_rrs = b'\x00\x00'

    qname = b'\x03www\x06google\x03com\x00'
    qtype = b'\x00\x01'
    qclass = b'\x00\x01'

    dns_query = (
        transaction_id + flags + questions +
        answer_rrs + authority_rrs + additional_rrs +
        qname + qtype + qclass
    )
    return dns_query

def parse_response(data):
    transaction_id = data[:2]
    flags = data[2:4]
    qdcount = struct.unpack(">H", data[4:6])[0]
    ancount = struct.unpack(">H", data[6:8])[0]

    print(f"🔍 Ответ ID: {transaction_id.hex()}")
    print(f"⚙️ Флаги: {flags.hex()}")
    print(f"❓ Кол-во вопросов: {qdcount}")
    print(f"✅ Кол-во ответов: {ancount}")

    print("\n📦 Ответ (hex):")
    print(data.hex())

    if ancount > 0:
        ip_addresses = []
        offset = 12
        while data[offset] != 0:
            offset += 1
        offset += 5

        for _ in range(ancount):
            offset += 10
            rdlength = struct.unpack(">H", data[offset - 2:offset])[0]
            rdata = data[offset:offset + rdlength]

            if rdlength == 4:  # IPv4
                ip = '.'.join(str(b) for b in rdata)
                ip_addresses.append(ip)

            offset += rdlength

        print("\n🌐 IP-адреса в ответе:")
        for ip in ip_addresses:
            print(f"  - {ip}")

def send_dns_query():
    server_address = ('127.0.0.1', 53)
    query = build_dns_query()

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(5)
        try:
            sock.sendto(query, server_address)
            data, _ = sock.recvfrom(512)
            print(f"\n✅ Получено {len(data)} байт от DNS-сервера.")
            parse_response(data)
        except socket.timeout:
            print("❌ Ошибка: DNS-сервер не отвечает (таймаут).")
        except Exception as e:
            print(f"❌ Ошибка при отправке запроса: {e}")

if __name__ == '__main__':
    send_dns_query()
