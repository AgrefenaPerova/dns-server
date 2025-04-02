import os
import pickle
import time
import logging
from threading import Thread
from socket import socket, AF_INET, SOCK_DGRAM
from dnslib import DNSRecord, DNSQuestion, QTYPE, A, AAAA, NS

CACHE_FILE = "cache.pickle"
DNS_PORT = 53
DNS_HOST = '127.0.0.1'
UPSTREAM_DNS = '8.26.56.26'

CACHE_TTL = 30
CACHE = {}
RUNNING = True

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

class DNSCacheEntry:
    def __init__(self, name):
        self.name = name
        self.records = {}

    def add(self, qtype, records):
        self.records[qtype] = (time.time(), records)
        Thread(target=self._expire_record, args=(qtype,)).start()

    def get(self, qtype):
        entry = self.records.get(qtype)
        if not entry:
            return None
        timestamp, data = entry
        if time.time() - timestamp < CACHE_TTL:
            return data
        else:
            del self.records[qtype]
            return None

    def _expire_record(self, qtype):
        time.sleep(CACHE_TTL)
        if qtype in self.records:
            del self.records[qtype]
            logging.info(f"Expired: {self.name} {QTYPE[qtype]}")
            save_cache()


def save_cache():
    try:
        with open(CACHE_FILE, 'wb') as f:
            pickle.dump(CACHE, f)
        logging.info("Cache saved to disk.")
    except Exception as e:
        logging.error(f"Failed to save cache: {e}")


def load_cache():
    global CACHE
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'rb') as f:
                CACHE = pickle.load(f)
            logging.info("Cache loaded from disk.")
        except Exception as e:
            logging.error(f"Failed to load cache: {e}")


def send_to_upstream(dns_query):
    try:
        with socket(AF_INET, SOCK_DGRAM) as upstream:
            upstream.settimeout(5)
            upstream.sendto(dns_query, (UPSTREAM_DNS, DNS_PORT))
            response, _ = upstream.recvfrom(4096)
            return response
    except Exception as e:
        logging.warning(f"Upstream DNS failed: {e}")
        return None


def handle_client(data, client_addr, server_sock):
    try:
        request = DNSRecord.parse(data)
        domain = str(request.q.qname)
        qtype = request.q.qtype
        logging.info(f"Request: {domain} {QTYPE[qtype]}")

        if domain in CACHE and (cached := CACHE[domain].get(qtype)):
            reply = request.reply()
            for record in cached:
                reply.add_answer(record)
            server_sock.sendto(reply.pack(), client_addr)
            logging.info("Response served from cache.")
            return

        response_data = send_to_upstream(data)
        if not response_data:
            logging.error("Failed to get response from upstream.")
            return

        response = DNSRecord.parse(response_data)
        if domain not in CACHE:
            CACHE[domain] = DNSCacheEntry(domain)
        records = list(response.rr)
        CACHE[domain].add(qtype, records)
        server_sock.sendto(response_data, client_addr)
        logging.info("Response from upstream cached and sent.")
    except Exception as e:
        logging.error(f"Failed to handle request: {e}")


def start_server():
    load_cache()
    try:
        with socket(AF_INET, SOCK_DGRAM) as server_sock:
            server_sock.bind((DNS_HOST, DNS_PORT))
            logging.info(f"DNS server started on {DNS_HOST}:{DNS_PORT}")
            while RUNNING:
                try:
                    data, client_addr = server_sock.recvfrom(4096)
                    Thread(target=handle_client, args=(data, client_addr, server_sock)).start()
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    logging.error(f"Server error: {e}")
    finally:
        save_cache()
        logging.info("Server shutdown gracefully.")


if __name__ == '__main__':
    start_server()
