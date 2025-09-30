import asyncio
import json
import logging
import redis.asyncio as redis
import socket
from dnslib import DNSRecord, QTYPE, RCODE

# --- Basic Configuration ---
CONFIG_PATH = 'config.json'
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Load Config ---
with open(CONFIG_PATH, 'r') as f:
    config = json.load(f)

# --- Redis Connection Pool ---
redis_pool = redis.ConnectionPool(
    host=config['redis']['host'],
    port=config['redis']['port'],
    db=config['redis']['db'],
    decode_responses=False
)
redis_client = redis.Redis(connection_pool=redis_pool)


# ---------------- Cache Helpers ----------------
async def get_from_cache(key):
    cached_data = await redis_client.get(key)
    if cached_data:
        await redis_client.incr(f"{key}:hits")
        return cached_data # Return raw bytes
    return None

async def add_to_cache(key, response_bytes):
    try:
        response_record = DNSRecord.parse(response_bytes)
        min_ttl = 600 # Default for negative cache
        if response_record.rr:
            min_ttl = min((r.ttl for r in response_record.rr), default=600)
        
        if min_ttl <= 0:
            logging.warning(f"DNS response for '{key}' had a non-positive TTL ({min_ttl}). Caching for 60s instead.")
            min_ttl = 60

        await redis_client.setex(key, min_ttl, response_bytes)
        logging.info(f"Cached '{key}' with TTL {min_ttl}s and RCODE {RCODE[response_record.header.rcode]}.")
    except Exception as e:
        logging.error(f"Failed to cache response for '{key}': {e}")


# ---------------- Upstream Resolver (Highly Resilient) ----------------
def resolve_upstream_sync(request_bytes):
    """
    Forwards the original raw request bytes to upstream servers with resilient failover.
    It now checks for a conclusive answer before returning.
    """
    qname = "unknown"
    try:
        qname = str(DNSRecord.parse(request_bytes).q.qname)
    except Exception:
        pass

    for ns in config['forwarders']:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(5)
                sock.sendto(request_bytes, (ns, 53))
                response_bytes, _ = sock.recvfrom(4096)
                
                # ******************** FINAL LOGIC CHANGE IS HERE ********************
                # We now parse the response inside the loop to check if it's a conclusive answer.
                if len(response_bytes) >= 4:
                    try:
                        parsed_response = DNSRecord.parse(response_bytes)
                        # A conclusive answer is either NXDOMAIN or a NOERROR that has records.
                        if parsed_response.header.rcode == RCODE.NXDOMAIN or \
                           (parsed_response.header.rcode == RCODE.NOERROR and parsed_response.rr):
                            logging.info(f"Received conclusive response for '{qname}' from {ns}.")
                            return response_bytes
                        else:
                            # This handles SERVFAIL and empty NOERROR responses, telling the loop to continue.
                            logging.warning(f"Received non-conclusive response (RCODE: {RCODE[parsed_response.header.rcode]}) from {ns}. Trying next forwarder...")
                            continue
                    except Exception as parse_error:
                        logging.warning(f"Could not parse response from {ns}: {parse_error}. Trying next forwarder...")
                        continue
                # ********************************************************************
                else:
                    logging.warning(f"Received malformed/short packet from {ns} for '{qname}'. Trying next...")
                    continue

        except socket.timeout:
            logging.warning(f"Upstream query to {ns} for '{qname}' timed out. Trying next forwarder...")
            continue
        except Exception as e:
            logging.warning(f"Upstream query to {ns} for '{qname}' failed with an exception: {e}. Trying next forwarder...")
            continue
            
    logging.error(f"All upstream forwarders failed to provide a valid response for '{qname}'.")
    return None


# ---------------- DNS Server ----------------
class DnsServerProtocol(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        loop = asyncio.get_running_loop()
        loop.create_task(self.handle_query(data, addr))

    async def handle_query(self, data, addr):
        reply_packet = None
        request_id = data[:2]
        try:
            request_record = DNSRecord.parse(data)
            q = request_record.q
            qname = str(q.qname)
            qtype_name = QTYPE[q.qtype]
            cache_key = f"dns:{qname.rstrip('.')}:{qtype_name}"

            logging.info(f"Request from {addr[0]}: ('{qname.rstrip('.')}', {qtype_name})")

            cached_response_bytes = await get_from_cache(cache_key)
            if cached_response_bytes:
                logging.info(f"Cache HIT for '{cache_key}'")
                reply_packet_mutable = bytearray(cached_response_bytes)
                reply_packet_mutable[:2] = request_id
                reply_packet = bytes(reply_packet_mutable)
            else:
                logging.info(f"Cache MISS for '{cache_key}'. Querying upstream...")
                loop = asyncio.get_running_loop()
                response_bytes = await loop.run_in_executor(
                    None, resolve_upstream_sync, data
                )
                
                if response_bytes:
                    reply_packet_mutable = bytearray(response_bytes)
                    reply_packet_mutable[:2] = request_id
                    reply_packet = bytes(reply_packet_mutable)
                    
                    response_record = DNSRecord.parse(reply_packet)
                    logging.info(f"Resolver succeeded for '{qname}' with status {RCODE[response_record.header.rcode]}.")
                    
                    if (response_record.header.rcode == RCODE.NOERROR and response_record.rr) or \
                       (response_record.header.rcode == RCODE.NXDOMAIN):
                        await add_to_cache(cache_key, reply_packet)
                    else:
                        logging.info(f"Not caching empty 'NOERROR' response for '{cache_key}' to align with desired logic.")

                else:
                    logging.error(f"All resolvers failed for '{qname}'.")
                    reply = request_record.reply()
                    reply.header.rcode = RCODE.SERVFAIL
                    reply_packet = reply.pack()

            if reply_packet:
                self.transport.sendto(reply_packet, addr)

        except Exception as e:
            logging.error(f"Critical error in handle_query: {e}")
            try:
                reply = DNSRecord.parse(data).reply()
                reply.header.rcode = RCODE.SERVFAIL
                self.transport.sendto(reply.pack(), addr)
            except Exception:
                pass


# ---------------- Main ----------------
async def main():
    logging.info("Starting DNS server (dnslib/asyncio) on 0.0.0.0:53")
    loop = asyncio.get_running_loop()
    
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: DnsServerProtocol(),
        local_addr=('0.0.0.0', 53),
        reuse_port=True)

    try:
        await asyncio.sleep(3600_000)
    finally:
        transport.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except PermissionError:
        logging.error("Permission denied to bind to port 53. Run as root.")
    except Exception as e:
         logging.error(f"Server failed to start: {e}")
