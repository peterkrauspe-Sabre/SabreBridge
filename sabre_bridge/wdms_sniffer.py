import asyncio
import logging
from datetime import datetime

FORWARD_HOST = "cloud.sabreproducts.com"
FORWARD_PORT = 81
LISTEN_PORT = 9091
LOG_FILE = "wdms_sniffer.log"

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s",
                    handlers=[logging.FileHandler(LOG_FILE, "a", encoding="utf-8"),
                              logging.StreamHandler()])

async def handle_client(local_reader, local_writer):
    peer = local_writer.get_extra_info("peername")
    logging.info(f"Connection from {peer}")

    try:
        remote_reader, remote_writer = await asyncio.open_connection(FORWARD_HOST, FORWARD_PORT)
    except Exception as e:
        logging.error(f"Failed to connect to WDMS: {e}")
        local_writer.close()
        return

    async def pipe(reader, writer, direction):
        try:
            while not reader.at_eof():
                data = await reader.read(4096)
                if not data:
                    break
                text_preview = data.decode(errors="ignore")[:300].replace("\n", "\\n")
                logging.info(f"{direction} {len(data)} bytes: {text_preview}")
                writer.write(data)
                await writer.drain()
        except Exception as e:
            logging.error(f"Pipe error {direction}: {e}")
        finally:
            try:
                writer.close()
            except:
                pass

    await asyncio.gather(
        pipe(local_reader, remote_writer, "IN "),
        pipe(remote_reader, local_writer, "OUT")
    )

async def main():
    server = await asyncio.start_server(handle_client, "0.0.0.0", LISTEN_PORT)
    addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets)
    logging.info(f"Sniffer listening on {addrs} → {FORWARD_HOST}:{FORWARD_PORT}")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Sniffer stopped")
