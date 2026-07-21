import asyncio
import socket as s
import ipaddress
import time

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 81, 110, 135, 143, 443,
                465, 587, 993, 995, 3389, 5900, 8080, 9100]

class PortScanner():
    def __init__(self, ip, concurrency=500, timeout=1, *args, **kwargs):
        """
        :param: ip: IP address we are scanning
        :param concurrency: max amount of simultaneous connections, 500 is default
        :param timeout: time we wait before closing a connection (seconds)

        """
        self.ip = ip
        self.concurrency = concurrency
        self.timeout = timeout
        self.sem = asyncio.Semaphore(concurrency) # handler for concurrency

    async def scan_port(self, ip, port):
        async with self.sem: # to ensure we are under concurrency
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    self.timeout
                                                        )
                writer.close()
                await writer.wait_closed()
                return port
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return None

    async def scan_ports(self, ip , ports):
        start = time.time()
        tasks = [self.scan_port(ip, p) for p in ports]
        results = await asyncio.gather(*tasks)

        open_ports = sorted(p for p in results if p is not None)
        time_elapsed = time.time() - start
        print(f"Open Ports on {ip}: [{open_ports}]")

