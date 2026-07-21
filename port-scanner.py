import asyncio
import socket as s
import ipaddress
import time

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

    async def check_port(self, ip, port):
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