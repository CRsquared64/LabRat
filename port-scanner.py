import asyncio
import socket
import socket as s
import ipaddress
import time

from scapy.all import ARP, Ether, srp

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 81, 110, 135, 143, 443,
                465, 554, 587, 993, 995, 3389, 5900, 8080, 9100]

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


    def hostname_resolve(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return None

    def arp_scan(self, network):
        arp = ARP(pdst=network)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp

        answered, unanswered = srp(packet, timeout=self.timeout, verbose=False)
        devices = []

        for sent, received in answered:
            devices.append({
                "ip": received.psrc,
                "mac": received.hwsrc
            })

        for device in devices:
            print(f"IP: {device['ip']:15} MAC: {device['mac']} Name: {self.hostname_resolve(device['ip'])}")

        return devices
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

    async def scan_ports(self , ports):
        start = time.time()
        tasks = [self.scan_port(self.ip, p) for p in ports]
        results = await asyncio.gather(*tasks)

        open_ports = sorted(p for p in results if p is not None)
        time_elapsed = time.time() - start
        print(f"\nOpen Ports on {self.ip}: [{open_ports}] \n"
              f"Time Taken [{time_elapsed:.2f}s]\n"
              f"Scanned [{len(ports)}] ports \n"
              f"[{len(open_ports)}/{len(ports)}] ports open")

    async def scan_common_ports(self):
        print(f'Estimated Time [{len(COMMON_PORTS)/self.concurrency * self.timeout}]')
        await self.scan_ports(COMMON_PORTS)

    async def full_port_scan(self, min=1, max=2001):
        print(f'Estimated Time [{max/self.concurrency * self.timeout}]')

        await self.scan_ports(range(min, max+1))




async def main():
    portScanner = PortScanner("192.168.133.1")
    print(time.ctime())
    portScanner.arp_scan("192.168.133.1/24")
    await portScanner.scan_common_ports()
if __name__ == "__main__":
    asyncio.run(main())