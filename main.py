import nmap
from getmac import get_mac_address 
from telegram import Bot 
import asyncio
import time

IP = "192.168.188.255"
KNOWN_DEVICES = ['f8:54:f6:5c:4d:f6']  
TELEGRAM_BOT_TOKEN = "7507800332:AAG5FBzZwWln0qQQwWV1eBQ2rdBI26GIlZc"
CHAT_ID = "-4736179538"  


class NetworkScanner:

    def __init__(self, ip: str):
        self.ip = ip
        self.connected_devices = set()

    def scan(self):
        network = f"{self.ip}/24"
        nm = nmap.PortScanner()

        # Create the event loop
        loop = asyncio.get_event_loop()

        while True:
            try:
                nm.scan(hosts=network, arguments="-sn")
                host_list = nm.all_hosts()

                for host in host_list:
                    mac = get_mac_address(ip=host)
                    print(f"Found MAC: {mac}")

                    if mac and mac not in self.connected_devices and mac not in KNOWN_DEVICES:
                        print("New device found")
                        loop.create_task(self.notify_new_devices(mac))  # Schedule the async task
                        self.connected_devices.add(mac)

            except Exception as e:
                print(f"Error during scan: {e}")

            time.sleep(5)  # Delay of 60 seconds before scanning again

    async def send_telegram_message(self, bot, chat_id, message):
        await bot.send_message(chat_id=chat_id, text=message)

    async def notify_new_devices(self, mac):
        bot = Bot(token=TELEGRAM_BOT_TOKEN)
        await self.send_telegram_message(bot, CHAT_ID, f"New device found: {mac}")


if __name__ == "__main__":
    scanner = NetworkScanner(IP)
    scanner.scan()
