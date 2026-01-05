import asyncio
import os
import signal
import json
import subprocess
import aiohttp
from typing import Dict, Set
from scapy.all import sniff, IP, TCP, UDP, send, conf
from datetime import datetime
import yaml
import re


CONFIG = {}

def load_config():
    """Загрузка конфига"""
    global CONFIG
    with open('config.yaml', 'r') as f:
        raw_config = yaml.safe_load(f)
        CONFIG['interface'] = raw_config['network']['interface']
        CONFIG['whitelist'] = raw_config['network']['whitelist']
        CONFIG['honey_ports'] = raw_config['honey_ports']
        CONFIG['ban_threshold'] = raw_config['rules']['ban_threshold']
        CONFIG['ban_time'] = raw_config['rules']['ban_time']
        CONFIG['packet_limit'] = raw_config['rules']['packets_limit']
        CONFIG['bot_id'] = raw_config['telegram']['bot_id']
        CONFIG['user_id'] = raw_config['telegram']['user_id']
        CONFIG['log_file'] = raw_config['logging']['log_file']
        CONFIG['geoip'] = raw_config['logging']['geoip_enabled']

def get_white_list():
    """Получение белого списка IP-адресов"""
    try:
        with open(CONFIG['whitelist'], 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        return []

async def escape_md2(text: str) -> str:
    "Корректировка текста под верное"
    md2_pattern = r'_*[]()~`>#+-=|{}.!'
    escaped_text = re.sub(f'([{re.escape(md2_pattern)}])', r'\\\1', text)

    return escaped_text

async def send_telegram_msg(text):
    """Отправка телеграм уведомлений"""
    url = f"https://api.telegram.org/bot{CONFIG['bot_id']}/sendMessage"
    payload = {
        "chat_id": CONFIG['user_id'],
        "text": text,
        "parse_mode": "MarkdownV2"
    }
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload) as resp:
                if resp.status != 200:
                    pass
    except Exception as e:
        pass
            
load_config()
conf.L2socket


class AsyncFirewall:
    """Управление iptables через асинхронные подпроцессы."""
    def __init__(self, chain="SHADEWALL"):
        self.chain = chain

    async def setup(self):
        """Инициализация цепочки правил"""
        await self._run_cmd(f"iptables -N {self.chain}")
        await self._run_cmd(f"iptables -I INPUT -j {self.chain}")

    async def _run_cmd(self, cmd: str):
        proc = await asyncio.create_subprocess_shell(
            cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        await proc.communicate()

    async def ban(self, ip: str):
        """Создание правил IPTABLES"""
        await self._run_cmd(f"iptables -A {self.chain} -s {ip} -j DROP")

    async def unban(self, ip: str):
        """Удаление правил IPTABLES"""
        await self._run_cmd(f"iptables -D {self.chain} -s {ip} -j DROP")

    async def cleanup(self):
        await self._run_cmd(f"iptables -D INPUT -j {self.chain}")
        await self._run_cmd(f"iptables -F {self.chain}")
        await self._run_cmd(f"iptables -X {self.chain}")

class AsyncAlertManager:
    """Асинхронные уведомления и GeoIP"""
    def __init__(self):
        self.session: aiohttp.ClientSession = None

    async def start(self):
        self.session = aiohttp.ClientSession()

    async def stop(self):
        if self.session:
            await self.session.close()

    async def enrich_and_report(self, ip: str, reason: str, dport: int):
        """Получает GeoIP и отправляет отчет (не блокируя детекцию)"""
        country = 'Unknown'
        isp = 'Unknown'
        try:
            async with self.session.get(f"{CONFIG['geoip_url']}{ip}", timeout=5) as resp:
                data = await resp.json()
                country = data.get("country", "Unknown")
                isp = data.get("isp", "Unknown")
        except:
            pass
        
        log_entry = {
            "time": str(datetime.now()),
            "ip": ip,
            "port": dport,
            "reason": reason,
            "geo": f"{country} ({isp})"
        }
        message = (
            f"🚨 *ShadeWall Alert*\n"
            f"🔴 *БАН:* `{await escape_md2(ip)}`\n"
            f"❓ *Причина:* {await escape_md2(reason)}\n"
            f"🎯 *Порт:* {await escape_md2(str(dport))}\n"
            f"🕒 *Время:* {await escape_md2(datetime.now().strftime('%H:%M:%S'))}"
        )
        await send_telegram_msg(message)
        with open(CONFIG['log_file'], "a", encoding='utf-8') as f:
            f.write(json.dumps(log_entry) + '\n')

class Detector:
    """Логика анализа угроз"""
    def __init__(self, firewall: AsyncFirewall, alerter: AsyncAlertManager):
        self.fw = firewall
        self.alerter = alerter
        self.scores: Dict[str, int] = {}
        self.banned: Set[str] = set()
        self.packet_counts = {}
        self.last_check = datetime.now()

    async def process_packet(self, ip_src: str, dport: int, flags: str):
        """Анализ пакета"""
        if ip_src in self.banned or ip_src in get_white_list():
            return
        score = 0
        reason = "Behavior Analysis"
        now = datetime.now()
        if (now - self.last_check).seconds >= 1:
            self.packet_counts = {}
            self.last_check = now
        self.packet_counts[ip_src] = self.packet_counts.get(ip_src, 0) + 1
        if self.packet_counts[ip_src] > CONFIG['packet_limit']:
            await self.trigger_ban(ip_src, "DoS Attack Detected", 0)
            return
        
        if dport in CONFIG["honey_ports"]:
            self.banned.add(ip_src)
            score += 20
            reason = f"Honey-Port Access ({dport})"
        
        if flags in ["FPU", "0", "F"]:
            score += 10
            reason = "Invalid TCP Flags Scan"

        self.scores[ip_src] = self.scores.get(ip_src, 0) + score

        if self.scores[ip_src] >= CONFIG["ban_threshold"]:
            await self.trigger_ban(ip_src, reason, dport)

    async def trigger_ban(self, ip: str, reason: str, dport: int):
        """Планировка блокировки"""
        self.banned.add(ip)
        await self.fw.ban(ip)
        asyncio.create_task(self.alerter.enrich_and_report(ip, reason, dport))
        asyncio.create_task(self.schedule_unban(ip))

    async def schedule_unban(self, ip: str):
        """Планировка разблокировки"""
        await asyncio.sleep(CONFIG["ban_time"])
        await self.fw.unban(ip)
        self.banned.discard(ip)
        self.scores[ip] = 0
            
class ShadeWallCore:
    """Главный оркестратор"""
    def __init__(self):
        self.fw = AsyncFirewall()
        self.alerter = AsyncAlertManager()
        self.detector = Detector(self.fw, self.alerter)
        self.loop = None

    def _packet_handler(self, pkt):
        """Мост между синхронным Scapy и асинхронным детектором"""
        if IP in pkt:
            ip_src = pkt[IP].src
            dport = None
            proto_flags = "N/A"
            if TCP in pkt:
                dport = pkt[TCP].dport
                proto_flags = str(pkt[TCP].flags)
            elif UDP in pkt:
                dport = pkt[UDP].dport
                proto_flags = "UDP"
            if dport:
                if self.loop and self.loop.is_running():
                    self.loop.call_soon_threadsafe(
                        lambda: asyncio.run_coroutine_threadsafe(
                            self.detector.process_packet(ip_src, dport, proto_flags), self.loop
                        )
                    )
                    
    async def run(self):
        """Запуск оркестратора"""
        self.loop = asyncio.get_running_loop()
        await self.fw.setup()
        await self.alerter.start()
        await self.loop.run_in_executor(
            None, 
            lambda: sniff(iface=CONFIG['interface'], prn=self._packet_handler, store=0, filter='tcp or udp')
        )

    async def shutdown(self):
        """Выключение оркестратора"""
        await self.fw.cleanup()
        await self.alerter.stop()
        tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        [t.cancel() for t in tasks]
        await asyncio.gather(*tasks, return_exceptions=True)
        self.loop.stop()

if __name__ == "__main__":
    core = ShadeWallCore()

    async def main():
        loop = asyncio.get_running_loop()

        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, lambda: asyncio.create_task(core.shutdown()))
                        
        await core.run()
    try:
        asyncio.run(main())
    except Exception as e:
        print(f"Критическая ошибка: {e}")