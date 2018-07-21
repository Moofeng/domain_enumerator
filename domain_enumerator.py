import asyncio
import aiodns


class DomainEnumerator(object):
    def __init__(self, domain, num):
        self.domain = domain
        self.num = num
        self.sub_filename = 'subnames.txt'
        self.loop = asyncio.get_event_loop()
        self.queue = asyncio.Queue(loop=self.loop)
        self.resolver = aiodns.DNSResolver(
            timeout=0.3, loop=self.loop, nameservers=['114.114.114.114', '119.29.29.29'])
        self.load_subnames()
        self.found_subs = {}

    def load_subnames(self):
        print("[+] Loading subnames...")
        with open(self.sub_filename) as f:
            for line in f:
                sub = line.strip().lower()
                if sub == '':
                    continue
                self.queue.put_nowait(sub)

    async def query(self):
        while not self.queue.empty():
            sub = await self.queue.get()
            sub_domain = sub + '.' + self.domain
            try:
                result = await self.resolver.query(sub_domain, 'A')
                ips = [r.host for r in result]
            except aiodns.error.DNSError as e:
                # print(e)
                pass
            else:
                for ip in ips:
                    if ip in ['0.0.0.1', '0.0.0.0', '1.1.1.1']:
                        ips.remove(ip)
                if ips:
                    print('{domain}: {ip}'.format(domain=sub_domain, ip=ips))
                    self.found_subs[sub_domain] = ips

    def run(self):
        tasks = (self.query() for _ in range(self.num))
        self.loop.run_until_complete(asyncio.gather(*tasks))
        # print(self.found_subs)
        print('一共找到域名 {domain} 下 {length} 个子域名！'.format(
            domain=self.domain, length=len(self.found_subs)))
        self.loop.close()


if __name__ == '__main__':
    s = DomainEnumerator('qq.com', 10000)
    s.run()
