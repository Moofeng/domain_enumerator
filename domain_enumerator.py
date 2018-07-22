import asyncio
import argparse
import aiodns
import logging
import time


logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class DomainEnumerator(object):
    def __init__(self, domain, sub_filename='subnames.txt', num=1000, timeout=0.2, nameserver='119.29.29.29', log_level='INFO'):
        self.domain = domain
        self.num = num
        self.sub_filename = sub_filename
        self.loop = asyncio.get_event_loop()
        self.queue = asyncio.Queue(loop=self.loop)
        self.resolver = aiodns.DNSResolver(
            timeout=timeout, loop=self.loop, nameservers=[nameserver])
        self.load_subnames()
        self.found_subs = {}
        eval("logger.setLevel(logging.{})".format(log_level))

    def load_subnames(self):
        logger.info("[+] Loading subnames...")
        with open(self.sub_filename) as f:
            for line in f:
                sub = line.strip().lower()
                if sub == '':
                    continue
                self.queue.put_nowait(sub)

    async def query(self):
        while not self.queue.empty():
            sub = await self.queue.get()
            if sub in self.found_subs:
                continue
            full_domain = sub + '.' + self.domain
            try:
                result = await self.resolver.query(full_domain, 'A')
                ips = [r.host for r in result]
            except aiodns.error.DNSError as e:
                # 1:  DNS server returned answer with no data
                # 4:  Domain name not found
                # 11: Could not contact DNS servers
                # 12: Timeout while contacting DNS servers
                err_code, err_msg = e.args[0], e.args[1]
                logger.debug("Resolving the domain '{domain}' : {msg}".format(
                    domain=full_domain, msg=err_msg))
            else:
                for ip in ips:
                    if ip in ['0.0.0.1', '0.0.0.0', '1.1.1.1']:
                        ips.remove(ip)
                if ips:
                    logger.info('{domain}: {ips}'.format(
                        domain=full_domain, ips=ips))
                    self.found_subs[full_domain] = ips

    def run(self):
        start_time = time.time()
        tasks = (self.query() for _ in range(self.num))
        self.loop.run_until_complete(asyncio.gather(*tasks))
        logger.debug(self.found_subs)
        logger.info('一共找到 {domain} 下 {length} 个子域名, 总耗时为 {second:.5}s'.format(
            domain=self.domain, length=len(self.found_subs), second=time.time()-start_time))
        self.loop.close()


def main():
    parser = argparse.ArgumentParser(description="Enumeration Subdomain")
    parser.add_argument(
        '-d', '--domain', help='The target domain.', required=True)
    parser.add_argument('-n', '--num',
                        help='The number of coroutine.', default=1000, type=int)
    parser.add_argument('-f', '--sub_filename',
                        help="The name of subdomain file.", default='subnames.txt')
    parser.add_argument('-t', '--timeout',
                        help='The number of seconds each name server is given to respond to a query on the first try.', default=0.2, type=float)
    parser.add_argument('-s', '--nameserver',
                        help='The nameserver to be used to do the lookups.', default='119.29.29.29')
    parser.add_argument('-l', '--log_level', help='The level of logging.',
                        default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'])
    args = parser.parse_args()

    domain = args.domain
    sub_filename = args.sub_filename
    num = args.num
    timeout = args.timeout
    nameserver = args.nameserver
    log_level = args.log_level

    s = DomainEnumerator(domain, sub_filename, num,
                         timeout, nameserver, log_level)
    s.run()


if __name__ == '__main__':
    main()
