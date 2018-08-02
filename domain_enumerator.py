import aiodns
import aiohttp
import argparse
import asyncio
from bs4 import BeautifulSoup as bs
import logging
import re
from collections import defaultdict

    
CRT_DB_HOST = 'crt.sh'
CRT_DB_NAME = 'certwatch'
CRT_DB_USER = 'guest'

_default_logger = logging.getLogger(__name__) 
_reg_name_value = re.compile(r"\'(.+?)\'")
_reg_ip = re.compile(r'([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})')
_dnsdumpster_url = 'https://dnsdumpster.com/'
    
class DomainEnumerator(object):
    def __init__(self, domain, sub_filename='subnames.txt', next_sub_filename = "subnames2.txt",
                 num=1000, timeout=0.2, nameservers=('119.29.29.29', ), logger = _default_logger, 
                 query_next_sub = True, CT = True, third_part = True, pg_pool = None, loop = None):
        self.domain = domain
        self._num = num
        self._sub_filename = sub_filename
        self._query_next_sub = query_next_sub
        self._CT = CT
        self._third_part = third_part
        self._next_sub_filename = next_sub_filename
        self._loop = loop or asyncio.get_event_loop()
        self._dns_resolve_queue = asyncio.Queue(loop=self._loop)
        self._resolver = aiodns.DNSResolver(timeout = timeout, loop = self._loop, 
                                            nameservers = (nameservers ,) if 
                                            isinstance(nameservers, str) else nameservers)
        self._next_subs = tuple()
        self._found_domains = {}
        self._bad_domains = set()
        self._bad_ips = set()
        self._ip_domains = defaultdict(lambda: [])
        self._logger = logger
        self._pg_pool = pg_pool
        self._CT_finished = False
        self._3rd_finished = False
    
    async def _dns_query(self):
        while not self._dns_resolve_queue.empty() or (self._CT and not self._CT_finished) or (self._third_part and not self._3rd_finished):
            if self._dns_resolve_queue.empty():
                await asyncio.sleep(0, loop = self._loop)
                continue
            domain = await self._dns_resolve_queue.get()
            if domain in self._found_domains or domain in self._bad_domains:
                continue
            try:
                result = await self._resolver.query(domain, 'A')
                ips = [r.host for r in result if r not in ('0.0.0.1', '0.0.0.0', '1.1.1.1')]
            except aiodns.error.DNSError as e:
                # 1:  DNS server returned answer with no data
                # 4:  Domain name not found
                # 11: Could not contact DNS servers
                # 12: Timeout while contacting DNS servers
                self._logger.debug("Resolving the domain '%s': %s", domain, e.args[1])
            else:
                if ips:
                    ips.sort()
                    # 给每个域名解析所得ＩＰ结果计数，若某个ＩＰ超过２０次出现，可能存在域名泛解析问题，则舍弃对应域名
                    str_ips = str(ips)
                    if str_ips in self._bad_ips:
                        self._bad_domains.add(domain)
                        continue
                    elif len(self._ip_domains[str_ips]) == 20:
                        self._bad_domains.add(domain)
                        for domain in self._ip_domains[str_ips]:
                            try:
                                del self._found_domains[domain]
                            except KeyError:
                                pass
                        del self._ip_domains[str_ips]
                        self._bad_ips.add(str_ips)
                        continue
                    
                    self._found_domains[domain] = ips
                    self._ip_domains[str_ips].append(domain)
                    
                    self._logger.debug('%s: %s', domain, str_ips)
                    
                    # 通过解析一个不存在的三级域名时产生的错误代号判断是否存在三级域名
                    if self._query_next_sub:
                        try:
                            await self._resolver.query('moofengxsfdsa.'+ domain, 'A')
                        except aiodns.error.DNSError as e:
                            err_code = e.args[0]
                            if err_code is 4:
                                for next_sub in self._next_subs:
                                    await self._dns_resolve_queue.put(next_sub+'.' + domain)

    async def _get_by_CT(self):
        # 该功能容易出现查询超时
        self._logger.info("try to find sub domains by Certificate-Transparency")
        if not self._pg_pool:
            self._logger.warn("no postgresql-connection-pool provided, but use Certificate-Transparency")
            return
        async with self._pg_pool.acquire() as conn:
            try:
                records = await conn.fetch("SELECT ci.NAME_VALUE NAME_VALUE FROM certificate_identity ci "
                                          "WHERE ci.NAME_TYPE = 'dNSName' AND reverse(lower(ci.NAME_VALUE))"
                                          " LIKE reverse(lower($1));", self.domain)
                subdomains = []
                domain_len = -len(self.domain)-1
                for record in records:
                    matches = re.findall(_reg_name_value, record['NAME_VALUE'])
                    for subdomain in matches:
                        if ".{}".format(self.domain) in subdomain:
                            subdomains.append(subdomain)
                            await self._dns_resolve_queue.put(subdomains[:domain_len])
            except Exception as e:
                print(e)
        self._logger.info("find Certificates:")
        self._logger.info(subdomains)
        self._CT_finished = True

    async def _get_by_dict(self):
        self._logger.info("try to find sub domains by dict")
        if self._query_next_sub:
            with open(self._next_sub_filename) as f:
                self._next_subs = tuple(sub for sub in (line.strip().lower() for line in f) if sub)
        with open(self._sub_filename) as f:
            for line in f:
                sub = line.strip().lower()
                if sub:
                    await self._dns_resolve_queue.put(sub + "." + self.domain)
                    
        self._logger.info("load %s sub domains from dict", self._dns_resolve_queue.qsize())
        self._logger.info("start enumerate sub domains by dict...")
        tasks = (self._dns_query() for _ in range(self._num))
        await asyncio.gather(*tasks)

    async def _get_by_third_part(self):
        self._logger.info('try to enumerate sub domains from dnsdumpster.com...')
        async with aiohttp.ClientSession() as session:
            async with session.get(_dnsdumpster_url):
                csrf_token = session.cookie_jar.filter_cookies(_dnsdumpster_url)['csrftoken'].value
            data = {'csrfmiddlewaretoken': csrf_token, "targetip": self.domain}
            async with session.post(_dnsdumpster_url, data = data, headers = {'Referer': _dnsdumpster_url}) as resp:
                content = await resp.text()
        soup = bs(content, 'html.parser')
        table = soup.findAll('table')[3]
        trs = table.findAll('tr')
        i = 0
        for tr in trs:
            tds = tr.findAll('td')
            try:
                domain = self._fetch_first_text(tds[0].strings)
                await self._dns_resolve_queue.put(domain)
                i += 1
            except Exception as e:
                print(e)
        self._3rd_finished = True        
        self._logger.info('find %s domains from %s', i, _dnsdumpster_url)
    
    def _fetch_first_text(self, strings):
        for s in strings:
            return s
        
    async def get_sub_domains(self):
        futs = [self._get_by_dict()]
        if self._CT:
            futs.append(self._get_by_CT())
        if self._third_part:
            futs.append(self._get_by_third_part())
        await asyncio.gather(*futs, loop = self._loop)
        return self._found_domains
        

async def main():
    import time
    import json
    
    logging.logProcesses = 0
    logging.logThreads = 0
    logging.basicConfig(level=logging.INFO,
                    format='[+] %(asctime)s - %(levelname)s - %(message)s')
    
    parser = argparse.ArgumentParser(description="Enumeration Subdomain")
    parser.add_argument(
        '-d', '--domain', help='The target domain.', required=True)
    parser.add_argument('-n', '--num',
                        help='The number of coroutine.The default value is 1000.', default=1000, type=int)
    parser.add_argument('-f', '--sub_filename',
                        help="The name of subdomain file.The default value is subnames.txt", default='subnames.txt')
    parser.add_argument('-t', '--timeout', default=0.2, type=float,
                        help='The number of seconds each name server is given to respond to a _dns_query on the first try.The default value is 0.2')
    parser.add_argument('-s', '--nameservers', nargs = "+", default=['119.29.29.29', ],
                        help='The nameserver to be used to do the lookups.The default value is 119.29.29.29')
    parser.add_argument('-l', '--log_level', help='The level of logging.The default value is INFO.',
                        default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'])
    parser.add_argument('-q', '--query_next_sub',
                        help='Whether to enumerate multiple subdomains.', default=0, type=int, choices=[0, 1])
    parser.add_argument('-c', '--CT', help='Whether to use _CT log enumeration technology.',
                        default=0, type=int, choices=[0, 1])
    parser.add_argument('-p', '--third_part', help='Whether to use a third party interface to _dns_query subdomain information.',
                        default=1, type=int, choices=[0, 1])
    parser.add_argument('-o', '--output_filename', help='Specifies the name of the file that holds the results', default='result.json')
    args = parser.parse_args().__dict__
 
    output_filename = args.pop("output_filename")
    eval('_default_logger.setLevel(logging.%s)'%(args.pop("log_level")))
    enumerator = DomainEnumerator(**args)
    
    _default_logger.info("start enumerate sub domains for '%s'", args['domain'])
    
    pg_pool = None
    if args['CT']:
        try:
            import asyncpg
        except ImportError:
            _default_logger.error("'asyncpg' is required if use Certificate-Transparency")
            exit(1)
        pg_pool = await asyncpg.create_pool(database = CRT_DB_NAME, user = CRT_DB_USER, host = CRT_DB_HOST,
                                            min_size = 1, max_size = 1)
        args['pg_pool'] = pg_pool
    time_start = time.time()
    
    try:
        sub_domains = await enumerator.get_sub_domains()
        if output_filename == "-":
            import sys
            json.dumps(sub_domains, sys.stdout, indent = 2)
        else:
            with open(output_filename, 'w') as f:
                json.dump(sub_domains, f)
        _default_logger.info("found %s sub domains, used %s seconds", len(sub_domains), time.time() - time_start)
    finally:
        if pg_pool:
            await pg_pool.close()

if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
    loop.close()
