from bs4 import BeautifulSoup as bs
import psycopg2
import argparse
import requests
import asyncio
import logging
import aiodns
import json
import time
import re


logging.basicConfig(level=logging.INFO,
                    format='[+] %(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

DB_HOST = 'crt.sh'
DB_NAME = 'certwatch'
DB_USER = 'guest'


class DomainEnumerator(object):
    def __init__(self, domain, sub_filename='subnames.txt', num=1000, timeout=0.2, nameserver='119.29.29.29', log_level='INFO', query_next_sub=1, CT=1, third_part=1, output_filename='result.json'):
        self.domain = domain
        self.num = num
        self.sub_filename = sub_filename
        self.query_next_sub = query_next_sub
        self.CT = CT
        self.third_part = third_part
        self.next_sub_filename = 'subnames2.txt'
        self.output_filename = output_filename
        self.loop = asyncio.get_event_loop()
        self.queue = asyncio.Queue(loop=self.loop)
        self.resolver = aiodns.DNSResolver(
            timeout=timeout, loop=self.loop, nameservers=[nameserver])
        self.next_subs = []
        self.found_domain = {}
        self._ips = {}
        eval("logger.setLevel(logging.{})".format(log_level))

    async def query(self):
        while not self.queue.empty():
            sub = await self.queue.get()
            full_domain = sub + '.' + self.domain
            if full_domain in self.found_domain:
                continue
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
                    ips.sort()
                    # 给每个域名解析所得ＩＰ结果计数，若某个ＩＰ超过２０次出现，可能存在域名泛解析问题，则舍弃对应域名
                    try:
                        self._ips[str(ips)] += 1
                        if self._ips[str(ips)] > 20:
                            continue
                    except KeyError:
                        self._ips[str(ips)] = 0
                    logger.debug('{domain}: {ips}'.format(
                        domain=full_domain, ips=ips))
                    self.found_domain[full_domain] = ips
                    # 通过解析一个不存在的三级域名时产生的错误代号判断是否存在三级域名
                    if self.query_next_sub:
                        try:
                            await self.resolver.query('moofeng.'+full_domain, 'A')
                        except aiodns.error.DNSError as e:
                            err_code, err_msg = e.args[0], e.args[1]
                            if err_code is 4:
                                for next_sub in self.next_subs:
                                    self.queue.put_nowait(next_sub+'.'+sub)

    def get_by_CT(self):
        # 该功能容易出现查询超时
        logger.info("正在通过检索CT日志枚举子域名...")
        try:
            conn = psycopg2.connect(
                "dbname={0} user={1} host={2}".format(DB_NAME, DB_USER, DB_HOST))
            cursor = conn.cursor()
            cursor.execute(
                "SELECT ci.NAME_VALUE NAME_VALUE FROM certificate_identity ci WHERE ci.NAME_TYPE = 'dNSName' AND reverse(lower(ci.NAME_VALUE)) LIKE reverse(lower('%{}'));".format(self.domain))
        except:
            logger.error("连接到crt.sh的数据库失败！" + str(e))
        subdomains = []
        domain_len = -len(self.domain)-1
        for i in cursor.fetchall():
            matches = re.findall(r"\'(.+?)\'", str(i))
            for subdomain in matches:
                if subdomain not in subdomains:
                    if ".{}".format(self.domain) in subdomain:
                        subdomains.append(subdomain)
        logger.info("在数据库中找到以下公开的证书：")
        logger.info(subdomains)
        for subdomain in subdomains:
            self.queue.put_nowait(subdomain[:domain_len])

    def get_by_dic(self):
        logger.info("正在从字典中加载子域名...")
        if self.query_next_sub:
            with open(self.next_sub_filename) as f:
                for line in f:
                    sub = line.strip().lower()
                    if sub == '':
                        continue
                    self.next_subs.append(sub)
        with open(self.sub_filename) as f:
            for line in f:
                sub = line.strip().lower()
                if sub == '':
                    continue
                self.queue.put_nowait(sub)
        logger.info("成功加载{size}个子域名!".format(size=self.queue.qsize()))
        tasks = (self.query() for _ in range(self.num))
        self.loop.run_until_complete(asyncio.gather(*tasks))
        self.loop.close()

    def get_by_third_part(self):
        logger.info('正在通过第三方网站(dnsdumpster.com)接口查询...')
        url = 'https://dnsdumpster.com/'
        req = requests.get(url)
        soup = bs(req.content, 'html.parser')
        csrf_token = soup.findAll(
            'input', attrs={'name': 'csrfmiddlewaretoken'})[0]['value']
        cookies = {'csrftoken': csrf_token}
        headers = {'Referer': url}
        data = {'csrfmiddlewaretoken': csrf_token, 'targetip': self.domain}
        req = requests.post(url, cookies=cookies, data=data, headers=headers)
        soup = bs(req.content, 'html.parser')
        table = soup.findAll('table')[3]
        trs = table.findAll('tr')
        for tr in trs:
            tds = tr.findAll('td')
            pattern_ip = r'([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})'
            try:
                ip = re.findall(pattern_ip, tds[1].text)[0]
                domain = str(tds[0]).split('<br/>')[0].split('>')[1]
                self.found_domain[domain] = ip
            except:
                logger.error('未获取到相关子域名信息！')

    # 清洗可能存在的泛解析域名
    def data_cleaning(self):
        ips = []
        for ip, num in self._ips.items():
            if num > 20:
                ips.append(eval(ip))
        for domain, ip in self.found_domain.copy().items():
            if ip in ips:
                self.found_domain.pop(domain)
        logger.info("可能存在域名泛解析问题的ＩＰ: {}".format(ips))

    def run(self):
        start_time = time.time()
        logger.info("正在进行子域名枚举...")
        if self.CT:
            self.get_by_CT()
        if self.third_part:
            self.get_by_third_part()
        self.get_by_dic()
        self.data_cleaning()
        # 以json形式存储查询结果
        with open(self.output_filename, 'w') as f:
            json.dump(self.found_domain, f)
            logger.info('查询结果以输出到文件 {} 中！'.format(self.output_filename))
        logger.info('一共找到 {domain} 下 {length} 个子域名, 总耗时为 {second:.3f}s'.format(
            domain=self.domain, length=len(self.found_domain), second=time.time()-start_time))


def main():
    parser = argparse.ArgumentParser(description="Enumeration Subdomain")
    parser.add_argument(
        '-d', '--domain', help='The target domain.', required=True)
    parser.add_argument('-n', '--num',
                        help='The number of coroutine.The default value is 1000.', default=1000, type=int)
    parser.add_argument('-f', '--sub_filename',
                        help="The name of subdomain file.The default value is subnames.txt", default='subnames.txt')
    parser.add_argument('-t', '--timeout',
                        help='The number of seconds each name server is given to respond to a query on the first try.The default value is 0.2', default=0.2, type=float)
    parser.add_argument('-s', '--nameserver',
                        help='The nameserver to be used to do the lookups.The default value is 119.29.29.29', default='119.29.29.29')
    parser.add_argument('-l', '--log_level', help='The level of logging.The default value is INFO.',
                        default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'])
    parser.add_argument('-q', '--query_next_sub',
                        help='Whether to enumerate multiple subdomains.', default=1, type=int, choices=[0, 1])
    parser.add_argument('-c', '--CT', help='Whether to use CT log enumeration technology.',
                        default=1, type=int, choices=[0, 1])
    parser.add_argument('-p', '--third_part', help='Whether to use a third party interface to query subdomain information.',
                        default=1, type=int, choices=[0, 1])
    parser.add_argument('-o', '--output_filename', help='Specifies the name of the file that holds the results', default='result.json')
    args = parser.parse_args()

    domain = args.domain
    sub_filename = args.sub_filename
    num = args.num
    timeout = args.timeout
    nameserver = args.nameserver
    log_level = args.log_level
    query_next_sub = args.query_next_sub
    CT = args.CT
    third_part = args.third_part
    output_filename = args.output_filename

    s = DomainEnumerator(domain, sub_filename, num,
                         timeout, nameserver, log_level, query_next_sub, CT, third_part, output_filename)
    s.run()


if __name__ == '__main__':
    main()
