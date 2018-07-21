import asyncio
import random
import time

class TestQueue(object):
    def __init__(self, num):
        self.num = num
        self.loop = asyncio.get_event_loop()
        self.queue = asyncio.Queue(loop=self.loop)
        self.load_data()

    def load_data(self):
        print("[+] Loading data...")
        for i in range(76119):
            self.queue.put_nowait(i)

    async def do_something(self):
        while not self.queue.empty():
            data = await self.queue.get()
            print("Processing the data : {}".format(data))
            process_time = random.random()
            await asyncio.sleep(process_time)
            print("Processed the data : {} It used the time : {:.2}s".format(data, process_time))

    def run(self):
        tasks = (self.do_something() for _ in range(self.num))
        self.loop.run_until_complete(asyncio.gather(*tasks))
        self.loop.close()


if __name__ == '__main__':
    s = TestQueue(10000)
    start_time = time.time()
    s.run()
    print("All used the time : {:.3}".format(time.time()-start_time))
