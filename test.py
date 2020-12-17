import urllib
import urllib2
import json
class test:
    def __init__(self):
        self._contentType = "json"
        self._url = "http://www.baidu.com"
        self._headers = {
            'User-Agent':'Mozilla/6.0 (iPhone; CPU iPhone OS 8_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/8.0 Mobile/10A5376e Safari/8536.25',
            'Content-Type': self._contentType,
        }
        self._data = {'test':'value'}
        self._respTokenRegx = ''
        self._repTokenRegx = ''
    def getNewToken(self,cookie):
        print(cookie)
        print("getNewToken")
        url = self._url
        self._headers['Cookie'] = cookie

        data = self._data
        # data = urllib.urlencode(data)
        # req = urllib2.Request(url,headers=headers)
        # resp = urllib2.urlopen(req).read()
        resp = self.sendGetHttp(url,headers,data)
        if re.match(r'.*"_tokenName":"(.*?)"',resp,re.M|re.I):
            newToken = re.match(r'.*"_tokenName":"(.*?)"',resp,re.M|re.I).group(1)
            print(newToken)
            return newToken
        return "JCTest"

    def sendGetHttp(self,url,headers,data):
        data = urllib.urlencode(data)
        url = url + "?"+data
        req = urllib2.Request(url,headers=headers)
        resp = urllib2.urlopen(req).read()
        print(resp)
        return resp
    def sendPostHttp(self,url,headers,data,contentType):
        if contentType == "urlencode":
            data = urllib.urlencode(data)
            print(data)
            req = urllib2.Request(url,headers=headers,data = data)
            resp = urllib2.urlopen(req).read()
        else:
            data = json.dumps(data)
            req = urllib2.Request(url,headers=headers,data = data)
            resp = urllib2.urlopen(req)
            for header in resp.info().headers:
                print(header)
            print(resp.info().getheader('Set-Cookie'))
        print(resp)
        return resp
obj = test()
url = "http://www.baidu.com"
headers={
            'Cookie':"xxxxx",
            'User-Agent':'Mozilla/6.0 (iPhone; CPU iPhone OS 8_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/8.0 Mobile/10A5376e Safari/8536.25'
            }
data = {'test':'value'}
obj.sendPostHttp(url,headers,data,"json")