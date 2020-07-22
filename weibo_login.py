import  requests
import time
import base64
import json
import rsa
import re
import binascii
from urllib import parse
class Weibo_login():
    def __init__(self):
        self.usrname='**'
        self.password='136185jKl'
        self.sess=requests.session()
        self.sess.headers={
            'Referer': 'https://weibo.com/',
           "User-Agent":"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.132 Safari/537.36"

        }
    def pre_login(self):
        
            param={
                'entry': 'weibo',
                'callback': 'sinaSSOController.preloginCallBack',
                # parse.quote处理特殊符号@，相当于js里面的urlencode
                'su': base64.b64encode(parse.quote(self.usrname).encode()).decode(),
                'rsakt': 'mod',
                'client':' ssologin.js(v1.4.19)',
                '_': int(time.time()*1000),

                 }
            url='https://login.sina.com.cn/sso/prelogin.php'
            r=self.sess.get(url,params=param)
            print(r.text)
            start=r.text.index('{')
            end=r.text.index('}')
            dc=json.loads(r.text[start:end+1])
            return dc
    def get_login(self,dc):
        data_a={
            'entry': 'weibo',
            'gateway': '1',
            'from': '',
            'savestate': '7',
            'qrcode_flag': 'false',
            'useticket': '1',
            'pagerefer':'' ,
            'vsnf': '1',
            'su': base64.b64encode(parse.quote(self.usrname).encode()).decode(),
            'service': 'miniblog',
            'servertime': dc['servertime'],
            'nonce': dc['nonce'],
            'pwencode': 'rsa2',
            'rsakv':dc['rsakv'] ,
            'sp': '',
            'sr': '1536*864',
            'encoding': 'UTF-8',
            'prelt': '79',
            'url': 'https://weibo.com/ajaxlogin.php?framelogin=1&callback=parent.sinaSSOController.feedBackUrlCallBack',
            'returntype': 'META',
               
          }
        PubKey_arg=dc['pubkey']
        # 构造非对称公钥
        pubkey=rsa.PublicKey(int(PubKey_arg,16),int('10001',16))
        sp=rsa.encrypt(('\t'.join((str(dc['servertime']),dc['nonce']))+'\n'+self.password).encode(),pubkey)
        # 去掉加密结果中的\x
        sp=binascii.b2a_hex(sp).decode()
        data_a['sp']=sp
        print("sp",sp)
        r=self.sess.post('https://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.19)',data=data_a)
        r.encoding='gbk'
        print("----:")
        login_url=re.search(r'location\.replace\("(.+)"\)',r.text).group(1)
        return login_url
    def get_cook(self,url):
        # 获取cookies
        r=self.sess.get(url)
        r.encoding='gbk'
        print('爱你',r.text)
        ls=re.search('"arrURL":(.+?)}',r.text).group(1)
        ls.replace('\\',' ')
        # 字符串转换成列表对象
        ls=json.loads(ls)
        print("++++++++++++++++premse",self.sess.cookies)
        for url in ls:
            self.sess.get(ls)
        print('++++',self.sess.cookies)
        
    def check(self):
        # 检查时候登陆成功
        r=self.sess.get('https://www.weibo.com')
        r.encoding='utf-8'
    
        print('登陆状态','某某用户名' in r.text)






    def run(self):
        # 预登陆，取得nonce参数
        dic=self.pre_login()     
        pubkey_retrun=self.get_login(dic)
        print(pubkey_retrun)
        self.get_cook(pubkey_retrun)
        self.check()

if __name__=='__main__':
    w=Weibo_login()
    w.run()
)

