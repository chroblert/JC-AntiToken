# -*- coding: utf-8 -*- 
#!python
#!/usr/bin/env python
# 测试
from burp import IBurpExtender
from burp import IContextMenuFactory
from burp import IBurpExtenderCallbacks
from burp import IHttpListener
from burp import ISessionHandlingAction
from burp import ITab
#from burp import ICookie

from javax.swing import JMenu
from javax.swing import JMenuItem
from javax.swing import JPanel
from javax.swing import JButton
from javax.swing import JFrame
from javax.swing import JLabel
from javax.swing import JTextField
from javax.swing import JComboBox
from javax.swing import JSplitPane
from javax.swing.border import Border
from javax.swing import BorderFactory
from javax.swing import JRadioButton
from javax.swing import ButtonGroup
from javax.swing import Box

from java.awt import Color
from java.awt import Dimension
from java.awt.event import *

from java.awt import GridLayout
from javax.swing import BoxLayout
from java.awt import FlowLayout


import re
import urllib
import urllib2
import json
import sys

sys_encoding = sys.getfilesystemencoding()


class BurpExtender(IBurpExtender,IContextMenuFactory,IHttpListener,ISessionHandlingAction,ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("JC-AntiToken")
        callbacks.registerContextMenuFactory(self)
        callbacks.registerHttpListener(self)
        callbacks.registerSessionHandlingAction(self)
        self.drawUI()
    def printcn(self,msg):
        print(msg.decode('utf-8').encode(sys_encoding))
    def drawUI(self):
        # 最外层：垂直盒子，内放一个水平盒子+一个胶水
        out_vBox_main = Box.createVerticalBox()
        # 次外层：水平盒子，内放两个垂直盒子
        hBox_main = Box.createHorizontalBox()
        # 左垂直盒子
        vBox_left = Box.createVerticalBox()
        # 右垂直盒子
        vBox_right = Box.createVerticalBox()

        # 左垂直盒子内部：发送请求包拿token
        # URL标签
        jlabel_url = JLabel("URL: ")
        self.jtext_url = JTextField(25)
        # self.jtext_url.setPreferredSize(Dimension(20,40))
        self.jtext_url.setMaximumSize(self.jtext_url.getPreferredSize())
        hbox_url = Box.createHorizontalBox()
        hbox_url.add(jlabel_url)
        hbox_url.add(self.jtext_url)
        hglue_url = Box.createHorizontalGlue()
        hbox_url.add(hglue_url)
        # hbox_url.setBorder(BorderFactory.createLineBorder(Color.red, 3))
        # 请求方法标签
        jlabel_reqMeth = JLabel("RequestMethod: ")   
        self.jcombobox_reqMeth = JComboBox()
        self.jcombobox_reqMeth.addItem("GET")
        self.jcombobox_reqMeth.addItem("POST")
        hbox_reqMeth = Box.createHorizontalBox()
        hbox_reqMeth.add(jlabel_reqMeth)
        hbox_reqMeth.add(self.jcombobox_reqMeth)
        self.jcombobox_reqMeth.setMaximumSize(self.jcombobox_reqMeth.getPreferredSize())
        hglue_reqMeth = Box.createHorizontalGlue()
        hbox_reqMeth.add(hglue_reqMeth)
        # hbox_reqMeth.setBorder(BorderFactory.createLineBorder(Color.red, 3))
        # ContentType标签        
        jlabel_contentType = JLabel("ContentType: ")
        self.jcombobox_contentType = JComboBox()
        self.jcombobox_contentType.addItem("application/json")
        self.jcombobox_contentType.addItem("text/plain")
        hbox_contentType = Box.createHorizontalBox()
        hbox_contentType.add(jlabel_contentType)
        hbox_contentType.add(self.jcombobox_contentType)
        self.jcombobox_contentType.setMaximumSize(self.jcombobox_contentType.getPreferredSize())
        hglue_contentType = Box.createHorizontalGlue()
        hbox_contentType.add(hglue_contentType)
        # hbox_contentType.setBorder(BorderFactory.createLineBorder(Color.red, 3))
        # 请求头标签
        jlabel_headers = JLabel("Headers: ")
        self.jtext_headers = JTextField(25)
        # self.jtext_headers.setPreferredSize(Dimension(20,40))
        self.jtext_headers.setMaximumSize(self.jtext_headers.getPreferredSize())
        hbox_headers = Box.createHorizontalBox()
        hbox_headers.add(jlabel_headers)
        hbox_headers.add(self.jtext_headers)
        hglue_headers = Box.createHorizontalGlue()
        hbox_headers.add(hglue_headers)
        # hbox_headers.setBorder(BorderFactory.createLineBorder(Color.red, 3))
        # 请求参数标签
        jlabel_data = JLabel("Data: ")
        self.jtext_data = JTextField(25)
        self.jtext_data.setPreferredSize(Dimension(20,40))
        self.jtext_data.setMaximumSize(self.jtext_data.getPreferredSize())
        hbox_data = Box.createHorizontalBox()
        hbox_data.add(jlabel_data)
        hbox_data.add(self.jtext_data)
        hglue_data = Box.createHorizontalGlue()
        hbox_data.add(hglue_data)
        # hbox_data.setBorder(BorderFactory.createLineBorder(Color.red, 3))
        # token标志位置标签
        hbox_radiobtn = Box.createHorizontalBox()
        jlabel_tokenPosition = JLabel("Token Position: ")
        self.radioBtn01 = JRadioButton("Header")
        self.radioBtn02 = JRadioButton("Body")
        btnGroup = ButtonGroup()
        btnGroup.add(self.radioBtn01)
        btnGroup.add(self.radioBtn02)
        self.radioBtn01.setSelected(True)
        hbox_radiobtn.add(jlabel_tokenPosition)
        hbox_radiobtn.add(self.radioBtn01)
        hbox_radiobtn.add(self.radioBtn02)
        # token正则表达式标签
        hbox_token = Box.createHorizontalBox()
        hbox_token_header = Box.createHorizontalBox()
        hbox_token_body = Box.createHorizontalBox()
        # token正则表达式标签：header中
        jlabel_tokenName = JLabel("tokenName: ")
        self.jtext_tokenName = JTextField(25)
        # self.jtext_tokenName.setPreferredSize(Dimension(20,40))
        self.jtext_tokenName.setMaximumSize(self.jtext_tokenName.getPreferredSize())
        hbox_token_header.add(jlabel_tokenName)
        hbox_token_header.add(self.jtext_tokenName)
        hglue_token_header = Box.createHorizontalGlue()
        hbox_token_header.add(hglue_token_header)
        # hbox_token_header.setBorder(BorderFactory.createLineBorder(Color.red, 3))
        # token正则表达式标签：body中
        jlabel_tokenRegex = JLabel("tokenRegex: ")
        self.jtext_tokenRegex = JTextField(25)
        # self.jtext_tokenRegex.setPreferredSize(Dimension(20,40))
        self.jtext_tokenRegex.setMaximumSize(self.jtext_tokenRegex.getPreferredSize())
        hbox_token_body.add(jlabel_tokenRegex)
        hbox_token_body.add(self.jtext_tokenRegex)
        hglue_token_body = Box.createHorizontalGlue()
        hbox_token_body.add(hglue_token_body)
        # hbox_token_body.setBorder(BorderFactory.createLineBorder(Color.red, 3))
        # token正则表达式标签
        hbox_token.add(hbox_token_header)
        hbox_token.add(hbox_token_body)
        # test测试按钮
        hbox_test = Box.createHorizontalBox()
        jbtn_test = JButton("TEST",actionPerformed=self.btnTest)
        self.jlabel_test = JLabel("Result: ")
        hbox_test.add(jbtn_test)
        hbox_test.add(self.jlabel_test)
        # hbox_test.setBorder(BorderFactory.createLineBorder(Color.red, 3))
        # 水平胶水填充
        hGlue_test = Box.createHorizontalGlue()
        hbox_test.add(hGlue_test)
        # 左垂直盒子：添加各种水平盒子
        vBox_left.add(hbox_url)
        vBox_left.add(hbox_reqMeth)
        vBox_left.add(hbox_contentType)
        vBox_left.add(hbox_headers)
        vBox_left.add(hbox_data)
        vBox_left.add(hbox_radiobtn)
        vBox_left.add(hbox_token)
        vBox_left.add(hbox_test)
        # 左垂直盒子：垂直胶水填充
        vGlue_test = Box.createGlue()
        vBox_left.add(vGlue_test)
        # vBox_left.setBorder(BorderFactory.createLineBorder(Color.green, 3))


        # 右垂直盒子内部：指定token在请求包中的位置
        # token标志位置单选按钮
        hbox_radiobtn_r = Box.createHorizontalBox()
        jlabel_tokenPosition_r = JLabel("Token Position: ")
        self.radioBtn01_r = JRadioButton("Header")
        self.radioBtn02_r = JRadioButton("Body")
        btnGroup_r = ButtonGroup()
        btnGroup_r.add(self.radioBtn01_r)
        btnGroup_r.add(self.radioBtn02_r)
        self.radioBtn01_r.setSelected(True)
        hbox_radiobtn_r.add(jlabel_tokenPosition_r)
        hbox_radiobtn_r.add(self.radioBtn01_r)
        hbox_radiobtn_r.add(self.radioBtn02_r)
        
        # token正则表达式
        hbox_token_r = Box.createHorizontalBox()
        hbox_token_header_r = Box.createHorizontalBox()
        hbox_token_body_r = Box.createHorizontalBox()
        # token正则表达式：在header中
        jlabel_tokenName_r = JLabel("tokenName: ")
        self.jtext_tokenName_r = JTextField(25)
        # self.jtext_tokenName_r.setPreferredSize(Dimension(20,40))
        # self.jtext_tokenName_r.setMaximumSize(Dimension(9999999,9999999))
        self.jtext_tokenName_r.setMaximumSize(self.jtext_tokenName_r.getPreferredSize())
        hbox_token_header_r.add(jlabel_tokenName_r)
        hbox_token_header_r.add(self.jtext_tokenName_r)
        hglue_token_header_r = Box.createHorizontalGlue()
        hbox_token_header_r.add(hglue_token_header_r)
        # hbox_token_header_r.setBorder(BorderFactory.createLineBorder(Color.red, 3))
        # token正则表达式：在Body中
        jlabel_tokenRegex_r = JLabel("tokenRegex: ")
        self.jtext_tokenRegex_r = JTextField(25)
        # self.jtext_tokenRegex_r.setPreferredSize(Dimension(20,40))
        # self.jtext_tokenRegex_r.setMaximumSize(Dimension(9999999,9999999))
        self.jtext_tokenRegex_r.setMaximumSize( self.jtext_tokenRegex_r.getPreferredSize() )
        hbox_token_body_r.add(jlabel_tokenRegex_r)
        hbox_token_body_r.add(self.jtext_tokenRegex_r)
        hglue_token_body_r = Box.createHorizontalGlue()
        hbox_token_body_r.add(hglue_token_body_r)
        # hbox_token_body_r.setBorder(BorderFactory.createLineBorder(Color.red, 3))
        # token正则表达式
        hbox_token_r.add(hbox_token_header_r)
        hbox_token_r.add(hbox_token_body_r)
        # 测试按钮
        hbox_test_r = Box.createHorizontalBox()
        jbtn_test_r = JButton("TEST",actionPerformed=self.btnTest_r)
        self.jlabel_test_r = JLabel("Result: ")
        hbox_test_r.add(jbtn_test_r)
        hbox_test_r.add(self.jlabel_test_r)
        # hbox_test_r.setBorder(BorderFactory.createLineBorder(Color.red, 3))
        # 水平胶水填充
        hGlue02 = Box.createHorizontalGlue()
        hbox_test_r.add(hGlue02)
        
        # 右垂直盒子：添加各种水平盒子
        vBox_right.add(hbox_radiobtn_r)
        vBox_right.add(hbox_token_r)
        vBox_right.add(hbox_test_r)
        # jtext_gluetest2 = JTextField(25)
        # jtext_gluetest2.setPreferredSize(Dimension(20,40))
        # jtext_gluetest2.setMaximumSize(Dimension(9999999,9999999))
        # vBox_right.add(jtext_gluetest2)
        vGlue = Box.createVerticalGlue()
        vBox_right.add(vGlue)

        vBox_left.setBorder(BorderFactory.createLineBorder(Color.black, 3))
        vBox_right.setBorder(BorderFactory.createLineBorder(Color.black, 3))

        # 次外层水平盒子：添加左右两个垂直盒子
        hBox_main.add(vBox_left)
        hBox_main.add(vBox_right)
        # 最外层垂直盒子：添加次外层水平盒子，垂直胶水
        out_vBox_main.add(hBox_main)
        # 测试用JTextField
        # jtext_gluetest = JTextField(25)
        # jtext_gluetest.setPreferredSize(Dimension(20,40))
        # jtext_gluetest.setMaximumSize(Dimension(100000010,1000000010))
        # out_vBox_main.add(jtext_gluetest)
        # out_hGlue_main = Box.createGlue()
        # out_vBox_main.add(out_hGlue_main)
        
        self.mainPanel = out_vBox_main
        self._callbacks.customizeUiComponent(self.mainPanel)
        self._callbacks.addSuiteTab(self)
        
    
    def getTabCaption(self):
        return "JC-AntiToken"

    def getUiComponent(self):
        return self.mainPanel

    def testBtn_onClick(self,event):
        print("click button")

    def createMenuItems(self, invocation):
        menu = []
        if invocation.getToolFlag() == IBurpExtenderCallbacks.TOOL_REPEATER:
            menu.append(JMenuItem("Test menu", None, actionPerformed=self.testmenu)) 
        return menu

    def testmenu(self,event):
        print(event)
        print("JCTest test menu")

    def processHttpMessage(self, toolflag, messageIsRequest, messageInfo):
        service = messageInfo.getHttpService()
        if messageIsRequest:
            print("Host: " + str(service.getHost()))
            print("Port: "+ str(service.getPort()))
            print("Protocol: " + str(service.getProtocol()))
            print("-----------------------------------")
    
    def getActionName(self):
        return "JCAntiToken"

    def performAction(self,currentRequest,macroItems):
        # url
        url = self._helpers.analyzeRequest(currentRequest).getUrl()
        print(url)
        reqInfo = self._helpers.analyzeRequest(currentRequest)
        # request headers
        headers = reqInfo.getHeaders()
        print("ReqHeaders: " + headers)
        # get cookie from request header
        cookie = self.getCookieFromReq(headers)
        print(cookie)
        print(type(cookie))
        # offset to req body
        reqBodyOffset = reqInfo.getBodyOffset()
        reqBody = str(bytearray(currentRequest.getRequest()[reqBodyOffset:]))
        print("ReqBody: " + reqBody)
        # modify Request Body
        newToken = self.getNewToken(cookie)
        if newToken != None:
            # tokenInReqHeader
            res = False
            if self.tokenInHeader_r:
                # pass
                # 普通header中
                for header in headers:
                    if ":" in header:
                        if header.split(":")[0] == self.tokenName_r:
                            headers = [self.tokenName_r + ": "+newToken  if i.split(":")[0] == self.tokenName_r else i for i in headers]
                            res = True
                            break
                # cookie中
                if not res and cookie != None and self.tokenName_r+"=" in cookie:
                    # pass
                    for i in range(len(headers)):
                        if headers[i].startwith("Cookie:"):
                            cookies2 = headers[i]
                            cookies3 = cookies2.split(":")[1]
                            if ";" not in cookies3:
                                headers[i] = "Cookie: " + self.tokenName_r+"="+newToken
                                res = True
                                break
                            else:
                                cookies4 = cookies3.split(";")
                                for cookie_idx in range(len(cookies4)):
                                    if self.tokenName_r+"+" in cookies4[cookie_idx]:
                                        cookies4[cookie_idx] = self.tokenName_r+"="+newToken
                                        res = True
                                        break
                                headers[i] = "Cookie: "+";".join(cookies4)
                                break
                # query string中
                if not res:
                    meth = headers[0].split(" ")[0]
                    url = headers[0].split(" ")[1]
                    ver = headers[0].split(" ")[2]
                    if self.tokenName_r+"=" not in url:
                        pass
                    else:
                        if "&" not in url:
                            url = url.split("?")[0] + "?"+ self.tokenName_r+"=" + newToken
                            headers[0] = meth + " " + url + " " + ver
                        else:
                            params = url.split("?")[1].split("&")
                            for i in range(len(params)):
                                if self.tokenName_r+"=" in params[i]:
                                    params[i] = self.tokenName_r+"="+newToken
                                    break
                            url = url.split("?")[0]+"?"+"&".join(params)
                            headers[0] = meth + " " + url + " " + ver
            # tokenInReqBody
            else:
                if re.match(self.tokenRegex_r,reqBody):
                    reqBody = re.sub(self.tokenRegex_r,r'\1'+newToken+r'\3',reqBody,0,re.M|re.I)
            # if re.match(r'(.*?"_tokenName":")([a-zA-Z0-9]{6,})(")',reqBody):
            #     reqBody = re.sub(r'(.*?"_tokenName":")([a-zA-Z0-9]{6,})(")',r'\1'+newToken+r'\3',reqBody,0,re.M|re.I)
        # rebuild request
        reqMessage = self._helpers.buildHttpMessage(headers,bytes(reqBody))
        # forward
        currentRequest.setRequest(reqMessage)
        print("++++++++++++++++++++++++")

    def getCookieFromReq(self,headers):
        for header in headers:
            if re.match(r'^Cookie:',header,re.I):
                return re.match(r'^Cookie: (.*)',header,re.I).group(1)
    # get new token
    def getNewToken(self,cookie):
        print(cookie)
        print("getNewToken")
        # url = "http://myip.ipip.net"
        headers2={
            'Cookie':cookie,
            'User-Agent':'Mozilla/6.0 (iPhone; CPU iPhone OS 8_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/8.0 Mobile/10A5376e Safari/8536.25'
            }
        self.headers.update(**headers2)
        if self.reqMeth == "GET":
            resp = self.sendGetHttp(self.url,self.headers,self.data)
        else:
            resp = self.sendPostHttp(self.url,self.headers,self.data,self.contentType)
        respBody = resp.read()
        respInfo = resp.info()
        if self.tokenInHeader:
            if respInfo.getheader(self.tokenName) != None:
                newToken = respInfo.getheader(self.tokenName)
                print(newToken)
                return newToken
            else:
                regexPattern = '.*'+self.tokenName+'=(.*?);'
                if respInfo.getheader("set-cookie") != None:
                    cookies = respInfo.getheader("set-cookie")
                    if re.match(regexPattern,cookies,re.M|re.I):
                        newToken = re.match(regexPattern,cookies,re.M|re.I).group(1)
                        print("newToken: ",newToken)
                        return newToken
                    else:
                        return None
                else:
                    return None
        else:
            regexPattern = self.tokenRegex
            if re.match(regexPattern,respBody,re.M|re.I):
                newToken = re.match(regexPattern,respBody,re.M|re.I).group(1)
                print("newToken: ",newToken)
                return newToken
            else:
                return None

    def sendGetHttp(self,url,headers,data):
        if data:
            data = urllib.urlencode(data)
            url = url + "?"+data
            if headers:
                req = urllib2.Request(url,headers=headers)
            else:
                req = urllib2.Request(url)
            resp = urllib2.urlopen(req)
            return resp
        else:
            if headers:
                req = urllib2.Request(url,headers=headers)
            else:
                req = urllib2.Request(url)
            resp = urllib2.urlopen(req)
            return resp

    def sendPostHttp(self,url,headers,data,contentType):
        resp = ""
        if data:
            if headers:
                if contentType == "urlencode":
                    data = urllib.urlencode(data)
                    req = urllib2.Request(url,headers=headers,data = data)
                    resp = urllib2.urlopen(req)
                    return resp
                else:
                    data = json.dumps(data)
                    req = urllib2.Request(url,headers=headers,data = data)
                    resp = urllib2.urlopen(req)
            else:
                if contentType == "urlencode":
                    data = urllib.urlencode(data)
                    req = urllib2.Request(url,data = data)
                    resp = urllib2.urlopen(req)
                    return resp
                else:
                    data = json.dumps(data)
                    req = urllib2.Request(url,data = data)
                    resp = urllib2.urlopen(req)
        else:
            if headers:
                if contentType == "urlencode":
                    req = urllib2.Request(url,headers=headers)
                    resp = urllib2.urlopen(req)
                    return resp
                else:
                    data = json.dumps(data)
                    req = urllib2.Request(url,headers=headers)
                    resp = urllib2.urlopen(req)
            else:
                if contentType == "urlencode":
                    data = urllib.urlencode(data)
                    req = urllib2.Request(url)
                    resp = urllib2.urlopen(req)
                    return resp
                else:
                    data = json.dumps(data)
                    req = urllib2.Request(url)
                    resp = urllib2.urlopen(req)
        return resp

    def btnTest(self,e):
        self.printcn("中文测试")
        self.url = self.jtext_url.getText()
        self.reqMeth = self.jcombobox_reqMeth.getSelectedItem()
        self.contentType = self.jcombobox_contentType.getSelectedItem()
        if self.jtext_headers.getText() != "":
            self.headers = json.loads(self.jtext_headers.getText())
        else:
            self.headers = {}
        if self.jtext_data.getText() != "":
            self.data = json.loads(self.jtext_data.getText())
        else:
            self.data = {}
        self.tokenName = self.jtext_tokenName.getText()
        self.tokenRegex = self.jtext_tokenRegex.getText()
        resp = ''
        if self.reqMeth == "GET":
            resp = self.sendGetHttp(self.url,self.headers,self.data)
            # print(resp)
        else:
            resp = self.sendPostHttp(self.url,self.headers,self.data,self.contentType)
            # print(resp)
        respHeader = resp.info().headers
        print(respHeader)
        print(resp.info().getheader("content-type"))
        print(resp.info().getheader("set-cookie"))
        print(resp.info().getheader("xxx"))
        respBody = resp.read()
        print("respBody: ",respBody)
        if(self.radioBtn01.isSelected()):
            self.tokenInHeader = True
            if self.tokenName == "":
                self.jlabel_test.setText("please input tokenName")
                return
        else:
            self.tokenInHeader = False
            if self.tokenRegex == "":
                self.jlabel_test.setText("please input tokenRegex")
                return
        print(self.reqMeth)
        newToken = self.getNewToken("var1=value1")
        if newToken != None:
            self.jlabel_test.setText("Result: "+str(newToken))
            self.jlabel_test.setBackground(Color.cyan)
        else:
            self.jlabel_test.setText("Result: None")

    def btnTest_r(self,e):
        self.tokenName_r = self.jtext_tokenName_r.getText()
        self.tokenRegex_r = self.jtext_tokenRegex_r.getText()
        if(self.radioBtn01_r.isSelected()):
            self.tokenInHeader_r = True
            if self.tokenName_r == "":
                self.jlabel_test_r.setText("please input tokenName")
                return
        else:
            self.tokenInHeader_r = False
            if self.tokenRegex_r == "":
                self.jlabel_test_r.setText("please input tokenRegex")
                return
        