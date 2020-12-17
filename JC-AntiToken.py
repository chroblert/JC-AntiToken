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
        # self.mainPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        # self.testBtn = JButton(u'one button',actionPerformed=self.testBtn_onClick)
        # self.mainPanel.add(self.testBtn)
        # self._callbacks.customizeUiComponent(self.mainPanel)
        # self._callbacks.addSuiteTab(self)
        # jpanel_left = JPanel(FlowLayout(FlowLayout.LEFT))


        jsplitpane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT,True)
        jpanel_left = JPanel(FlowLayout(FlowLayout.LEFT))
        jpanel_right = JPanel(FlowLayout(FlowLayout.LEFT))
        hBox_main = Box.createHorizontalBox()
        vBox_left = Box.createVerticalBox()
        vBox_right = Box.createVerticalBox()

        # left panel
        layout = BoxLayout(jpanel_left, BoxLayout.Y_AXIS)
        jpanel_left.setLayout(layout)
        jlabel_url = JLabel("URL: ")
        self.jtext_url = JTextField(25)
        # jpanel_url = JPanel(FlowLayout(FlowLayout.LEFT))
        hbox_url = Box.createHorizontalBox()
        hbox_url.add(jlabel_url)
        hbox_url.add(self.jtext_url)
        hbox_url.setBorder(BorderFactory.createLineBorder(Color.red, 3))

        jlabel_reqMeth = JLabel("RequestMethod: ")   
        self.jcombobox_reqMeth = JComboBox()
        self.jcombobox_reqMeth.addItem("GET")
        self.jcombobox_reqMeth.addItem("POST")
        # jpanel_reqMeth = JPanel(FlowLayout(FlowLayout.LEFT))
        hbox_reqMeth = Box.createHorizontalBox()
        hbox_reqMeth.add(jlabel_reqMeth)
        hbox_reqMeth.add(self.jcombobox_reqMeth)
        hbox_reqMeth.setBorder(BorderFactory.createLineBorder(Color.red, 3))


        
        jlabel_contentType = JLabel("ContentType: ")
        self.jcombobox_contentType = JComboBox()
        self.jcombobox_contentType.addItem("application/json")
        self.jcombobox_contentType.addItem("text/plain")
        # jpanel_contentType = JPanel(FlowLayout(FlowLayout.LEFT))
        hbox_contentType = Box.createHorizontalBox()
        hbox_contentType.add(jlabel_contentType)
        hbox_contentType.add(self.jcombobox_contentType)
        hbox_contentType.setBorder(BorderFactory.createLineBorder(Color.red, 3))

        jlabel_headers = JLabel("Headers: ")
        self.jtext_headers = JTextField(25)
        # jpanel_headers = JPanel(FlowLayout(FlowLayout.LEFT))
        hbox_headers = Box.createHorizontalBox()
        hbox_headers.add(jlabel_headers)
        hbox_headers.add(self.jtext_headers)
        hbox_headers.setBorder(BorderFactory.createLineBorder(Color.red, 3))

        jlabel_data = JLabel("Data: ")
        self.jtext_data = JTextField(25)
        # jpanel_data = JPanel(FlowLayout(FlowLayout.LEFT))
        hbox_data = Box.createHorizontalBox()
        hbox_data.add(jlabel_data)
        hbox_data.add(self.jtext_data)
        hbox_data.setBorder(BorderFactory.createLineBorder(Color.red, 3))
        
        # radioButton
        # jpanel_radiobtn = JPanel(FlowLayout(FlowLayout.LEFT))
        hbox_radiobtn = Box.createHorizontalBox()
        jlabel_tokenPosition = JLabel("Token Position: ")
        self.radioBtn01 = JRadioButton("Header")
        self.radioBtn02 = JRadioButton("Body")
        # radioBtn01.setSelected(True)
        btnGroup = ButtonGroup()
        btnGroup.add(self.radioBtn01)
        btnGroup.add(self.radioBtn02)
        self.radioBtn01.setSelected(True)
        hbox_radiobtn.add(jlabel_tokenPosition)
        hbox_radiobtn.add(self.radioBtn01)
        hbox_radiobtn.add(self.radioBtn02)
        
        # token
        hbox_token = Box.createHorizontalBox()
        vbox_token_header = Box.createVerticalBox()
        vbox_token_body = Box.createVerticalBox()

        jlabel_tokenName = JLabel("tokenName: ")
        self.jtext_tokenName = JTextField(25)
        vbox_token_header.add(jlabel_tokenName)
        vbox_token_header.add(self.jtext_tokenName)
        vbox_token_header.setBorder(BorderFactory.createLineBorder(Color.red, 3))

        jlabel_tokenRegex = JLabel("tokenRegex: ")
        self.jtext_tokenRegex = JTextField(25)
        vbox_token_body.add(jlabel_tokenRegex)
        vbox_token_body.add(self.jtext_tokenRegex)
        vbox_token_body.setBorder(BorderFactory.createLineBorder(Color.red, 3))

        hbox_token.add(vbox_token_header)
        hbox_token.add(vbox_token_body)

        # test
        hbox_test = Box.createHorizontalBox()
        jbtn_test = JButton("TEST",actionPerformed=self.btnTest)
        self.jlabel_test = JLabel("Result: ")

        hbox_test.add(jbtn_test)
        hbox_test.add(self.jlabel_test)
        hbox_test.setBorder(BorderFactory.createLineBorder(Color.red, 3))
        # 填充
        hGlue_test = Box.createHorizontalGlue()
        hbox_test.add(hGlue_test)


        # jpanel_left.add(hbox_url)
        # jpanel_left.add(hbox_reqMeth)
        # jpanel_left.add(hbox_contentType)
        # jpanel_left.add(hbox_headers)
        # jpanel_left.add(hbox_data)
        # jpanel_left.add(hbox_radiobtn)
        # jpanel_left.add(hbox_token)
        # jpanel_left.add(hbox_test)
        # jsplitpane.add(jpanel_left,JSplitPane.LEFT)
        # jsplitpane.add(jpanel_right,JSplitPane.RIGHT)
        # jsplitpane.setDividerLocation(0.5)
        vBox_left.add(hbox_url)
        vBox_left.add(hbox_reqMeth)
        vBox_left.add(hbox_contentType)
        vBox_left.add(hbox_headers)
        vBox_left.add(hbox_data)
        vBox_left.add(hbox_radiobtn)
        vBox_left.add(hbox_token)
        vBox_left.add(hbox_test)


        # right panel
        layout = BoxLayout(jpanel_right, BoxLayout.Y_AXIS)
        jpanel_right.setLayout(layout )
        # radioButton
        hbox_radiobtn_r = Box.createHorizontalBox()
        # jpanel_radiobtn_r = JPanel(FlowLayout(FlowLayout.LEFT))
        jlabel_tokenPosition_r = JLabel("Token Position: ")
        self.radioBtn01_r = JRadioButton("Header")
        self.radioBtn02_r = JRadioButton("Body")
        # radioBtn01.setSelected(True)
        btnGroup_r = ButtonGroup()
        btnGroup_r.add(self.radioBtn01_r)
        btnGroup_r.add(self.radioBtn02_r)
        self.radioBtn01_r.setSelected(True)
        hbox_radiobtn_r.add(jlabel_tokenPosition_r)
        hbox_radiobtn_r.add(self.radioBtn01_r)
        hbox_radiobtn_r.add(self.radioBtn02_r)
        # 填充
        vGlue01 = Box.createGlue()
        hbox_radiobtn_r.add(vGlue01)
        
        # token
        hbox_token_r = Box.createHorizontalBox()
        vbox_token_header_r = Box.createVerticalBox()
        vbox_token_body_r = Box.createVerticalBox()

        jlabel_tokenName_r = JLabel("tokenName: ")
        self.jtext_tokenName_r = JTextField(25)
        vbox_token_header_r.add(jlabel_tokenName_r)
        vbox_token_header_r.add(self.jtext_tokenName_r)
        vbox_token_header_r.setBorder(BorderFactory.createLineBorder(Color.red, 3))

        jlabel_tokenRegex_r = JLabel("tokenRegex: ")
        self.jtext_tokenRegex_r = JTextField(25)
        vbox_token_body_r.add(jlabel_tokenRegex_r)
        vbox_token_body_r.add(self.jtext_tokenRegex_r)
        vbox_token_body_r.setBorder(BorderFactory.createLineBorder(Color.red, 3))

        hbox_token_r.add(vbox_token_header_r)
        hbox_token_r.add(vbox_token_body_r)

        # test
        hbox_test_r = Box.createHorizontalBox()
        jbtn_test_r = JButton("TEST",actionPerformed=self.btnTest_r)
        self.jlabel_test_r = JLabel("Result: ")

        hbox_test_r.add(jbtn_test_r)
        hbox_test_r.add(self.jlabel_test_r)
        hbox_test_r.setBorder(BorderFactory.createLineBorder(Color.red, 3))
        # 填充
        hGlue02 = Box.createHorizontalGlue()
        hbox_test_r.add(hGlue02)

        vGlue = Box.createVerticalGlue()
        # hbox_test_r = Box.createHorizontalBox()
        # vBox_right = Box.createVerticalBox()
        vBox_right.add(hbox_radiobtn_r)
        vBox_right.add(hbox_token_r)
        vBox_right.add(hbox_test_r)
        vBox_right.add(vGlue)
        # jpanel_right.add(vbox)

        hBox_main.add(vBox_left)
        hBox_main.add(vBox_right)
        # self.mainPanel = jsplitpane
        self.mainPanel = hBox_main
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
        