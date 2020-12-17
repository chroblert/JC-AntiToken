from burp import IBurpExtender
from burp import IHttpListener

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks

        callbacks.setExtensionName("test")
        callbacks.registerHttpListener(self)

    def processHttpMessage(self, toolflag, messageIsRequest, messageInfo):
        service = messageInfo.getHttpService()
        print("Host: " + str(service.getHost()))
        print("Port: "+ str(service.getPort()))
        print("Protocol: " + str(service.getProtocol()))
        print("-----------------------------------")