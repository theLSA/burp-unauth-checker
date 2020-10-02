#coding:utf-8
#Author:LSA
#Description:burpsuite extension for unauth checker
#Date:20200521




try:
    from burp import IBurpExtender, ITab
    from burp import IScannerCheck
    from burp import IExtensionStateListener
    from burp import IHttpRequestResponse
    from burp import IScanIssue
    from array import array
    from time import sleep
    import difflib
    import json
    #import ast

    from java.io import PrintWriter
    from java.net import URL
    from java.util import ArrayList, List
    from java.util.regex import Matcher, Pattern
    import binascii
    import base64
    import re
    import os
    from javax import swing
    from java.awt import Font, Color
    from threading import Thread
    from array import array
    from java.awt import EventQueue
    from java.lang import Runnable
    from thread import start_new_thread
    from javax.swing import JFileChooser
    from javax.swing import JPanel, JLabel, JButton, JTextArea, JTextField, JCheckBox, JTabbedPane, JScrollPane, SwingConstants, JOptionPane
    from java.awt import BorderLayout

except ImportError:
    print "Failed to load dependencies. Maybe by using an unstable Jython version."


authParamCfgFile = "authParams.cfg"

filterSuffixList = "jpg,jpeg,png,gif,ico,bmp,svg,js,css,html,avi,mp4,mkv,mp3,txt"


class Run(Runnable):
    def __init__(self, runner):
        self.runner = runner

    def run(self):
        self.runner()

class BurpExtender(IBurpExtender, ITab, IScannerCheck, IExtensionStateListener, IHttpRequestResponse):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName("burp-unauth-checker")

        #callbacks.issueAlert("burp-unauth-checker Passive Scanner enabled")

        stdout = PrintWriter(callbacks.getStdout(), True)
        stderr = PrintWriter(callbacks.getStderr(), True)
        self._callbacks.registerScannerCheck(self)
        self._callbacks.registerExtensionStateListener(self)


        self.authParamsList = self.getAuthParamConfig()

        self.initUI()
        self._callbacks.addSuiteTab(self)
        
        print ("burp-unauth-checker loaded.")
        print ("Author:LSA")
        print ("https://github.com/theLSA/burp-unauth-checker")

        self.outputTxtArea.setText("")
        
        self.excludeAuthParamsList = self.getExcludeAuthParams()

        print 'authParamsList: ' + str(self.authParamsList) + '\n'

        if self.excludeAuthParamsList != None:
            self.authParamsList = list(set(self.authParamsList).difference(set(self.excludeAuthParamsList)))

            print 'excludeAuthParamsList: ' + str(self.excludeAuthParamsList) + '\n'
            print "finalAuthParamsList: " + ",".join(self.authParamsList) + "\n"

    
    def extensionUnloaded(self):
        print "burp-unauth-checker Unloaded."
        return    

    def doPassiveScan(self, baseRequestResponse):

        islaunchBurpUnauthChecker = int(self.launchBurpUnauthCheckerCheckBox.isSelected())

        if (not islaunchBurpUnauthChecker) or (self.isFilterSuffix(baseRequestResponse)) or (self.isFilterStatusCode(baseRequestResponse)):
            return


        scan_issues = []

        newRequestResponse = self.sendUnauthenticatedRequest(baseRequestResponse)

        #print str(self._helpers.analyzeRequest(baseRequestResponse).getUrl()) + '\n'

        issue = self.compareResponses(newRequestResponse, baseRequestResponse)


        scan_issues.append(issue)
        return scan_issues


    def consolidateDuplicateIssues(self, isb, isa):
        return -1




    def sendUnauthenticatedRequest(self, requestResponse):

        newRequest = self.stripAuthenticationCharacteristics(requestResponse)
        return self._callbacks.makeHttpRequest(requestResponse.getHttpService(), newRequest)

    def stripAuthenticationCharacteristics(self, requestResponse):

        
        self.excludeAuthParamsList = self.getExcludeAuthParams()

        print 'authParamsList: ' + str(self.authParamsList) + '\n'

        if self.excludeAuthParamsList != None:
            self.authParamsList = list(set(self.authParamsList).difference(set(self.excludeAuthParamsList)))

            #print 'authParamsList: ' + str(self.authParamsList) + '\n'
            print 'excludeAuthParamsList: ' + str(self.excludeAuthParamsList) + '\n'
            print "finalAuthParamsList: " + ",".join(self.authParamsList) + "\n"
            
        reqHeaders = self._helpers.analyzeRequest(requestResponse).getHeaders()
        reqBodyOffset = self._helpers.analyzeRequest(requestResponse).getBodyOffset()

        reqBodyByte = requestResponse.getRequest().tostring()[reqBodyOffset:]



        newHeaders = [] 

        newAuthHeaderVal = self.replaceHeaderValWithTextField.getText()


        for header in reqHeaders:
            headerName = header.split(':')[0]
        #    if headerName.lower() not in self.authParamsList:
        #        newHeaders.append(header)
        #return self._helpers.buildHttpMessage(newHeaders, None)
            if headerName.lower() in self.authParamsList:
                header = headerName + ": " + newAuthHeaderVal
                newHeaders.append(header)
            else:
                newHeaders.append(header)


        #newRemoveAuthHeaderRequest = self._helpers.buildHttpMessage(newHeaders, None)

        newRemoveAuthHeaderRequest = self._helpers.buildHttpMessage(newHeaders, reqBodyByte)

        if self.removeGetPostAuthParamsCheckBox.isSelected():
            newRemoveGetPostAuthParamsRequest = self.removeGetPostAuthParams(requestResponse,newRemoveAuthHeaderRequest,self.authParamsList)
            
            if newRemoveGetPostAuthParamsRequest:
                #print newRemoveGetPostAuthParamsRequest    
                return newRemoveGetPostAuthParamsRequest
            else:
                return self._helpers.buildHttpMessage(newHeaders, reqBodyByte)


        else:
            return self._helpers.buildHttpMessage(newHeaders, reqBodyByte)



    def compareResponses(self, newRequestResponse, oldRequestResponse):
        """Compare new rsp and old rsp body contents"""
        result = None
        nResponse = newRequestResponse.getResponse()
        if nResponse is None:
            return result
        nResponseInfo = self._helpers.analyzeResponse(nResponse)
        # Only considering non-cached HTTP responses
        if nResponseInfo.getStatusCode() == 304:
            return result
        nBodyOffset = nResponseInfo.getBodyOffset()
        nBody = nResponse.tostring()[nBodyOffset:]
        oResponse = oldRequestResponse.getResponse()
        oResponseInfo = self._helpers.analyzeResponse(oResponse)
        oBodyOffset = oResponseInfo.getBodyOffset()
        oBody = oResponse.tostring()[oBodyOffset:]

        #print 'oBody:' + str(oBody) + '\n'

        #print 'nBody:' + str(nBody) + '\n'

        #self.outputTxtArea.append("[url]%s\n" % self._helpers.analyzeRequest(oldRequestResponse).getUrl())

        isShowRspContent = int(self.showRspContentCheckBox.isSelected())
        isShowPostBody = int(self.showPostBodyCheckBox.isSelected())

        if (str(nBody).split() == str(oBody).split()):
            
            self.outputTxtArea.append("[%s][URL]%s\n" % (self._helpers.analyzeRequest(oldRequestResponse).getMethod(),self._helpers.analyzeRequest(oldRequestResponse).getUrl()))
            
            if isShowPostBody:
                oldReqBodyOffset = self._helpers.analyzeRequest(oldRequestResponse).getBodyOffset()
                oldReqBodyString = oldRequestResponse.getRequest().tostring()[oldReqBodyOffset:]
                self.outputTxtArea.append("%s\n" % oldReqBodyString)

            if isShowRspContent:
                self.outputTxtArea.append("[rspContent]%s\n" % str(nBody))

            self.outputTxtArea.append("\n------------------------------------------------------------------------\n")

            issuename = "unauth-endpoint"
            issuelevel = "Medium"
            issuedetail = "Unauthorization endpoint."
            issuebackground = "The endpoint is unauthorizated."
            issueremediation = "Senstive endpoint must have authorization."
            issueconfidence = "Firm"
            result = ScanIssue(oldRequestResponse.getHttpService(),self._helpers.analyzeRequest(oldRequestResponse).getUrl(),issuename, issuelevel, issuedetail, issuebackground, issueremediation, issueconfidence, [oldRequestResponse,newRequestResponse])
            print result
            return result
        else:
            print "body difference!\n"



    def initUI(self):
        self.tab = swing.JPanel()

        # UI for Output
        self.outputLabel = swing.JLabel("unauth api result:")
        self.outputLabel.setFont(Font("Tahoma", Font.BOLD, 14))
        self.outputLabel.setForeground(Color(255,102,52))
        self.logPane = swing.JScrollPane()
        self.outputTxtArea = swing.JTextArea()
        self.outputTxtArea.setFont(Font("Consolas", Font.PLAIN, 12))
        self.outputTxtArea.setLineWrap(True)
        self.logPane.setViewportView(self.outputTxtArea)
        self.clearBtn = swing.JButton("Clear", actionPerformed=self.clearRst)
        self.exportBtn = swing.JButton("Export", actionPerformed=self.exportRst)
        self.parentFrm = swing.JFileChooser()

        self.showRspContentCheckBox = JCheckBox("show rspContent")
        self.showPostBodyCheckBox = JCheckBox("show post body")

        self.launchBurpUnauthCheckerCheckBox = JCheckBox("launchBurpUnauthChecker")

        #self.includeAuthParamsLabel = swing.JLabel("includeAuthParams:")
        self.excludeAuthParamsLabel = swing.JLabel("excludeAuthParams:")

        self.filterSuffixLabel = swing.JLabel("filterSuffix:")





        self.removeAuthParamListText = self.authParamsList

        #print self.removeAuthParamListText

        self.removeAuthParamListTextField = JTextField(",".join(self.removeAuthParamListText))

        self.excludeAuthParamsTextField = JTextField()

        self.filterSuffixTextField = JTextField(filterSuffixList)

        self.onlyIncludeStatusCodeTextField = JTextField("200")

        self.onlyIncludeStatusCodeLabel = JLabel("onlyIncludeStatusCode:")

        self.saveAuthParamsListButton = swing.JButton("save", actionPerformed=self.addAndSaveAuthParam)

        self.alertSaveSuccess = JOptionPane()

        self.removeGetPostAuthParamsCheckBox = JCheckBox("replace GET/POST Auth Params with ")

        self.replaceGetPostAuthParamsWithTextField = JTextField("unauthp")

        self.replaceHeaderValWithLabel = JLabel("replace header value with ")

        self.replaceHeaderValWithTextField = JTextField("unauthh")

        self.tab.setLayout(None)




        self.tab.add(self.launchBurpUnauthCheckerCheckBox)
        self.tab.add(self.showRspContentCheckBox)
        self.tab.add(self.showPostBodyCheckBox)
        self.tab.add(self.outputLabel)
        self.tab.add(self.logPane)

        self.tab.add(self.clearBtn)
        self.tab.add(self.exportBtn)

        self.tab.add(self.removeAuthParamListTextField)

        #self.tab.add(self.includeAuthParamsLabel)
        self.tab.add(self.excludeAuthParamsLabel)
        self.tab.add(self.filterSuffixLabel)
        self.tab.add(self.excludeAuthParamsTextField)
        self.tab.add(self.filterSuffixTextField)

        self.tab.add(self.onlyIncludeStatusCodeTextField)
        self.tab.add(self.onlyIncludeStatusCodeLabel)

        self.tab.add(self.saveAuthParamsListButton)

        self.tab.add(self.alertSaveSuccess)

        self.tab.add(self.removeGetPostAuthParamsCheckBox)

        self.tab.add(self.replaceGetPostAuthParamsWithTextField)

        self.tab.add(self.replaceHeaderValWithTextField)

        self.tab.add(self.replaceHeaderValWithLabel)

        self.launchBurpUnauthCheckerCheckBox.setBounds(20,10,200,20)
        self.showRspContentCheckBox.setBounds(20,40,150,30)
        self.showPostBodyCheckBox.setBounds(20,75,150,30)
        self.outputLabel.setBounds(400,200,150,50)
        self.logPane.setBounds(20,250,900,400)
        
        self.clearBtn.setBounds(20,650,100,30)
        self.exportBtn.setBounds(820,650,100,30)

        self.removeAuthParamListTextField.setBounds(20,140,400,30)

        #self.includeAuthParamsLabel.setBounds(20,100,100,20)
        self.excludeAuthParamsLabel.setBounds(580,100,150,20)
        self.excludeAuthParamsTextField.setBounds(580,120,400,30)
        self.filterSuffixLabel.setBounds(200,40,100,20)
        self.filterSuffixTextField.setBounds(200,60,500,30)

        self.onlyIncludeStatusCodeTextField.setBounds(750,170,120,30)
        self.onlyIncludeStatusCodeLabel.setBounds(600,170,190,20)

        self.saveAuthParamsListButton.setBounds(20,180,80,30)

        self.removeGetPostAuthParamsCheckBox.setBounds(120,170,280,20)

        self.replaceGetPostAuthParamsWithTextField.setBounds(380,170,70,30)

        self.replaceHeaderValWithLabel.setBounds(20,100,180,20)

        self.replaceHeaderValWithTextField.setBounds(190,100,70,30)




    def getTabCaption(self):
        return "burp-unauth-checker"

    def getUiComponent(self):
        return self.tab

    def clearRst(self, event):
          self.outputTxtArea.setText("")

    def exportRst(self, event):
        chooseFile = JFileChooser()
        ret = chooseFile.showDialog(self.logPane, "Choose file")
        filename = chooseFile.getSelectedFile().getCanonicalPath()
        print "\n" + "Export to : " + filename
        open(filename, 'w', 0).write(self.outputTxtArea.text)


    def getAuthParamConfig(self):
        authFieldList = []
        with open(authParamCfgFile,"r") as fauth:
            
            #authFieldList = fauth.readlines()

            for authParamLine in fauth.readlines():
                authFieldList.append(authParamLine.strip())

        #print authFieldList

        return authFieldList


    def getFilterSuffixList(self):
           filterSuffixList = []

           filterSuffixList = self.filterSuffixTextField.getText().split(",")

           print filterSuffixList

           return filterSuffixList

    def getExcludeAuthParams(self):
           excludeAuthParamsList = []
           excludeAuthParamsList = self.excludeAuthParamsTextField.getText().split(",")
           #print excludeAuthParamsList
           return excludeAuthParamsList


    def checkStatusCode(self):
        filterStatusCodeList = []
        filterStatusCodeList = self.onlyIncludeStatusCodeTextField.getText().split(",")
        print "Only check thoes status code: " + ",".join(filterStatusCodeList)
        return filterStatusCodeList


    def isFilterSuffix(self,requestResponse):
        reqUrl = str(self._helpers.analyzeRequest(requestResponse).getUrl())

        print reqUrl + '\n'

        try:
            reqUrlSuffix = os.path.basename(reqUrl).split(".")[-1].split("?")[0].lower()



        except:
            reqUrlSuffix = "causeExceptionSuffix"

        if reqUrlSuffix == "":
            reqUrlSuffix = "spaceSuffix"

        print reqUrlSuffix

        
        if (reqUrlSuffix in self.getFilterSuffixList()) and (reqUrlSuffix!="causeExceptionSuffix") and (reqUrlSuffix!="spaceSuffix"):

            print 'filterSuffix: ' + reqUrlSuffix

            print 'filterUrl: ' + reqUrl

            return True


    def isFilterStatusCode(self,requestResponse):
        baseResponse = requestResponse.getResponse()
        baseResponseInfo = self._helpers.analyzeResponse(baseResponse)



        if str(baseResponseInfo.getStatusCode()) not in self.checkStatusCode():

            print baseResponseInfo.getStatusCode()
            return True


    def addAndSaveAuthParam(self, event):
        oldAuthParamsList = []
        oldAuthParamsList = self.authParamsList

        newAuthParamsList = []
        newAuthParamsList = self.removeAuthParamListTextField.getText().split(",")

        addAuthParamsList = list(set(newAuthParamsList).difference(set(oldAuthParamsList)))
        print addAuthParamsList

        with open(authParamCfgFile,'a') as f1:
            for newAuthParam in addAuthParamsList:
                f1.write('\n'+newAuthParam)

        self.authParamsList = self.getAuthParamConfig()

        self.alertSaveSuccess.showMessageDialog(self.tab, "save success!");  



    def removeGetPostAuthParams(self,requestResponse,newRemoveAuthHeaderRequest,authParamsListNew):
        paramList = self._helpers.analyzeRequest(requestResponse).getParameters()
        authParamsList = authParamsListNew

        newAuthParamValue = self.replaceGetPostAuthParamsWithTextField.getText()

        #print paramList

        #return paramList

        newRemoveGetPostAuthParamsRequest = newRemoveAuthHeaderRequest

        haveRemoveGetPostAuthParams = False

        #isJsonReq = False


        for para in paramList:
            paramType= para.getType()

            if (paramType == 0) or (paramType == 1):
                paramKey = para.getName()
                paramValue = para.getValue()

                print paramKey + ":" + paramValue

        
                if paramKey.lower() in authParamsList:
                    newAuthParam = self._helpers.buildParameter(paramKey, newAuthParamValue, paramType)
                    newRemoveGetPostAuthParamsRequest = self._helpers.updateParameter(newRemoveGetPostAuthParamsRequest, newAuthParam)
                    haveRemoveGetPostAuthParams = True
            
            if paramType == 6:

                paramKey = para.getName()
                paramValue = para.getValue()

                print paramKey + ":" + paramValue

                reqJsonBodyOffset = self._helpers.analyzeRequest(requestResponse).getBodyOffset()
                reqJsonBodyString = requestResponse.getRequest().tostring()[reqJsonBodyOffset:]

                print reqJsonBodyString

                reqJsonBodyStringDict = json.loads(reqJsonBodyString)

                #reqJsonBodyStringDict = ast.literal_eval(reqJsonBodyString)

                for authParamName in authParamsList:
                    if authParamName in reqJsonBodyStringDict.keys():
                        reqJsonBodyStringDict[authParamName] = newAuthParamValue

                '''        

                ks = reqJsonBodyStringDict.keys()
                for k in ks:
                    val = reqJsonBodyStringDict.pop(k)
                    if isinstance(val, unicode):
                        val = val.encode('utf8')
                    #elif isinstance(val, dict):
                    #    val = encode_dict(val, codec)
                    if isinstance(k, unicode):
                        k = k.encode('utf8')
                    reqJsonBodyStringDict[k] = val

                #for key in reqJsonBodyStringDict:
                #    key = key.encode('utf8')
                #    reqJsonBodyStringDict[key] = reqJsonBodyStringDict[key].encode('utf8')
                
                '''

                newReqJsonBodyString = json.dumps(reqJsonBodyStringDict,separators=(',', ':'))

                jsonReqHeaders = self._helpers.analyzeRequest(newRemoveAuthHeaderRequest).getHeaders()

                haveRemoveGetPostAuthParams = True

                #isJsonReq = True

                #newRemoveGetPostAuthParamsRequest = self._helpers.buildHttpMessage(jsonReqHeaders, str(reqJsonBodyStringDict).replace("': ","':").replace(", '", ",'").replace(", {", ",{"))
                newRemoveGetPostAuthParamsRequest = self._helpers.buildHttpMessage(jsonReqHeaders, newReqJsonBodyString)


        if haveRemoveGetPostAuthParams:
        #requestResponse.setRequest(new_Request)

            return newRemoveGetPostAuthParamsRequest
        else:
            print 'do not haveRemoveGetPostAuthParams\n'
            return False






class ScanIssue(IScanIssue):

    def __init__(self, httpservice, url, name, severity, detailmsg, background, remediation, confidence, requests):
        self._url = url
        self._httpservice = httpservice
        self._name = name
        self._severity = severity
        self._detailmsg = detailmsg
        self._issuebackground = background
        self._issueremediation = remediation
        self._confidence = confidence
        self._httpmsgs = requests


    def getUrl(self):
        #print self._url
        return self._url


    def getHttpMessages(self):
        return self._httpmsgs

    def getHttpService(self):
        return self._httpservice

    def getRemediationDetail(self):
        return None

    def getIssueDetail(self):
        return self._detailmsg

    def getIssueBackground(self):
        return self._issuebackground

    def getRemediationBackground(self):
        return self._issueremediation

    def getIssueType(self):
        return 0

    def getIssueName(self):
        return self._name

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return self._confidence



if __name__ in ('__main__', 'main'):
    EventQueue.invokeLater(Run(BurpExtender))