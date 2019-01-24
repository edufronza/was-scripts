import getopt, os, shutil, re, sys, time
from java.lang import System
from xml.dom import minidom, Node

global AdminApp
global AdminConfig
global AdminControl
global AdminTask

class ConfigReport:
    def __init__(self):
        self.cellName = ''
        self.cellId = ''
        self.nodesList = ''
        self.clustersList = ''
        self.coreGroupsList = ''
        self.terminal = sys.stdout
        self.log = ''
        self.doc = minidom.Document()
    
    def loadArguments(self):
        if (len(sys.argv) > 0):
            try:
                args = sys.argv[:]  # Copy so don't destroy original
                while len(args) > 0:
                    current_arg = args[0]
                    if current_arg == '--cell' or current_arg == '-cell':
                        self.cellName = args[1]
                        break
                    args = args[1:]
            except:
                print "+---------------------------------------------------------------------+"
                print "+ Error: Parameter not found, please check the example below:"
                print "+ Example: ConfigReport.py --cell was_dry_ibm_cell3"
                print "+---------------------------------------------------------------------+"
                return 0                
        else:
            print "+---------------------------------------------------------------------+"
            print "+ Error: Parameter not found, please check the example below:"
            print "+ Example: ConfigReport.py --cell was_dry_ibm_cell3"
            print "+---------------------------------------------------------------------+"
            return 0            
        return 1

    def writeMsg(self, message):
        self.terminal.write(message+"\n")
        #self.log.write(message+"\n")
                
    def convertToList(self, inlist):
        outlist = []
        if( len(inlist) > 0):
            if( inlist[0] == '[' and inlist[len(inlist) - 1] == ']'):
                if( inlist[1] == "\"" and inlist[len(inlist)-2] == "\""):
                    clist = inlist[1:len(inlist) -1].split(")\" ")
                else:
                    clist = inlist[1:len(inlist) - 1].split(" ")
            else:
                clist = inlist.split(System.getProperty("line.separator"))
            
            for elem in clist:
                elem = elem.rstrip();
                if( len(elem) > 0):
                    if( elem[0] == "\"" and elem[len(elem) -1] != "\""):
                        elem = elem+")\""
                    outlist.append(elem)
        return outlist

    def getCell(self):
        self.cellName = AdminControl.getCell()
    
    def getCellId(self):
        self.cellId = AdminConfig.getid( '/Cell:'+self.cellName+'/')

    def getCellManagerNode(self, nodeId):
        sList = AdminConfig.list("Server", nodeId )
        sList = self.convertToList(sList)
        for server in sList:
            if (AdminConfig.showAttribute(server, "name") == 'dmgr'):
                return 1
        return 0
        
    def getNodes(self):
        nList = AdminTask.listNodes()
        self.nodesList = self.convertToList(nList) 

    def getNodeId(self, nodeName):
        return AdminConfig.getid("/Node:"+nodeName+"/")

    def getHostName(self, nodeName):
        nodeID = self.getNodeId(nodeName)
        if( len(nodeID) > 0):
            return AdminConfig.showAttribute(nodeID,'hostName')
        return ""

    def getVersion(self, nodeName, serverName):
        auxServerObj = AdminControl.completeObjectName('cell='+self.cellName+',node='+nodeName+',name='+serverName+',type=Server,*')
        if ( auxServerObj != "" ):
            version = AdminControl.getAttribute(auxServerObj, 'platformVersion')
        else:
            version = ""
        return version    

    def getCoreGroups(self):
        cgList = AdminConfig.list('CoreGroup', self.cellId)
        self.coreGroupsList = self.convertToList(cgList)

    def getCoreGroupName(self, coreGroup):
        return AdminConfig.showAttribute(coreGroup, "name")
            
    def getCoreGroupId(self, coreGroup):
        cgName = self.getCoreGroupName(coreGroup)
        return AdminConfig.getid('/Cell:'+self.cellName+'/CoreGroup:'+cgName+'/')
    
    def getCoreGroupMembers(self, coreGroup):
        cgId = self.getCoreGroupId(coreGroup)
        cgMembersList = AdminConfig.list('CoreGroupServer', cgId) 
        cgMembersList = self.convertToList(cgMembersList)
        return cgMembersList
    
    def getCoreGroupCoordinators(self, coreGroup):
        cgCoordinators = AdminConfig.showAttribute(coreGroup, 'preferredCoordinatorServers')
        cgCoordinators = self.convertToList(cgCoordinators)
        return cgCoordinators
    
    def getClusters(self):
        cList = AdminConfig.list('ServerCluster', self.cellId)
        self.clustersList = self.convertToList(cList)
          
    def getClusterName(self, cluster):
        return AdminConfig.showAttribute(cluster, "name")
    
    def getClusterId(self,clusterName):
        return AdminConfig.getid( '/Cell:'+self.cellName+'/ServerCluster:'+clusterName+'/')
    
    def getClusterMembers(self, clusterName):
        clusterId = self.getClusterId(clusterName)
        membersList = AdminConfig.list('ClusterMember', clusterId)
        membersList = self.convertToList(membersList)
        return membersList
    
    def getAppServerName(self, appServer):
        return AdminConfig.showAttribute(appServer,"memberName")
    
    def getAppServerNodeName(self, appServer):
        return AdminConfig.showAttribute(appServer,"nodeName")
    
    def getServerId(self, nodeName, serverName):
        return AdminConfig.getid( '/Cell:'+self.cellName+'/Node:'+nodeName+'/Server:'+serverName+'/')
    
    def getAppServerId(self, serverId):
       return AdminConfig.list('ApplicationServer',serverId)
       
    def getProcessDef(self, appServerId):
        return AdminConfig.list('ProcessDef', appServerId)

    def getJavaVirtualMachineId (self, auxServerId):
        auxJvmId = AdminConfig.list("JavaVirtualMachine", auxServerId)
        return auxJvmId

    def getJavaVirtualMachineProperties(self, auxJvmId):
        jvmItems = AdminConfig.show(auxJvmId)
        jvmItems = jvmItems.splitlines()
        if( len(jvmItems)>0):
            jvmDict = {}
            for item in jvmItems:
                item = item[1:len(item) - 1]
                spacePos = item.find(' ')
                jvmDict[item[0:spacePos]] = item[spacePos + 1:]
        return jvmDict

    def getServerPID(self, nodeName, serverName = '' ):
        if (len(serverName) == 0):
            serverMBean = AdminControl.queryNames("node="+nodeName+",type=NodeAgent,*")
        else:
            serverMBean = AdminControl.queryNames("node="+nodeName+",process="+serverName+",type=Server,*")
        if (len(serverMBean) == 0):
            return ""
        else:
            return AdminControl.getAttribute(serverMBean, "pid")

    def getServerState(self, nodeName, serverName = '' ):
        if (len(serverName) == 0):
            serverMBean = AdminControl.queryNames("node="+nodeName+",type=NodeAgent,*")
        else:
            serverMBean = AdminControl.queryNames("node="+nodeName+",process="+serverName+",type=Server,*")
        if (len(serverMBean) == 0):
            return ""
        else:
            return AdminControl.getAttribute(serverMBean, "state")

    def getServerEntryForServerName(self, serverName ):
        serverIndexList = AdminConfig.list("ServerIndex")
        serverIndexList = self.convertToList(serverIndexList)
        for serverIndex in serverIndexList:
            serverEntryList = AdminConfig.showAttribute(serverIndex,"serverEntries")
            serverEntryList = self.convertToList(serverEntryList)
            for serverEntry in serverEntryList:
                if( string.find(serverEntry,serverName) != -1 ):
                    return serverEntry

    def getSecurity(self, xmlCell):
        security = AdminConfig.list('Security')
        activeAuthMechanism = AdminConfig.showAttribute(security, 'activeAuthMechanism')
        authConfig = AdminConfig.showAttribute(activeAuthMechanism, 'authConfig')
        activeUserRegistry = AdminConfig.showAttribute(security, 'activeUserRegistry')
        appSecurity = AdminConfig.showAttribute(security, 'appEnabled')
        globalSecurity = AdminConfig.showAttribute(security, 'enabled')
        java2Security = AdminConfig.showAttribute(security, 'enforceJava2Security')
        xmlGlobalSecurity = self.doc.createElement('Security')
        xmlGlobalSecurity.setAttribute('activeAuthMechanism', authConfig)
        xmlGlobalSecurity.setAttribute('activeUserRegistry', activeUserRegistry)
        xmlGlobalSecurity.setAttribute('appEnabled', appSecurity)
        xmlGlobalSecurity.setAttribute('enabled', globalSecurity)
        xmlGlobalSecurity.setAttribute('enforceJava2Security', java2Security)
        xmlCell.appendChild(xmlGlobalSecurity)
        if (activeUserRegistry.find('LDAPUserRegistry') != -1):
            ldapBaseDN = AdminConfig.showAttribute(activeUserRegistry, 'baseDN')
            bindDN = AdminConfig.showAttribute(activeUserRegistry, 'bindDN')
            endpointStr = AdminConfig.showAttribute(activeUserRegistry, "hosts")
            endpointStr = endpointStr[1:len(endpointStr)-1];
            endpoint = endpointStr.split(' ')[0];
            host = AdminConfig.showAttribute(endpoint, 'host')
            port = AdminConfig.showAttribute(endpoint, 'port')
            primaryAdminId = AdminConfig.showAttribute(activeUserRegistry, 'primaryAdminId')
            realm = AdminConfig.showAttribute(activeUserRegistry, 'realm')
            sslEnabled = AdminConfig.showAttribute(activeUserRegistry, 'sslEnabled')
            type = AdminConfig.showAttribute(activeUserRegistry, 'type')
            xmlLdapSec = self.doc.createElement('LDAPUserRegistry')
            xmlLdapSec.setAttribute('realm', realm)
            xmlLdapSec.setAttribute('type', type)
            xmlLdapSec.setAttribute('host', host)
            xmlLdapSec.setAttribute('port', port)
            xmlLdapSec.setAttribute('sslEnabled', sslEnabled)
            xmlLdapSec.setAttribute('primaryAdminId', primaryAdminId)
            xmlLdapSec.setAttribute('bindDN', bindDN)
            xmlLdapSec.setAttribute('ldapBaseDN', ldapBaseDN)
            xmlGlobalSecurity.appendChild(xmlLdapSec)
        elif (activeUserRegistry.find('WIMUserRegistry') != -1):
            primaryAdminId = AdminConfig.showAttribute(activeUserRegistry, 'primaryAdminId')
            realm = AdminConfig.showAttribute(activeUserRegistry, 'realm')
            repoStr = AdminTask.listIdMgrRepositories()
            repoStr = repoStr[1:len(repoStr)-1].replace('}, ','}\n')
            repoList = self.convertToList(repoStr)
            if (len(repoList) > 0):
                for entry in repoList:
                    if (entry.find('repositoryType=LDAP') != -1):
                        ldapId = entry.split('=')[0]
                        baseDN = AdminTask.listIdMgrRepositoryBaseEntries('[-id '+ldapId+']')
                        baseDN = baseDN[1:len(baseDN)-1]
                        ldapHost = AdminTask.listIdMgrLDAPServers('[-id '+ldapId+']')
                        ldapInfo = AdminTask.getIdMgrLDAPServer('[-id '+ldapId+' -host '+ldapHost+']')
                        ldapInfo = ldapInfo[1:len(ldapInfo)-1].replace(', ','\n')
                        ldapInfoList = self.convertToList(ldapInfo)
                        if (len(ldapInfoList) > 0):
                            for info in ldapInfoList:
                                if (info.find('host=') != -1):
                                    host = info.split('=')[1]
                                if (info.find('port=') != -1):
                                    port = info.split('=')[1]
                                if (info.find('ldapServerType=') != -1):
                                    ldapServerType = info.split('=')[1]
                                if (info.find('sslEnabled=') != -1):
                                    sslEnabled = info.split('=')[1]
                                if (info.find('bindDN=') != -1):
                                    bindDN = info.split('=')[1]
                            xmlLdapSec = self.doc.createElement('WIMUserRegistry')
                            xmlLdapSec.setAttribute('realm', realm)
                            xmlLdapSec.setAttribute('type', ldapServerType)
                            xmlLdapSec.setAttribute('host', host)
                            xmlLdapSec.setAttribute('port', port)
                            xmlLdapSec.setAttribute('sslEnabled', sslEnabled)
                            xmlLdapSec.setAttribute('primaryAdminId', primaryAdminId)
                            xmlLdapSec.setAttribute('bindDN', bindDN)
                            xmlLdapSec.setAttribute('ldapBaseDN', baseDN)
                            xmlGlobalSecurity.appendChild(xmlLdapSec)
                            ldapBkpServersList = AdminTask.listIdMgrLDAPBackupServers('[-id '+ldapId+' -primary_host '+host+']')
                            ldapBkpServersList = self.convertToList(ldapBkpServersList)
                            if (len(ldapBkpServersList) > 0):
                                xmlBkpServersList = self.doc.createElement('LDAPBackupServer')
                                xmlLdapSec.appendChild(xmlBkpServersList)
                                for bkpInfo in ldapBkpServersList:
                                    bkpHost = bkpInfo.split('=')[0]
                                    bkpPort = bkpInfo.split('=')[1]
                                    xmlBkpServer = self.doc.createElement('server')
                                    xmlBkpServer.setAttribute('host', bkpHost)
                                    xmlBkpServer.setAttribute('port', bkpPort)
                                    xmlBkpServersList.appendChild(xmlBkpServer)
                            registryGroupsList = AdminTask.listRegistryGroups()
                            registryGroupsList = self.convertToList(registryGroupsList)
                            if (len(registryGroupsList) > 0):
                                xmlRegistryGroupsList = self.doc.createElement('RegistryGroups')
                                xmlLdapSec.appendChild(xmlRegistryGroupsList)
                                for group in registryGroupsList:
                                    xmlRegistryGroup = self.doc.createElement('group')
                                    xmlRegistryGroup.setAttribute('name', group)
                                    xmlRegistryGroupsList.appendChild(xmlRegistryGroup)
                            registryUsersList = AdminTask.listRegistryUsers()
                            registryUsersList = self.convertToList(registryUsersList)
                            if (len(registryUsersList) > 0):
                                xmlRegistryUsersList = self.doc.createElement('RegistryUsers')
                                xmlLdapSec.appendChild(xmlRegistryUsersList)
                                for user in registryUsersList:
                                    xmlRegistryUser = self.doc.createElement('user')
                                    xmlRegistryUser.setAttribute('name', user)
                                    xmlRegistryUsersList.appendChild(xmlRegistryUser)
        
    def getSslConfig(self, xmlCell='', xmlNode='', scope='', nodeName=''):
        sslConfigsList = AdminTask.listSSLConfigs('[-all true -displayObjectName true ]').split()
        if (len(sslConfigsList) > 0):
            xmlSslConfigsList = self.doc.createElement('SSLConfigsList')
            for sslConfig in sslConfigsList:
                managementScope = AdminConfig.showAttribute(sslConfig, 'managementScope')
                scopeName = AdminConfig.showAttribute(managementScope, 'scopeName')
                if (scope == 'node'):
                    if (scopeName.find('(cell):'+self.cellName+':(node):'+nodeName) == -1):
                        continue
                    xmlNode.appendChild(xmlSslConfigsList)
                elif (scope == 'cell'):
                    if (scopeName.find('(cell):'+self.cellName+':(node):') != -1):
                        continue
                    xmlCell.appendChild(xmlSslConfigsList)
                alias = AdminConfig.showAttribute(sslConfig, 'alias')
                sslSettings = AdminConfig.showAttribute(sslConfig, 'setting')
                sslSettingsList = AdminConfig.show(sslSettings).splitlines()
                if (len(sslSettingsList) > 0):
                    xmlSslConfig = self.doc.createElement('sslConfig')
                    xmlSslConfig.setAttribute('alias', alias)
                    for setting in sslSettingsList:
                        if (setting.find('securityLevel') != -1):
                            securityLevel = setting.split(' ')[1].replace(']','')
                            xmlSslConfig.setAttribute('securityLevel', securityLevel)
                        if (setting.find('sslProtocol') != -1):
                            sslProtocol = setting.split(' ')[1].replace(']','')
                            xmlSslConfig.setAttribute('sslProtocol', sslProtocol)
                        if (setting.find('serverKeyAlias') != -1):
                            serverKeyAlias = setting.split(' ')[1].replace(']','')
                        else:
                             serverKeyAlias = 'default'
                        xmlSslConfig.setAttribute('serverKeyAlias', serverKeyAlias)
                        if (setting.find('enabledCiphers') != -1):
                            enabledCiphers = setting.split(' ')[1]
                            xmlSslConfig.setAttribute('enabledCiphers', str(enabledCiphers))
                        if (setting.find('keyStore') != -1):
                            keyStoreId = setting.split(' ')[1].replace(']','')
                            keyStoreName = AdminConfig.showAttribute(keyStoreId, 'name')
                            xmlSslConfig.setAttribute('keyStoreName', keyStoreName)
                        if (setting.find('trustStore') != -1):
                            trustStoreId = setting.split(' ')[1].replace(']','')
                            trustStoreName = AdminConfig.showAttribute(trustStoreId, 'name')
                            xmlSslConfig.setAttribute('trustStoreName', trustStoreName)
                    xmlSslConfigsList.appendChild(xmlSslConfig)
                if (len(keyStoreName) > 0) and (len(scopeName) > 0) and (len(alias) > 0):
                    personalCertsList = AdminTask.listPersonalCertificates('[-keyStoreName '+keyStoreName+' -keyStoreScope '+scopeName+' ]').splitlines()
                    if (len(personalCertsList) > 0):
                        for cert in personalCertsList:
                            if (cert.find('[alias '+serverKeyAlias+']') == -1):
                                continue
                            xmlPersonalCert = self.doc.createElement('PersonalCertificate')
                            cert = cert.replace('] [',']\n[')
                            certList = cert.splitlines()
                            for personalCert in certList:
                                if (personalCert.find('alias') != -1):
                                    certAlias = personalCert.split(' ')[1].split(']')[0]
                                    xmlPersonalCert.setAttribute('certAlias', certAlias)
                                if (personalCert.find('version') != -1):
                                    version = personalCert.split(' ')[1].split(']')[0]
                                    xmlPersonalCert.setAttribute('version', version)
                                if (personalCert.find('size') != -1):
                                    size = personalCert.split(' ')[1].split(']')[0]
                                    xmlPersonalCert.setAttribute('size', size)
                                if (personalCert.find('signatureAlgorithm') != -1):
                                    signatureAlgorithm = personalCert.split(' ')[1].split('(')[0]
                                    xmlPersonalCert.setAttribute('signatureAlgorithm', signatureAlgorithm)
                                if (personalCert.find('validity') != -1):
                                    validity = personalCert.split(' to ')[1].split('.')[0].replace(' ','/').replace(',','')
                                    xmlPersonalCert.setAttribute('validity', validity)
                                if (personalCert.find('fingerPrint') != -1):
                                    fingerPrint = personalCert.split(' ')[1].split(']')[0]
                                    xmlPersonalCert.setAttribute('fingerPrint', fingerPrint)
                                if (personalCert.find('issuedTo') != -1):
                                    issuedTo = personalCert.split(' [')[1].split(']]')[0]
                                    xmlPersonalCert.setAttribute('issuedTo', issuedTo)
                                if (personalCert.find('issuedBy') != -1):
                                    issuedBy = personalCert.split(' [')[1].split(']]')[0]
                                    xmlPersonalCert.setAttribute('issuedBy', issuedBy)
                            xmlSslConfig.appendChild(xmlPersonalCert)
                            
    def cellInfra(self, xmlCell):
        self.getSecurity(xmlCell)
        self.getSslConfig(xmlCell, '', 'cell', '')
        self.getResources('cell', self.cellId, 'DataSource', xmlCell, '', '', '')
        self.getResources('cell', self.cellId, 'JMSProvider', xmlCell, '', '', '')
        self.getResources('cell', self.cellId, 'Library', xmlCell, '', '', '')
        self.getResources('cell', self.cellId, 'J2CResourceAdapter', xmlCell, '', '', '')
        self.getResources('cell', self.cellId, 'J2CConnectionFactory', xmlCell, '', '', '')
        self.getResources('cell', self.cellId, 'URLProvider', xmlCell, '', '', '')
        self.getResources('cell', self.cellId, 'SchedulerConfiguration', xmlCell, '', '', '')
        self.getResources('cell', self.cellId, 'WorkManagerInfo', xmlCell, '', '', '')
        self.getResources('cell', self.cellId, 'TimerManagerInfo', xmlCell, '', '', '')              

        xmlNodesList = self.doc.createElement('nodes')
        xmlCell.appendChild(xmlNodesList)       
        for node in self.nodesList:
            sdk = ''
            arch = ''
            sdkbits = ''
            sdkversion = ''
            list = AdminTask.getMetadataProperties('[-nodeName '+node+']')[2:-1].replace('] [',']\n[').split('\n')
            for item in list:
                if (item.find('com.ibm.websphere.nodeOperatingSystem') != -1):
                    os = item[item.find(' ') + 1:].replace(']','')
                if (item.find('com.ibm.websphere.sdk.architecture') != -1):
                    if (len(arch) == 0):
    	                arch = item[item.find(' ') + 1:].replace(']','')
                if (item.find('com.ibm.websphere.baseProductShortName') != -1):
                    product = item[item.find(' ') + 1:].replace(']','')
                if (item.find('com.ibm.websphere.baseProductVersion') != -1):
                    version = item[item.find(' ') + 1:].replace(']','')
                if (item.find('com.ibm.websphere.sdk.version') != -1):
                    if (len(sdk) > 0):
                        aux = item[item.find(' ') + 1:].replace(']','')
                        if ((int(aux.replace('.','')) - int(sdk.replace('.',''))) > 0):
                            sdk = aux
                    else:
            	        sdk = item[item.find(' ') + 1:].replace(']','')
                if (item.find('com.ibm.websphere.sdk.bits') != -1):
                    if (len(sdkbits) == 0):
                        sdkbits = item[item.find(' ') + 1:].replace(']','')
            if (len(sdk) > 0) and (len(sdkbits) > 0):
               sdkversion = sdk+'_'+sdkbits
            hostName = self.getHostName(node)
            nodeId = self.getNodeId(node)
            isCellManager = self.getCellManagerNode(nodeId)           
            if (isCellManager):
                profileType='Cell Manager'               
                #serverVersion = self.getVersion(node,'dmgr')
                #if (serverVersion.split('.')[0] == '8'):
                #    sdkVersion = AdminTask.getSDKVersion('[-nodeName '+node+' -serverName dmgr]')
            else:
                profileType='Managed Node'
                serverVersion = self.getVersion(node,'nodeagent')
                #if (serverVersion.split('.')[0] == '8'):
                #    sdkVersion = AdminTask.getSDKVersion('[-nodeName '+node+' -serverName nodeagent]')
            xmlNode = self.doc.createElement('node')
            xmlNode.setAttribute('name',node)
            xmlNode.setAttribute('host',hostName)
            xmlNode.setAttribute('os',os)
            if (len(arch) > 0):
                xmlNode.setAttribute('arch',arch)
            xmlNode.setAttribute('product','WAS'+product)
            xmlNode.setAttribute('version',version)
            if (len(sdkversion) > 0):
                xmlNode.setAttribute('sdk',sdkversion)
            xmlNode.setAttribute('profileType',profileType)
            #if (len(serverVersion) > 0):
            #    xmlNode.setAttribute('version',serverVersion)
            #if (len(sdkVersion) > 0):
            #    xmlNode.setAttribute('sdk', sdkVersion)
            if (profileType == 'Managed Node'):
                self.getSslConfig('', xmlNode, 'node', node)
            self.getResources('node', nodeId, 'DataSource', '', xmlNode, '', '')
            self.getResources('node', nodeId, 'JMSProvider', '', xmlNode, '', '')
            self.getResources('node', nodeId, 'Library', '', xmlNode, '', '')
            self.getResources('node', nodeId, 'J2CResourceAdapter', '', xmlNode, '', '')
            self.getResources('node', nodeId, 'J2CConnectionFactory', '', xmlNode, '', '')
            self.getResources('node', nodeId, 'URLProvider', '', xmlNode, '', '')
            self.getResources('node', nodeId, 'SchedulerConfiguration', '', xmlNode, '', '')
            self.getResources('node', nodeId, 'WorkManagerInfo', '', xmlNode, '', '')
            self.getResources('node', nodeId, 'TimerManagerInfo', '', xmlNode, '', '')            
            
            xmlNodesList.appendChild(xmlNode)            

        self.getClusters()
        if (len(self.clustersList) > 0):
            xmlClustersList = self.doc.createElement('clusters')
            xmlCell.appendChild(xmlClustersList)
            for cluster in self.clustersList:
                clusterName = self.getClusterName(cluster)
                clusterMembers = self.getClusterMembers(clusterName)
                xmlCluster = self.doc.createElement('cluster')
                xmlCluster.setAttribute('name',clusterName)
                xmlCluster.setAttribute('members',str(len(clusterMembers)))
                xmlClustersList.appendChild(xmlCluster)
                                
        self.getCoreGroups()
        if (len(self.coreGroupsList) > 0):
            xmlCGList = self.doc.createElement('coregroups')
            xmlCell.appendChild(xmlCGList)
            for cg in self.coreGroupsList:
                cgName = AdminConfig.showAttribute(cg, 'name')
                cgProtocol = AdminConfig.showAttribute(cg, 'protocolVersion')
                cgMemorySize = AdminConfig.showAttribute(cg, 'transportMemorySize')  
                xmlCG = self.doc.createElement('coregroup')
                xmlCG.setAttribute('name', cgName)
                xmlCG.setAttribute('protocol', cgProtocol)
                xmlCG.setAttribute('memory', cgMemorySize)
                xmlCGList.appendChild(xmlCG)
                cgMembers = self.getCoreGroupMembers(cg)
                if (len(cgMembers) > 0):
                    xmlCGmembers = self.doc.createElement('members')
                    xmlCG.appendChild(xmlCGmembers)
                    for member in cgMembers:
                        cgMemberName = AdminConfig.showAttribute(member,"serverName")
                        cgNodeName = AdminConfig.showAttribute(member,"nodeName")                       
                        xmlCGmember = self.doc.createElement('member')
                        xmlCGmember.setAttribute('name', cgMemberName)
                        xmlCGmember.setAttribute('node', cgNodeName)
                        xmlCGmembers.appendChild(xmlCGmember)
                cgCoordinators = self.getCoreGroupCoordinators(cg)
                if (len(cgCoordinators) > 0):
                    xmlCGcoordinators = self.doc.createElement('coordinators')
                    xmlCG.appendChild(xmlCGcoordinators)
                    for coord in cgCoordinators:
                        coordName = AdminConfig.showAttribute(coord,"serverName")
                        coordNode = AdminConfig.showAttribute(coord,"nodeName")
                        xmlCGcoord = self.doc.createElement('coordinator')
                        xmlCGcoord.setAttribute('name', coordName)
                        xmlCGcoord.setAttribute('node', coordNode)
                        xmlCGcoordinators.appendChild(xmlCGcoord)
        return xmlCell

    def getAdminUsersGroups(self, xmlCell):
        rolesList = AdminTask.listUserIDsOfAuthorizationGroup().replace(" ", "").replace("],","];").replace("{","").replace("}","").split(";")
        if (len(rolesList) > 0):
            xmlUserRolesList = self.doc.createElement('userRoles')
            xmlCell.appendChild(xmlUserRolesList)
            for role in rolesList:
                usersList = []
                roleName = role.replace("=", "").split('[')[0]
                users = role.split('[')[1].split(']')[0]
                users = str(users)
                xmlRole = self.doc.createElement('role')
                xmlRole.setAttribute('name', roleName)
                xmlUserRolesList.appendChild(xmlRole)
                if (users.find('CN=') != -1):
                    users = users.replace("CN=","%")
                elif (users.find('cn=') != -1):
                    users = users.replace("cn=","%")
                if (users.find('%') != -1):
                    usersList = users.split('%')
                else:
                    if (users.find(',') != -1):
                        usersList = users.split(',')
                if (len(usersList) > 0):
                    for user in usersList:
                        if (user.find(',') != -1):
                            user = str(user.split(',')[0])
                        xmlRoleUser = self.doc.createElement('user')
                        xmlRoleUser.setAttribute('name', user)
                        xmlRole.appendChild(xmlRoleUser)
                else:
                    if (users.find(',') != -1):
                        users = str(users.split(',')[0])
                    xmlRoleUser = self.doc.createElement('user')
                    xmlRoleUser.setAttribute('name', users)
                    xmlRole.appendChild(xmlRoleUser)
        
        rolesList = AdminTask.listGroupIDsOfAuthorizationGroup().replace(" ", "").replace("],","];").replace("{","").replace("}","").split(";")
        if (len(rolesList) > 0):
            xmlGroupRolesList = self.doc.createElement('groupRoles')
            xmlCell.appendChild(xmlGroupRolesList)
            for role in rolesList:
                groupsList = []
                roleName = role.replace("=", "").split('[')[0]
                groups = role.split('[')[1].split(']')[0]
                groups = str(groups)
                xmlRole = self.doc.createElement('role')
                xmlRole.setAttribute('name', roleName)
                xmlGroupRolesList.appendChild(xmlRole)
                if (groups.find('CN=') != -1):
                    groups = groups.replace("CN=","%")
                elif (groups.find('cn=') != -1):
                    groups = groups.replace("cn=","%")
                if (groups.find('%') != -1):    
                    groupsList = groups.split('%')
                else:
                    if (groups.find(',') != -1):
                        groupsList = groups.split(',')
                if (len(groupsList) > 0):
                    for group in groupsList:
                        if (group.find(',') != -1):
                            group = str(group.split(',')[0])
                        xmlRoleGroup = self.doc.createElement('group')
                        xmlRoleGroup.setAttribute('name', group)
                        xmlRole.appendChild(xmlRoleGroup)
                else:
                    if (groups.find(',') != -1):
                        groups = str(groups.split(',')[0])
                    xmlRoleGroup = self.doc.createElement('group')
                    xmlRoleGroup.setAttribute('name', groups)
                    xmlRole.appendChild(xmlRoleGroup)
                            
    def getResources(self, scope, scopeId, resourceType, xmlCell='', xmlNode='', xmlCluster='', xmlMember=''):
        resourcesList = AdminConfig.list(resourceType, scopeId)
        resourcesList = self.convertToList(resourcesList)
        if (len(resourcesList) > 0):
            xmlResourcesList = self.doc.createElement(resourceType+'List')
            xmlResourcesList.setAttribute('scope', scope)
            if (scope == 'cell'):
                xmlCell.appendChild(xmlResourcesList)
            elif (scope == 'node'):
                xmlNode.appendChild(xmlResourcesList)
            elif (scope == 'cluster'):
                xmlCluster.appendChild(xmlResourcesList)
            elif (scope == 'appserver'):
                xmlMember.appendChild(xmlResourcesList)

            for resource in resourcesList:
                if (scope == 'cell'):
                    if (resource.find('/nodes/') != -1) or (resource.find('/servers/') != -1) or (resource.find('/clusters/') != -1):
                        continue
                if (resource.find('JMSProvider') != -1) and (resource.find('builtin_mqprovider') != -1):                       
                    mqConnFactoryList = AdminConfig.list('MQConnectionFactory',resource)
                    mqConnFactoryList = self.convertToList(mqConnFactoryList)
                    if( len(mqConnFactoryList)>0):
                        xmlMQConnectionFactoryList = self.doc.createElement('MQConnectionFactoryList')
                        xmlResourcesList.appendChild(xmlMQConnectionFactoryList)
                        for mqconn in mqConnFactoryList:
                            mqconnName = AdminConfig.showAttribute(mqconn, "jndiName")
                            mqconnType = AdminConfig.showAttribute(mqconn, "transportType")
                            xmlResource = self.doc.createElement('MQConnectionFactory')
                            xmlResource.setAttribute('name', mqconnName)
                            xmlResource.setAttribute('transportType', mqconnType)
                            if ( mqconnType != "BINDINGS" ):
                                mqconnQmgr = AdminConfig.showAttribute(mqconn, "queueManager")
                                mqconnQmgrHost = AdminConfig.showAttribute(mqconn, "host")
                                mqconnQmgrPort = AdminConfig.showAttribute(mqconn, "port")
                                mqconnQmgrChannel = AdminConfig.showAttribute(mqconn, "channel")
                                xmlResource.setAttribute('queueManager', mqconnQmgr)
                                xmlResource.setAttribute('host', mqconnQmgrHost)
                                xmlResource.setAttribute('port', mqconnQmgrPort)
                                xmlResource.setAttribute('channel', mqconnQmgrChannel)
                            xmlMQConnectionFactoryList.appendChild(xmlResource)
                            self.getPoolData(mqconn, 'connectionPool', xmlResource)
                            self.getPoolData(mqconn, 'sessionPool', xmlResource)
                    mqQueueConnFactoryList = AdminConfig.list('MQQueueConnectionFactory',resource)
                    mqQueueConnFactoryList = self.convertToList(mqQueueConnFactoryList)
                    if( len(mqQueueConnFactoryList)>0):
                        xmlMQQueueConnectionFactoryList = self.doc.createElement('MQQueueConnectionFactoryList')
                        xmlResourcesList.appendChild(xmlMQQueueConnectionFactoryList)
                        for mqconn in mqQueueConnFactoryList:
                            mqconnName = AdminConfig.showAttribute(mqconn, "jndiName")
                            mqconnType = AdminConfig.showAttribute(mqconn, "transportType")
                            xmlResource = self.doc.createElement('MQQueueConnectionFactory')
                            xmlResource.setAttribute('name', mqconnName)
                            xmlResource.setAttribute('transportType', mqconnType)
                            if ( mqconnType != "BINDINGS" ):
                                mqconnQmgr = AdminConfig.showAttribute(mqconn, "queueManager")
                                mqconnQmgrHost = AdminConfig.showAttribute(mqconn, "host")
                                mqconnQmgrPort = AdminConfig.showAttribute(mqconn, "port")
                                mqconnQmgrChannel = AdminConfig.showAttribute(mqconn, "channel")
                                xmlResource.setAttribute('queueManager', mqconnQmgr)
                                xmlResource.setAttribute('host', mqconnQmgrHost)
                                xmlResource.setAttribute('port', mqconnQmgrPort)
                                xmlResource.setAttribute('channel', mqconnQmgrChannel)
                            xmlMQQueueConnectionFactoryList.appendChild(xmlResource)
                            self.getPoolData(mqconn, 'connectionPool', xmlResource)
                            self.getPoolData(mqconn, 'sessionPool', xmlResource)
                    queuesList = AdminConfig.list('MQQueue',resource)
                    queuesList = self.convertToList(queuesList)
                    if(len(queuesList) > 0):
                        xmlMQQueueList = self.doc.createElement('MQQueuesList')
                        xmlResourcesList.appendChild(xmlMQQueueList)
                        for queue in queuesList:
                            queueName = AdminConfig.showAttribute(queue, "name" )
                            baseQueueName = AdminConfig.showAttribute(queue, "baseQueueName" )
                            targetClient = AdminConfig.showAttribute(queue, "targetClient" )
                            baseQueueManagerName = AdminConfig.showAttribute(queue, "baseQueueManagerName" )
                            xmlResource = self.doc.createElement('Queue')
                            xmlResource.setAttribute('name', queueName)
                            xmlResource.setAttribute('baseQueueName', baseQueueName)
                            xmlResource.setAttribute('targetClient', targetClient)                           
                            if ( baseQueueManagerName ):
                                xmlResource.setAttribute('baseQueueManagerName', baseQueueManagerName)
                            xmlMQQueueList.appendChild(xmlResource)
                elif (resourceType == 'J2CResourceAdapter'):
                    if (resource.find('SIB JMS Resource Adapter') == -1) and (resource.find('WebSphere MQ Resource Adapter') == -1) and (resource.find('WebSphere Relational Resource Adapter') == -1):
                        name = AdminConfig.showAttribute(resource, 'name')
                        classPath = AdminConfig.showAttribute(resource, 'classpath')
                        nativePath = AdminConfig.showAttribute(resource, 'nativepath')
                        archivePath = AdminConfig.showAttribute(resource, 'archivePath')
                        threadPoolAlias = AdminConfig.showAttribute(resource, 'threadPoolAlias')
                        isolatedClassLoader = AdminConfig.showAttribute(resource, 'isolatedClassLoader')
                        xmlResource = self.doc.createElement('J2CResourceAdapter')
                        xmlResource.setAttribute('name', name)
                        xmlResource.setAttribute('classpath', classPath)
                        xmlResource.setAttribute('nativepath', nativePath)
                        xmlResource.setAttribute('archivePath', archivePath)
                        xmlResource.setAttribute('threadPoolAlias', threadPoolAlias)
                        xmlResource.setAttribute('isolatedClassLoader', isolatedClassLoader)
                        xmlResourcesList.appendChild(xmlResource)
                elif (resourceType == 'J2CConnectionFactory'):
                    provider = AdminConfig.showAttribute(resource, 'provider')
                    if (provider.find('WebSphere Relational Resource Adapter') == -1):
                        name = AdminConfig.showAttribute(resource, 'name')
                        jndiName = AdminConfig.showAttribute(resource, 'jndiName')
                        providerName = AdminConfig.showAttribute(provider, 'name')
                        logMissingTransactionContext = AdminConfig.showAttribute(resource, 'logMissingTransactionContext')
                        xmlResource = self.doc.createElement('J2CConnectionFactory')
                        xmlResource.setAttribute('name', name)
                        xmlResource.setAttribute('jndiName', jndiName)
                        xmlResource.setAttribute('provider', providerName)
                        xmlResource.setAttribute('logMissingTransactionContext', logMissingTransactionContext)
                        xmlResourcesList.appendChild(xmlResource)
                        self.getPoolData(resource, 'connectionPool', xmlResource)
                elif (resourceType == 'TimerManagerInfo'):
                    name = AdminConfig.showAttribute(resource, 'name')
                    jndiName = AdminConfig.showAttribute(resource, 'jndiName')
                    numAlarmThreads = AdminConfig.showAttribute(resource, 'numAlarmThreads')
                    serviceNames = AdminConfig.showAttribute(resource, 'serviceNames')
                    xmlResource = self.doc.createElement('TimerManagerInfo')
                    xmlResource.setAttribute('name', name)
                    xmlResource.setAttribute('jndiName', jndiName)
                    xmlResource.setAttribute('numAlarmThreads', numAlarmThreads)
                    xmlResource.setAttribute('serviceNames', serviceNames)
                    xmlResourcesList.appendChild(xmlResource)
                elif (resourceType == 'URLProvider'):
                    urlProviderName = AdminConfig.showAttribute(resource, 'name')
                    protocol = AdminConfig.showAttribute(resource, 'protocol')
                    classpath = AdminConfig.showAttribute(resource, 'classpath')
                    #nativePath = AdminConfig.showAttribute(resource, 'nativepath')
                    streamHandlerClassName = AdminConfig.showAttribute(resource, 'streamHandlerClassName')
                    isolatedClassLoader = AdminConfig.showAttribute(resource, 'isolatedClassLoader')
                    xmlResource = self.doc.createElement('URLProvider')
                    xmlResource.setAttribute('name', urlProviderName)
                    xmlResource.setAttribute('protocol', protocol)
                    xmlResource.setAttribute('streamHandlerClassName', streamHandlerClassName)
                    xmlResource.setAttribute('classpath', classpath)
                    #xmlResource.setAttribute('nativepath', nativepath)
                    xmlResource.setAttribute('isolatedClassLoader', isolatedClassLoader)
                    xmlResourcesList.appendChild(xmlResource)
                                      
                    urlsList = AdminConfig.list('URL', scopeId)
                    urlsList = self.convertToList(urlsList)
                    if (len(urlsList) > 0):
                        xmlURLsList = self.doc.createElement('URLs')
                        xmlResource.appendChild(xmlURLsList)
                        for url in urlsList:
                            provider = AdminConfig.showAttribute(url, 'provider')
                            if (str(provider) == str(resource)):
                                urlName = AdminConfig.showAttribute(url, 'name')
                                jndiName = AdminConfig.showAttribute(url, 'jndiName')
                                spec = AdminConfig.showAttribute(url, 'spec')
                                providerName = AdminConfig.showAttribute(provider, 'name')
                                xmlURL = self.doc.createElement('URLProvider')
                                xmlURL.setAttribute('name', urlName)
                                xmlURL.setAttribute('jndiName', jndiName)
                                xmlURL.setAttribute('spec', spec)
                                xmlURL.setAttribute('provider', providerName)
                                xmlURLsList.appendChild(xmlURL)
                    
                elif (resourceType == 'WorkManagerInfo'):
                    name = AdminConfig.showAttribute(resource, 'name')
                    if (name.find('DefaultWorkManager') == -1) and (name.find('AsyncRequestDispatcherWorkManager') == -1):
                        jndiName = AdminConfig.showAttribute(resource, 'jndiName')
                        category = AdminConfig.showAttribute(resource, 'category')
                        isDistributable = AdminConfig.showAttribute(resource, 'isDistributable')
                        isGrowable = AdminConfig.showAttribute(resource, 'isGrowable')
                        maxThreads = AdminConfig.showAttribute(resource, 'maxThreads')
                        minThreads = AdminConfig.showAttribute(resource, 'minThreads')
                        numAlarmThreads = AdminConfig.showAttribute(resource, 'numAlarmThreads')
                        serviceNames = AdminConfig.showAttribute(resource, 'serviceNames')
                        threadPriority = AdminConfig.showAttribute(resource, 'threadPriority')
                        workReqQFullAction = AdminConfig.showAttribute(resource, 'workReqQFullAction')
                        workReqQSize = AdminConfig.showAttribute(resource, 'workReqQSize')
                        workTimeout = AdminConfig.showAttribute(resource, 'workTimeout')
                        xmlResource = self.doc.createElement('WorkManagerInfo')
                        xmlResource.setAttribute('name', name)
                        xmlResource.setAttribute('jndiName', jndiName)
                        xmlResource.setAttribute('category', category)
                        xmlResource.setAttribute('isDistributable', isDistributable)
                        xmlResource.setAttribute('isGrowable', isGrowable)
                        xmlResource.setAttribute('maxThreads', maxThreads)
                        xmlResource.setAttribute('minThreads', minThreads)
                        xmlResource.setAttribute('numAlarmThreads', numAlarmThreads)
                        xmlResource.setAttribute('serviceNames', serviceNames)
                        xmlResource.setAttribute('threadPriority', threadPriority)
                        xmlResource.setAttribute('workReqQFullAction', workReqQFullAction)
                        xmlResource.setAttribute('workReqQSize', workReqQSize)
                        xmlResource.setAttribute('workTimeout', workTimeout)
                        xmlResourcesList.appendChild(xmlResource)
                elif (resourceType == 'SchedulerConfiguration'):
                    name = AdminConfig.showAttribute(resource, 'name')
                    jndiName = AdminConfig.showAttribute(resource, 'jndiName')
                    datasourceJNDIName = AdminConfig.showAttribute(resource, 'datasourceJNDIName')
                    pollInterval = AdminConfig.showAttribute(resource, 'pollInterval')
                    tablePrefix = AdminConfig.showAttribute(resource, 'tablePrefix')
                    workManagerInfoJNDIName = AdminConfig.showAttribute(resource, 'workManagerInfoJNDIName')
                    xmlResource = self.doc.createElement('SchedulerConfiguration')
                    xmlResource.setAttribute('name', name)
                    xmlResource.setAttribute('jndiName', jndiName)
                    xmlResource.setAttribute('datasourceJNDIName', datasourceJNDIName)
                    xmlResource.setAttribute('pollInterval', pollInterval)
                    xmlResource.setAttribute('tablePrefix', tablePrefix)
                    xmlResource.setAttribute('workManagerInfoJNDIName', workManagerInfoJNDIName)
                    xmlResourcesList.appendChild(xmlResource)
                elif (resourceType == 'Library'):
                    name = AdminConfig.showAttribute(resource, 'name')
                    classPath = AdminConfig.showAttribute(resource, 'classPath')
                    nativePath = AdminConfig.showAttribute(resource, 'nativePath')
                    isolatedClassLoader = AdminConfig.showAttribute(resource, 'isolatedClassLoader')
                    xmlResource = self.doc.createElement('Library')
                    xmlResource.setAttribute('name', name)
                    xmlResource.setAttribute('classPath', classPath)
                    xmlResource.setAttribute('nativePath', nativePath)
                    xmlResource.setAttribute('isolatedClassLoader', isolatedClassLoader)
                    xmlResourcesList.appendChild(xmlResource)
                elif (resourceType == 'DataSource'):
                    name = AdminConfig.showAttribute(resource,"name")
                    provider = AdminConfig.showAttribute(resource, "provider" )
                    if (name.find('EJBTimer') == -1) and (name.find('OTiSDataSource') == -1):
                        implClass = AdminConfig.showAttribute(provider, "implementationClassName" )
                        if (implClass.find('Derby') == -1):
                            jndiName = AdminConfig.showAttribute(resource,"jndiName")
                            stmtCacheSize = AdminConfig.showAttribute(resource, "statementCacheSize" )                            
                            dsAuthDataAlias = AdminConfig.showAttribute(resource,"authDataAlias")
                            if (dsAuthDataAlias == ""):
                                dsAuthMapping = AdminConfig.showAttribute(resource, "mapping")
                                dsAuthDataAlias =  AdminConfig.showAttribute(dsAuthMapping,"authDataAlias")
                            if ( dsAuthDataAlias != "" ):
                                dsAuthId = self.getJAASAuthData(dsAuthDataAlias)
                            xmlResource = self.doc.createElement('DataSource')
                            xmlResource.setAttribute('name', name)
                            xmlResource.setAttribute('jndiName', jndiName)
                            xmlResource.setAttribute('provider', implClass)
                            xmlResource.setAttribute('stmtCacheSize', stmtCacheSize)                           
                            if ( dsAuthId != "" ):
                                xmlResource.setAttribute('userId', dsAuthId)
                            xmlResourcesList.appendChild(xmlResource)
                            dsPropSet = AdminConfig.showAttribute(resource, "propertySet" )
                            dsPropSet = self.convertToList(dsPropSet)
                            if( len(dsPropSet)>0):
                                xmlResourcePropList = self.doc.createElement('resourceProperties')
                                xmlResource.appendChild(xmlResourcePropList)
                                for prop in dsPropSet:
                                    dsResProps = AdminConfig.showAttribute(prop, "resourceProperties")
                                    dsResProps = self.convertToList(dsResProps)
                                    if( len(dsResProps)>0):
                                        for res in dsResProps:
                                            resName = AdminConfig.showAttribute(res, "name")
                                            if resName in ("serverName", "databaseName", "portNumber","URL"):
                                                resValue = AdminConfig.showAttribute(res, "value")
                                                xmlResourceProp = self.doc.createElement('Property')
                                                xmlResourceProp.setAttribute('name', resName)
                                                xmlResourceProp.setAttribute('value', resValue)
                                                xmlResourcePropList.appendChild(xmlResourceProp)
                            self.getPoolData(resource, 'connectionPool', xmlResource)

    def getPoolData(self, resource, poolType, xmlResource):
        dsPool = AdminConfig.showAttribute(resource, poolType)
        connectionTimeout = AdminConfig.showAttribute(dsPool, "connectionTimeout")
        maxConnections = AdminConfig.showAttribute(dsPool, "maxConnections")
        minConnections = AdminConfig.showAttribute(dsPool, "minConnections")
        reapTime = AdminConfig.showAttribute(dsPool, "reapTime")
        unusedTimeout = AdminConfig.showAttribute(dsPool, "unusedTimeout")
        agedTimeout = AdminConfig.showAttribute(dsPool, "agedTimeout")
        purgePolicy = AdminConfig.showAttribute(dsPool, "purgePolicy")
        xmlConnPool = self.doc.createElement(poolType)
        xmlConnPool.setAttribute('connectionTimeout', connectionTimeout)
        xmlConnPool.setAttribute('maxConnections', maxConnections)
        xmlConnPool.setAttribute('minConnections', minConnections)
        xmlConnPool.setAttribute('reapTime', reapTime)
        xmlConnPool.setAttribute('unusedTimeout', unusedTimeout)
        xmlConnPool.setAttribute('agedTimeout', agedTimeout)
        xmlConnPool.setAttribute('purgePolicy', purgePolicy)
        xmlResource.appendChild(xmlConnPool)

    def getJAASAuthData(self, authData):
        security = AdminConfig.getid('/Cell:'+self.cellName+'/Security:/')
        jaasList = AdminConfig.list('JAASAuthData', security)
        jaasList = self.convertToList(jaasList)
        userId = ""
        if( len(jaasList)>0):
            for jaas in jaasList:
                jaasAlias = AdminConfig.showAttribute(jaas, 'alias')
                if ( authData == jaasAlias ):
                    userId = AdminConfig.showAttribute(jaas, 'userId')
        return userId

    def getApps (self, clusterName, xmlCluster):
        lf = java.lang.System.getProperty("line.separator")
        appsList = AdminApp.list("WebSphere:cell="+self.cellName+",cluster="+clusterName+"")
        appsList = self.convertToList(appsList)
        if (len(appsList) > 0):
            xmlAppsList = self.doc.createElement('Applications')
            xmlCluster.appendChild(xmlAppsList)
            for app in appsList:
                xmlApp = self.doc.createElement('Application')
                xmlApp.setAttribute('name', app)
                xmlAppsList.appendChild(xmlApp)
                modulesList = AdminApp.listModules(app).split('\n')
                if (len(modulesList) > 0):
                    xmlAppModuleList = self.doc.createElement('Modules')
                    xmlApp.appendChild(xmlAppModuleList)
                    for module in modulesList:
                        lMapping = []
                        lMapping = AdminApp.view(module, ['-MapModulesToServers']).split('\n')
                        if (len(lMapping) > 0):
                            for mapping in lMapping:
                                if (mapping.find('Server:  WebSphere:cell=') != -1):
                                    appMapping = mapping.split(":  ")[1]
                        lMapping = AdminApp.view(module, ['-MapWebModToVH']).split('\n')
                        if (len(lMapping) > 0):
                            for mapping in lMapping:
                                if (mapping.find('Virtual host:') != -1):
                                    vHost = mapping.split(":  ")[1]
                        lMapping = []
                        lMapping =  AdminApp.view(module, ['-CtxRootForWebMod']).split('\n')
                        if (len(lMapping) > 0):
                            for mapping in lMapping:
                                if (mapping.find('Context Root:') != -1):
                                    ctxRoot = mapping.split(":  ")[1]
                        xmlAppModule = self.doc.createElement('module')
                        xmlAppModule.setAttribute('name', module)
                        xmlAppModule.setAttribute('mapping', appMapping)
                        xmlAppModule.setAttribute('contextRoot', ctxRoot)
                        xmlAppModule.setAttribute('virtualHost', vHost)
                        xmlAppModuleList.appendChild(xmlAppModule)
                deployment = AdminConfig.getid('/Deployment:'+app+'/')
                appDeploy = AdminConfig.showAttribute(deployment, 'deployedObject')
                classLoader = AdminConfig.showAttribute(appDeploy, 'classloader')
                appClassLoaderMode = AdminConfig.showAttribute(classLoader, 'mode')
                if (len(appClassLoaderMode) > 0):
                    appSharedLibList = AdminConfig.list('LibraryRef', appDeploy).split()
                    if( len(appSharedLibList)>0):
                        xmlAppSharedLibsList = self.doc.createElement('SharedLibraries')
                        xmlApp.appendChild(xmlAppSharedLibsList)
                        for appLib in appSharedLibList:
                            libraryName = AdminConfig.showAttribute(appLib, 'libraryName')
                            sharedClassloader = AdminConfig.showAttribute(appLib, 'sharedClassloader')
                            xmlAppSharedLib = self.doc.createElement('library')
                            xmlAppSharedLib.setAttribute('name', libraryName)
                            xmlAppSharedLib.setAttribute('classloader', sharedClassloader)
                            xmlAppSharedLibsList.appendChild(xmlAppSharedLib)

    def getVhost(self, xmlCell):
        vHostsList = AdminConfig.list("VirtualHost", self.cellId )
        vHostsList = self.convertToList(vHostsList)
        if( len(vHostsList)>0):
            xmlVhostsList = self.doc.createElement('virtualhosts')
            xmlCell.appendChild(xmlVhostsList)
            for vhost in vHostsList:
                vhostName = AdminConfig.showAttribute(vhost,'name')
                xmlVhost = self.doc.createElement('virtualhost')
                xmlVhost.setAttribute('name', vhostName)
                xmlVhostsList.appendChild(xmlVhost)                
                aliasList = AdminConfig.list('HostAlias',vhost)
                aliasList = self.convertToList(aliasList)
                if( len(aliasList)>0):
                    xmlVhostAliases = self.doc.createElement('aliases')
                    xmlVhost.appendChild(xmlVhostAliases)
                    for alias in aliasList:
                        aliasHostname = AdminConfig.showAttribute(alias,'hostname')
                        aliasPort = AdminConfig.showAttribute(alias,'port')
                        xmlVhostAlias = self.doc.createElement('alias')
                        xmlVhostAlias.setAttribute('name',aliasHostname)
                        xmlVhostAlias.setAttribute('port',aliasPort)
                        xmlVhostAliases.appendChild(xmlVhostAlias)

    def execute (self):
        self.getCell()
        self.getCellId()
        self.getNodes()
        if (len(self.nodesList) > 0):
            xmlCell = self.doc.createElement('cell')
            xmlCell.setAttribute('name', self.cellName)
            self.doc.appendChild(xmlCell)
            self.cellInfra(xmlCell)
            self.getVhost(xmlCell)
            self.getAdminUsersGroups(xmlCell)

        if (len(self.clustersList) > 0):
            xmlClustersList = self.doc.createElement('clusters')
            xmlCell.appendChild(xmlClustersList)
            for cluster in self.clustersList:
                clusterName = self.getClusterName(cluster)
                clusterMembers = self.getClusterMembers(clusterName)
                clusterId = self.getClusterId(clusterName)
                if (len(clusterMembers) > 0):

                    xmlCluster = self.doc.createElement('cluster')
                    xmlCluster.setAttribute('name', clusterName)
                    xmlClustersList.appendChild(xmlCluster)

                    xmlMembersList = self.doc.createElement('members')
                    xmlCluster.appendChild(xmlMembersList)
                    
                    for member in clusterMembers:
                        memberName = self.getAppServerName(member)
                        nodeName = self.getAppServerNodeName(member)
                        serverId = self.getServerId(nodeName,memberName)
                        nodeId = self.getNodeId(nodeName)

                        xmlMember = self.doc.createElement('appserver')
                        xmlMember.setAttribute('name', memberName)
                        xmlMember.setAttribute('node', nodeName)
                        xmlMembersList.appendChild(xmlMember)

                        sysLog = AdminConfig.showAttribute(serverId, 'outputStreamRedirect')
                        if (len(sysLog) > 0):                           
                            maxLogs = AdminConfig.showAttribute(sysLog, 'maxNumberOfBackupFiles')
                            rolloverType = AdminConfig.showAttribute(sysLog, 'rolloverType')
                            rolloverSize = AdminConfig.showAttribute(sysLog, 'rolloverSize')
                            rolloverPeriod = AdminConfig.showAttribute(sysLog, 'rolloverPeriod')
                            fileName = AdminConfig.showAttribute(sysLog, 'fileName')
                            baseHour = AdminConfig.showAttribute(sysLog, 'baseHour')
                            
                            xmlSysOut = self.doc.createElement('outputStreamRedirect')
                            xmlSysOut.setAttribute('maxLogs', maxLogs)
                            xmlSysOut.setAttribute('rolloverType', rolloverType)
                            xmlSysOut.setAttribute('rolloverSize', rolloverSize)
                            xmlSysOut.setAttribute('rolloverPeriod', rolloverPeriod)
                            xmlSysOut.setAttribute('fileName', fileName)
                            xmlSysOut.setAttribute('baseHour', baseHour)
                            xmlMember.appendChild(xmlSysOut)                            
                                
                        errLog = AdminConfig.showAttribute(serverId, 'errorStreamRedirect')
                        if (len(errLog) > 0):
                            maxLogs = AdminConfig.showAttribute(errLog, 'maxNumberOfBackupFiles')
                            rolloverType = AdminConfig.showAttribute(errLog, 'rolloverType')
                            rolloverSize = AdminConfig.showAttribute(errLog, 'rolloverSize')
                            rolloverPeriod = AdminConfig.showAttribute(errLog, 'rolloverPeriod')
                            fileName = AdminConfig.showAttribute(errLog, 'fileName')
                            baseHour = AdminConfig.showAttribute(errLog, 'baseHour')

                            xmlSysErr = self.doc.createElement('errorStreamRedirect')
                            xmlSysErr.setAttribute('maxLogs', maxLogs)
                            xmlSysErr.setAttribute('rolloverType', rolloverType)
                            xmlSysErr.setAttribute('rolloverSize', rolloverSize)
                            xmlSysErr.setAttribute('rolloverPeriod', rolloverPeriod)
                            xmlSysErr.setAttribute('fileName', fileName)
                            xmlSysErr.setAttribute('baseHour', baseHour)
                            xmlMember.appendChild(xmlSysErr)                            
                        
                        appServerID = self.getAppServerId(serverId)
                        classLoaderPolicy = AdminConfig.showAttribute(appServerID,'applicationClassLoaderPolicy')
                        classLoadingMode = AdminConfig.showAttribute(appServerID,'applicationClassLoadingMode')
                    
                        xmlclassLoader = self.doc.createElement('ClassLoader')
                        xmlclassLoader.setAttribute('classLoaderPolicy', classLoaderPolicy)
                        xmlclassLoader.setAttribute('classLoadingMode', classLoadingMode)
                        xmlMember.appendChild(xmlclassLoader)
                        
                        xmlJavaProcDef = self.doc.createElement('JavaProcDef')
                        xmlMember.appendChild(xmlJavaProcDef)
                        jvmId = self.getJavaVirtualMachineId(serverId)
                        jvmItems = self.getJavaVirtualMachineProperties(jvmId)
                        if( len(jvmItems)>0):
                            xmlJVM = self.doc.createElement('JavaVirtualMachine')
                            if jvmItems.has_key("initialHeapSize"):
                                xmlJVM.setAttribute('initialHeapSize', jvmItems["initialHeapSize"])
                            if jvmItems.has_key("maximumHeapSize"):
                                xmlJVM.setAttribute('maximumHeapSize', jvmItems["maximumHeapSize"])
                            if jvmItems.has_key("genericJvmArguments"):
                                xmlJVM.setAttribute('genericJvmArguments', jvmItems["genericJvmArguments"])
                            if jvmItems.has_key("verboseModeGarbageCollection"):
                                xmlJVM.setAttribute('verboseGC', jvmItems["verboseModeGarbageCollection"])
                            xmlJavaProcDef.appendChild(xmlJVM)
                            
                        jvmCustomProps = AdminConfig.list('Property', jvmId)
                        jvmCustomProps = self.convertToList(jvmCustomProps)
                        if( len(jvmCustomProps)>0):
                            xmlJvmCustomProp = self.doc.createElement('JVMCustomProperties')
                            xmlJavaProcDef.appendChild(xmlJvmCustomProp)                           
                            for jcProp in jvmCustomProps:
                                jcPropName = AdminConfig.showAttribute(jcProp,'name')
                                jcPropValue = AdminConfig.showAttribute(jcProp,'value')
                                xmlJvmProp = self.doc.createElement('property')
                                xmlJvmProp.setAttribute('name', jcPropName)
                                xmlJvmProp.setAttribute('value', jcPropValue)
                                xmlJvmCustomProp.appendChild(xmlJvmProp)

                        processDef = self.getProcessDef(serverId)                        
                        jvmEnvEntries = AdminConfig.list('Property', processDef)
                        jvmEnvEntries = self.convertToList(jvmEnvEntries)
                        if( len(jvmEnvEntries)>0):
                            xmlJvmEnvEntries = self.doc.createElement('JVMEnvironmentEntries')
                            xmlJavaProcDef.appendChild(xmlJvmEnvEntries)
                            for jvmEnv in jvmEnvEntries:
                                jvmEnvName = AdminConfig.showAttribute(jvmEnv,'name')
                                jvmEnvValue = AdminConfig.showAttribute(jvmEnv,'value')
                                xmlJVMEntry = self.doc.createElement('entry')
                                xmlJVMEntry.setAttribute('name', jvmEnvName)
                                xmlJVMEntry.setAttribute('value', jvmEnvValue)
                                xmlJvmEnvEntries.appendChild(xmlJVMEntry)
                                
                        appServerExec = AdminConfig.showAttribute(processDef,'execution')
                        if (len(appServerExec) > 0):
                            xmlAppServerExec = self.doc.createElement('ProcessExecution')
                            xmlAppServerExec.setAttribute('runAsUser', AdminConfig.showAttribute(appServerExec,'runAsUser'))
                            xmlAppServerExec.setAttribute('runAsGroup', AdminConfig.showAttribute(appServerExec,'runAsGroup'))
                            xmlAppServerExec.setAttribute('umask', AdminConfig.showAttribute(appServerExec,'umask'))
                            xmlJavaProcDef.appendChild(xmlAppServerExec)
                                                    
                        appServerClassLoadersList = AdminConfig.list('Classloader', serverId)
                        appServerClassLoadersList = self.convertToList(appServerClassLoadersList)
                        if( len(appServerClassLoadersList)>0):
                            for load in appServerClassLoadersList:
                                loadMode = AdminConfig.showAttribute(load,'mode')
                                loadLibraries = AdminConfig.list('LibraryRef',load)
                                loadLibraries = self.convertToList(loadLibraries)
                                if( len(loadLibraries)>0):
                                    xmlLibrariesList = self.doc.createElement('LibraryReferences')
                                    xmlJavaProcDef.appendChild(xmlLibrariesList)
                                    for lib in loadLibraries:
                                        libName = AdminConfig.showAttribute(lib,'libraryName')
                                        libLoader = AdminConfig.showAttribute(lib,'sharedClassloader')
                                        xmlLibrary = self.doc.createElement('library')
                                        xmlLibrary.setAttribute('name', libName)
                                        xmlLibrary.setAttribute('sharedClassloader',libLoader)
                                        xmlLibrary.setAttribute('classLoadingMode', loadMode)
                                        xmlLibrariesList.appendChild(xmlLibrary)
                                                                
                        serverEntries = AdminConfig.list('ServerEntry', nodeId)
                        serverEntries = self.convertToList(serverEntries)
                        if( len(serverEntries)>0):
                            for entry in serverEntries:
                                sName = AdminConfig.showAttribute(entry, "serverName")
                                if sName == memberName:
                                    specEndPointList = AdminConfig.showAttribute(entry, "specialEndpoints")
                                    specEndPointList = self.convertToList(specEndPointList)
                                    if( len(specEndPointList)>0):
                                        xmlPortsList = self.doc.createElement('specialEndpoints')
                                        xmlMember.appendChild(xmlPortsList)
                                        for specpoint in specEndPointList:
                                            specEndPointName = AdminConfig.showAttribute(specpoint,'endPointName')
                                            ePoint = AdminConfig.showAttribute(specpoint, "endPoint")
                                            ePointPort = AdminConfig.showAttribute(ePoint, "port")
                                            ePointHost = AdminConfig.showAttribute(ePoint, "host")                                            
                                            xmlEndPoint = self.doc.createElement('endPoint')
                                            xmlEndPoint.setAttribute('name', specEndPointName)
                                            xmlEndPoint.setAttribute('host', ePointHost)
                                            xmlEndPoint.setAttribute('port', ePointPort)
                                            xmlPortsList.appendChild(xmlEndPoint)

                        webContainer = AdminConfig.list('WebContainer',serverId)
                        xmlWebContainer = self.doc.createElement('WebContainerSettings')
                        xmlMember.appendChild(xmlWebContainer)
                        serverTransChannelsList = AdminConfig.list('TransportChannelService',serverId)
                        serverTransChannelsList = self.convertToList(serverTransChannelsList)
                        if( len(serverTransChannelsList)>0):
                            for channelServ in serverTransChannelsList:
                                wcInboundChannelList = AdminTask.listChains(channelServ, '[-acceptorFilter WebContainerInboundChannel]')
                                wcInboundChannelList = self.convertToList(wcInboundChannelList)
                                if (len(wcInboundChannelList) > 0):
                                    xmlWebContainerInboundChannelList = self.doc.createElement('WebContainerInboundChannel')
                                    xmlWebContainer.appendChild(xmlWebContainerInboundChannelList)
                                    for wcInboundChannel in wcInboundChannelList:
                                        wcInboundChannelName = AdminConfig.showAttribute(wcInboundChannel, 'name')
                                        if ((AdminConfig.showAttribute(wcInboundChannel,'enable') == 'true') and (wcInboundChannelName.find("WCInboundAdmin") == -1)):
                                            xmlwcInboundChannel = self.doc.createElement('wcInboundChannel')
                                            xmlwcInboundChannel.setAttribute('name', wcInboundChannelName)
                                            xmlWebContainerInboundChannelList.appendChild(xmlwcInboundChannel)
                                            wcTrChannelsList = AdminConfig.showAttribute(wcInboundChannel,'transportChannels')
                                            wcTrChannelsList = self.convertToList(wcTrChannelsList)
                                            if (len(wcTrChannelsList) > 0):
                                                xmlTransportChannelsList = self.doc.createElement('transportChannels')
                                                xmlwcInboundChannel.appendChild(xmlTransportChannelsList)
                                                for tranChannel in wcTrChannelsList:
                                                    tcName = AdminConfig.showAttribute(tranChannel, 'name')
                                                    if (tcName.find('TCP_') != -1):
                                                        endPointName = AdminConfig.showAttribute(tranChannel, 'endPointName')
                                                        inactivityTimeout = AdminConfig.showAttribute(tranChannel, 'inactivityTimeout')
                                                        maxOpenConnections = AdminConfig.showAttribute(tranChannel, 'maxOpenConnections')
                                                        threadPoolId = AdminConfig.showAttribute(tranChannel, 'threadPool')
                                                        threadPool = AdminConfig.showAttribute(threadPoolId, 'name')
                                                        xmlTransportChannel = self.doc.createElement('channel')
                                                        xmlTransportChannel.setAttribute('name', tcName)
                                                        xmlTransportChannel.setAttribute('endPointName', endPointName)
                                                        xmlTransportChannel.setAttribute('inactivityTimeout', inactivityTimeout)
                                                        xmlTransportChannel.setAttribute('maxOpenConnections', maxOpenConnections)
                                                        xmlTransportChannel.setAttribute('threadPool', threadPool)
                                                        xmlTransportChannelsList.appendChild(xmlTransportChannel)
                                                    elif (tcName.find('HTTP_') != -1):
                                                        keepAlive = AdminConfig.showAttribute(tranChannel, 'keepAlive')
                                                        maxFieldSize = AdminConfig.showAttribute(tranChannel, 'maxFieldSize')
                                                        maxHeaders = AdminConfig.showAttribute(tranChannel, 'maxHeaders')
                                                        maximumPersistentRequests = AdminConfig.showAttribute(tranChannel, 'maximumPersistentRequests')
                                                        persistentTimeout = AdminConfig.showAttribute(tranChannel, 'persistentTimeout')
                                                        readTimeout = AdminConfig.showAttribute(tranChannel, 'readTimeout')
                                                        writeTimeout = AdminConfig.showAttribute(tranChannel, 'writeTimeout')
                                                        xmlTransportChannel = self.doc.createElement('channel')
                                                        xmlTransportChannel.setAttribute('name', tcName)
                                                        xmlTransportChannel.setAttribute('keepAlive', keepAlive)
                                                        xmlTransportChannel.setAttribute('maxFieldSize', maxFieldSize)
                                                        xmlTransportChannel.setAttribute('maxHeaders', maxHeaders)
                                                        xmlTransportChannel.setAttribute('maximumPersistentRequests', maximumPersistentRequests)
                                                        xmlTransportChannel.setAttribute('persistentTimeout', persistentTimeout)
                                                        xmlTransportChannel.setAttribute('readTimeout', readTimeout)
                                                        xmlTransportChannel.setAttribute('writeTimeout', writeTimeout)
                                                        xmlTransportChannelsList.appendChild(xmlTransportChannel)
                                                        
                        wcCustomProps = AdminConfig.list('Property', webContainer) 
                        wcCustomProps = self.convertToList(wcCustomProps)
                        if( len(wcCustomProps)>0):
                            xmlWebContainerCustPropList = self.doc.createElement('CustomProperties')
                            xmlWebContainer.appendChild(xmlWebContainerCustPropList)
                            for wcProp in wcCustomProps:
                                wcPropName = AdminConfig.showAttribute(wcProp,'name')
                                wcPropValue = AdminConfig.showAttribute(wcProp,'value')
                                xmlWebContainerCustProp = self.doc.createElement('property')
                                xmlWebContainerCustProp.setAttribute('name', wcPropName)
                                xmlWebContainerCustProp.setAttribute('value', wcPropValue)
                                xmlWebContainerCustPropList.appendChild(xmlWebContainerCustProp)

                        wcSessionManager = AdminConfig.list('SessionManager',webContainer)
                        if (len(wcSessionManager) > 0):
                            sessionPersistence = AdminConfig.showAttribute(wcSessionManager,'sessionPersistenceMode')
                            sessionTunning = AdminConfig.showAttribute(wcSessionManager, 'tuningParams')
                            sessionTimeout = AdminConfig.showAttribute(sessionTunning, 'invalidationTimeout')
                            cookies = AdminConfig.showAttribute(wcSessionManager,'defaultCookieSettings')
                            cookieName = AdminConfig.showAttribute(cookies,'name')
                            xmlSessionManager = self.doc.createElement('WebContainerSessionSettings')
                            xmlSessionManager.setAttribute('cookieName', cookieName)
                            xmlSessionManager.setAttribute('sessionPersistence', sessionPersistence)
                            xmlSessionManager.setAttribute('sessionTimeout', sessionTimeout)
                            xmlWebContainer.appendChild(xmlSessionManager)

                        threadPoolManagerID = AdminConfig.list('ThreadPoolManager',serverId)
                        threadPoolList = AdminConfig.showAttribute(threadPoolManagerID,'threadPools')
                        threadPoolList = self.convertToList(threadPoolList)
                        if (len(threadPoolList) > 0):
                            xmlThreadPoolManagerList = self.doc.createElement('ThreadPoolManager')
                            xmlMember.appendChild(xmlThreadPoolManagerList)
                            for tpID in threadPoolList:
                                tpName = AdminConfig.showAttribute(tpID,'name')
                                if( tpName == 'WebContainer') or (tpName == 'ORB.thread.pool') or (tpName == 'Default'):
                                    tpMaxSize = AdminConfig.showAttribute(tpID,'maximumSize')
                                    tpMinSize = AdminConfig.showAttribute(tpID,'minimumSize')
                                    tpTimeOut = AdminConfig.showAttribute(tpID,'inactivityTimeout')
                                    tpIsGrowable = AdminConfig.showAttribute(tpID,'isGrowable')
                                    xmlThreadPoolManager = self.doc.createElement('ThreadPool')
                                    xmlThreadPoolManager.setAttribute('name', tpName)
                                    xmlThreadPoolManager.setAttribute('maximumSize', tpMaxSize)
                                    xmlThreadPoolManager.setAttribute('minimumSize', tpMinSize)
                                    xmlThreadPoolManager.setAttribute('inactivityTimeout', tpTimeOut)
                                    xmlThreadPoolManager.setAttribute('isGrowable', tpIsGrowable)
                                    xmlThreadPoolManagerList.appendChild(xmlThreadPoolManager)
                            
                        msgListenersList = AdminConfig.list('MessageListenerService', serverId)
                        msgListenersList = self.convertToList(msgListenersList)
                        if( len(msgListenersList)>0):
                            xmlMsgListeners = self.doc.createElement('MessageListeners')
                            xmlMember.appendChild(xmlMsgListeners)
                            for msgListener in msgListenersList:
                                listenerPortsList = AdminConfig.list('ListenerPort', msgListener)
                                listenerPortsList = self.convertToList(listenerPortsList)
                                if( len(listenerPortsList)>0):
                                    for listport in listenerPortsList:
                                        listPortName = AdminConfig.showAttribute(listport, "name")
                                        connFactJNDIName = AdminConfig.showAttribute(listport, "connectionFactoryJNDIName")
                                        destJNDIName = AdminConfig.showAttribute(listport, "destinationJNDIName")
                                        maxSessions = AdminConfig.showAttribute(listport, "maxSessions")
                                        maxRetries = AdminConfig.showAttribute(listport, "maxRetries")
                                        maxMessages = AdminConfig.showAttribute(listport, "maxMessages")
                                        xmlListPort = self.doc.createElement('ListenerPort')
                                        xmlListPort.setAttribute('name', listPortName)
                                        xmlListPort.setAttribute('connectionFactoryJNDIName', connFactJNDIName)
                                        xmlListPort.setAttribute('destinationJNDIName', destJNDIName)
                                        xmlListPort.setAttribute('maxSessions', maxSessions)
                                        xmlListPort.setAttribute('maxRetries', maxRetries)
                                        xmlListPort.setAttribute('maxMessages', maxMessages)
                                        xmlMsgListeners.appendChild(xmlListPort)
                
                        self.getResources('appserver', serverId, 'DataSource', '', '', '', xmlMember)
                        self.getResources('appserver', serverId, 'JMSProvider', '', '', '', xmlMember)
                        self.getResources('appserver', serverId, 'Library', '', '', '', xmlMember)
                        self.getResources('appserver', serverId, 'J2CResourceAdapter', '', '', '', xmlMember)
                        self.getResources('appserver', serverId, 'J2CConnectionFactory', '', '', '', xmlMember)
                        self.getResources('appserver', serverId, 'URLProvider', '', '', '', xmlMember)
                        self.getResources('appserver', serverId, 'SchedulerConfiguration', '', '', '', xmlMember)
                        self.getResources('appserver', serverId, 'WorkManagerInfo', '', '', '', xmlMember)
                        self.getResources('appserver', serverId, 'TimerManagerInfo', '', '', '', xmlMember)
                
                self.getResources('cluster', clusterId, 'DataSource', '', '', xmlCluster, '')
                self.getResources('cluster', clusterId, 'JMSProvider', '', '', xmlCluster, '')
                self.getResources('cluster', clusterId, 'Library', '', '', xmlCluster, '')
                self.getResources('cluster', clusterId, 'J2CResourceAdapter', '', '', xmlCluster, '')
                self.getResources('cluster', clusterId, 'J2CConnectionFactory', '', '', xmlCluster, '')
                self.getResources('cluster', clusterId, 'URLProvider', '', '', xmlCluster, '')
                self.getResources('cluster', clusterId, 'SchedulerConfiguration', '', '', xmlCluster, '')
                self.getResources('cluster', clusterId, 'WorkManagerInfo', '', '', xmlCluster, '')
                self.getResources('cluster', clusterId, 'TimerManagerInfo', '', '', xmlCluster, '')
                
                self.getApps(clusterName, xmlCluster)
            
        timestamp = time.strftime("%m.%d.%Y-%H.%M.%S", time.gmtime())
        xmlReportFile="/var/tmp/"+self.cellName+"."+timestamp+".xml"
        xmlFile = open(xmlReportFile, 'w')
        print >>xmlFile, self.doc.toprettyxml(indent = '   ')
        xmlFile.close()

#############################
## Main execution begins here
#############################
if __name__ == '__main__':

    report = ConfigReport()
    if( report.loadArguments() ):
        report.execute()
        exitCode = 0
    else:
        exitCode = 1
        print "+    ERROR! Failed to initialize the ConfigReport component for WebSphere."
        print "+    Aborting!"
    sys.exit(exitCode)
