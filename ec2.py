import boto3
import ipaddress

class ec2():

    def __init__(self):
        # Null init setup
        self._ = ''

    def connection(self, **kwargs):
        # Configure tokens and regions
        self._access = kwargs['aws_access_key']
        self._secret = kwargs['aws_secret_key']
        self._region = kwargs['region']

    def display(self):
        # Testing to display region and access key you are using
        print('Access Token:', self._access)
        print('Region:', self._region)

    def ec2Client(self):
        # Setups a boto3 client session
        ec2Client = boto3.client('ec2', 
            aws_access_key_id = self._access,
            aws_secret_access_key = self._secret,
            region_name = self._region)
        return(ec2Client)

    def ec2Resource(self):
        # Setups a boto3 resource session
        ec2Resource = boto3.resource('ec2', 
            aws_access_key_id = self._access,
            aws_secret_access_key = self._secret,
            region_name = self._region)
        return(ec2Resource)

    class networkSecurity():
        # Any Resource that is under ec2 > Network & Secuirty 
        def __init__(self):
            # Map inner class to outer class
            self.top = ec2()

        class networkInterface():
            # Any Resource that is under ec2 > Network & Secuirty > Network Interfaces
            def __init__(self):
                # Map inner class to outer class
                self.top = ec2()

            def ipAddressSecurityGroupList(self, ipAddress):
                # Function Looks for mathcing IP address on Network Interface
                ec2Client = self.top.ec2Client()
                response = ec2Client.describe_network_interfaces()
                # Iterate through all interfaces
                for x in range(0,len(response['NetworkInterfaces'])):
                    # Iterate through all Private IP's on interface
                    for y in range(0,len(response['NetworkInterfaces'][x]['PrivateIpAddresses'])):
                        # If it matches the queries IP
                        if response['NetworkInterfaces'][x]['PrivateIpAddresses'][y]['PrivateIpAddress'] == ipAddress:
                            # Create blank list for security group id's
                            sgList = []
                            # Iterate through them all and append to blank list
                            for z in range(0,len(response['NetworkInterfaces'][x]['Groups'])):
                                sgList.append(response['NetworkInterfaces'][x]['Groups'][z]['GroupId'])
                            # Return populated list
                            return(sgList)
                        else:
                            # Pass if IP address does not match
                            pass

        class securityGroups():
            # Any Resource that is under ec2 > Network & Secuirty > Security Groups
            def __init__(self):
                # Map inner class to outer class
                self.top = ec2()

            def securityGroupInboundRuleCheck(self, sgList):
                # This functions takes all the SG-ID's, and grabs all the rules for further parsing 
                # Create empty list to append rules
                inboundRuleList = []
                # Create a boto 3 resoucre session
                ec2Resource = self.top.ec2Resource()
                # Iterate through security group list and append rules to empty list
                for x in range(0,len(sgList)):
                    # Send Security Group ID from list to AWS
                    securityGroup = ec2Resource.SecurityGroup(sgList[x])
                    # For every rule in ip permission append to ipRuleList
                    for y in range(0,len(securityGroup.ip_permissions)):
                        inboundRuleList.append(securityGroup.ip_permissions[y])
                # Return List of rules
                return(inboundRuleList)

            class parsers():
                # Random parsers
                def __init__(self):
                    # Map inner class to outer class
                    self.top = ec2()
                    # Up one Level
                    self.uol = self.top.networkSecurity.securityGroups()

                def awsPortParser(fromPort, toPort, requestPort):
                    # Parse port entries to see if rule matches
                    if requestPort in range(fromPort, toPort) or requestPort == fromPort:
                        return(True)
                    else:
                        return(False)

                def awsIpAddressParser(ipAddress, cidr):
                    # Check if IP host address is present, or it falls with in a CIDR block
                    if ipaddress.ip_address(ipAddress) in ipaddress.ip_network(cidr):
                        return(True)
                    else:
                        return(False)

                def sgSrcPortParser(self, inboundRules, srcIpAddress, dstPort):
                    # Check if permit rule exists
                    # Iterate through all inbound rules
                    for x in range(0,len(inboundRules)):
                        # Send to parser to check for matching source IP
                        for y in range(0,len(inboundRules[x]['IpRanges'])):
                            parserReturnValue = self.awsIpAddressParser(srcIpAddress, inboundRules[x]['IpRanges'][y]['CidrIp'])
                            # If Parser matches, parse for dst ports
                            if parserReturnValue == True:
                                portParser = self.awsPortParser(inboundRules[x]['FromPort'], inboundRules[x]['ToPort'], dstPort)
                                # If Parser matches, return matching rule
                                if portParser == True:
                                    print('Matching Rule')
                                    #print(sgList[z])
                                    return(inboundRules[x])
                                # Else return no matching rule
                                else:
                                    print('No matching Port')
                            else:
                                return()


# I made these to work out my problem beteen inner and out classes

    def ipAddressSecurityGroupList(ipAddress):
        ns = ec2.networkSecurity()
        ni = ns.networkInterface()
        sgList = ni.ipAddressSecurityGroupList(ipAddress)
        return(sgList)

    def securityGroupInboundRuleCheck(sgList):
        ns = ec2.networkSecurity()
        sg = ns.securityGroups()
        inboundRuleList = sg.securityGroupInboundRuleCheck(sgList)
        return(inboundRuleList)

    def sgSrcPortParser(inboundRules, srcIpAddress, dstPort):
        ns = ec2.networkSecurity()
        sg = ns.securityGroups()
        parser = sg.parsers()
        inboundRuleList = parser.sgSrcPortParser(inboundRules, srcIpAddress, dstPort)
        return(inboundRuleList)


if __name__ == '__main__':
    aws_access_key = ''
    aws_secret_key = ''
    region = 'us-east-2'
    dstIpAddress = '172.16.90.43'
    labEc2Dict = {'aws_access_key': aws_access_key, 'aws_secret_key': aws_secret_key, 'region': region}
    labEc2 = ec2
    connection = labEc2.connection(labEc2, **labEc2Dict)
    sgList = labEc2.ipAddressSecurityGroupList(dstIpAddress)
    #print(sgList)
    rules = labEc2.securityGroupInboundRuleCheck(sgList)
    #print(rules)
    srcIpAddress = '192.168.1.1'
    dstPort = 443
    boop = labEc2.sgSrcPortParser(rules, srcIpAddress, dstPort)
    print(boop)
    #netSec = labEc2.networkSecurity(**labEc2Dict)
    #netInt = netSec.networkInterface(**labEc2Dict)
    #netInt.ipAddressSecurityGroupList()











