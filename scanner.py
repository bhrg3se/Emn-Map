import struct
from socket import *
from scapy.all import *
class Scanner:

    def scan(self, ip, port,typ):
        result=""
        if(typ=='CONN'):

            ping_result = self.tryConnect(ip, port)
            if(ping_result):
                result += str(ip) + ":" + str(port) + " >>> OPEN <<<"
        elif(typ=='SYN'):
            ping_result=self.halfConnect(ip,port)
            if(ping_result):
                result += str(ip) + ":" + str(port) + " >>> OPEN <<<"
        return result


    def tryConnect(self, ip, port):
        connSkt = socket.socket(AF_INET, SOCK_STREAM)
        connSkt.settimeout(1)
        try:
            connSkt.connect((ip, int(port)))
            return True
        except:
            return False
        finally:
            connSkt.close()
    
    def getHostByIp(self, ip):
        return gethostbyaddr(ip)[0]
            
    def getIpAddressesFromRange(self, start, end):
        ipstruct = struct.Struct('>I')
        start, = ipstruct.unpack(inet_aton(start))
        end, = ipstruct.unpack(inet_aton(end))
        return [inet_ntoa(ipstruct.pack(i)) for i in range(start, end+1)]

    def halfConnect(self,ip,port):
        sp=int(RandShort())
        p = sr1(IP(dst=ip) / TCP(sport=sp, dport=port, flags="S"))
        flag = p.getlayer(TCP).flags
        rst = IP(dst=ip) / TCP(sport=sp, dport=port, flags="R")
        send(rst)
        if flag == 18:
            return True
        else:
            return False
