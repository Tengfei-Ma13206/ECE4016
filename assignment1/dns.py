from socket import *
from dnslib import *
from dnslib.server import *

def get_middle(query_str,subString,endChar,begin=0,end=0):
    begin_flag = True
    end_flag = True
    while((begin_flag or end_flag) and end+len(subString) < len(query_str)):
        if(query_str[begin:begin+len(subString)] != subString and begin_flag):
            begin += 1
            end += 1
            continue
        else:
            begin_flag = False

        if(begin_flag == False and query_str[end+len(subString)] != endChar):
            end += 1
        else:
            end_flag = False
    if begin == end:
        raise(error)

    return query_str[begin+len(subString):end+len(subString)],end

def findString(query_str,begin_symbol,end_symbol,begin=0,end=0):
    begin_flag = True
    end_flag = True
    while((begin_flag or end_flag) and end+len(begin_symbol) < len(query_str)):
        if(query_str[begin:begin+len(begin_symbol)] != begin_symbol and begin_flag):
            begin += 1
            end += 1
            continue
        else:
            begin_flag = False

        if(begin_flag == False and query_str[end+len(begin_symbol)] != end_symbol):
            end += 1
        else:
            end_flag = False

    if begin == end:
        raise(error)

    return end

def get_nextDNSfromAuth(res_str):
    auth_end_pos = findString(res_str,"AUTHORITY SECTIO",":")
    dns_query_webName,endd_pos = get_middle(res_str,"NS      ","\n",auth_end_pos,auth_end_pos)
    return dns_query_webName

def get_nextDNSfromANS(res_str):
    end_pos= findString(res_str,"ANSWER SECTIO",":")
    webAddress,end_pos = get_middle(res_str,"IN      A       ","\n",end_pos,end_pos)
    return webAddress

def getCNAME(res_str):
        end_pos = findString(res_str,"ANSWER SECTIO",":")
        cname, end_p = get_middle(res_str,"IN      CNAME   ","\n",end_pos,end_pos)
        return cname

def iterative_query(query,cname,qid):
    webAddress = None
    former = query
    timeout = True
    # query root DNS
    a = query.send("202.12.27.33",timeout=5)
    print("via: ","202.12.27.33")
    response = DNSRecord.parse(a)
    response_str = str(response)
    ans = int(response.header.a)
    query_webName = str(response.q.qname)
    while(ans == 0):#no answer section
        timeout = True
        try:
            addi_end_pos = findString(response_str,"ADDITIONAL SECTIO",":")
            next_dns,end_pos = get_middle(response_str,"IN      A       ","\n",addi_end_pos,addi_end_pos)
            print("via: ",next_dns)
        except:
            q = DNSRecord.question(get_nextDNSfromAuth(response_str))
            q.header.id = qid
            next_dns,a,cname= iterative_query(q,cname,qid)
            que = DNSRecord.parse(a)
            que.q.qname = str(former.q.qname)
            a = bytes(DNSRecord.pack(que))
            print("via: ",next_dns)
        while(timeout):
            try:
                a = query.send(next_dns,timeout=3)
                timeout = False
            except:
                print("via: ",get_middle(response_str,"IN      A       ","\n",end_pos,end_pos)[0])
        response = DNSRecord.parse(a)
        response_str = str(response)
        ans = int(response.header.a)
        query_webName = str(response.q.qname)

    #find answer section
    if ans > 0:
        try:#find ip
            webAddress = get_nextDNSfromANS(response_str)
        except:#find cname
            cname += query_webName + ":"
            pureCNAME = getCNAME(response_str)
            cname += pureCNAME + ","
            print("CNAME: " + pureCNAME)     
            q = DNSRecord.question(pureCNAME)
            q.header.id = qid
            webAddress,a,cname = iterative_query(q,cname,qid)
    return webAddress,a,cname

if __name__ == "__main__":
    # create a cache to store ip and query
    Local_DNS_cache = {}
    Local_DNS_record = {}
    # create socket and bind to port 1234 of localhost
    serverSocket = socket.socket(AF_INET,SOCK_DGRAM)
    serverSocket.bind(("127.0.0.1",1234))

    flag = int(input("please enter flag (1 or 0): "))
    #query
    while(1):
        cname = ""
        # get dns query from client
        message,clientAddress = serverSocket.recvfrom(2048)
        # get qid,query_webName
        query = DNSRecord.parse(message)
        qid = query.header.id
        query_webName = query.q.qname
        # check cache
        webAddress = Local_DNS_cache.get(query_webName)
        if None != webAddress:
            print("get it from cache:" + webAddress)
            a = Local_DNS_record[query_webName]
            q = DNSRecord.parse(a)
            q.header.id = qid
            q.header.ra = 1
            a = bytes(DNSRecord.pack(q))
        # cache miss
        else:
            # flag = 0, ask public server
            if flag == 0:
                a = query.send("8.8.8.8")
                query = DNSRecord.parse(a)
                for rr in query.rr:
                    if rr.rtype == QTYPE.A:
                        webAddress = rr.rdata
                        break
            # flag = 1, do iterative query
            else:
                webAddress , a , cname = iterative_query(query,cname,qid)
            # load web ip into cache
            Local_DNS_cache[query_webName] = webAddress 
            #create response
            return_ans = DNSRecord.question(str(query.q.qname))
            cname_list = cname.split(",")
            #add cname
            cname = ""
            num_ans = 0
            for item in cname_list:
                if item != "":
                    items = item.split(":")
                    return_ans.add_answer(*RR.fromZone(items[0]+ " CNAME "+items[1]))
                    num_ans += 1
            #add answer
            for i in (DNSRecord.parse(a)).rr:
                return_ans.add_answer(*RR.fromZone(str(i)))
                num_ans += 1
            return_ans.header.ra = 1
            return_ans.header.aa = num_ans
            return_ans.header.id = qid
            a = bytes(DNSRecord.pack(return_ans))
            Local_DNS_record[query_webName] = a
    
        serverSocket.sendto(a,clientAddress)  
        print("The ip address for ",query_webName," is ",webAddress)      
