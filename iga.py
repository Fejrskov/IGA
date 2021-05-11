import ipaddress,sys
import numpy as np

#https://asecuritysite.com/encryption/ffx
import ffx
#https://github.com/mjschultz/py-radix
import radix

#Init
#List entries must be ordered increasing, and two entries must not overlap
listOfNonInternetPrefixes = [
"0.0.0.0/8", #RFC 1122 Unspecified address 
"10.0.0.0/8", # RFC 1918 Private use 
"100.64.0.0/10", # RFC 6598 Carrier-grade NAT 
"127.0.0.0/8", # RFC 1122 Loopback addresses 
"169.254.0.0/16", # RFC 3927 Link-local addresses 
"172.16.0.0/12", # RFC 1918 Private use 
"192.0.0.0/24", # RFC 6890 IETF assignments
"192.0.2.0/24", #4 RFC 5737 Documentation (TEST-NET-1)
"192.168.0.0/16", # RFC 1918 Private use
"198.18.0.0/15", # RFC 2544 Benchmarking
"198.51.100.0/24", # RFC 5737 Documentation (TEST-NET-2)
"203.0.113.0/24", # RFC 5737 Documentation (TEST-NET-3)
"224.0.0.0/4", # Multicast
"240.0.0.0/4" # RFC 1112 Reserved
#"255.255.255.255/32" # RFC 1122 Limited broadcast. Is included in the 240.0.0.0/4 prefix.
]
rtree = radix.Radix()  #Radix tree for searching
minlist = [] # List of first IP in each listed prefix
maxlist = [] # List of last IP in each listed prefix
numlist = [] # List of the number of addresses in each listed prefix
numsum = 0 # Total number of non-internet IPs
prefixlistrange = range(0,len(listOfNonInternetPrefixes)-1)

for prefix in listOfNonInternetPrefixes:
    rnode = rtree.add(prefix)
    ipnet = ipaddress.IPv4Network(prefix)
    minlist.append(int(ipnet.network_address))
    maxlist.append(int(ipnet.broadcast_address))
    numlist.append(ipnet.num_addresses)
    numsum+=ipnet.num_addresses

intmax=2**32-1
rankmax=2**32-1-numsum
#Find most suitable radix for representing the max value "rankmax" with four bytes
rad = int(np.ceil(rankmax**(1/4)))
radixmax=rad**4-1
extraIPspace = ipaddress.IPv4Network("224.0.0.0/4")
extraIPspaceStart = int(extraIPspace.network_address)
extraIPspaceEnd = int(extraIPspace.broadcast_address)
key = None
c = None

#Set encryption key, input type is bytes()
def setKey(encryptionkey):
    global key
    global c
    key=encryptionkey
    c = ffx.FFX(key)

setKey(b'someGoodKey')

def printinitvalues():
    print("numsum="+str(numsum))
    print("intmax="+str(intmax))
    print("rankmax="+str(rankmax))
    print("rad="+str(rad))
    print("radixmax="+str(radixmax))
    print("extraIPspaceStart="+str(extraIPspaceStart))
    print("extraIPspaceEnd="+str(extraIPspaceEnd))

#Check if str or int is a valid Internet IP
def isInternetIP(ip):
    rnode = None
    if type(ip) is str:
        rnode = rtree.search_best(ip)
    elif type(ip) is int:
        b = ip.to_bytes(4,byteorder='big', signed=False)
        rnode = rtree.search_best(packed=b)
    else:
        raise ValueError("Input IP "+str(ip)+" is type "+str(type(ip))+". String or int is required by isInternetIP().")
    
    if rnode:
        return False
    else:
        return True

# convert int to byte array of length 4 using specified radix
def base_encoder(i,r):
    if i>radixmax:
        raise ValueError("Input value "+str(i)+" cannot be represented in radix "+str(r))
    b=[0,0,0,0]
    i,b[3] = divmod(i,r)
    i,b[2] = divmod(i,r)
    b[0],b[1] = divmod(i,r)
    return bytearray(b)

# convert byte array of length 4 using specified radix to int
def base_decoder(b,r):
    i=0
    i+=b[0]*r*r*r
    i+=b[1]*r*r
    i+=b[2]*r
    i+=b[3]
    return i

#Rank int, returns int. Raises exception if IP is non-internet or invalid
def rank(i):
    if isInternetIP(i):
        numberOfNonInternetIPsBelowInputIP = 0
        for index in prefixlistrange: #For each entry in the list of NonInternetPrefixes
            if i>maxlist[index]:
                numberOfNonInternetIPsBelowInputIP += numlist[index]
            else:
                break
        i=i-numberOfNonInternetIPsBelowInputIP
        return i
    else:
        raise ValueError("Non-internet IP: "+str(i))

#Derank int, returns int
def derank(i):
    for index in prefixlistrange: #For each entry in the list of NonInternetPrefixes
        if i>=minlist[index]:
            i += numlist[index]
        else:
            break
    valid = isInternetIP(i)
    if valid:
        return i
    else:
        raise ValueError("Deranking resulted in non-internet IP: "+str(i))

#Map encrypted int to valid internet IPs (except for a small amount that we have to map to the extraIPspace range)
def mapp(i):
    if i > rankmax:
        o = i-rankmax-1+extraIPspaceStart 
    else:
        o = derank(i)
    return o

#Unmap int from valid internet address ranges, returns int in a range suitable for decryption
def unmap(i):
    if i >= extraIPspaceStart and i <= extraIPspaceEnd:
        o = i-extraIPspaceStart+1+rankmax
        if o > radixmax:
            raise ValueError("Unmapping of extraspace IP resulted in an IP that exceeds the radixmax: "+str(o)) 
    else:
        o = rank(i)
    return o
    
#Encrypt int, returns int
def encrypt(i):
    b = base_encoder(i,rad)
    encryptedbytes = c.encrypt(rad,b)
    encryptedint = base_decoder(encryptedbytes,rad)
    return encryptedint
    
#Decrypt int, returns int
def decrypt(i):
    b = base_encoder(i,rad)
    decryptedbytes = c.decrypt(rad,b)
    decryptedint = base_decoder(decryptedbytes,rad)
    return decryptedint


#Rand and Encrypt string, returns string. Raises exception if IP is non-internet or invalid
def rankAndEncrypt(ipstring):
    unrankedint = int(ipaddress.IPv4Address(ipstring))
    rankedint = rank(unrankedint)
    encryptedint = encrypt(rankedint)
    mappedint = mapp(encryptedint)    
    encryptedip = ipaddress.IPv4Address(mappedint).exploded
    return(encryptedip)

#Decrypt and derank string, returns string
def decryptAndDerank(ipstring):
    encryptedint = int(ipaddress.IPv4Address(ipstring))
    unmappedint = unmap(encryptedint)
    decryptedrankedint = decrypt(unmappedint)
    derankedint = derank(decryptedrankedint) 
    decryptedip = ipaddress.IPv4Address(derankedint).exploded
    return(decryptedip)





# Methods used for module testing. No user serviceable parts below

from datetime import datetime

def decodeencode_test():
    now = datetime.now()
    print("Encode/decode test start: "+now.strftime("%H:%M:%S"))
    for i in range(0,radixmax+1):
        enc = base_encoder(i,rad)
        dec = base_decoder(enc,rad)
        if not (i==dec):
            raise ValueError("Encoding/decoding failed! Input: "+str(i)+", enc:"+str(enc)+", dec:"+str(dec))

def rankderank_test():
    now = datetime.now()
    print("Rank/derank test start: "+now.strftime("%H:%M:%S"))
    for i in range(0,rankmax+1):
        try:
            enc = rank(i)
        except:
            #If input is non-internet-IP, just skip it, deranking should not work anyways
            continue
        dec = derank(enc)
        if not (i==dec):
            raise ValueError("Ranking/deranking failed! Input: "+str(i)+", ranked:"+str(enc)+", deranked:"+str(dec))
    
def mapunmap_test():
    now = datetime.now()
    print("map/unmap test start: "+now.strftime("%H:%M:%S"))
    for i in range(0,radixmax+1):
        enc = mapp(i)
        dec = unmap(enc)
        if not (i==dec):
            raise ValueError("Mapping/unmapping failed! Input: "+str(i)+", mapped:"+str(enc)+", unmapped:"+str(dec))
        
def test():
    success=0
    rejected=0
    error=0
    printprogressevery=2**20
    now = datetime.now()
    print("Test start: "+now.strftime("%H:%M:%S"))
    
    for ip in range(intmax+1,0,-1):
        currenterror = False
        rankedint = 0
        encryptedint = 0
        mappedint = 0
        unmappedint = 0
        decryptedrankedint = 0
        derankedint = 0
        
        #Print progress now and then
        if (ip+1) % printprogressevery == 0:
            now = datetime.now()
            print(str(int((ip+1)/printprogressevery))+"/"+str(int((intmax+1)/printprogressevery))+
                  "\t Current time: "+now.strftime("%H:%M:%S"))

        #Perform ranking, encryption, decryption and deranking
        try:
            rankedint = rank(ip)
        except:
            rejected+=1  #This is expected when the IP is a non-internet IP
            continue
        try:
            encryptedint = encrypt(rankedint)
            mappedint = mapp(encryptedint)
            unmappedint = unmap(mappedint)
            decryptedrankedint = decrypt(unmappedint)
            derankedint = derank(decryptedrankedint) 
        except Exception as e:
            print("Error: "+str(e)) 
            currenterror = True # We do not expect this. Print as much debug info as possible.
            
        #Checks
        if ip==derankedint and rankedint==decryptedrankedint and encryptedint==unmappedint:
            success+=1
            #print("Encryption/decryption succesfull and correct: "+plainip+" -> "+encryptedip)
        else:
            error+=1
            currenterror = True
            
        if currenterror == True:
            #Create readable conveniencies

            print()
            print("Crypt/rank/map error!")           

            print("Unranked int         : "+str(ip))
            if type(ip) is int:
                plainip     = ipaddress.IPv4Address(ip).exploded
                print("Plain IP             : "+plainip)
            
            print("Ranked int           : "+str(rankedint))
            print("Encrypted int        : "+str(encryptedint))
            print("Mapped int           : "+str(mappedint))
            if type(mappedint) is int:
                encryptedip = ipaddress.IPv4Address(mappedint).exploded
                print("Encrypted IP         : "+encryptedip)

            print("Unmapped int         : "+str(unmappedint))
            print("Decrypted, ranked int: "+str(decryptedrankedint))
            print("Deranked int         : "+str(derankedint))
            if type(derankedint) is int:            
                decryptedip = ipaddress.IPv4Address(derankedint).exploded     
                print("Decrypted IP         : "+decryptedip)
            
            break
    
    print()
    print("Final Success : "+str(success) +" (expected "+str(intmax-numsum)+")")
    print("Final Rejected: "+str(rejected)+" (expected "+str(numsum)+")")
    print("Final Error   : "+str(error)   +" (expected 0)")
    now = datetime.now()
    print("Test end: "+now.strftime("%H:%M:%S"))

#decodeencode_test()
#rankderank_test()
#mapunmap_test()
#test()
