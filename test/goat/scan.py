#coding:utf-8
  
import optparse
import socket
from socket import *

def main():
    usage="%prog -H <target host> -p <target port>"
    parser=optparse.OptionParser(usage)
    parser.add_option('-H',dest='tgthost',type='string',help='target host')
    parser.add_option('-p',dest='tgtport',type='string',help='target port[s]')
    (options,args)=parser.parse_args()
    port_list=str(options.tgtport).split(',')
    for port in port_list:
        portScan(options.tgthost,int(port))

def portScan(host,port):
    try:
        sock=socket(AF_INET,SOCK_STREAM)
        sock.connect((host,port))
        print("%d/tcp open"+str(port))
        sock.close()
    except:
        print("%d/tcp close"+str(port))

if __name__=='__main__':
    main()
