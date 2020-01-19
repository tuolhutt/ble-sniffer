#!/usr/bin/env python
# -*- coding: utf-8 -*-

from subprocess import Popen,PIPE
import time,json,os,commands

hci = "hci0"
homeFile="home.conf"

tcSensors,tcSensors2 = [[],[]]

command = ['sudo', 'hcidump', '-i', hci, '--raw']
command2 = "sudo hcitool -i "+hci+" lescan --whitelist --duplicates > /dev/null &"


def main():
    global homeFile
    
    try:
        if hciStart()!=0:
            rjson=readjson(homeFile)
            if rjson!=0:
                jsonMacListMake(rjson["tempsensors"],tcSensors,tcSensors2)
                
                whitelistMake(tcSensors)
                os.system(command2)
                print timePrint()+" "+"lescan started."
                
                rawdump=startScan(command)
                if rawdump!=0:
                    print timePrint()+" "+"rawdump started."
                    sniffer(rawdump)
    except Exception,e:
        print timePrint()+" "+"Error in main(): "+str(e)
    finally:
        os.system("sudo pkill --signal SIGINT hcitool")
        print timePrint()+" "+"hcitool killed."


def jsonMacListMake(js,macs,macs2):
    keys=js.keys()
    keys.sort()
    for i in range(len(keys)):
        apu2=js[keys[i]]["id"]
        apu3=apu2.split(":")
        if len(apu2)==17 and len(apu3)==6:
            macs.append(apu2)
            macs2.append(" ".join(list(reversed(apu3))))
        else:
            print timePrint()+" "+apu2+" false mac."
    return 1


def whitelistMake(tsList):
    try:
        os.system("sudo hcitool lewlclr")
        print timePrint()+" "+"Whitelist cleared."
        for mac in tsList:
            if len(mac)==17:
                os.system("sudo hcitool lewladd --random "+mac)
                print timePrint()+" "+mac+" added to whitelist."
            else:
                print timePrint()+" "+mac+" false mac."
        print timePrint()+" "+"Whitelist ok."
    except Exception,e:
        print timePrint()+" "+"Error in whitelistMake(): "+str(e)
        return 0


def hciStart():
    try:
        if "UP RUNNING" not in commands.getstatusoutput('hciconfig '+hci)[1]:
            i=0
            while "DOWN" not in commands.getstatusoutput('hciconfig '+hci)[1]:
                print timePrint()+" "+hci+" RESTARTING"
                i+=1
                if i==30:
                    os.system("sudo /etc/init.d/bluetooth restart && sudo hciconfig "+hci+" up")
                    i=0
                time.sleep(10)
            if "UP RUNNING" not in commands.getstatusoutput('hciconfig '+hci)[1]:
                print timePrint()+" "+hci+" UP RUNNING"
        return 1
    except Exception,e:
        print timePrint()+" "+"Error in hciStart(): "+str(e)
        return 0


def readjson(file):
    ret=0
    try:
        with open(file) as json_data:
            ret=json.load(json_data)
    except Exception,e:
        print timePrint()+" "+"Error in readjson(): "+str(e)
        return 0
    return ret


def startScan(cmd):
    try:
        scan = Popen(cmd, stdout=PIPE, bufsize=1)
        return scan
    except Exception,e:
        print timePrint()+" "+"Error in startScan(): "+str(e)
    return 0


def timeNow(): # in milliseconds
    return long(round(time.time() * 1000))


def timePrint():
    return time.strftime('%Y-%m-%d_%H:%M:%S')


def parseTH(s):
    temp,humi,pres,accx,accy,accz,bat=[999,999,999,999,999,999,999]
    
    try:
        a=s.find("04 03 ")
        a2=s[a+6:].split(" ")
        
        #humidity
        humi=int(a2[0],16)/2.0
        
        #temperature
        t1,t2=[int(a2[1],16),int(a2[2],16)/100.0]
        if t1<128:
            temp=t1+t2
        else:
            temp=-1*(t1-128+t2)
        
        #pressure
        pres=(int(a2[3]+a2[4],16)+50000)/100.0
        
        #acceleration
        accx=int(a2[5]+a2[6],16)
        if accx>32000:
            accx-=65536
        accx=accx/1000.0
        accy=int(a2[7]+a2[8],16)
        if accy>32000:
            accy-=65536
        accy=accy/1000.0
        accz=int(a2[9]+a2[10],16)
        if accz>32000:
            accz-=65536
        accz=accz/1000.0
        
        #battery
        bat=int(a2[11]+a2[12],16)/1000.0
        
    except Exception,e:
        print timePrint()+" "+"Error in parseTH(): "+str(e)
    
    return temp,humi,pres,accx,accy,accz,bat


def sniffer(scan):
    print timePrint()+" "+"Sniffer started."
    while True:
        try:
            line=unicode(scan.stdout.readline(), "utf-8")
            if line.startswith(">"):
                while True:
                    line2=unicode(scan.stdout.readline(), "utf-8")
                    if line2.startswith(">"):
                        line=line2
                    else:
                        line+=line2
                        break
        except Exception,e:
            print timePrint()+" "+"Error in sniffer-loop: "+str(e)
            line=""
            time.sleep(0.1)
        if "04 3E 25 02 01 03 01" in line:
            for i in range(len(tcSensors)):
                if tcSensors2[i] in line:
                    temp,humi,pres,accx,accy,accz,bat=parseTH(line)
                    print tcSensors[i]
                    print "t:"+str(temp)+" h:"+str(humi)+" p:"+str(pres)+" ax:"+str(accx)+" ay:"+str(accy)+" az:"+str(accz)+" b:"+str(bat)
                    break



if __name__ == "__main__":
    main()
