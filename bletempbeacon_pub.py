#!/usr/bin/env python
# -*- coding: utf-8 -*-

from subprocess import Popen,PIPE
import time,redis,json,os,commands

hci = "hci0"
homeFile="home_pub.conf"
sensorInterval,beaconInterval = 15000L,5000L

# redis
red = redis.StrictRedis(host='localhost', port=6379, db=0)

tcSensors,tcSensors2,beacons,beacons2 = [],[],[],[]
lastRedisTempTime,lastRedisHumiTime=[],[]
lastRedisPresTime,lastRedisBatTime=[],[]
lastRedisBeacTime=[]

command = ['sudo', 'hcidump', '-i', hci, '--raw']
command2 = "sudo hcitool -i "+hci+" lescan --whitelist --duplicates > /dev/null &"


def main():
    global homeFile
    try:
        if hciStart()!=0:
            rjson=readjson(homeFile)
            if rjson!=0:
                jsonMacListMake(rjson["tempsensors"],tcSensors,tcSensors2)
                for i in range(len(tcSensors)):
                    lastRedisTempTime.append(0L)
                    lastRedisHumiTime.append(0L)
                    lastRedisPresTime.append(0L)
                    lastRedisBatTime.append(0L)
                
                jsonMacListMake(rjson["beacons"],beacons,beacons2)
                for i in range(len(beacons)):
                    lastRedisBeacTime.append(0L)
                
                whitelistMake(tcSensors,beacons)
                os.system(command2)
                print timePrint()+" "+"lescan started."
                rawdump=startScan(command)
                if rawdump!=0:
                    print timePrint()+" "+"rawdump started."
                    sniffer(rawdump)
    except Exception,e:
        print timePrint()+" Error in main(): "+str(e)
    finally:
         os.system("sudo pkill --signal SIGINT hcitool")


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


def whitelistMake(tsList,bList):
    try:
        os.system("sudo hcitool lewlclr")
        print timePrint()+" "+"Whitelist cleared."
        for mac in tsList:
            if len(mac)==17:
                os.system("sudo hcitool lewladd --random "+mac)
                print timePrint()+" "+mac+" added to whitelist."
            else:
                print timePrint()+" "+mac+" false mac."
        for mac in bList:
            if len(mac)==17:
                os.system("sudo hcitool lewladd "+mac)
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
    temp,humi=999,999
    pres,bat=999,999
    try:
        a=s.find("FF EE FF 04 01 ")
        a2=s[a+15:].split(" ")
        i=1
        while i<len(a2):
            #temperature
            if a2[i]=="01" and i+2<len(a2):
                temp=int(a2[i+1]+a2[i+2], 16)/100.0
                if temp<999 and temp>500:
                    temp-=655.35
                i+=3
            #humidity
            elif a2[i]=="04" and i+2<len(a2):
                humi=int(a2[i+1]+a2[i+2], 16)/100.0
                i+=3
            #pressure
            elif a2[i]=="05" and i+4<len(a2):
                pres=int(a2[i+1]+a2[i+2]+a2[i+3]+a2[i+4], 16)/100.0
                i+=5
            #orientation
            elif a2[i]=="06":
                i+=7
            #pir
            elif a2[i]=="07":
                i+=2
            #pir
            elif a2[i]=="08":
                i+=2
            #shock
            elif a2[i]=="09":
                i+=4
            #battery
            elif a2[i]=="0A" and i+1<len(a2):
                bat=int(a2[i+1], 16)
                i+=2
            else:
                break
    except Exception,e:
        print timePrint()+" "+"Error in parseTH(): "+str(e)
    
    return temp,humi,pres,bat


def sniffer(scan):
    global sensorInterval,beaconInterval
    print timePrint()+" "+"Sniffer started."
    while True:
        try:
            line=unicode(scan.stdout.readline(), "utf-8")
            if line.startswith(">"):
                while True:
                    tNow=timeNow()
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
        
        if "FF EE FF 04 01" in line:
            for i in range(len(tcSensors)):
                if tcSensors2[i] in line:
                    tNow=timeNow()
                    temp,humi,pres,bat=parseTH(line)
                    if temp!=999 and lastRedisTempTime[i]+sensorInterval<tNow:
                        print timePrint()+" "+tcSensors[i]+" temp:"+str(temp)
                        red.set(tcSensors[i]+"-temp",str(temp))
                        lastRedisTempTime[i]=tNow
                    if humi!=999 and lastRedisHumiTime[i]+sensorInterval<tNow:
                        print timePrint()+" "+tcSensors[i]+" humi:"+str(humi)
                        red.set(tcSensors[i]+"-humi",str(humi))
                        lastRedisHumiTime[i]=tNow
                    if pres!=999 and lastRedisPresTime[i]+sensorInterval<tNow:
                        print timePrint()+" "+tcSensors[i]+" pres:"+str(pres)
                        red.set(tcSensors[i]+"-pres",str(pres))
                        lastRedisPresTime[i]=tNow
                    if bat!=999 and lastRedisBatTime[i]+sensorInterval<tNow:
                        print timePrint()+" "+tcSensors[i]+" batt:"+str(bat)
                        red.set(tcSensors[i]+"-bat",str(bat))
                        lastRedisBatTime[i]=tNow
                    break



if __name__ == "__main__":
    main()
