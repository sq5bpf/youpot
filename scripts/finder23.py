#!/usr/bin/python3

# dumb script to get interesting ssh and telnet sessions from the youpot logs
# it puts them in /home/youpot/youpot/find23 and marks the source directory by creating a file named 'processed' so that it is not scanned again
#
# Jacek Lipkowski <sq5bpf@lipkowski.org>
# Licensed GPLv3

import os
import json
import sys
import string 
import sys
import shutil

# just make an empty file
def touch(f):
    open(f, 'a').close()

# process ssh mitm logs
def process_sshmitm(d):
    f=d+"/ssh_mitm.log"
    interesting=False

    try:

        with open(f, mode="r", encoding="utf-8") as j:
            for l in j.readlines():
                p=json.loads(l)
                if "Remote authentication succeeded" in p["message"]:
                    interesting=True
                if interesting:
                    print(p["message"])
    except:
        pass
        # btw: if we get a json parse error later on, then we still copy, this is often due to ssh_mitm error

    if interesting:
        touch(d+"/processed")
        b=f.split("/")
        dstdir="/home/youpot/youpot/find23"

        dstpath=dstdir+"/sshmitm_"+b[-4]+"_"+b[-3]+"_"+b[-2]
        shutil.copytree(d,dstpath, ignore = shutil.ignore_patterns('hexdump.log','textdump.log'))

 

    


#strip telnet negotiation
def striptelnet(s):
    o=""
    skip=0
    for x in s:
        if skip>0:
            skip-=1
            #print("skip",hex(ord(x)))
            o="" # yes i know negotiation can be after some strings are sent, but let's ignore that for now
            continue
        if x=="\xff":
            skip=2 #yes i know that the negotiation can be more that 3 chars each, let's ignore that too
            #print("skip IAC",hex(ord(x)))
            continue
        else:
            #print("hex:",hex(ord(x)),x)
            o+=x
    return(o)


# try to interpret this as a telnet session, try to extract login/pass and the session if it exists using very broken heuristics
def process_telnet(dd):
    STATE_BEGIN=0
    STATE_USER=1
    STATE_PASSWORD=2
    STATE_AFTERPASS=3
    prompt=""
    user=""
    state=STATE_BEGIN
    interesting=False
    blocks_afterpass=0
    textclient=""
    textserver=""
    wasprompt=False

    f=dd+"/connection.json"
    t=dd+"/textdump.log"
    with open(f, mode="r", encoding="utf-8") as j:
        try:
            d=json.load(j)
        except:
            print("*********  ERROR loading",f)
            return

    if not d:
        return
    for p in d["packets"]:
        #pr = ''.join(filter(lambda x: x in string.printable, p["data"]))
        pr = striptelnet(p["data"])
        prl= pr.lower()
        #print(pr)
        if  p["fromclient"]:
            if state==STATE_USER or state==STATE_PASSWORD:
                user+=pr
                if user.count('\n')>1:

                    if not wasprompt:
                        #print("file:",f)
                        wasprompt=True

                    #print("prompt:",prompt, "user input:[",user.replace('\n','  |  ').replace('\r','').replace('\0',''),"]")
                    state=STATE_AFTERPASS

        else:
            if not prompt and len(pr.strip())>5:
                prompt=pr.strip()
            if state==STATE_BEGIN:
                if "login" in prl or "username" in prl:
                    state=STATE_USER
                elif "password" in prl:
                    state=STATE_PASSWORD
            elif state==STATE_AFTERPASS:
                if "authorization failed" in prl or "password is incorrect" in prl:
                    textserver+="*** INCORRECT ***"
                    blocks_afterpass=0
                    state=STATE_BEGIN
                if "login" in prl or "username" in prl:
                    blocks_afterpass=0
                    state=STATE_BEGIN

        if state==STATE_AFTERPASS:
            blocks_afterpass+=1
            if  p["fromclient"]:
                textclient+=p["data"].replace('\r','')
            else:
                textserver+=p["data"].replace('\r','')


    if blocks_afterpass>5:
        touch(dd+"/processed")

        b=f.split("/")
        dstdir="/home/youpot/youpot/find23"

        # maybe just copytree here?

        dstpath=dstdir+"/connection_"+b[-4]+"_"+b[-3]+"_"+b[-2]+".json"
        shutil.copyfile(f,dstpath)
        shutil.copyfile(t,dstdir+"/textdump_"+b[-4]+"_"+b[-3]+"_"+b[-2]+".log")



        print("###########  Interesting session:",d["info"]["ip"]+" "+str(d["info"]["dstport"])+"/tcp\nfileorig: "+f+"\nfile: "+dstpath+"\n"+user, "\n\n\n***** client:\n",textclient,"\n***** server:\n",textserver)
            
  

l=0
for x in os.walk("/home/youpot/youpot/log"):
    if "connection.json" in x[2] and not "processed" in x[2]:
        #print(x[0])
        process_telnet(x[0])
        process_sshmitm(x[0])
        l+=1

