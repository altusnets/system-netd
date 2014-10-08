/*
 * Copyright (C) 2009/2010 Motorola Inc.
 * All Rights Reserved.
 * Motorola Confidential Restricted.
 */

#ifndef _IPLOG_CONTROLLER_H
#define _IPLOG_CONTROLLER_H

class IpLogController {
    pid_t mPidList[10];
    char mIfNameList[10][16];

public:
    IpLogController();
    virtual ~IpLogController();
    int runRawCmd(int argc, char **argv);


private:
    int ipCmd();
    int ipInfoCmd(const char* fileName);//IKXLUPGRD-696
    //Moto, dbk378, 14/Oct/2013, IKJBMR2-5601:
    //Data Partition getting filled up during Stability Testing
    int startTcpdump(const char *iface, char *packetSize, char *fileName, char *totalPackets);
    int stopTcpdump(const char *pid);
    int doIpCommands(const char *cmd);
    char* getDefaultPcapFileName(char* fileNameBuff, int buffSize);
    char* getDate(char* dateBuff, int buffSize);
};

#endif
