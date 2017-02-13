/*
 * Copyright (C) 2009/2010 Motorola Inc.
 * All Rights Reserved.
 * Motorola Confidential Restricted.
 */

#include <dirent.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <dirent.h>
#include <cutils/properties.h>
#include <time.h>
#include <string.h>
#include "IpLogController.h"

#define LOG_TAG "IpLogController"
#include <cutils/log.h>
#include <logwrap/logwrap.h>

#include "NetdConstants.h"

IpLogController::IpLogController() {
    for (int index=0; index<10; index++) {
        mPidList[index] = -1;
    }
}

IpLogController::~IpLogController() {
}

int IpLogController::runRawCmd(int argc, char **argv) {
    ALOGD("%s",__FUNCTION__);
    int rc = 0;

    if (argc < 2) {
        ALOGE("Missing argument");
        return -1;
    }
    if (!strcmp(argv[1], "ip")) {
        rc = ipCmd();
    //BEGIN, e7976c, IKXLUPGRD-696, trigger ipInfo script to collect ip information
    } else if (!strcmp(argv[1], "ipInfo")) {
       if (argc != 3) {
            ALOGE("Missing argument");
            return -1;
        }
        rc = ipInfoCmd(argv[2]);
    //END,IKXLUPGRD-696
    //BEGIN,mot,e7976c,04/04/2015,IKSWL-6859,add rule for log packets
    }  else if (!strcmp(argv[1], "logPackets")) {
       if (argc != 3) {
            ALOGE("Missing argument");
            return -1;
        }
        rc = logPackets(!strcmp(argv[2], "1"));
    //END,IKSWL-6859
    } else if (!strcmp(argv[1], "tcpdump")) {
        if (!strcmp(argv[2], "start")) {
            if (argc < 6) {
                ALOGE("tcpdump log, Missing argument");
                return -1;
            }
            char fileName[100];
            char packetSize[32];
            //BEGIN Moto, dbk378, 14/Oct/2013, IKJBMR2-5601:
            //Data Partition getting filled up during Stability Testing
            char totalPackets[20];
            strncpy(packetSize, argv[4], 32);
            strncpy(fileName, argv[5], 100);
            if (argc > 6) {
                strncpy(totalPackets, argv[6], 20);
                rc = startTcpdump(argv[3],packetSize,fileName, totalPackets);
            } else {
                rc = startTcpdump(argv[3],packetSize,fileName, NULL);
            }
            //END IKJBMR2-5601
        } else if (!strcmp(argv[2], "stop")) {
            if (argc < 4) {
                ALOGE("tcpdump log, Missing argument");
                return -1;
            }
            rc = stopTcpdump(argv[3]);
        } else {
            ALOGE("Unsupported tcpdump cmd: %s", argv[2]);
            return -1;
        }
    } else {
        ALOGE("Unsupported iplog cmd: %s", argv[2]);
        return -1;
    }
    return rc;
}
char* IpLogController::getDefaultPcapFileName(char* fileNameBuff, int buffSize) {
    char date[64];
    snprintf(fileNameBuff, buffSize, "/data/tmp/T_%s.pcap", getDate(date, 64));
    return fileNameBuff;
}
char* IpLogController::getDate(char* dateBuff, int buffSize) {
    time_t t = time(0);
    strftime(dateBuff, buffSize, "%Y-%m-%d_%H_%M_%S",localtime(&t));
    return dateBuff;
}

//BEGIN, e7976c, IKXLUPGRD-696, trigger ipInfo script to collect ip information
int IpLogController::ipInfoCmd(const char* fileName) {
    ALOGD("%s",__FUNCTION__);
    pid_t pid;
    if ((pid = fork()) < 0) {
        ALOGE("fork failed (%s)", strerror(errno));
        return -1;
    }
    if (!pid) { //Child
        ALOGD("In child, run ipInfoCmd, logfile = %s.", fileName);
        if (execl("/system/bin/ipInfo", "ipInfo", fileName, NULL)) {
            ALOGE("execl failed (%s)", strerror(errno));
        }
        ALOGE("Should never get here!");
        return 0;
    } else { //Parent
        ALOGD("In parent, pid = %d.", pid);
        waitpid(pid, NULL, 0);
        ALOGD("In parent, child exit");
    }
    return 0;
}
//END,IKXLUPGRD-696

int IpLogController::ipCmd() {
    ALOGD("%s",__FUNCTION__);
    doIpCommands("addr");
    doIpCommands("route");
    return 0;
}

//BEGIN Moto, dbk378, 14/Oct/2013, IKJBMR2-5601:
//Data Partition getting filled up during Stability Testing
int IpLogController::startTcpdump(const char *iface,
                                  char *packetSize,
                                  char *fileName,
                                  char *totalPackets) {
    ALOGD("%s",__FUNCTION__);
    char* ifName = NULL;
    pid_t pid;
    int index = 0;

    if ((iface == NULL) || (iface[0] == 0)) {
        ALOGE("No interface name, fail.");
        errno = -EINVAL;
        return -1;
    }
    for (index=0; index<10; index++) {
        if (mPidList[index] < 0) {
            ifName = mIfNameList[index];
            break;
        }
    }
    if (ifName == NULL) {
        ALOGE("can not support more tcpdump session.");
        return -1;
    }
    DIR *path;
    char pathName[100];
    char* pIndex = strrchr(fileName, '/');
    if (pIndex != NULL) {
        int len = pIndex - fileName;
        strncpy(pathName, fileName, len);
        pathName[len] = 0;
    } else {
        ALOGE("file name is wrong:%s", fileName);
        return -1;
    }
    path = opendir(pathName);
    if (path == NULL) {
        ALOGE("file path not exist:%s", pathName);
        return -1;
    }
    closedir(path); //IKJBREL1-9111 moto w20079, Oct 10, 2012
    strncpy(ifName, iface, 15);
    ifName[15] = 0;
    ALOGD("ifName = %s.", ifName);
    if ((pid = fork()) < 0) {
        ALOGE("fork failed (%s)", strerror(errno));
        return -1;
    }
    if (!pid) { //Child
        char logfile[100];
        strncpy(logfile, fileName, 100);
        ALOGD("In child, run tcpdump, logfile = %s.", logfile);
        if (totalPackets != NULL && totalPackets > 0) {
             ALOGD("In child, run tcpdump, totalPackets = %s", totalPackets);
             if (execl("/system/xbin/tcpdump", "tcpdump", "-i", ifName, "-c", totalPackets, "-s", packetSize, "-w", logfile, NULL)) {
                ALOGE("execl failed (%s)", strerror(errno));
            }
        } else {
            if (execl("/system/xbin/tcpdump", "tcpdump", "-i", ifName, "-s", packetSize, "-w", logfile, NULL)) {
                ALOGE("execl failed (%s)", strerror(errno));
            }
        }
        ALOGE("Should never get here!");
        return 0;
    } else { //Parent
        mPidList[index] = pid;
        ALOGD("In parent, pid = %d.", pid);
        usleep(500000); //sleep 0.5s to wait for tcpdump start.
    }
    return pid;
}
//END IKJBMR2-5601

int IpLogController::stopTcpdump(const char* pid) {
    ALOGD("%s",__FUNCTION__);
    int index = 0;
    for (index=0; index<10; index++) {
        if (mPidList[index] == atoi(pid)) {
            break;
        }
    }
    if (index >= 10) {
        ALOGE("not find the pid %s", pid);
        return 0;
    }
    ALOGD("Stopping Tcpdump service on interface %s", mIfNameList[index]);
    kill(mPidList[index], SIGTERM);
    waitpid(mPidList[index], NULL, 0);
    ALOGD("Tcpdump service on pid %d stopped", mPidList[index]);
    mPidList[index] = -1;
    return 0;
}

int IpLogController::doIpCommands(const char *cmd) {
    ALOGD("%s",__FUNCTION__);
    pid_t pid;

    if ((pid = fork()) < 0) {
        ALOGE("fork failed (%s)", strerror(errno));
        return -1;
    }

    if (!pid) { //Child
        char logfile[64];
        int fd;
        if (strcmp(cmd, "addr") == 0) {
            sprintf((char*)logfile, "/data/tmp/netintf_current.txt");
        } else if (strcmp(cmd, "route") == 0) {
            sprintf((char*)logfile, "/data/tmp/routing_current.txt");
        } else {
            ALOGE("Unsupported ip command: ip %s.", cmd);
            return 0;
        }
        if ((fd = open(logfile, O_RDWR | O_CREAT, 0660)) == -1) { //open the file
            ALOGE("Open logfile failure.");
            return 0;
        }
        dup2(fd, STDOUT_FILENO); //copy the file descriptor fd into standard output
        dup2(fd, STDERR_FILENO); // same, for the standard error
        close(fd); // close the file descriptor as we don't need it more
        ALOGD("In child, run ip command: ip %s, logfile: %s.", cmd, logfile);
        if (execl("/system/bin/ip", "ip", cmd, NULL)) {
            ALOGE("execl failed (%s)", strerror(errno));
        }
        ALOGE("Should never get here!");
        return 0;
    } else { //Parent
        ALOGD("In Parent.");
        waitpid(pid, NULL, 0);
    }
    return 0;
}
//BEGIN,mot,e7976c,04/04/2015,IKSWL-6859,add rule for log packets
int IpLogController::logPackets(bool enabled) {
    const char *cmd1[] = {
            IPTABLES_PATH,
            "-t",
            "raw",
            enabled ? "-A" : "-D",
            "OUTPUT",
            "-j",
            "LOG",
            "--log-level",
            "4",
            "--log-prefix",
            "ROW_OUTv4"
    };
    int ret1 = android_fork_execvp(ARRAY_SIZE(cmd1), (char **)cmd1, NULL, false, false);
    const char *cmd2[] = {
            IPTABLES_PATH,
            "-t",
            "raw",
            enabled ? "-A" : "-D",
            "PREROUTING",
            "-j",
            "LOG",
            "--log-level",
            "4",
            "--log-prefix",
            "ROW_PREv4"
    };
    int ret2 = android_fork_execvp(ARRAY_SIZE(cmd2), (char **)cmd2, NULL, false, false);
    return (ret1 || ret2);
}
//END,IKSWL-6859
