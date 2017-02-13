/*
* Copyright (C) 2014 MediaTek Inc.
* Modification based on code covered by the mentioned copyright
* and/or permission notice(s).
*/
/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _COMMANDLISTENER_H__
#define _COMMANDLISTENER_H__

#include <sysutils/FrameworkListener.h>
#include "utils/RWLock.h"

#include "NetdCommand.h"
#include "NetdConstants.h"
#include "NetworkController.h"
#include "TetherController.h"
#include "NatController.h"
#include "PppController.h"
#include "SoftapController.h"
#include "BandwidthController.h"
#include "IdletimerController.h"
#include "InterfaceController.h"
#include "ResolverController.h"
#include "FirewallController.h"
#include "ClatdController.h"
#include "StrictController.h"
#include "PPPOEController.h"
#include "NetInfoListener.h"
#include "ThroughputMonitor.h"
#include "ThrottleController.h"
#include "IPv6TetherController.h"
#include "PerfController.h"
#include "IpLogController.h" // Motorola, <w20580>, <2010/10/15>, <IKHALFMWK-43> / <add ip related log and tcpdump log in netd>

class CommandListener : public FrameworkListener {
public:
    CommandListener();
    virtual ~CommandListener() {}

private:
    void registerLockingCmd(FrameworkCommand *cmd, android::RWLock& lock);
    void registerLockingCmd(FrameworkCommand *cmd) {
        registerLockingCmd(cmd, android::net::gBigNetdLock);
    }

    class SoftapCmd : public NetdCommand {
    public:
        SoftapCmd();
        virtual ~SoftapCmd() {}
        int runCommand(SocketClient *c, int argc, char ** argv);
    };

    class InterfaceCmd : public NetdCommand {
    public:
        InterfaceCmd();
        virtual ~InterfaceCmd() {}
        int runCommand(SocketClient *c, int argc, char ** argv);
    };

    class IpFwdCmd : public NetdCommand {
    public:
        IpFwdCmd();
        virtual ~IpFwdCmd() {}
        int runCommand(SocketClient *c, int argc, char ** argv);
    };

    class TetherCmd : public NetdCommand {
    public:
        TetherCmd();
        virtual ~TetherCmd() {}
        int runCommand(SocketClient *c, int argc, char ** argv);
    };

    class NatCmd : public NetdCommand {
    public:
        NatCmd();
        virtual ~NatCmd() {}
        int runCommand(SocketClient *c, int argc, char ** argv);
    };

    class ListTtysCmd : public NetdCommand {
    public:
        ListTtysCmd();
        virtual ~ListTtysCmd() {}
        int runCommand(SocketClient *c, int argc, char ** argv);
    };

    class PppdCmd : public NetdCommand {
    public:
        PppdCmd();
        virtual ~PppdCmd() {}
        int runCommand(SocketClient *c, int argc, char ** argv);
    };

    // BEGIN MOTO IKHALFMWK-43 add ip related log and tcpdump log in netd
    class IpLogCmd : public NetdCommand {
    public:
        IpLogCmd();
        virtual ~IpLogCmd() {}
        int runCommand(SocketClient *c, int argc, char ** argv);
    };
    // END IKHALFMWK-43

    class BandwidthControlCmd : public NetdCommand {
    public:
        BandwidthControlCmd();
        virtual ~BandwidthControlCmd() {}
        int runCommand(SocketClient *c, int argc, char ** argv);
    protected:
        void sendGenericOkFail(SocketClient *cli, int cond);
        void sendGenericOpFailed(SocketClient *cli, const char *errMsg);
        void sendGenericSyntaxError(SocketClient *cli, const char *usageMsg);
    };

    class IdletimerControlCmd : public NetdCommand {
    public:
        IdletimerControlCmd();
        virtual ~IdletimerControlCmd() {}
        int runCommand(SocketClient *c, int argc, char ** argv);
    };

    class ResolverCmd : public NetdCommand {
    public:
        ResolverCmd();
        virtual ~ResolverCmd() {}
        int runCommand(SocketClient *c, int argc, char ** argv);

    private:
        bool parseAndExecuteSetNetDns(int netId, int argc, const char** argv);
    };

    class FirewallCmd: public NetdCommand {
    public:
        FirewallCmd();
        virtual ~FirewallCmd() {}
        int runCommand(SocketClient *c, int argc, char ** argv);
    protected:
        int sendGenericOkFail(SocketClient *cli, int cond);
        static FirewallRule parseRule(const char* arg);
        static FirewallType parseFirewallType(const char* arg);
        static ChildChain parseChildChain(const char* arg);
        // mtk03594: Support enhanced firewall @{
        static FirewallChinaRule parseChain(const char* arg);

    };

    class ClatdCmd : public NetdCommand {
    public:
        ClatdCmd();
        virtual ~ClatdCmd() {}
        int runCommand(SocketClient *c, int argc, char ** argv);
    };

    class StrictCmd : public NetdCommand {
    public:
        StrictCmd();
        virtual ~StrictCmd() {}
        int runCommand(SocketClient *c, int argc, char ** argv);
    protected:
        int sendGenericOkFail(SocketClient *cli, int cond);
        static StrictPenalty parsePenalty(const char* arg);
    };

    class NetworkCommand : public NetdCommand {
    public:
        NetworkCommand();
        virtual ~NetworkCommand() {}
        int runCommand(SocketClient* client, int argc, char** argv);
    private:
        int syntaxError(SocketClient* cli, const char* message);
        int operationError(SocketClient* cli, const char* message, int ret);
        int success(SocketClient* cli);
    };
    class Ipv6FwdCmd : public NetdCommand {
	public:
	    Ipv6FwdCmd();
	    virtual ~Ipv6FwdCmd() {}
	    int runCommand(SocketClient *c, int argc, char ** argv);
    };

    class IPv6TetherCmd : public NetdCommand {
	public:
	    IPv6TetherCmd();
	    virtual ~IPv6TetherCmd() {}
	    int runCommand(SocketClient *c, int argc, char ** argv);
    };

    class NetInfoCmd : public NetdCommand {
    public:
        NetInfoCmd();
        virtual ~NetInfoCmd() {}
        int runCommand(SocketClient *c, int argc, char ** argv);
    };

    class ThroughputCmd : public NetdCommand {
    public:
        ThroughputCmd();
        virtual ~ThroughputCmd() {}
        int runCommand(SocketClient *c, int argc, char ** argv);
    };

    class PPPOEctlCmd : public NetdCommand {
    public:
        PPPOEctlCmd();
        virtual ~PPPOEctlCmd() {}
        int runCommand(SocketClient *c, int argc, char ** argv);
    };
/*
public:
    static ThrottleController * getThrottleCtrl() {return sThrottleCtrl; }
*/

};

#endif
