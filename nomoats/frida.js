/*
 *  This file is part of AutoLabel <http://athinagroup.eng.uci.edu/projects/autolabel/>.
 *  Copyright (C) 2019 Anastasia Shuba, University of California, Irvine.
 *
 *  AutoLabel is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation version 2 of the License only.
 *
 *  AutoLabel is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with AutoLabel.  If not, see <http://www.gnu.org/licenses/>.
 */
 
// Definitions from socket.h
const AF_INET = 2;
const AF_INET6 = 10;

const SOL_SOCKET = 1;
const SO_TYPE = 3;
const SOCK_STREAM = 1;
const SOCK_DGRAM = 2;

/** int, uint32, and socklent_t size in bytes - on arm architecture */
const INT_SIZE = 4;

/** Socket address size in bytes - see <netinet/in.h> */
const SOCK_ADDR_SIZE = 16;

/** IPv6 socket address size in bytes - see <netinet/in6.h> */
const SOCK_ADDR6_SIZE = 28;

/** Pointer to function for determining IP level */
const getPeerNamePtr = Module.findExportByName("libc.so", "getpeername");
/** Function for determining IP level. Based on the C function signature:
  * int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
  * socklent_t is unit32 in our arch
  */
const getPeerName = new NativeFunction(getPeerNamePtr, 'int', ['int', 'pointer', 'pointer']);

/** Pointer to function for determining TCP vs. UDP sockets */
const getSockTypePtr = Module.findExportByName("libc.so", "getsockopt");

/** Function for determining TCP vs. UDP sockets */
const getSockType = new NativeFunction(getSockTypePtr, 'int', ['int', 'int', 'int', 'pointer', 'pointer']);

/** OpenSSL library used by Android */
const libSSL = "libssl.so";
exports.libSSL = libSSL;

/** The SSL function used for outgoing packets */
const sslWrite = "SSL_write";
exports.sslWrite = sslWrite;

/** Stores the Java Thread class - used to get stack traces */
var JAVA_THREAD;

const TYPE_STOP = "stop";
const TYPE_INFO = "info";
const TYPE_DATA = "data";

function init(JavaThread) {
    JAVA_THREAD = JavaThread;
}
exports.init = init;

/** Object for communication with Python */
function PythonMsg(type) {
    this.type = type;
}
exports.PythonMsg = PythonMsg;

/**
 * Stops the Python process early
 */
function stopPython(reason) {
    var stopMessage = new PythonMsg(TYPE_STOP);
    stopMessage.reason = reason;
    send(stopMessage);
}
exports.stopPython = stopPython;

/**
 * Sends a message of TYPE_INFO to Python
 */
function sendInfoToPython(info) {
    var message = new PythonMsg(TYPE_INFO);
    message.info = info;
    send(message);
}
exports.sendInfoToPython = sendInfoToPython;

/**
 * Extracts information about the socket based on the provided fd 
 * and sends info to the Python process
 */
function sendToPython(sockFd, packet, packetSize, caller, context) {      
    // Pointer to address size
    const lenPtr = Memory.alloc(INT_SIZE);
    Memory.writeInt(lenPtr, SOCK_ADDR6_SIZE);
    
    // Pointer to socket addr
    const sockAddrPtr = Memory.alloc(SOCK_ADDR6_SIZE);
    
    var ret = getPeerName(sockFd, sockAddrPtr, lenPtr);
    
    // We only care about IPv6 and IPv4 communication
    var ipLevel = Memory.readU16(sockAddrPtr);
    if (ipLevel != AF_INET6 && ipLevel != AF_INET)
        return;
    
    // Check for errors
    if (ret != 0 || 
        (ipLevel == AF_INET6 && Memory.readInt(lenPtr) != SOCK_ADDR6_SIZE)  ||
        (ipLevel == AF_INET && Memory.readInt(lenPtr) != SOCK_ADDR_SIZE)) {
        const logMsg = "ERROR: length value = " + Memory.readInt(lenPtr) + 
                        " for ip level = " + ipLevel;
        console.log(logMsg);
        console.log(hexdump(sockAddrPtr, {
            offset: 0,
            length: SOCK_ADDR6_SIZE,
            header: true,
            ansi: true
        }));
        console.log("message:");
        console.log(hexdump(packet, {
            offset: 0,
            length: packetSize,
            header: true,
            ansi: true
        }));
        
        stopPython(logMsg);
        
        return;
    }

    // Now determine if this is TCP or UDP
    const typePtr = Memory.alloc(INT_SIZE);
    Memory.writeInt(lenPtr, INT_SIZE);
    getSockType(sockFd, SOL_SOCKET, SO_TYPE, typePtr, lenPtr);
    if (Memory.readInt(typePtr) != SOCK_STREAM) {
        // Non-TCP socket, write handlers later if needed
        stopPython("WARNING: Non-TCP stream: " + Memory.readInt(typePtr));
        return;
    }

    const sendData = preparePythonData(ipLevel, sockAddrPtr, packet, packetSize);
    
    var traceStr = caller + "\n";
    
    var traceArr;
    var threadName;
    Java.perform(function() {          
        traceArr = JAVA_THREAD.currentThread().getStackTrace();
        threadName = JAVA_THREAD.currentThread().getName();
    });
    
    // If we couldn't get the Java trace, attempt to get the native trace
    const traceWrapIdx = 2;
    if (traceArr != null && traceArr.length > traceWrapIdx) {
        traceStr += "Java trace:\n"
        for (var i = traceWrapIdx; i < traceArr.length; i++)
            traceStr += traceArr[i] + "\n";
    } else {
        // Note: we could use backtrace here, but it's usually not printing anything useful
        traceStr += "Thread name: " + JAVA_THREAD.currentThread().getName() + "\n";
    } 
    
    var message = new PythonMsg(TYPE_DATA);
    message.ip_level = ipLevel;
    message.trace = traceStr;
    send(message, sendData);
}

/**
 * Packages the packet data, IP address and port number for binary sending to Python
 */
function preparePythonData(ipLevel, sockAddrPtr, packet, packetSize) {   
    // Skip family - 2 bytes, and read 2-byte long port number. This format is the same in
    // both IP struct sockaddr_in (http://man7.org/linux/man-pages/man7/ip.7.html)
    // and IPv6 struct sockaddr_in6 (http://man7.org/linux/man-pages/man7/ipv6.7.html)
    var u16SizeBytes = 2;
    var portBytes = Memory.readByteArray(sockAddrPtr.add(u16SizeBytes), u16SizeBytes);

    // IPv6 case: address is 16 bytes long
    var addrSizeBytes = 16;
    // IPv6 case: skip family (u16), port (u16), and flow info (u32) --> 8 bytes
    var byteSkip = 8;
    
    if (ipLevel == AF_INET) {
        // IPv4 case: address is 4 bytes long
        var addrSizeBytes = 4;
        // IPv4 case: skip family (u16) and port (u16) --> 4 bytes
        var byteSkip = 4;
    }
    
    // Read off IP address
    var ipBytes = Memory.readByteArray(sockAddrPtr.add(byteSkip), addrSizeBytes);
    
    var sendData = new Uint8Array(u16SizeBytes + addrSizeBytes + packetSize);
    sendData.set(portBytes, 0);
    sendData.set(ipBytes, u16SizeBytes);
    sendData.set(Memory.readByteArray(packet, packetSize), u16SizeBytes + addrSizeBytes);
    
    return sendData;
}

/** Pointer for function for getting fd of an SSL object */
const getSSLwfdPtr = Module.findExportByName("libssl.so", "SSL_get_wfd");

/** Function for getting fd of an SSL object. Based on the C function signature:
  * int SSL_get_wfd(const SSL *ssl) */
const getSSLwfd = new NativeFunction(getSSLwfdPtr, 'int', ['pointer']);

/** Callback for intercepting int SSL_write(SSL *ssl, const void *buf, int num); */
function SSLcallback(funcName) {
    this.funcName = funcName;

    this.onEnter = function (args) {
        this.ssl = args[0];
        this.sslPkt = args[1];
    };

    this.onLeave = function (retval) {
        if (retval <= 0)
            return; // no bytes were written
        
        var sockFd = getSSLwfd(this.ssl);
        if (sockFd < 0) {
            sendInfoToPython("ERROR: could not get SSL fd. Return value = " + sockFd);
            return;
        }
        
        sendToPython(sockFd, this.sslPkt, retval.toInt32(), funcName, this.context);
    };
};
exports.SSLcallback = SSLcallback;
    
const libc = "libc.so";
const sendto = "sendto";
const write = "write";

/** Callback for intercepting sendto */
function SendtoCallback(funcName) {
    this.funcName = funcName;
    
    this.onEnter = function (args) {      
        //console.log("Write called");
        this.sockFd = args[0].toInt32();
        this.packet = args[1];
    };
    
    this.onLeave = function (retval) {
        if (retval == -1)
            return;
        
        sendToPython(this.sockFd, this.packet, retval.toInt32(), funcName, this.context);
    };
};

Interceptor.attach(Module.findExportByName(libc, sendto), new SendtoCallback(libc + ":" + sendto));
Interceptor.attach(Module.findExportByName(libc, write), new SendtoCallback(libc + ":" + write));
Interceptor.attach(Module.findExportByName(libSSL, sslWrite), new SSLcallback(libSSL + ":" + sslWrite));

// TODO: eventually we probably want to use this instead:
/* Interceptor.attach(Module.findExportByName(libc, "sendmsg"), {
    onEnter: function (args) {
        stopPython("sendmsg function called");
    },
    
    onLeave: function (retval) {
    
    };
}); */
