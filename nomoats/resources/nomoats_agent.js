(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
/*
 *  This file is part of NoMoATS <http://athinagroup.eng.uci.edu/projects/nomoads/>.
 *  Copyright (C) 2019 Anastasia Shuba.
 *
 *  NoMoATS is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  NoMoATS is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with NoMoATS.  If not, see <http://www.gnu.org/licenses/>.
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
  Memory.writeInt(lenPtr, SOCK_ADDR6_SIZE); // Pointer to socket addr

  const sockAddrPtr = Memory.alloc(SOCK_ADDR6_SIZE);
  var ret = getPeerName(sockFd, sockAddrPtr, lenPtr); // We only care about IPv6 and IPv4 communication

  var ipLevel = Memory.readU16(sockAddrPtr);
  if (ipLevel != AF_INET6 && ipLevel != AF_INET) return; // Check for errors

  if (ret != 0 || ipLevel == AF_INET6 && Memory.readInt(lenPtr) != SOCK_ADDR6_SIZE || ipLevel == AF_INET && Memory.readInt(lenPtr) != SOCK_ADDR_SIZE) {
    const logMsg = "ERROR: length value = " + Memory.readInt(lenPtr) + " for ip level = " + ipLevel;
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
  } // Now determine if this is TCP or UDP


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
  Java.perform(function () {
    traceArr = JAVA_THREAD.currentThread().getStackTrace();
    threadName = JAVA_THREAD.currentThread().getName();
  }); // If we couldn't get the Java trace, attempt to get the native trace

  const traceWrapIdx = 2;

  if (traceArr != null && traceArr.length > traceWrapIdx) {
    traceStr += "Java trace:\n";

    for (var i = traceWrapIdx; i < traceArr.length; i++) traceStr += traceArr[i] + "\n";
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
  var portBytes = Memory.readByteArray(sockAddrPtr.add(u16SizeBytes), u16SizeBytes); // IPv6 case: address is 16 bytes long

  var addrSizeBytes = 16; // IPv6 case: skip family (u16), port (u16), and flow info (u32) --> 8 bytes

  var byteSkip = 8;

  if (ipLevel == AF_INET) {
    // IPv4 case: address is 4 bytes long
    var addrSizeBytes = 4; // IPv4 case: skip family (u16) and port (u16) --> 4 bytes

    var byteSkip = 4;
  } // Read off IP address


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
    if (retval <= 0) return; // no bytes were written

    var sockFd = getSSLwfd(this.ssl);

    if (sockFd < 0) {
      sendInfoToPython("ERROR: could not get SSL fd. Return value = " + sockFd);
      return;
    }

    sendToPython(sockFd, this.sslPkt, retval.toInt32(), funcName, this.context);
  };
}

;
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
    if (retval == -1) return;
    sendToPython(this.sockFd, this.packet, retval.toInt32(), funcName, this.context);
  };
}

;
Interceptor.attach(Module.findExportByName(libc, sendto), new SendtoCallback(libc + ":" + sendto));
Interceptor.attach(Module.findExportByName(libc, write), new SendtoCallback(libc + ":" + write));
Interceptor.attach(Module.findExportByName(libSSL, sslWrite), new SSLcallback(libSSL + ":" + sslWrite)); // TODO: eventually we probably want to use this instead:

/* Interceptor.attach(Module.findExportByName(libc, "sendmsg"), {
    onEnter: function (args) {
        stopPython("sendmsg function called");
    },
    
    onLeave: function (retval) {
    
    };
}); */

},{}],2:[function(require,module,exports){
/*
 *  This file is part of NoMoATS <http://athinagroup.eng.uci.edu/projects/nomoads/>.
 *  Copyright (C) 2019 Anastasia Shuba.
 *
 *  NoMoATS is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  NoMoATS is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with NoMoATS.  If not, see <http://www.gnu.org/licenses/>.
 */
'use strict';

const ClassFactory = require('frida-java/lib/class-factory');

const mf = require('./frida.js');
/** Message indicating an intercepted WebView request triggered by a load */


const TYPE_WEB_INTC = "web_intc";
/** Stores the Android Log class - used to get stack traces */

var JAVA_LOG;
/** Stores the Java exception class - used to get stack traces */

var JAVA_EXCEPTION; // TODO: ideally all msg types should be in a separate module

const TYPE_LIB = "lib";
var WEB_VIEW_INIT_DONE = false;
const webViewClients = {};

function interceptRequest() {
  // Note that this only works in single process webview - must disable Chrome
  const classOfInterest = "com.android.webview.chromium.WebViewContentsClientAdapter";
  var classLoaders = Java.enumerateClassLoadersSync();
  var classLoaderToUse = null;
  const origLoader = Java.classFactory.loader;

  for (var i = 0; i < classLoaders.length; i++) {
    try {
      var res = classLoaders[i].findClass(classOfInterest); //console.log("Done: " + classLoaders[i]);

      classLoaderToUse = classLoaders[i];
      break;
    } catch (e) {
      //console.log("Exception loading class");
      continue;
    }
  }

  if (classLoaderToUse == null) {
    mf.sendInfoToPython("Could not find class loader for " + classOfInterest);
  } else {
    const customClassFactory = new ClassFactory(Java.vm);
    customClassFactory.loader = classLoaderToUse;
    const ContentsClientAdapter = customClassFactory.use(classOfInterest); // TODO: if app crashes - restart with Frida

    ContentsClientAdapter.shouldInterceptRequest.implementation = function (params) {
      //console.log("shouldInterceptRequest: " + this.mWebViewClient.value);
      const retVal = ContentsClientAdapter.shouldInterceptRequest.call(this, params); // We only care about network requests:

      const url = params.url.value.toString();

      if (!url.startsWith("http")) {
        //mf.sendInfoToPython("Skipping resource: " + url);
        return retVal;
      }

      const headersMap = params.requestHeaders.value;
      const keySet = headersMap.keySet().toArray();
      var headers = {};

      for (var i = 0; i < keySet.length; i++) headers[keySet[i]] = headersMap.get(keySet[i]).toString();

      var message = new mf.PythonMsg(TYPE_WEB_INTC);
      message.url = url;
      message.headers = headers;
      message.method = params.method.value.toString();
      if (webViewClients[this.mWebViewClient.value] == null) mf.sendInfoToPython("NO TRACE for: " + this.mWebViewClient.value);
      message.trace = webViewClients[this.mWebViewClient.value];
      send(message);
      return retVal;
    };

    WEB_VIEW_INIT_DONE = true;
  }
}
/** Process loaded native libraries */


function processNativeLib(moduleName) {
  if (Process.findModuleByName(moduleName) == null) {
    console.log("WARNING: " + moduleName + " was not loaded!");
    return;
  }

  const trace = JAVA_LOG.getStackTraceString(JAVA_EXCEPTION.$new());
  var message = new mf.PythonMsg(TYPE_LIB);
  message.lib = moduleName;
  message.trace = trace;
  message.containsSSL = false; // Check if the library contains SSL functions, and if so, attach

  var sslWriteCustom = Module.findExportByName(moduleName, mf.sslWrite);

  if (sslWriteCustom != null && !sslWriteCustom.equals(Module.findExportByName(mf.libSSL, mf.sslWrite))) {
    Interceptor.attach(sslWriteCustom, new mf.SSLcallback(moduleName + ":" + mf.sslWrite));
    mf.sendInfoToPython(moduleName + " contains SSL");
    message.containsSSL = true;
  }

  send(message);
} // Catch any early NDK libraries loading
// using performNow - see note on https://github.com/frida/frida-java/issues/89


Java.performNow(function () {
  // Prepare Java objects for future use:
  JAVA_LOG = Java.use("android.util.Log");
  JAVA_EXCEPTION = Java.use("java.lang.Exception");
  mf.init(Java.use("java.lang.Thread")); // Catch native library loading
  // TODO: possibly hook dlopen as well
  // See https://github.com/frida/frida/issues/448

  const System = Java.use('java.lang.System');
  const Runtime = Java.use('java.lang.Runtime');
  const VMStack = Java.use('dalvik.system.VMStack');

  System.load.implementation = function (pathName) {
    var loaded = false;

    try {
      loaded = Runtime.getRuntime().load0(VMStack.getStackClass1(), pathName);
    } catch (ex) {
      console.log(ex);
      return loaded;
    }

    const Java_File = Java.use("java.io.File");
    const moduleName = Java_File.$new(pathName).getName();
    processNativeLib(moduleName);
    return loaded;
  };

  System.loadLibrary.implementation = function (library) {
    var loaded = false;

    try {
      loaded = Runtime.getRuntime().loadLibrary0(VMStack.getCallingClassLoader(), library);
    } catch (ex) {
      console.log(ex);
      return loaded;
    } // Libraries get prefixed with 'lib' and suffixed with the .so extension:


    const moduleName = "lib" + library + ".so";
    processNativeLib(moduleName);
    return loaded;
  };

  const webViewClientClass = 'android.webkit.WebViewClient';
  const WebViewClient = Java.use(webViewClientClass);

  WebViewClient.$init.implementation = function () {
    const trace = JAVA_LOG.getStackTraceString(JAVA_EXCEPTION.$new());
    const res = this.$init();
    console.log("Constructor called " + this.$className + ":" + (this in webViewClients));
    webViewClients[this] = trace;
    if (!WEB_VIEW_INIT_DONE) interceptRequest();
    return res;
  };

  mf.sendInfoToPython("Java loaded");
});

},{"./frida.js":1,"frida-java/lib/class-factory":151}],3:[function(require,module,exports){
module.exports = require("core-js/library/fn/array/from");
},{"core-js/library/fn/array/from":24}],4:[function(require,module,exports){
module.exports = require("core-js/library/fn/array/is-array");
},{"core-js/library/fn/array/is-array":25}],5:[function(require,module,exports){
module.exports = require("core-js/library/fn/get-iterator");
},{"core-js/library/fn/get-iterator":26}],6:[function(require,module,exports){
module.exports = require("core-js/library/fn/number/is-integer");
},{"core-js/library/fn/number/is-integer":27}],7:[function(require,module,exports){
module.exports = require("core-js/library/fn/object/assign");
},{"core-js/library/fn/object/assign":28}],8:[function(require,module,exports){
module.exports = require("core-js/library/fn/object/create");
},{"core-js/library/fn/object/create":29}],9:[function(require,module,exports){
module.exports = require("core-js/library/fn/object/define-properties");
},{"core-js/library/fn/object/define-properties":30}],10:[function(require,module,exports){
module.exports = require("core-js/library/fn/object/define-property");
},{"core-js/library/fn/object/define-property":31}],11:[function(require,module,exports){
module.exports = require("core-js/library/fn/object/get-own-property-names");
},{"core-js/library/fn/object/get-own-property-names":32}],12:[function(require,module,exports){
module.exports = require("core-js/library/fn/object/get-prototype-of");
},{"core-js/library/fn/object/get-prototype-of":33}],13:[function(require,module,exports){
module.exports = require("core-js/library/fn/object/keys");
},{"core-js/library/fn/object/keys":34}],14:[function(require,module,exports){
module.exports = require("core-js/library/fn/object/set-prototype-of");
},{"core-js/library/fn/object/set-prototype-of":35}],15:[function(require,module,exports){
module.exports = require("core-js/library/fn/parse-int");
},{"core-js/library/fn/parse-int":36}],16:[function(require,module,exports){
module.exports = require("core-js/library/fn/reflect/construct");
},{"core-js/library/fn/reflect/construct":37}],17:[function(require,module,exports){
module.exports = require("core-js/library/fn/set");
},{"core-js/library/fn/set":38}],18:[function(require,module,exports){
module.exports = require("core-js/library/fn/symbol");
},{"core-js/library/fn/symbol":39}],19:[function(require,module,exports){
var _Reflect$construct = require("../core-js/reflect/construct");

var setPrototypeOf = require("./setPrototypeOf");

function isNativeReflectConstruct() {
  if (typeof Reflect === "undefined" || !_Reflect$construct) return false;
  if (_Reflect$construct.sham) return false;
  if (typeof Proxy === "function") return true;

  try {
    Date.prototype.toString.call(_Reflect$construct(Date, [], function () {}));
    return true;
  } catch (e) {
    return false;
  }
}

function _construct(Parent, args, Class) {
  if (isNativeReflectConstruct()) {
    module.exports = _construct = _Reflect$construct;
  } else {
    module.exports = _construct = function _construct(Parent, args, Class) {
      var a = [null];
      a.push.apply(a, args);
      var Constructor = Function.bind.apply(Parent, a);
      var instance = new Constructor();
      if (Class) setPrototypeOf(instance, Class.prototype);
      return instance;
    };
  }

  return _construct.apply(null, arguments);
}

module.exports = _construct;
},{"../core-js/reflect/construct":16,"./setPrototypeOf":23}],20:[function(require,module,exports){
var _Object$defineProperty = require("../core-js/object/define-property");

function _defineProperties(target, props) {
  for (var i = 0; i < props.length; i++) {
    var descriptor = props[i];
    descriptor.enumerable = descriptor.enumerable || false;
    descriptor.configurable = true;
    if ("value" in descriptor) descriptor.writable = true;

    _Object$defineProperty(target, descriptor.key, descriptor);
  }
}

function _createClass(Constructor, protoProps, staticProps) {
  if (protoProps) _defineProperties(Constructor.prototype, protoProps);
  if (staticProps) _defineProperties(Constructor, staticProps);
  return Constructor;
}

module.exports = _createClass;
},{"../core-js/object/define-property":10}],21:[function(require,module,exports){
var _Object$create = require("../core-js/object/create");

function _inheritsLoose(subClass, superClass) {
  subClass.prototype = _Object$create(superClass.prototype);
  subClass.prototype.constructor = subClass;
  subClass.__proto__ = superClass;
}

module.exports = _inheritsLoose;
},{"../core-js/object/create":8}],22:[function(require,module,exports){
function _interopRequireDefault(obj) {
  return obj && obj.__esModule ? obj : {
    "default": obj
  };
}

module.exports = _interopRequireDefault;
},{}],23:[function(require,module,exports){
var _Object$setPrototypeOf = require("../core-js/object/set-prototype-of");

function _setPrototypeOf(o, p) {
  module.exports = _setPrototypeOf = _Object$setPrototypeOf || function _setPrototypeOf(o, p) {
    o.__proto__ = p;
    return o;
  };

  return _setPrototypeOf(o, p);
}

module.exports = _setPrototypeOf;
},{"../core-js/object/set-prototype-of":14}],24:[function(require,module,exports){
require('../../modules/es6.string.iterator');
require('../../modules/es6.array.from');
module.exports = require('../../modules/_core').Array.from;

},{"../../modules/_core":55,"../../modules/es6.array.from":125,"../../modules/es6.string.iterator":141}],25:[function(require,module,exports){
require('../../modules/es6.array.is-array');
module.exports = require('../../modules/_core').Array.isArray;

},{"../../modules/_core":55,"../../modules/es6.array.is-array":126}],26:[function(require,module,exports){
require('../modules/web.dom.iterable');
require('../modules/es6.string.iterator');
module.exports = require('../modules/core.get-iterator');

},{"../modules/core.get-iterator":124,"../modules/es6.string.iterator":141,"../modules/web.dom.iterable":148}],27:[function(require,module,exports){
require('../../modules/es6.number.is-integer');
module.exports = require('../../modules/_core').Number.isInteger;

},{"../../modules/_core":55,"../../modules/es6.number.is-integer":128}],28:[function(require,module,exports){
require('../../modules/es6.object.assign');
module.exports = require('../../modules/_core').Object.assign;

},{"../../modules/_core":55,"../../modules/es6.object.assign":129}],29:[function(require,module,exports){
require('../../modules/es6.object.create');
var $Object = require('../../modules/_core').Object;
module.exports = function create(P, D) {
  return $Object.create(P, D);
};

},{"../../modules/_core":55,"../../modules/es6.object.create":130}],30:[function(require,module,exports){
require('../../modules/es6.object.define-properties');
var $Object = require('../../modules/_core').Object;
module.exports = function defineProperties(T, D) {
  return $Object.defineProperties(T, D);
};

},{"../../modules/_core":55,"../../modules/es6.object.define-properties":131}],31:[function(require,module,exports){
require('../../modules/es6.object.define-property');
var $Object = require('../../modules/_core').Object;
module.exports = function defineProperty(it, key, desc) {
  return $Object.defineProperty(it, key, desc);
};

},{"../../modules/_core":55,"../../modules/es6.object.define-property":132}],32:[function(require,module,exports){
require('../../modules/es6.object.get-own-property-names');
var $Object = require('../../modules/_core').Object;
module.exports = function getOwnPropertyNames(it) {
  return $Object.getOwnPropertyNames(it);
};

},{"../../modules/_core":55,"../../modules/es6.object.get-own-property-names":133}],33:[function(require,module,exports){
require('../../modules/es6.object.get-prototype-of');
module.exports = require('../../modules/_core').Object.getPrototypeOf;

},{"../../modules/_core":55,"../../modules/es6.object.get-prototype-of":134}],34:[function(require,module,exports){
require('../../modules/es6.object.keys');
module.exports = require('../../modules/_core').Object.keys;

},{"../../modules/_core":55,"../../modules/es6.object.keys":135}],35:[function(require,module,exports){
require('../../modules/es6.object.set-prototype-of');
module.exports = require('../../modules/_core').Object.setPrototypeOf;

},{"../../modules/_core":55,"../../modules/es6.object.set-prototype-of":136}],36:[function(require,module,exports){
require('../modules/es6.parse-int');
module.exports = require('../modules/_core').parseInt;

},{"../modules/_core":55,"../modules/es6.parse-int":138}],37:[function(require,module,exports){
require('../../modules/es6.reflect.construct');
module.exports = require('../../modules/_core').Reflect.construct;

},{"../../modules/_core":55,"../../modules/es6.reflect.construct":139}],38:[function(require,module,exports){
require('../modules/es6.object.to-string');
require('../modules/es6.string.iterator');
require('../modules/web.dom.iterable');
require('../modules/es6.set');
require('../modules/es7.set.to-json');
require('../modules/es7.set.of');
require('../modules/es7.set.from');
module.exports = require('../modules/_core').Set;

},{"../modules/_core":55,"../modules/es6.object.to-string":137,"../modules/es6.set":140,"../modules/es6.string.iterator":141,"../modules/es7.set.from":143,"../modules/es7.set.of":144,"../modules/es7.set.to-json":145,"../modules/web.dom.iterable":148}],39:[function(require,module,exports){
require('../../modules/es6.symbol');
require('../../modules/es6.object.to-string');
require('../../modules/es7.symbol.async-iterator');
require('../../modules/es7.symbol.observable');
module.exports = require('../../modules/_core').Symbol;

},{"../../modules/_core":55,"../../modules/es6.object.to-string":137,"../../modules/es6.symbol":142,"../../modules/es7.symbol.async-iterator":146,"../../modules/es7.symbol.observable":147}],40:[function(require,module,exports){
module.exports = function (it) {
  if (typeof it != 'function') throw TypeError(it + ' is not a function!');
  return it;
};

},{}],41:[function(require,module,exports){
module.exports = function () { /* empty */ };

},{}],42:[function(require,module,exports){
module.exports = function (it, Constructor, name, forbiddenField) {
  if (!(it instanceof Constructor) || (forbiddenField !== undefined && forbiddenField in it)) {
    throw TypeError(name + ': incorrect invocation!');
  } return it;
};

},{}],43:[function(require,module,exports){
var isObject = require('./_is-object');
module.exports = function (it) {
  if (!isObject(it)) throw TypeError(it + ' is not an object!');
  return it;
};

},{"./_is-object":76}],44:[function(require,module,exports){
var forOf = require('./_for-of');

module.exports = function (iter, ITERATOR) {
  var result = [];
  forOf(iter, false, result.push, result, ITERATOR);
  return result;
};

},{"./_for-of":65}],45:[function(require,module,exports){
// false -> Array#indexOf
// true  -> Array#includes
var toIObject = require('./_to-iobject');
var toLength = require('./_to-length');
var toAbsoluteIndex = require('./_to-absolute-index');
module.exports = function (IS_INCLUDES) {
  return function ($this, el, fromIndex) {
    var O = toIObject($this);
    var length = toLength(O.length);
    var index = toAbsoluteIndex(fromIndex, length);
    var value;
    // Array#includes uses SameValueZero equality algorithm
    // eslint-disable-next-line no-self-compare
    if (IS_INCLUDES && el != el) while (length > index) {
      value = O[index++];
      // eslint-disable-next-line no-self-compare
      if (value != value) return true;
    // Array#indexOf ignores holes, Array#includes - not
    } else for (;length > index; index++) if (IS_INCLUDES || index in O) {
      if (O[index] === el) return IS_INCLUDES || index || 0;
    } return !IS_INCLUDES && -1;
  };
};

},{"./_to-absolute-index":112,"./_to-iobject":114,"./_to-length":115}],46:[function(require,module,exports){
// 0 -> Array#forEach
// 1 -> Array#map
// 2 -> Array#filter
// 3 -> Array#some
// 4 -> Array#every
// 5 -> Array#find
// 6 -> Array#findIndex
var ctx = require('./_ctx');
var IObject = require('./_iobject');
var toObject = require('./_to-object');
var toLength = require('./_to-length');
var asc = require('./_array-species-create');
module.exports = function (TYPE, $create) {
  var IS_MAP = TYPE == 1;
  var IS_FILTER = TYPE == 2;
  var IS_SOME = TYPE == 3;
  var IS_EVERY = TYPE == 4;
  var IS_FIND_INDEX = TYPE == 6;
  var NO_HOLES = TYPE == 5 || IS_FIND_INDEX;
  var create = $create || asc;
  return function ($this, callbackfn, that) {
    var O = toObject($this);
    var self = IObject(O);
    var f = ctx(callbackfn, that, 3);
    var length = toLength(self.length);
    var index = 0;
    var result = IS_MAP ? create($this, length) : IS_FILTER ? create($this, 0) : undefined;
    var val, res;
    for (;length > index; index++) if (NO_HOLES || index in self) {
      val = self[index];
      res = f(val, index, O);
      if (TYPE) {
        if (IS_MAP) result[index] = res;   // map
        else if (res) switch (TYPE) {
          case 3: return true;             // some
          case 5: return val;              // find
          case 6: return index;            // findIndex
          case 2: result.push(val);        // filter
        } else if (IS_EVERY) return false; // every
      }
    }
    return IS_FIND_INDEX ? -1 : IS_SOME || IS_EVERY ? IS_EVERY : result;
  };
};

},{"./_array-species-create":48,"./_ctx":57,"./_iobject":72,"./_to-length":115,"./_to-object":116}],47:[function(require,module,exports){
var isObject = require('./_is-object');
var isArray = require('./_is-array');
var SPECIES = require('./_wks')('species');

module.exports = function (original) {
  var C;
  if (isArray(original)) {
    C = original.constructor;
    // cross-realm fallback
    if (typeof C == 'function' && (C === Array || isArray(C.prototype))) C = undefined;
    if (isObject(C)) {
      C = C[SPECIES];
      if (C === null) C = undefined;
    }
  } return C === undefined ? Array : C;
};

},{"./_is-array":74,"./_is-object":76,"./_wks":122}],48:[function(require,module,exports){
// 9.4.2.3 ArraySpeciesCreate(originalArray, length)
var speciesConstructor = require('./_array-species-constructor');

module.exports = function (original, length) {
  return new (speciesConstructor(original))(length);
};

},{"./_array-species-constructor":47}],49:[function(require,module,exports){
'use strict';
var aFunction = require('./_a-function');
var isObject = require('./_is-object');
var invoke = require('./_invoke');
var arraySlice = [].slice;
var factories = {};

var construct = function (F, len, args) {
  if (!(len in factories)) {
    for (var n = [], i = 0; i < len; i++) n[i] = 'a[' + i + ']';
    // eslint-disable-next-line no-new-func
    factories[len] = Function('F,a', 'return new F(' + n.join(',') + ')');
  } return factories[len](F, args);
};

module.exports = Function.bind || function bind(that /* , ...args */) {
  var fn = aFunction(this);
  var partArgs = arraySlice.call(arguments, 1);
  var bound = function (/* args... */) {
    var args = partArgs.concat(arraySlice.call(arguments));
    return this instanceof bound ? construct(fn, args.length, args) : invoke(fn, args, that);
  };
  if (isObject(fn.prototype)) bound.prototype = fn.prototype;
  return bound;
};

},{"./_a-function":40,"./_invoke":71,"./_is-object":76}],50:[function(require,module,exports){
// getting tag from 19.1.3.6 Object.prototype.toString()
var cof = require('./_cof');
var TAG = require('./_wks')('toStringTag');
// ES3 wrong here
var ARG = cof(function () { return arguments; }()) == 'Arguments';

// fallback for IE11 Script Access Denied error
var tryGet = function (it, key) {
  try {
    return it[key];
  } catch (e) { /* empty */ }
};

module.exports = function (it) {
  var O, T, B;
  return it === undefined ? 'Undefined' : it === null ? 'Null'
    // @@toStringTag case
    : typeof (T = tryGet(O = Object(it), TAG)) == 'string' ? T
    // builtinTag case
    : ARG ? cof(O)
    // ES3 arguments fallback
    : (B = cof(O)) == 'Object' && typeof O.callee == 'function' ? 'Arguments' : B;
};

},{"./_cof":51,"./_wks":122}],51:[function(require,module,exports){
var toString = {}.toString;

module.exports = function (it) {
  return toString.call(it).slice(8, -1);
};

},{}],52:[function(require,module,exports){
'use strict';
var dP = require('./_object-dp').f;
var create = require('./_object-create');
var redefineAll = require('./_redefine-all');
var ctx = require('./_ctx');
var anInstance = require('./_an-instance');
var forOf = require('./_for-of');
var $iterDefine = require('./_iter-define');
var step = require('./_iter-step');
var setSpecies = require('./_set-species');
var DESCRIPTORS = require('./_descriptors');
var fastKey = require('./_meta').fastKey;
var validate = require('./_validate-collection');
var SIZE = DESCRIPTORS ? '_s' : 'size';

var getEntry = function (that, key) {
  // fast case
  var index = fastKey(key);
  var entry;
  if (index !== 'F') return that._i[index];
  // frozen object case
  for (entry = that._f; entry; entry = entry.n) {
    if (entry.k == key) return entry;
  }
};

module.exports = {
  getConstructor: function (wrapper, NAME, IS_MAP, ADDER) {
    var C = wrapper(function (that, iterable) {
      anInstance(that, C, NAME, '_i');
      that._t = NAME;         // collection type
      that._i = create(null); // index
      that._f = undefined;    // first entry
      that._l = undefined;    // last entry
      that[SIZE] = 0;         // size
      if (iterable != undefined) forOf(iterable, IS_MAP, that[ADDER], that);
    });
    redefineAll(C.prototype, {
      // 23.1.3.1 Map.prototype.clear()
      // 23.2.3.2 Set.prototype.clear()
      clear: function clear() {
        for (var that = validate(this, NAME), data = that._i, entry = that._f; entry; entry = entry.n) {
          entry.r = true;
          if (entry.p) entry.p = entry.p.n = undefined;
          delete data[entry.i];
        }
        that._f = that._l = undefined;
        that[SIZE] = 0;
      },
      // 23.1.3.3 Map.prototype.delete(key)
      // 23.2.3.4 Set.prototype.delete(value)
      'delete': function (key) {
        var that = validate(this, NAME);
        var entry = getEntry(that, key);
        if (entry) {
          var next = entry.n;
          var prev = entry.p;
          delete that._i[entry.i];
          entry.r = true;
          if (prev) prev.n = next;
          if (next) next.p = prev;
          if (that._f == entry) that._f = next;
          if (that._l == entry) that._l = prev;
          that[SIZE]--;
        } return !!entry;
      },
      // 23.2.3.6 Set.prototype.forEach(callbackfn, thisArg = undefined)
      // 23.1.3.5 Map.prototype.forEach(callbackfn, thisArg = undefined)
      forEach: function forEach(callbackfn /* , that = undefined */) {
        validate(this, NAME);
        var f = ctx(callbackfn, arguments.length > 1 ? arguments[1] : undefined, 3);
        var entry;
        while (entry = entry ? entry.n : this._f) {
          f(entry.v, entry.k, this);
          // revert to the last existing entry
          while (entry && entry.r) entry = entry.p;
        }
      },
      // 23.1.3.7 Map.prototype.has(key)
      // 23.2.3.7 Set.prototype.has(value)
      has: function has(key) {
        return !!getEntry(validate(this, NAME), key);
      }
    });
    if (DESCRIPTORS) dP(C.prototype, 'size', {
      get: function () {
        return validate(this, NAME)[SIZE];
      }
    });
    return C;
  },
  def: function (that, key, value) {
    var entry = getEntry(that, key);
    var prev, index;
    // change existing entry
    if (entry) {
      entry.v = value;
    // create new entry
    } else {
      that._l = entry = {
        i: index = fastKey(key, true), // <- index
        k: key,                        // <- key
        v: value,                      // <- value
        p: prev = that._l,             // <- previous entry
        n: undefined,                  // <- next entry
        r: false                       // <- removed
      };
      if (!that._f) that._f = entry;
      if (prev) prev.n = entry;
      that[SIZE]++;
      // add to index
      if (index !== 'F') that._i[index] = entry;
    } return that;
  },
  getEntry: getEntry,
  setStrong: function (C, NAME, IS_MAP) {
    // add .keys, .values, .entries, [@@iterator]
    // 23.1.3.4, 23.1.3.8, 23.1.3.11, 23.1.3.12, 23.2.3.5, 23.2.3.8, 23.2.3.10, 23.2.3.11
    $iterDefine(C, NAME, function (iterated, kind) {
      this._t = validate(iterated, NAME); // target
      this._k = kind;                     // kind
      this._l = undefined;                // previous
    }, function () {
      var that = this;
      var kind = that._k;
      var entry = that._l;
      // revert to the last existing entry
      while (entry && entry.r) entry = entry.p;
      // get next entry
      if (!that._t || !(that._l = entry = entry ? entry.n : that._t._f)) {
        // or finish the iteration
        that._t = undefined;
        return step(1);
      }
      // return step by kind
      if (kind == 'keys') return step(0, entry.k);
      if (kind == 'values') return step(0, entry.v);
      return step(0, [entry.k, entry.v]);
    }, IS_MAP ? 'entries' : 'values', !IS_MAP, true);

    // add [@@species], 23.1.2.2, 23.2.2.2
    setSpecies(NAME);
  }
};

},{"./_an-instance":42,"./_ctx":57,"./_descriptors":59,"./_for-of":65,"./_iter-define":79,"./_iter-step":81,"./_meta":84,"./_object-create":86,"./_object-dp":87,"./_redefine-all":100,"./_set-species":105,"./_validate-collection":119}],53:[function(require,module,exports){
// https://github.com/DavidBruant/Map-Set.prototype.toJSON
var classof = require('./_classof');
var from = require('./_array-from-iterable');
module.exports = function (NAME) {
  return function toJSON() {
    if (classof(this) != NAME) throw TypeError(NAME + "#toJSON isn't generic");
    return from(this);
  };
};

},{"./_array-from-iterable":44,"./_classof":50}],54:[function(require,module,exports){
'use strict';
var global = require('./_global');
var $export = require('./_export');
var meta = require('./_meta');
var fails = require('./_fails');
var hide = require('./_hide');
var redefineAll = require('./_redefine-all');
var forOf = require('./_for-of');
var anInstance = require('./_an-instance');
var isObject = require('./_is-object');
var setToStringTag = require('./_set-to-string-tag');
var dP = require('./_object-dp').f;
var each = require('./_array-methods')(0);
var DESCRIPTORS = require('./_descriptors');

module.exports = function (NAME, wrapper, methods, common, IS_MAP, IS_WEAK) {
  var Base = global[NAME];
  var C = Base;
  var ADDER = IS_MAP ? 'set' : 'add';
  var proto = C && C.prototype;
  var O = {};
  if (!DESCRIPTORS || typeof C != 'function' || !(IS_WEAK || proto.forEach && !fails(function () {
    new C().entries().next();
  }))) {
    // create collection constructor
    C = common.getConstructor(wrapper, NAME, IS_MAP, ADDER);
    redefineAll(C.prototype, methods);
    meta.NEED = true;
  } else {
    C = wrapper(function (target, iterable) {
      anInstance(target, C, NAME, '_c');
      target._c = new Base();
      if (iterable != undefined) forOf(iterable, IS_MAP, target[ADDER], target);
    });
    each('add,clear,delete,forEach,get,has,set,keys,values,entries,toJSON'.split(','), function (KEY) {
      var IS_ADDER = KEY == 'add' || KEY == 'set';
      if (KEY in proto && !(IS_WEAK && KEY == 'clear')) hide(C.prototype, KEY, function (a, b) {
        anInstance(this, C, KEY);
        if (!IS_ADDER && IS_WEAK && !isObject(a)) return KEY == 'get' ? undefined : false;
        var result = this._c[KEY](a === 0 ? 0 : a, b);
        return IS_ADDER ? this : result;
      });
    });
    IS_WEAK || dP(C.prototype, 'size', {
      get: function () {
        return this._c.size;
      }
    });
  }

  setToStringTag(C, NAME);

  O[NAME] = C;
  $export($export.G + $export.W + $export.F, O);

  if (!IS_WEAK) common.setStrong(C, NAME, IS_MAP);

  return C;
};

},{"./_an-instance":42,"./_array-methods":46,"./_descriptors":59,"./_export":63,"./_fails":64,"./_for-of":65,"./_global":66,"./_hide":68,"./_is-object":76,"./_meta":84,"./_object-dp":87,"./_redefine-all":100,"./_set-to-string-tag":106}],55:[function(require,module,exports){
var core = module.exports = { version: '2.6.11' };
if (typeof __e == 'number') __e = core; // eslint-disable-line no-undef

},{}],56:[function(require,module,exports){
'use strict';
var $defineProperty = require('./_object-dp');
var createDesc = require('./_property-desc');

module.exports = function (object, index, value) {
  if (index in object) $defineProperty.f(object, index, createDesc(0, value));
  else object[index] = value;
};

},{"./_object-dp":87,"./_property-desc":99}],57:[function(require,module,exports){
// optional / simple context binding
var aFunction = require('./_a-function');
module.exports = function (fn, that, length) {
  aFunction(fn);
  if (that === undefined) return fn;
  switch (length) {
    case 1: return function (a) {
      return fn.call(that, a);
    };
    case 2: return function (a, b) {
      return fn.call(that, a, b);
    };
    case 3: return function (a, b, c) {
      return fn.call(that, a, b, c);
    };
  }
  return function (/* ...args */) {
    return fn.apply(that, arguments);
  };
};

},{"./_a-function":40}],58:[function(require,module,exports){
// 7.2.1 RequireObjectCoercible(argument)
module.exports = function (it) {
  if (it == undefined) throw TypeError("Can't call method on  " + it);
  return it;
};

},{}],59:[function(require,module,exports){
// Thank's IE8 for his funny defineProperty
module.exports = !require('./_fails')(function () {
  return Object.defineProperty({}, 'a', { get: function () { return 7; } }).a != 7;
});

},{"./_fails":64}],60:[function(require,module,exports){
var isObject = require('./_is-object');
var document = require('./_global').document;
// typeof document.createElement is 'object' in old IE
var is = isObject(document) && isObject(document.createElement);
module.exports = function (it) {
  return is ? document.createElement(it) : {};
};

},{"./_global":66,"./_is-object":76}],61:[function(require,module,exports){
// IE 8- don't enum bug keys
module.exports = (
  'constructor,hasOwnProperty,isPrototypeOf,propertyIsEnumerable,toLocaleString,toString,valueOf'
).split(',');

},{}],62:[function(require,module,exports){
// all enumerable object keys, includes symbols
var getKeys = require('./_object-keys');
var gOPS = require('./_object-gops');
var pIE = require('./_object-pie');
module.exports = function (it) {
  var result = getKeys(it);
  var getSymbols = gOPS.f;
  if (getSymbols) {
    var symbols = getSymbols(it);
    var isEnum = pIE.f;
    var i = 0;
    var key;
    while (symbols.length > i) if (isEnum.call(it, key = symbols[i++])) result.push(key);
  } return result;
};

},{"./_object-gops":92,"./_object-keys":95,"./_object-pie":96}],63:[function(require,module,exports){
var global = require('./_global');
var core = require('./_core');
var ctx = require('./_ctx');
var hide = require('./_hide');
var has = require('./_has');
var PROTOTYPE = 'prototype';

var $export = function (type, name, source) {
  var IS_FORCED = type & $export.F;
  var IS_GLOBAL = type & $export.G;
  var IS_STATIC = type & $export.S;
  var IS_PROTO = type & $export.P;
  var IS_BIND = type & $export.B;
  var IS_WRAP = type & $export.W;
  var exports = IS_GLOBAL ? core : core[name] || (core[name] = {});
  var expProto = exports[PROTOTYPE];
  var target = IS_GLOBAL ? global : IS_STATIC ? global[name] : (global[name] || {})[PROTOTYPE];
  var key, own, out;
  if (IS_GLOBAL) source = name;
  for (key in source) {
    // contains in native
    own = !IS_FORCED && target && target[key] !== undefined;
    if (own && has(exports, key)) continue;
    // export native or passed
    out = own ? target[key] : source[key];
    // prevent global pollution for namespaces
    exports[key] = IS_GLOBAL && typeof target[key] != 'function' ? source[key]
    // bind timers to global for call from export context
    : IS_BIND && own ? ctx(out, global)
    // wrap global constructors for prevent change them in library
    : IS_WRAP && target[key] == out ? (function (C) {
      var F = function (a, b, c) {
        if (this instanceof C) {
          switch (arguments.length) {
            case 0: return new C();
            case 1: return new C(a);
            case 2: return new C(a, b);
          } return new C(a, b, c);
        } return C.apply(this, arguments);
      };
      F[PROTOTYPE] = C[PROTOTYPE];
      return F;
    // make static versions for prototype methods
    })(out) : IS_PROTO && typeof out == 'function' ? ctx(Function.call, out) : out;
    // export proto methods to core.%CONSTRUCTOR%.methods.%NAME%
    if (IS_PROTO) {
      (exports.virtual || (exports.virtual = {}))[key] = out;
      // export proto methods to core.%CONSTRUCTOR%.prototype.%NAME%
      if (type & $export.R && expProto && !expProto[key]) hide(expProto, key, out);
    }
  }
};
// type bitmap
$export.F = 1;   // forced
$export.G = 2;   // global
$export.S = 4;   // static
$export.P = 8;   // proto
$export.B = 16;  // bind
$export.W = 32;  // wrap
$export.U = 64;  // safe
$export.R = 128; // real proto method for `library`
module.exports = $export;

},{"./_core":55,"./_ctx":57,"./_global":66,"./_has":67,"./_hide":68}],64:[function(require,module,exports){
module.exports = function (exec) {
  try {
    return !!exec();
  } catch (e) {
    return true;
  }
};

},{}],65:[function(require,module,exports){
var ctx = require('./_ctx');
var call = require('./_iter-call');
var isArrayIter = require('./_is-array-iter');
var anObject = require('./_an-object');
var toLength = require('./_to-length');
var getIterFn = require('./core.get-iterator-method');
var BREAK = {};
var RETURN = {};
var exports = module.exports = function (iterable, entries, fn, that, ITERATOR) {
  var iterFn = ITERATOR ? function () { return iterable; } : getIterFn(iterable);
  var f = ctx(fn, that, entries ? 2 : 1);
  var index = 0;
  var length, step, iterator, result;
  if (typeof iterFn != 'function') throw TypeError(iterable + ' is not iterable!');
  // fast case for arrays with default iterator
  if (isArrayIter(iterFn)) for (length = toLength(iterable.length); length > index; index++) {
    result = entries ? f(anObject(step = iterable[index])[0], step[1]) : f(iterable[index]);
    if (result === BREAK || result === RETURN) return result;
  } else for (iterator = iterFn.call(iterable); !(step = iterator.next()).done;) {
    result = call(iterator, f, step.value, entries);
    if (result === BREAK || result === RETURN) return result;
  }
};
exports.BREAK = BREAK;
exports.RETURN = RETURN;

},{"./_an-object":43,"./_ctx":57,"./_is-array-iter":73,"./_iter-call":77,"./_to-length":115,"./core.get-iterator-method":123}],66:[function(require,module,exports){
// https://github.com/zloirock/core-js/issues/86#issuecomment-115759028
var global = module.exports = typeof window != 'undefined' && window.Math == Math
  ? window : typeof self != 'undefined' && self.Math == Math ? self
  // eslint-disable-next-line no-new-func
  : Function('return this')();
if (typeof __g == 'number') __g = global; // eslint-disable-line no-undef

},{}],67:[function(require,module,exports){
var hasOwnProperty = {}.hasOwnProperty;
module.exports = function (it, key) {
  return hasOwnProperty.call(it, key);
};

},{}],68:[function(require,module,exports){
var dP = require('./_object-dp');
var createDesc = require('./_property-desc');
module.exports = require('./_descriptors') ? function (object, key, value) {
  return dP.f(object, key, createDesc(1, value));
} : function (object, key, value) {
  object[key] = value;
  return object;
};

},{"./_descriptors":59,"./_object-dp":87,"./_property-desc":99}],69:[function(require,module,exports){
var document = require('./_global').document;
module.exports = document && document.documentElement;

},{"./_global":66}],70:[function(require,module,exports){
module.exports = !require('./_descriptors') && !require('./_fails')(function () {
  return Object.defineProperty(require('./_dom-create')('div'), 'a', { get: function () { return 7; } }).a != 7;
});

},{"./_descriptors":59,"./_dom-create":60,"./_fails":64}],71:[function(require,module,exports){
// fast apply, http://jsperf.lnkit.com/fast-apply/5
module.exports = function (fn, args, that) {
  var un = that === undefined;
  switch (args.length) {
    case 0: return un ? fn()
                      : fn.call(that);
    case 1: return un ? fn(args[0])
                      : fn.call(that, args[0]);
    case 2: return un ? fn(args[0], args[1])
                      : fn.call(that, args[0], args[1]);
    case 3: return un ? fn(args[0], args[1], args[2])
                      : fn.call(that, args[0], args[1], args[2]);
    case 4: return un ? fn(args[0], args[1], args[2], args[3])
                      : fn.call(that, args[0], args[1], args[2], args[3]);
  } return fn.apply(that, args);
};

},{}],72:[function(require,module,exports){
// fallback for non-array-like ES3 and non-enumerable old V8 strings
var cof = require('./_cof');
// eslint-disable-next-line no-prototype-builtins
module.exports = Object('z').propertyIsEnumerable(0) ? Object : function (it) {
  return cof(it) == 'String' ? it.split('') : Object(it);
};

},{"./_cof":51}],73:[function(require,module,exports){
// check on default Array iterator
var Iterators = require('./_iterators');
var ITERATOR = require('./_wks')('iterator');
var ArrayProto = Array.prototype;

module.exports = function (it) {
  return it !== undefined && (Iterators.Array === it || ArrayProto[ITERATOR] === it);
};

},{"./_iterators":82,"./_wks":122}],74:[function(require,module,exports){
// 7.2.2 IsArray(argument)
var cof = require('./_cof');
module.exports = Array.isArray || function isArray(arg) {
  return cof(arg) == 'Array';
};

},{"./_cof":51}],75:[function(require,module,exports){
// 20.1.2.3 Number.isInteger(number)
var isObject = require('./_is-object');
var floor = Math.floor;
module.exports = function isInteger(it) {
  return !isObject(it) && isFinite(it) && floor(it) === it;
};

},{"./_is-object":76}],76:[function(require,module,exports){
module.exports = function (it) {
  return typeof it === 'object' ? it !== null : typeof it === 'function';
};

},{}],77:[function(require,module,exports){
// call something on iterator step with safe closing on error
var anObject = require('./_an-object');
module.exports = function (iterator, fn, value, entries) {
  try {
    return entries ? fn(anObject(value)[0], value[1]) : fn(value);
  // 7.4.6 IteratorClose(iterator, completion)
  } catch (e) {
    var ret = iterator['return'];
    if (ret !== undefined) anObject(ret.call(iterator));
    throw e;
  }
};

},{"./_an-object":43}],78:[function(require,module,exports){
'use strict';
var create = require('./_object-create');
var descriptor = require('./_property-desc');
var setToStringTag = require('./_set-to-string-tag');
var IteratorPrototype = {};

// 25.1.2.1.1 %IteratorPrototype%[@@iterator]()
require('./_hide')(IteratorPrototype, require('./_wks')('iterator'), function () { return this; });

module.exports = function (Constructor, NAME, next) {
  Constructor.prototype = create(IteratorPrototype, { next: descriptor(1, next) });
  setToStringTag(Constructor, NAME + ' Iterator');
};

},{"./_hide":68,"./_object-create":86,"./_property-desc":99,"./_set-to-string-tag":106,"./_wks":122}],79:[function(require,module,exports){
'use strict';
var LIBRARY = require('./_library');
var $export = require('./_export');
var redefine = require('./_redefine');
var hide = require('./_hide');
var Iterators = require('./_iterators');
var $iterCreate = require('./_iter-create');
var setToStringTag = require('./_set-to-string-tag');
var getPrototypeOf = require('./_object-gpo');
var ITERATOR = require('./_wks')('iterator');
var BUGGY = !([].keys && 'next' in [].keys()); // Safari has buggy iterators w/o `next`
var FF_ITERATOR = '@@iterator';
var KEYS = 'keys';
var VALUES = 'values';

var returnThis = function () { return this; };

module.exports = function (Base, NAME, Constructor, next, DEFAULT, IS_SET, FORCED) {
  $iterCreate(Constructor, NAME, next);
  var getMethod = function (kind) {
    if (!BUGGY && kind in proto) return proto[kind];
    switch (kind) {
      case KEYS: return function keys() { return new Constructor(this, kind); };
      case VALUES: return function values() { return new Constructor(this, kind); };
    } return function entries() { return new Constructor(this, kind); };
  };
  var TAG = NAME + ' Iterator';
  var DEF_VALUES = DEFAULT == VALUES;
  var VALUES_BUG = false;
  var proto = Base.prototype;
  var $native = proto[ITERATOR] || proto[FF_ITERATOR] || DEFAULT && proto[DEFAULT];
  var $default = $native || getMethod(DEFAULT);
  var $entries = DEFAULT ? !DEF_VALUES ? $default : getMethod('entries') : undefined;
  var $anyNative = NAME == 'Array' ? proto.entries || $native : $native;
  var methods, key, IteratorPrototype;
  // Fix native
  if ($anyNative) {
    IteratorPrototype = getPrototypeOf($anyNative.call(new Base()));
    if (IteratorPrototype !== Object.prototype && IteratorPrototype.next) {
      // Set @@toStringTag to native iterators
      setToStringTag(IteratorPrototype, TAG, true);
      // fix for some old engines
      if (!LIBRARY && typeof IteratorPrototype[ITERATOR] != 'function') hide(IteratorPrototype, ITERATOR, returnThis);
    }
  }
  // fix Array#{values, @@iterator}.name in V8 / FF
  if (DEF_VALUES && $native && $native.name !== VALUES) {
    VALUES_BUG = true;
    $default = function values() { return $native.call(this); };
  }
  // Define iterator
  if ((!LIBRARY || FORCED) && (BUGGY || VALUES_BUG || !proto[ITERATOR])) {
    hide(proto, ITERATOR, $default);
  }
  // Plug for library
  Iterators[NAME] = $default;
  Iterators[TAG] = returnThis;
  if (DEFAULT) {
    methods = {
      values: DEF_VALUES ? $default : getMethod(VALUES),
      keys: IS_SET ? $default : getMethod(KEYS),
      entries: $entries
    };
    if (FORCED) for (key in methods) {
      if (!(key in proto)) redefine(proto, key, methods[key]);
    } else $export($export.P + $export.F * (BUGGY || VALUES_BUG), NAME, methods);
  }
  return methods;
};

},{"./_export":63,"./_hide":68,"./_iter-create":78,"./_iterators":82,"./_library":83,"./_object-gpo":93,"./_redefine":101,"./_set-to-string-tag":106,"./_wks":122}],80:[function(require,module,exports){
var ITERATOR = require('./_wks')('iterator');
var SAFE_CLOSING = false;

try {
  var riter = [7][ITERATOR]();
  riter['return'] = function () { SAFE_CLOSING = true; };
  // eslint-disable-next-line no-throw-literal
  Array.from(riter, function () { throw 2; });
} catch (e) { /* empty */ }

module.exports = function (exec, skipClosing) {
  if (!skipClosing && !SAFE_CLOSING) return false;
  var safe = false;
  try {
    var arr = [7];
    var iter = arr[ITERATOR]();
    iter.next = function () { return { done: safe = true }; };
    arr[ITERATOR] = function () { return iter; };
    exec(arr);
  } catch (e) { /* empty */ }
  return safe;
};

},{"./_wks":122}],81:[function(require,module,exports){
module.exports = function (done, value) {
  return { value: value, done: !!done };
};

},{}],82:[function(require,module,exports){
module.exports = {};

},{}],83:[function(require,module,exports){
module.exports = true;

},{}],84:[function(require,module,exports){
var META = require('./_uid')('meta');
var isObject = require('./_is-object');
var has = require('./_has');
var setDesc = require('./_object-dp').f;
var id = 0;
var isExtensible = Object.isExtensible || function () {
  return true;
};
var FREEZE = !require('./_fails')(function () {
  return isExtensible(Object.preventExtensions({}));
});
var setMeta = function (it) {
  setDesc(it, META, { value: {
    i: 'O' + ++id, // object ID
    w: {}          // weak collections IDs
  } });
};
var fastKey = function (it, create) {
  // return primitive with prefix
  if (!isObject(it)) return typeof it == 'symbol' ? it : (typeof it == 'string' ? 'S' : 'P') + it;
  if (!has(it, META)) {
    // can't set metadata to uncaught frozen object
    if (!isExtensible(it)) return 'F';
    // not necessary to add metadata
    if (!create) return 'E';
    // add missing metadata
    setMeta(it);
  // return object ID
  } return it[META].i;
};
var getWeak = function (it, create) {
  if (!has(it, META)) {
    // can't set metadata to uncaught frozen object
    if (!isExtensible(it)) return true;
    // not necessary to add metadata
    if (!create) return false;
    // add missing metadata
    setMeta(it);
  // return hash weak collections IDs
  } return it[META].w;
};
// add metadata on freeze-family methods calling
var onFreeze = function (it) {
  if (FREEZE && meta.NEED && isExtensible(it) && !has(it, META)) setMeta(it);
  return it;
};
var meta = module.exports = {
  KEY: META,
  NEED: false,
  fastKey: fastKey,
  getWeak: getWeak,
  onFreeze: onFreeze
};

},{"./_fails":64,"./_has":67,"./_is-object":76,"./_object-dp":87,"./_uid":118}],85:[function(require,module,exports){
'use strict';
// 19.1.2.1 Object.assign(target, source, ...)
var DESCRIPTORS = require('./_descriptors');
var getKeys = require('./_object-keys');
var gOPS = require('./_object-gops');
var pIE = require('./_object-pie');
var toObject = require('./_to-object');
var IObject = require('./_iobject');
var $assign = Object.assign;

// should work with symbols and should have deterministic property order (V8 bug)
module.exports = !$assign || require('./_fails')(function () {
  var A = {};
  var B = {};
  // eslint-disable-next-line no-undef
  var S = Symbol();
  var K = 'abcdefghijklmnopqrst';
  A[S] = 7;
  K.split('').forEach(function (k) { B[k] = k; });
  return $assign({}, A)[S] != 7 || Object.keys($assign({}, B)).join('') != K;
}) ? function assign(target, source) { // eslint-disable-line no-unused-vars
  var T = toObject(target);
  var aLen = arguments.length;
  var index = 1;
  var getSymbols = gOPS.f;
  var isEnum = pIE.f;
  while (aLen > index) {
    var S = IObject(arguments[index++]);
    var keys = getSymbols ? getKeys(S).concat(getSymbols(S)) : getKeys(S);
    var length = keys.length;
    var j = 0;
    var key;
    while (length > j) {
      key = keys[j++];
      if (!DESCRIPTORS || isEnum.call(S, key)) T[key] = S[key];
    }
  } return T;
} : $assign;

},{"./_descriptors":59,"./_fails":64,"./_iobject":72,"./_object-gops":92,"./_object-keys":95,"./_object-pie":96,"./_to-object":116}],86:[function(require,module,exports){
// 19.1.2.2 / 15.2.3.5 Object.create(O [, Properties])
var anObject = require('./_an-object');
var dPs = require('./_object-dps');
var enumBugKeys = require('./_enum-bug-keys');
var IE_PROTO = require('./_shared-key')('IE_PROTO');
var Empty = function () { /* empty */ };
var PROTOTYPE = 'prototype';

// Create object with fake `null` prototype: use iframe Object with cleared prototype
var createDict = function () {
  // Thrash, waste and sodomy: IE GC bug
  var iframe = require('./_dom-create')('iframe');
  var i = enumBugKeys.length;
  var lt = '<';
  var gt = '>';
  var iframeDocument;
  iframe.style.display = 'none';
  require('./_html').appendChild(iframe);
  iframe.src = 'javascript:'; // eslint-disable-line no-script-url
  // createDict = iframe.contentWindow.Object;
  // html.removeChild(iframe);
  iframeDocument = iframe.contentWindow.document;
  iframeDocument.open();
  iframeDocument.write(lt + 'script' + gt + 'document.F=Object' + lt + '/script' + gt);
  iframeDocument.close();
  createDict = iframeDocument.F;
  while (i--) delete createDict[PROTOTYPE][enumBugKeys[i]];
  return createDict();
};

module.exports = Object.create || function create(O, Properties) {
  var result;
  if (O !== null) {
    Empty[PROTOTYPE] = anObject(O);
    result = new Empty();
    Empty[PROTOTYPE] = null;
    // add "__proto__" for Object.getPrototypeOf polyfill
    result[IE_PROTO] = O;
  } else result = createDict();
  return Properties === undefined ? result : dPs(result, Properties);
};

},{"./_an-object":43,"./_dom-create":60,"./_enum-bug-keys":61,"./_html":69,"./_object-dps":88,"./_shared-key":107}],87:[function(require,module,exports){
var anObject = require('./_an-object');
var IE8_DOM_DEFINE = require('./_ie8-dom-define');
var toPrimitive = require('./_to-primitive');
var dP = Object.defineProperty;

exports.f = require('./_descriptors') ? Object.defineProperty : function defineProperty(O, P, Attributes) {
  anObject(O);
  P = toPrimitive(P, true);
  anObject(Attributes);
  if (IE8_DOM_DEFINE) try {
    return dP(O, P, Attributes);
  } catch (e) { /* empty */ }
  if ('get' in Attributes || 'set' in Attributes) throw TypeError('Accessors not supported!');
  if ('value' in Attributes) O[P] = Attributes.value;
  return O;
};

},{"./_an-object":43,"./_descriptors":59,"./_ie8-dom-define":70,"./_to-primitive":117}],88:[function(require,module,exports){
var dP = require('./_object-dp');
var anObject = require('./_an-object');
var getKeys = require('./_object-keys');

module.exports = require('./_descriptors') ? Object.defineProperties : function defineProperties(O, Properties) {
  anObject(O);
  var keys = getKeys(Properties);
  var length = keys.length;
  var i = 0;
  var P;
  while (length > i) dP.f(O, P = keys[i++], Properties[P]);
  return O;
};

},{"./_an-object":43,"./_descriptors":59,"./_object-dp":87,"./_object-keys":95}],89:[function(require,module,exports){
var pIE = require('./_object-pie');
var createDesc = require('./_property-desc');
var toIObject = require('./_to-iobject');
var toPrimitive = require('./_to-primitive');
var has = require('./_has');
var IE8_DOM_DEFINE = require('./_ie8-dom-define');
var gOPD = Object.getOwnPropertyDescriptor;

exports.f = require('./_descriptors') ? gOPD : function getOwnPropertyDescriptor(O, P) {
  O = toIObject(O);
  P = toPrimitive(P, true);
  if (IE8_DOM_DEFINE) try {
    return gOPD(O, P);
  } catch (e) { /* empty */ }
  if (has(O, P)) return createDesc(!pIE.f.call(O, P), O[P]);
};

},{"./_descriptors":59,"./_has":67,"./_ie8-dom-define":70,"./_object-pie":96,"./_property-desc":99,"./_to-iobject":114,"./_to-primitive":117}],90:[function(require,module,exports){
// fallback for IE11 buggy Object.getOwnPropertyNames with iframe and window
var toIObject = require('./_to-iobject');
var gOPN = require('./_object-gopn').f;
var toString = {}.toString;

var windowNames = typeof window == 'object' && window && Object.getOwnPropertyNames
  ? Object.getOwnPropertyNames(window) : [];

var getWindowNames = function (it) {
  try {
    return gOPN(it);
  } catch (e) {
    return windowNames.slice();
  }
};

module.exports.f = function getOwnPropertyNames(it) {
  return windowNames && toString.call(it) == '[object Window]' ? getWindowNames(it) : gOPN(toIObject(it));
};

},{"./_object-gopn":91,"./_to-iobject":114}],91:[function(require,module,exports){
// 19.1.2.7 / 15.2.3.4 Object.getOwnPropertyNames(O)
var $keys = require('./_object-keys-internal');
var hiddenKeys = require('./_enum-bug-keys').concat('length', 'prototype');

exports.f = Object.getOwnPropertyNames || function getOwnPropertyNames(O) {
  return $keys(O, hiddenKeys);
};

},{"./_enum-bug-keys":61,"./_object-keys-internal":94}],92:[function(require,module,exports){
exports.f = Object.getOwnPropertySymbols;

},{}],93:[function(require,module,exports){
// 19.1.2.9 / 15.2.3.2 Object.getPrototypeOf(O)
var has = require('./_has');
var toObject = require('./_to-object');
var IE_PROTO = require('./_shared-key')('IE_PROTO');
var ObjectProto = Object.prototype;

module.exports = Object.getPrototypeOf || function (O) {
  O = toObject(O);
  if (has(O, IE_PROTO)) return O[IE_PROTO];
  if (typeof O.constructor == 'function' && O instanceof O.constructor) {
    return O.constructor.prototype;
  } return O instanceof Object ? ObjectProto : null;
};

},{"./_has":67,"./_shared-key":107,"./_to-object":116}],94:[function(require,module,exports){
var has = require('./_has');
var toIObject = require('./_to-iobject');
var arrayIndexOf = require('./_array-includes')(false);
var IE_PROTO = require('./_shared-key')('IE_PROTO');

module.exports = function (object, names) {
  var O = toIObject(object);
  var i = 0;
  var result = [];
  var key;
  for (key in O) if (key != IE_PROTO) has(O, key) && result.push(key);
  // Don't enum bug & hidden keys
  while (names.length > i) if (has(O, key = names[i++])) {
    ~arrayIndexOf(result, key) || result.push(key);
  }
  return result;
};

},{"./_array-includes":45,"./_has":67,"./_shared-key":107,"./_to-iobject":114}],95:[function(require,module,exports){
// 19.1.2.14 / 15.2.3.14 Object.keys(O)
var $keys = require('./_object-keys-internal');
var enumBugKeys = require('./_enum-bug-keys');

module.exports = Object.keys || function keys(O) {
  return $keys(O, enumBugKeys);
};

},{"./_enum-bug-keys":61,"./_object-keys-internal":94}],96:[function(require,module,exports){
exports.f = {}.propertyIsEnumerable;

},{}],97:[function(require,module,exports){
// most Object methods by ES6 should accept primitives
var $export = require('./_export');
var core = require('./_core');
var fails = require('./_fails');
module.exports = function (KEY, exec) {
  var fn = (core.Object || {})[KEY] || Object[KEY];
  var exp = {};
  exp[KEY] = exec(fn);
  $export($export.S + $export.F * fails(function () { fn(1); }), 'Object', exp);
};

},{"./_core":55,"./_export":63,"./_fails":64}],98:[function(require,module,exports){
var $parseInt = require('./_global').parseInt;
var $trim = require('./_string-trim').trim;
var ws = require('./_string-ws');
var hex = /^[-+]?0[xX]/;

module.exports = $parseInt(ws + '08') !== 8 || $parseInt(ws + '0x16') !== 22 ? function parseInt(str, radix) {
  var string = $trim(String(str), 3);
  return $parseInt(string, (radix >>> 0) || (hex.test(string) ? 16 : 10));
} : $parseInt;

},{"./_global":66,"./_string-trim":110,"./_string-ws":111}],99:[function(require,module,exports){
module.exports = function (bitmap, value) {
  return {
    enumerable: !(bitmap & 1),
    configurable: !(bitmap & 2),
    writable: !(bitmap & 4),
    value: value
  };
};

},{}],100:[function(require,module,exports){
var hide = require('./_hide');
module.exports = function (target, src, safe) {
  for (var key in src) {
    if (safe && target[key]) target[key] = src[key];
    else hide(target, key, src[key]);
  } return target;
};

},{"./_hide":68}],101:[function(require,module,exports){
module.exports = require('./_hide');

},{"./_hide":68}],102:[function(require,module,exports){
'use strict';
// https://tc39.github.io/proposal-setmap-offrom/
var $export = require('./_export');
var aFunction = require('./_a-function');
var ctx = require('./_ctx');
var forOf = require('./_for-of');

module.exports = function (COLLECTION) {
  $export($export.S, COLLECTION, { from: function from(source /* , mapFn, thisArg */) {
    var mapFn = arguments[1];
    var mapping, A, n, cb;
    aFunction(this);
    mapping = mapFn !== undefined;
    if (mapping) aFunction(mapFn);
    if (source == undefined) return new this();
    A = [];
    if (mapping) {
      n = 0;
      cb = ctx(mapFn, arguments[2], 2);
      forOf(source, false, function (nextItem) {
        A.push(cb(nextItem, n++));
      });
    } else {
      forOf(source, false, A.push, A);
    }
    return new this(A);
  } });
};

},{"./_a-function":40,"./_ctx":57,"./_export":63,"./_for-of":65}],103:[function(require,module,exports){
'use strict';
// https://tc39.github.io/proposal-setmap-offrom/
var $export = require('./_export');

module.exports = function (COLLECTION) {
  $export($export.S, COLLECTION, { of: function of() {
    var length = arguments.length;
    var A = new Array(length);
    while (length--) A[length] = arguments[length];
    return new this(A);
  } });
};

},{"./_export":63}],104:[function(require,module,exports){
// Works with __proto__ only. Old v8 can't work with null proto objects.
/* eslint-disable no-proto */
var isObject = require('./_is-object');
var anObject = require('./_an-object');
var check = function (O, proto) {
  anObject(O);
  if (!isObject(proto) && proto !== null) throw TypeError(proto + ": can't set as prototype!");
};
module.exports = {
  set: Object.setPrototypeOf || ('__proto__' in {} ? // eslint-disable-line
    function (test, buggy, set) {
      try {
        set = require('./_ctx')(Function.call, require('./_object-gopd').f(Object.prototype, '__proto__').set, 2);
        set(test, []);
        buggy = !(test instanceof Array);
      } catch (e) { buggy = true; }
      return function setPrototypeOf(O, proto) {
        check(O, proto);
        if (buggy) O.__proto__ = proto;
        else set(O, proto);
        return O;
      };
    }({}, false) : undefined),
  check: check
};

},{"./_an-object":43,"./_ctx":57,"./_is-object":76,"./_object-gopd":89}],105:[function(require,module,exports){
'use strict';
var global = require('./_global');
var core = require('./_core');
var dP = require('./_object-dp');
var DESCRIPTORS = require('./_descriptors');
var SPECIES = require('./_wks')('species');

module.exports = function (KEY) {
  var C = typeof core[KEY] == 'function' ? core[KEY] : global[KEY];
  if (DESCRIPTORS && C && !C[SPECIES]) dP.f(C, SPECIES, {
    configurable: true,
    get: function () { return this; }
  });
};

},{"./_core":55,"./_descriptors":59,"./_global":66,"./_object-dp":87,"./_wks":122}],106:[function(require,module,exports){
var def = require('./_object-dp').f;
var has = require('./_has');
var TAG = require('./_wks')('toStringTag');

module.exports = function (it, tag, stat) {
  if (it && !has(it = stat ? it : it.prototype, TAG)) def(it, TAG, { configurable: true, value: tag });
};

},{"./_has":67,"./_object-dp":87,"./_wks":122}],107:[function(require,module,exports){
var shared = require('./_shared')('keys');
var uid = require('./_uid');
module.exports = function (key) {
  return shared[key] || (shared[key] = uid(key));
};

},{"./_shared":108,"./_uid":118}],108:[function(require,module,exports){
var core = require('./_core');
var global = require('./_global');
var SHARED = '__core-js_shared__';
var store = global[SHARED] || (global[SHARED] = {});

(module.exports = function (key, value) {
  return store[key] || (store[key] = value !== undefined ? value : {});
})('versions', []).push({
  version: core.version,
  mode: require('./_library') ? 'pure' : 'global',
  copyright: '© 2019 Denis Pushkarev (zloirock.ru)'
});

},{"./_core":55,"./_global":66,"./_library":83}],109:[function(require,module,exports){
var toInteger = require('./_to-integer');
var defined = require('./_defined');
// true  -> String#at
// false -> String#codePointAt
module.exports = function (TO_STRING) {
  return function (that, pos) {
    var s = String(defined(that));
    var i = toInteger(pos);
    var l = s.length;
    var a, b;
    if (i < 0 || i >= l) return TO_STRING ? '' : undefined;
    a = s.charCodeAt(i);
    return a < 0xd800 || a > 0xdbff || i + 1 === l || (b = s.charCodeAt(i + 1)) < 0xdc00 || b > 0xdfff
      ? TO_STRING ? s.charAt(i) : a
      : TO_STRING ? s.slice(i, i + 2) : (a - 0xd800 << 10) + (b - 0xdc00) + 0x10000;
  };
};

},{"./_defined":58,"./_to-integer":113}],110:[function(require,module,exports){
var $export = require('./_export');
var defined = require('./_defined');
var fails = require('./_fails');
var spaces = require('./_string-ws');
var space = '[' + spaces + ']';
var non = '\u200b\u0085';
var ltrim = RegExp('^' + space + space + '*');
var rtrim = RegExp(space + space + '*$');

var exporter = function (KEY, exec, ALIAS) {
  var exp = {};
  var FORCE = fails(function () {
    return !!spaces[KEY]() || non[KEY]() != non;
  });
  var fn = exp[KEY] = FORCE ? exec(trim) : spaces[KEY];
  if (ALIAS) exp[ALIAS] = fn;
  $export($export.P + $export.F * FORCE, 'String', exp);
};

// 1 -> String#trimLeft
// 2 -> String#trimRight
// 3 -> String#trim
var trim = exporter.trim = function (string, TYPE) {
  string = String(defined(string));
  if (TYPE & 1) string = string.replace(ltrim, '');
  if (TYPE & 2) string = string.replace(rtrim, '');
  return string;
};

module.exports = exporter;

},{"./_defined":58,"./_export":63,"./_fails":64,"./_string-ws":111}],111:[function(require,module,exports){
module.exports = '\x09\x0A\x0B\x0C\x0D\x20\xA0\u1680\u180E\u2000\u2001\u2002\u2003' +
  '\u2004\u2005\u2006\u2007\u2008\u2009\u200A\u202F\u205F\u3000\u2028\u2029\uFEFF';

},{}],112:[function(require,module,exports){
var toInteger = require('./_to-integer');
var max = Math.max;
var min = Math.min;
module.exports = function (index, length) {
  index = toInteger(index);
  return index < 0 ? max(index + length, 0) : min(index, length);
};

},{"./_to-integer":113}],113:[function(require,module,exports){
// 7.1.4 ToInteger
var ceil = Math.ceil;
var floor = Math.floor;
module.exports = function (it) {
  return isNaN(it = +it) ? 0 : (it > 0 ? floor : ceil)(it);
};

},{}],114:[function(require,module,exports){
// to indexed object, toObject with fallback for non-array-like ES3 strings
var IObject = require('./_iobject');
var defined = require('./_defined');
module.exports = function (it) {
  return IObject(defined(it));
};

},{"./_defined":58,"./_iobject":72}],115:[function(require,module,exports){
// 7.1.15 ToLength
var toInteger = require('./_to-integer');
var min = Math.min;
module.exports = function (it) {
  return it > 0 ? min(toInteger(it), 0x1fffffffffffff) : 0; // pow(2, 53) - 1 == 9007199254740991
};

},{"./_to-integer":113}],116:[function(require,module,exports){
// 7.1.13 ToObject(argument)
var defined = require('./_defined');
module.exports = function (it) {
  return Object(defined(it));
};

},{"./_defined":58}],117:[function(require,module,exports){
// 7.1.1 ToPrimitive(input [, PreferredType])
var isObject = require('./_is-object');
// instead of the ES6 spec version, we didn't implement @@toPrimitive case
// and the second argument - flag - preferred type is a string
module.exports = function (it, S) {
  if (!isObject(it)) return it;
  var fn, val;
  if (S && typeof (fn = it.toString) == 'function' && !isObject(val = fn.call(it))) return val;
  if (typeof (fn = it.valueOf) == 'function' && !isObject(val = fn.call(it))) return val;
  if (!S && typeof (fn = it.toString) == 'function' && !isObject(val = fn.call(it))) return val;
  throw TypeError("Can't convert object to primitive value");
};

},{"./_is-object":76}],118:[function(require,module,exports){
var id = 0;
var px = Math.random();
module.exports = function (key) {
  return 'Symbol('.concat(key === undefined ? '' : key, ')_', (++id + px).toString(36));
};

},{}],119:[function(require,module,exports){
var isObject = require('./_is-object');
module.exports = function (it, TYPE) {
  if (!isObject(it) || it._t !== TYPE) throw TypeError('Incompatible receiver, ' + TYPE + ' required!');
  return it;
};

},{"./_is-object":76}],120:[function(require,module,exports){
var global = require('./_global');
var core = require('./_core');
var LIBRARY = require('./_library');
var wksExt = require('./_wks-ext');
var defineProperty = require('./_object-dp').f;
module.exports = function (name) {
  var $Symbol = core.Symbol || (core.Symbol = LIBRARY ? {} : global.Symbol || {});
  if (name.charAt(0) != '_' && !(name in $Symbol)) defineProperty($Symbol, name, { value: wksExt.f(name) });
};

},{"./_core":55,"./_global":66,"./_library":83,"./_object-dp":87,"./_wks-ext":121}],121:[function(require,module,exports){
exports.f = require('./_wks');

},{"./_wks":122}],122:[function(require,module,exports){
var store = require('./_shared')('wks');
var uid = require('./_uid');
var Symbol = require('./_global').Symbol;
var USE_SYMBOL = typeof Symbol == 'function';

var $exports = module.exports = function (name) {
  return store[name] || (store[name] =
    USE_SYMBOL && Symbol[name] || (USE_SYMBOL ? Symbol : uid)('Symbol.' + name));
};

$exports.store = store;

},{"./_global":66,"./_shared":108,"./_uid":118}],123:[function(require,module,exports){
var classof = require('./_classof');
var ITERATOR = require('./_wks')('iterator');
var Iterators = require('./_iterators');
module.exports = require('./_core').getIteratorMethod = function (it) {
  if (it != undefined) return it[ITERATOR]
    || it['@@iterator']
    || Iterators[classof(it)];
};

},{"./_classof":50,"./_core":55,"./_iterators":82,"./_wks":122}],124:[function(require,module,exports){
var anObject = require('./_an-object');
var get = require('./core.get-iterator-method');
module.exports = require('./_core').getIterator = function (it) {
  var iterFn = get(it);
  if (typeof iterFn != 'function') throw TypeError(it + ' is not iterable!');
  return anObject(iterFn.call(it));
};

},{"./_an-object":43,"./_core":55,"./core.get-iterator-method":123}],125:[function(require,module,exports){
'use strict';
var ctx = require('./_ctx');
var $export = require('./_export');
var toObject = require('./_to-object');
var call = require('./_iter-call');
var isArrayIter = require('./_is-array-iter');
var toLength = require('./_to-length');
var createProperty = require('./_create-property');
var getIterFn = require('./core.get-iterator-method');

$export($export.S + $export.F * !require('./_iter-detect')(function (iter) { Array.from(iter); }), 'Array', {
  // 22.1.2.1 Array.from(arrayLike, mapfn = undefined, thisArg = undefined)
  from: function from(arrayLike /* , mapfn = undefined, thisArg = undefined */) {
    var O = toObject(arrayLike);
    var C = typeof this == 'function' ? this : Array;
    var aLen = arguments.length;
    var mapfn = aLen > 1 ? arguments[1] : undefined;
    var mapping = mapfn !== undefined;
    var index = 0;
    var iterFn = getIterFn(O);
    var length, result, step, iterator;
    if (mapping) mapfn = ctx(mapfn, aLen > 2 ? arguments[2] : undefined, 2);
    // if object isn't iterable or it's array with default iterator - use simple case
    if (iterFn != undefined && !(C == Array && isArrayIter(iterFn))) {
      for (iterator = iterFn.call(O), result = new C(); !(step = iterator.next()).done; index++) {
        createProperty(result, index, mapping ? call(iterator, mapfn, [step.value, index], true) : step.value);
      }
    } else {
      length = toLength(O.length);
      for (result = new C(length); length > index; index++) {
        createProperty(result, index, mapping ? mapfn(O[index], index) : O[index]);
      }
    }
    result.length = index;
    return result;
  }
});

},{"./_create-property":56,"./_ctx":57,"./_export":63,"./_is-array-iter":73,"./_iter-call":77,"./_iter-detect":80,"./_to-length":115,"./_to-object":116,"./core.get-iterator-method":123}],126:[function(require,module,exports){
// 22.1.2.2 / 15.4.3.2 Array.isArray(arg)
var $export = require('./_export');

$export($export.S, 'Array', { isArray: require('./_is-array') });

},{"./_export":63,"./_is-array":74}],127:[function(require,module,exports){
'use strict';
var addToUnscopables = require('./_add-to-unscopables');
var step = require('./_iter-step');
var Iterators = require('./_iterators');
var toIObject = require('./_to-iobject');

// 22.1.3.4 Array.prototype.entries()
// 22.1.3.13 Array.prototype.keys()
// 22.1.3.29 Array.prototype.values()
// 22.1.3.30 Array.prototype[@@iterator]()
module.exports = require('./_iter-define')(Array, 'Array', function (iterated, kind) {
  this._t = toIObject(iterated); // target
  this._i = 0;                   // next index
  this._k = kind;                // kind
// 22.1.5.2.1 %ArrayIteratorPrototype%.next()
}, function () {
  var O = this._t;
  var kind = this._k;
  var index = this._i++;
  if (!O || index >= O.length) {
    this._t = undefined;
    return step(1);
  }
  if (kind == 'keys') return step(0, index);
  if (kind == 'values') return step(0, O[index]);
  return step(0, [index, O[index]]);
}, 'values');

// argumentsList[@@iterator] is %ArrayProto_values% (9.4.4.6, 9.4.4.7)
Iterators.Arguments = Iterators.Array;

addToUnscopables('keys');
addToUnscopables('values');
addToUnscopables('entries');

},{"./_add-to-unscopables":41,"./_iter-define":79,"./_iter-step":81,"./_iterators":82,"./_to-iobject":114}],128:[function(require,module,exports){
// 20.1.2.3 Number.isInteger(number)
var $export = require('./_export');

$export($export.S, 'Number', { isInteger: require('./_is-integer') });

},{"./_export":63,"./_is-integer":75}],129:[function(require,module,exports){
// 19.1.3.1 Object.assign(target, source)
var $export = require('./_export');

$export($export.S + $export.F, 'Object', { assign: require('./_object-assign') });

},{"./_export":63,"./_object-assign":85}],130:[function(require,module,exports){
var $export = require('./_export');
// 19.1.2.2 / 15.2.3.5 Object.create(O [, Properties])
$export($export.S, 'Object', { create: require('./_object-create') });

},{"./_export":63,"./_object-create":86}],131:[function(require,module,exports){
var $export = require('./_export');
// 19.1.2.3 / 15.2.3.7 Object.defineProperties(O, Properties)
$export($export.S + $export.F * !require('./_descriptors'), 'Object', { defineProperties: require('./_object-dps') });

},{"./_descriptors":59,"./_export":63,"./_object-dps":88}],132:[function(require,module,exports){
var $export = require('./_export');
// 19.1.2.4 / 15.2.3.6 Object.defineProperty(O, P, Attributes)
$export($export.S + $export.F * !require('./_descriptors'), 'Object', { defineProperty: require('./_object-dp').f });

},{"./_descriptors":59,"./_export":63,"./_object-dp":87}],133:[function(require,module,exports){
// 19.1.2.7 Object.getOwnPropertyNames(O)
require('./_object-sap')('getOwnPropertyNames', function () {
  return require('./_object-gopn-ext').f;
});

},{"./_object-gopn-ext":90,"./_object-sap":97}],134:[function(require,module,exports){
// 19.1.2.9 Object.getPrototypeOf(O)
var toObject = require('./_to-object');
var $getPrototypeOf = require('./_object-gpo');

require('./_object-sap')('getPrototypeOf', function () {
  return function getPrototypeOf(it) {
    return $getPrototypeOf(toObject(it));
  };
});

},{"./_object-gpo":93,"./_object-sap":97,"./_to-object":116}],135:[function(require,module,exports){
// 19.1.2.14 Object.keys(O)
var toObject = require('./_to-object');
var $keys = require('./_object-keys');

require('./_object-sap')('keys', function () {
  return function keys(it) {
    return $keys(toObject(it));
  };
});

},{"./_object-keys":95,"./_object-sap":97,"./_to-object":116}],136:[function(require,module,exports){
// 19.1.3.19 Object.setPrototypeOf(O, proto)
var $export = require('./_export');
$export($export.S, 'Object', { setPrototypeOf: require('./_set-proto').set });

},{"./_export":63,"./_set-proto":104}],137:[function(require,module,exports){

},{}],138:[function(require,module,exports){
var $export = require('./_export');
var $parseInt = require('./_parse-int');
// 18.2.5 parseInt(string, radix)
$export($export.G + $export.F * (parseInt != $parseInt), { parseInt: $parseInt });

},{"./_export":63,"./_parse-int":98}],139:[function(require,module,exports){
// 26.1.2 Reflect.construct(target, argumentsList [, newTarget])
var $export = require('./_export');
var create = require('./_object-create');
var aFunction = require('./_a-function');
var anObject = require('./_an-object');
var isObject = require('./_is-object');
var fails = require('./_fails');
var bind = require('./_bind');
var rConstruct = (require('./_global').Reflect || {}).construct;

// MS Edge supports only 2 arguments and argumentsList argument is optional
// FF Nightly sets third argument as `new.target`, but does not create `this` from it
var NEW_TARGET_BUG = fails(function () {
  function F() { /* empty */ }
  return !(rConstruct(function () { /* empty */ }, [], F) instanceof F);
});
var ARGS_BUG = !fails(function () {
  rConstruct(function () { /* empty */ });
});

$export($export.S + $export.F * (NEW_TARGET_BUG || ARGS_BUG), 'Reflect', {
  construct: function construct(Target, args /* , newTarget */) {
    aFunction(Target);
    anObject(args);
    var newTarget = arguments.length < 3 ? Target : aFunction(arguments[2]);
    if (ARGS_BUG && !NEW_TARGET_BUG) return rConstruct(Target, args, newTarget);
    if (Target == newTarget) {
      // w/o altered newTarget, optimization for 0-4 arguments
      switch (args.length) {
        case 0: return new Target();
        case 1: return new Target(args[0]);
        case 2: return new Target(args[0], args[1]);
        case 3: return new Target(args[0], args[1], args[2]);
        case 4: return new Target(args[0], args[1], args[2], args[3]);
      }
      // w/o altered newTarget, lot of arguments case
      var $args = [null];
      $args.push.apply($args, args);
      return new (bind.apply(Target, $args))();
    }
    // with altered newTarget, not support built-in constructors
    var proto = newTarget.prototype;
    var instance = create(isObject(proto) ? proto : Object.prototype);
    var result = Function.apply.call(Target, instance, args);
    return isObject(result) ? result : instance;
  }
});

},{"./_a-function":40,"./_an-object":43,"./_bind":49,"./_export":63,"./_fails":64,"./_global":66,"./_is-object":76,"./_object-create":86}],140:[function(require,module,exports){
'use strict';
var strong = require('./_collection-strong');
var validate = require('./_validate-collection');
var SET = 'Set';

// 23.2 Set Objects
module.exports = require('./_collection')(SET, function (get) {
  return function Set() { return get(this, arguments.length > 0 ? arguments[0] : undefined); };
}, {
  // 23.2.3.1 Set.prototype.add(value)
  add: function add(value) {
    return strong.def(validate(this, SET), value = value === 0 ? 0 : value, value);
  }
}, strong);

},{"./_collection":54,"./_collection-strong":52,"./_validate-collection":119}],141:[function(require,module,exports){
'use strict';
var $at = require('./_string-at')(true);

// 21.1.3.27 String.prototype[@@iterator]()
require('./_iter-define')(String, 'String', function (iterated) {
  this._t = String(iterated); // target
  this._i = 0;                // next index
// 21.1.5.2.1 %StringIteratorPrototype%.next()
}, function () {
  var O = this._t;
  var index = this._i;
  var point;
  if (index >= O.length) return { value: undefined, done: true };
  point = $at(O, index);
  this._i += point.length;
  return { value: point, done: false };
});

},{"./_iter-define":79,"./_string-at":109}],142:[function(require,module,exports){
'use strict';
// ECMAScript 6 symbols shim
var global = require('./_global');
var has = require('./_has');
var DESCRIPTORS = require('./_descriptors');
var $export = require('./_export');
var redefine = require('./_redefine');
var META = require('./_meta').KEY;
var $fails = require('./_fails');
var shared = require('./_shared');
var setToStringTag = require('./_set-to-string-tag');
var uid = require('./_uid');
var wks = require('./_wks');
var wksExt = require('./_wks-ext');
var wksDefine = require('./_wks-define');
var enumKeys = require('./_enum-keys');
var isArray = require('./_is-array');
var anObject = require('./_an-object');
var isObject = require('./_is-object');
var toObject = require('./_to-object');
var toIObject = require('./_to-iobject');
var toPrimitive = require('./_to-primitive');
var createDesc = require('./_property-desc');
var _create = require('./_object-create');
var gOPNExt = require('./_object-gopn-ext');
var $GOPD = require('./_object-gopd');
var $GOPS = require('./_object-gops');
var $DP = require('./_object-dp');
var $keys = require('./_object-keys');
var gOPD = $GOPD.f;
var dP = $DP.f;
var gOPN = gOPNExt.f;
var $Symbol = global.Symbol;
var $JSON = global.JSON;
var _stringify = $JSON && $JSON.stringify;
var PROTOTYPE = 'prototype';
var HIDDEN = wks('_hidden');
var TO_PRIMITIVE = wks('toPrimitive');
var isEnum = {}.propertyIsEnumerable;
var SymbolRegistry = shared('symbol-registry');
var AllSymbols = shared('symbols');
var OPSymbols = shared('op-symbols');
var ObjectProto = Object[PROTOTYPE];
var USE_NATIVE = typeof $Symbol == 'function' && !!$GOPS.f;
var QObject = global.QObject;
// Don't use setters in Qt Script, https://github.com/zloirock/core-js/issues/173
var setter = !QObject || !QObject[PROTOTYPE] || !QObject[PROTOTYPE].findChild;

// fallback for old Android, https://code.google.com/p/v8/issues/detail?id=687
var setSymbolDesc = DESCRIPTORS && $fails(function () {
  return _create(dP({}, 'a', {
    get: function () { return dP(this, 'a', { value: 7 }).a; }
  })).a != 7;
}) ? function (it, key, D) {
  var protoDesc = gOPD(ObjectProto, key);
  if (protoDesc) delete ObjectProto[key];
  dP(it, key, D);
  if (protoDesc && it !== ObjectProto) dP(ObjectProto, key, protoDesc);
} : dP;

var wrap = function (tag) {
  var sym = AllSymbols[tag] = _create($Symbol[PROTOTYPE]);
  sym._k = tag;
  return sym;
};

var isSymbol = USE_NATIVE && typeof $Symbol.iterator == 'symbol' ? function (it) {
  return typeof it == 'symbol';
} : function (it) {
  return it instanceof $Symbol;
};

var $defineProperty = function defineProperty(it, key, D) {
  if (it === ObjectProto) $defineProperty(OPSymbols, key, D);
  anObject(it);
  key = toPrimitive(key, true);
  anObject(D);
  if (has(AllSymbols, key)) {
    if (!D.enumerable) {
      if (!has(it, HIDDEN)) dP(it, HIDDEN, createDesc(1, {}));
      it[HIDDEN][key] = true;
    } else {
      if (has(it, HIDDEN) && it[HIDDEN][key]) it[HIDDEN][key] = false;
      D = _create(D, { enumerable: createDesc(0, false) });
    } return setSymbolDesc(it, key, D);
  } return dP(it, key, D);
};
var $defineProperties = function defineProperties(it, P) {
  anObject(it);
  var keys = enumKeys(P = toIObject(P));
  var i = 0;
  var l = keys.length;
  var key;
  while (l > i) $defineProperty(it, key = keys[i++], P[key]);
  return it;
};
var $create = function create(it, P) {
  return P === undefined ? _create(it) : $defineProperties(_create(it), P);
};
var $propertyIsEnumerable = function propertyIsEnumerable(key) {
  var E = isEnum.call(this, key = toPrimitive(key, true));
  if (this === ObjectProto && has(AllSymbols, key) && !has(OPSymbols, key)) return false;
  return E || !has(this, key) || !has(AllSymbols, key) || has(this, HIDDEN) && this[HIDDEN][key] ? E : true;
};
var $getOwnPropertyDescriptor = function getOwnPropertyDescriptor(it, key) {
  it = toIObject(it);
  key = toPrimitive(key, true);
  if (it === ObjectProto && has(AllSymbols, key) && !has(OPSymbols, key)) return;
  var D = gOPD(it, key);
  if (D && has(AllSymbols, key) && !(has(it, HIDDEN) && it[HIDDEN][key])) D.enumerable = true;
  return D;
};
var $getOwnPropertyNames = function getOwnPropertyNames(it) {
  var names = gOPN(toIObject(it));
  var result = [];
  var i = 0;
  var key;
  while (names.length > i) {
    if (!has(AllSymbols, key = names[i++]) && key != HIDDEN && key != META) result.push(key);
  } return result;
};
var $getOwnPropertySymbols = function getOwnPropertySymbols(it) {
  var IS_OP = it === ObjectProto;
  var names = gOPN(IS_OP ? OPSymbols : toIObject(it));
  var result = [];
  var i = 0;
  var key;
  while (names.length > i) {
    if (has(AllSymbols, key = names[i++]) && (IS_OP ? has(ObjectProto, key) : true)) result.push(AllSymbols[key]);
  } return result;
};

// 19.4.1.1 Symbol([description])
if (!USE_NATIVE) {
  $Symbol = function Symbol() {
    if (this instanceof $Symbol) throw TypeError('Symbol is not a constructor!');
    var tag = uid(arguments.length > 0 ? arguments[0] : undefined);
    var $set = function (value) {
      if (this === ObjectProto) $set.call(OPSymbols, value);
      if (has(this, HIDDEN) && has(this[HIDDEN], tag)) this[HIDDEN][tag] = false;
      setSymbolDesc(this, tag, createDesc(1, value));
    };
    if (DESCRIPTORS && setter) setSymbolDesc(ObjectProto, tag, { configurable: true, set: $set });
    return wrap(tag);
  };
  redefine($Symbol[PROTOTYPE], 'toString', function toString() {
    return this._k;
  });

  $GOPD.f = $getOwnPropertyDescriptor;
  $DP.f = $defineProperty;
  require('./_object-gopn').f = gOPNExt.f = $getOwnPropertyNames;
  require('./_object-pie').f = $propertyIsEnumerable;
  $GOPS.f = $getOwnPropertySymbols;

  if (DESCRIPTORS && !require('./_library')) {
    redefine(ObjectProto, 'propertyIsEnumerable', $propertyIsEnumerable, true);
  }

  wksExt.f = function (name) {
    return wrap(wks(name));
  };
}

$export($export.G + $export.W + $export.F * !USE_NATIVE, { Symbol: $Symbol });

for (var es6Symbols = (
  // 19.4.2.2, 19.4.2.3, 19.4.2.4, 19.4.2.6, 19.4.2.8, 19.4.2.9, 19.4.2.10, 19.4.2.11, 19.4.2.12, 19.4.2.13, 19.4.2.14
  'hasInstance,isConcatSpreadable,iterator,match,replace,search,species,split,toPrimitive,toStringTag,unscopables'
).split(','), j = 0; es6Symbols.length > j;)wks(es6Symbols[j++]);

for (var wellKnownSymbols = $keys(wks.store), k = 0; wellKnownSymbols.length > k;) wksDefine(wellKnownSymbols[k++]);

$export($export.S + $export.F * !USE_NATIVE, 'Symbol', {
  // 19.4.2.1 Symbol.for(key)
  'for': function (key) {
    return has(SymbolRegistry, key += '')
      ? SymbolRegistry[key]
      : SymbolRegistry[key] = $Symbol(key);
  },
  // 19.4.2.5 Symbol.keyFor(sym)
  keyFor: function keyFor(sym) {
    if (!isSymbol(sym)) throw TypeError(sym + ' is not a symbol!');
    for (var key in SymbolRegistry) if (SymbolRegistry[key] === sym) return key;
  },
  useSetter: function () { setter = true; },
  useSimple: function () { setter = false; }
});

$export($export.S + $export.F * !USE_NATIVE, 'Object', {
  // 19.1.2.2 Object.create(O [, Properties])
  create: $create,
  // 19.1.2.4 Object.defineProperty(O, P, Attributes)
  defineProperty: $defineProperty,
  // 19.1.2.3 Object.defineProperties(O, Properties)
  defineProperties: $defineProperties,
  // 19.1.2.6 Object.getOwnPropertyDescriptor(O, P)
  getOwnPropertyDescriptor: $getOwnPropertyDescriptor,
  // 19.1.2.7 Object.getOwnPropertyNames(O)
  getOwnPropertyNames: $getOwnPropertyNames,
  // 19.1.2.8 Object.getOwnPropertySymbols(O)
  getOwnPropertySymbols: $getOwnPropertySymbols
});

// Chrome 38 and 39 `Object.getOwnPropertySymbols` fails on primitives
// https://bugs.chromium.org/p/v8/issues/detail?id=3443
var FAILS_ON_PRIMITIVES = $fails(function () { $GOPS.f(1); });

$export($export.S + $export.F * FAILS_ON_PRIMITIVES, 'Object', {
  getOwnPropertySymbols: function getOwnPropertySymbols(it) {
    return $GOPS.f(toObject(it));
  }
});

// 24.3.2 JSON.stringify(value [, replacer [, space]])
$JSON && $export($export.S + $export.F * (!USE_NATIVE || $fails(function () {
  var S = $Symbol();
  // MS Edge converts symbol values to JSON as {}
  // WebKit converts symbol values to JSON as null
  // V8 throws on boxed symbols
  return _stringify([S]) != '[null]' || _stringify({ a: S }) != '{}' || _stringify(Object(S)) != '{}';
})), 'JSON', {
  stringify: function stringify(it) {
    var args = [it];
    var i = 1;
    var replacer, $replacer;
    while (arguments.length > i) args.push(arguments[i++]);
    $replacer = replacer = args[1];
    if (!isObject(replacer) && it === undefined || isSymbol(it)) return; // IE8 returns string on undefined
    if (!isArray(replacer)) replacer = function (key, value) {
      if (typeof $replacer == 'function') value = $replacer.call(this, key, value);
      if (!isSymbol(value)) return value;
    };
    args[1] = replacer;
    return _stringify.apply($JSON, args);
  }
});

// 19.4.3.4 Symbol.prototype[@@toPrimitive](hint)
$Symbol[PROTOTYPE][TO_PRIMITIVE] || require('./_hide')($Symbol[PROTOTYPE], TO_PRIMITIVE, $Symbol[PROTOTYPE].valueOf);
// 19.4.3.5 Symbol.prototype[@@toStringTag]
setToStringTag($Symbol, 'Symbol');
// 20.2.1.9 Math[@@toStringTag]
setToStringTag(Math, 'Math', true);
// 24.3.3 JSON[@@toStringTag]
setToStringTag(global.JSON, 'JSON', true);

},{"./_an-object":43,"./_descriptors":59,"./_enum-keys":62,"./_export":63,"./_fails":64,"./_global":66,"./_has":67,"./_hide":68,"./_is-array":74,"./_is-object":76,"./_library":83,"./_meta":84,"./_object-create":86,"./_object-dp":87,"./_object-gopd":89,"./_object-gopn":91,"./_object-gopn-ext":90,"./_object-gops":92,"./_object-keys":95,"./_object-pie":96,"./_property-desc":99,"./_redefine":101,"./_set-to-string-tag":106,"./_shared":108,"./_to-iobject":114,"./_to-object":116,"./_to-primitive":117,"./_uid":118,"./_wks":122,"./_wks-define":120,"./_wks-ext":121}],143:[function(require,module,exports){
// https://tc39.github.io/proposal-setmap-offrom/#sec-set.from
require('./_set-collection-from')('Set');

},{"./_set-collection-from":102}],144:[function(require,module,exports){
// https://tc39.github.io/proposal-setmap-offrom/#sec-set.of
require('./_set-collection-of')('Set');

},{"./_set-collection-of":103}],145:[function(require,module,exports){
// https://github.com/DavidBruant/Map-Set.prototype.toJSON
var $export = require('./_export');

$export($export.P + $export.R, 'Set', { toJSON: require('./_collection-to-json')('Set') });

},{"./_collection-to-json":53,"./_export":63}],146:[function(require,module,exports){
require('./_wks-define')('asyncIterator');

},{"./_wks-define":120}],147:[function(require,module,exports){
require('./_wks-define')('observable');

},{"./_wks-define":120}],148:[function(require,module,exports){
require('./es6.array.iterator');
var global = require('./_global');
var hide = require('./_hide');
var Iterators = require('./_iterators');
var TO_STRING_TAG = require('./_wks')('toStringTag');

var DOMIterables = ('CSSRuleList,CSSStyleDeclaration,CSSValueList,ClientRectList,DOMRectList,DOMStringList,' +
  'DOMTokenList,DataTransferItemList,FileList,HTMLAllCollection,HTMLCollection,HTMLFormElement,HTMLSelectElement,' +
  'MediaList,MimeTypeArray,NamedNodeMap,NodeList,PaintRequestList,Plugin,PluginArray,SVGLengthList,SVGNumberList,' +
  'SVGPathSegList,SVGPointList,SVGStringList,SVGTransformList,SourceBufferList,StyleSheetList,TextTrackCueList,' +
  'TextTrackList,TouchList').split(',');

for (var i = 0; i < DOMIterables.length; i++) {
  var NAME = DOMIterables[i];
  var Collection = global[NAME];
  var proto = Collection && Collection.prototype;
  if (proto && !proto[TO_STRING_TAG]) hide(proto, TO_STRING_TAG, NAME);
  Iterators[NAME] = Iterators.Array;
}

},{"./_global":66,"./_hide":68,"./_iterators":82,"./_wks":122,"./es6.array.iterator":127}],149:[function(require,module,exports){
'use strict';

var _interopRequireDefault = require("@babel/runtime-corejs2/helpers/interopRequireDefault");

var _parseInt2 = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/parse-int"));

var _keys = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/object/keys"));

var _set = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/set"));

var _require = require('./result'),
    checkJniResult = _require.checkJniResult;

var VM = require('./vm');

var jsizeSize = 4;
var pointerSize = Process.pointerSize;
var kAccPublic = 0x0001;
var kAccStatic = 0x0008;
var kAccFinal = 0x0010;
var kAccNative = 0x0100;
var kAccPublicApi = 0x10000000;
var STD_STRING_SIZE = pointerSize === 4 ? 12 : 24;
var getArtRuntimeSpec = memoize(_getArtRuntimeSpec);
var getArtClassLinkerSpec = memoize(_getArtClassLinkerSpec);
var getArtMethodSpec = memoize(_getArtMethodSpec);
var getArtThreadSpec = memoize(_getArtThreadSpec);
var getArtThreadStateTransitionImpl = memoize(_getArtThreadStateTransitionImpl);
var getAndroidVersion = memoize(_getAndroidVersion);
var getAndroidApiLevel = memoize(_getAndroidApiLevel);
var makeCxxMethodWrapperReturningPointerByValue = Process.arch === 'ia32' ? makeCxxMethodWrapperReturningPointerByValueInFirstArg : makeCxxMethodWrapperReturningPointerByValueGeneric;
var nativeFunctionOptions = {
  exceptions: 'propagate'
};
var artThreadStateTransitions = {};
var cachedApi = null;

function getApi() {
  if (cachedApi === null) {
    cachedApi = _getApi();
  }

  return cachedApi;
}

function _getApi() {
  var vmModules = Process.enumerateModulesSync().filter(function (m) {
    return /^lib(art|dvm).so$/.test(m.name);
  }).filter(function (m) {
    return !/\/system\/fake-libs/.test(m.path);
  });

  if (vmModules.length === 0) {
    return null;
  }

  var vmModule = vmModules[0];
  var flavor = vmModule.name.indexOf('art') !== -1 ? 'art' : 'dalvik';
  var isArt = flavor === 'art';
  var temporaryApi = {
    addLocalReference: null,
    flavor: flavor
  };
  var pending = isArt ? [{
    module: vmModule.path,
    functions: {
      'JNI_GetCreatedJavaVMs': ['JNI_GetCreatedJavaVMs', 'int', ['pointer', 'int', 'pointer']],
      // Android < 7
      'artInterpreterToCompiledCodeBridge': function artInterpreterToCompiledCodeBridge(address) {
        this.artInterpreterToCompiledCodeBridge = address;
      },
      // Android >= 8
      '_ZN3art9JavaVMExt12AddGlobalRefEPNS_6ThreadENS_6ObjPtrINS_6mirror6ObjectEEE': ['art::JavaVMExt::AddGlobalRef', 'pointer', ['pointer', 'pointer', 'pointer']],
      // Android >= 6
      '_ZN3art9JavaVMExt12AddGlobalRefEPNS_6ThreadEPNS_6mirror6ObjectE': ['art::JavaVMExt::AddGlobalRef', 'pointer', ['pointer', 'pointer', 'pointer']],
      // Android < 6: makeAddGlobalRefFallbackForAndroid5() needs these:
      '_ZN3art17ReaderWriterMutex13ExclusiveLockEPNS_6ThreadE': ['art::ReaderWriterMutex::ExclusiveLock', 'void', ['pointer', 'pointer']],
      '_ZN3art17ReaderWriterMutex15ExclusiveUnlockEPNS_6ThreadE': ['art::ReaderWriterMutex::ExclusiveUnlock', 'void', ['pointer', 'pointer']],
      // Android <= 7
      '_ZN3art22IndirectReferenceTable3AddEjPNS_6mirror6ObjectE': function _ZN3art22IndirectReferenceTable3AddEjPNS_6mirror6ObjectE(address) {
        this['art::IndirectReferenceTable::Add'] = new NativeFunction(address, 'pointer', ['pointer', 'uint', 'pointer'], nativeFunctionOptions);
      },
      // Android > 7
      '_ZN3art22IndirectReferenceTable3AddENS_15IRTSegmentStateENS_6ObjPtrINS_6mirror6ObjectEEE': function _ZN3art22IndirectReferenceTable3AddENS_15IRTSegmentStateENS_6ObjPtrINS_6mirror6ObjectEEE(address) {
        this['art::IndirectReferenceTable::Add'] = new NativeFunction(address, 'pointer', ['pointer', 'uint', 'pointer'], nativeFunctionOptions);
      },
      // Android >= 7
      '_ZN3art9JavaVMExt12DecodeGlobalEPv': function _ZN3art9JavaVMExt12DecodeGlobalEPv(address) {
        var decodeGlobal;

        if (getAndroidApiLevel() >= 26) {
          // Returns ObjPtr<mirror::Object>
          decodeGlobal = makeCxxMethodWrapperReturningPointerByValue(address, ['pointer', 'pointer']);
        } else {
          // Returns mirror::Object *
          decodeGlobal = new NativeFunction(address, 'pointer', ['pointer', 'pointer'], nativeFunctionOptions);
        }

        this['art::JavaVMExt::DecodeGlobal'] = function (vm, thread, ref) {
          return decodeGlobal(vm, ref);
        };
      },
      // Android >= 6
      '_ZN3art9JavaVMExt12DecodeGlobalEPNS_6ThreadEPv': ['art::JavaVMExt::DecodeGlobal', 'pointer', ['pointer', 'pointer', 'pointer']],
      // Android < 6: makeDecodeGlobalFallbackForAndroid5() fallback uses:
      '_ZNK3art6Thread13DecodeJObjectEP8_jobject': ['art::Thread::DecodeJObject', 'pointer', ['pointer', 'pointer']],
      // Android >= 6
      '_ZN3art10ThreadList10SuspendAllEPKcb': ['art::ThreadList::SuspendAll', 'void', ['pointer', 'pointer', 'bool']],
      // or fallback:
      '_ZN3art10ThreadList10SuspendAllEv': function _ZN3art10ThreadList10SuspendAllEv(address) {
        var suspendAll = new NativeFunction(address, 'void', ['pointer'], nativeFunctionOptions);

        this['art::ThreadList::SuspendAll'] = function (threadList, cause, longSuspend) {
          return suspendAll(threadList);
        };
      },
      '_ZN3art10ThreadList9ResumeAllEv': ['art::ThreadList::ResumeAll', 'void', ['pointer']],
      // Android >= 7
      '_ZN3art11ClassLinker12VisitClassesEPNS_12ClassVisitorE': ['art::ClassLinker::VisitClasses', 'void', ['pointer', 'pointer']],
      // Android < 7
      '_ZN3art11ClassLinker12VisitClassesEPFbPNS_6mirror5ClassEPvES4_': function _ZN3art11ClassLinker12VisitClassesEPFbPNS_6mirror5ClassEPvES4_(address) {
        var visitClasses = new NativeFunction(address, 'void', ['pointer', 'pointer', 'pointer'], nativeFunctionOptions);

        this['art::ClassLinker::VisitClasses'] = function (classLinker, visitor) {
          visitClasses(classLinker, visitor, NULL);
        };
      },
      '_ZNK3art11ClassLinker17VisitClassLoadersEPNS_18ClassLoaderVisitorE': ['art::ClassLinker::VisitClassLoaders', 'void', ['pointer', 'pointer']],
      '_ZN3art2gc4Heap12VisitObjectsEPFvPNS_6mirror6ObjectEPvES5_': ['art::gc::Heap::VisitObjects', 'void', ['pointer', 'pointer', 'pointer']],
      '_ZN3art2gc4Heap12GetInstancesERNS_24VariableSizedHandleScopeENS_6HandleINS_6mirror5ClassEEEiRNSt3__16vectorINS4_INS5_6ObjectEEENS8_9allocatorISB_EEEE': ['art::gc::Heap::GetInstances', 'void', ['pointer', 'pointer', 'pointer', 'int', 'pointer']],
      // Android >= 9
      '_ZN3art2gc4Heap12GetInstancesERNS_24VariableSizedHandleScopeENS_6HandleINS_6mirror5ClassEEEbiRNSt3__16vectorINS4_INS5_6ObjectEEENS8_9allocatorISB_EEEE': function _ZN3art2gc4Heap12GetInstancesERNS_24VariableSizedHandleScopeENS_6HandleINS_6mirror5ClassEEEbiRNSt3__16vectorINS4_INS5_6ObjectEEENS8_9allocatorISB_EEEE(address) {
        var getInstances = new NativeFunction(address, 'void', ['pointer', 'pointer', 'pointer', 'bool', 'int', 'pointer'], nativeFunctionOptions);

        this['art::gc::Heap::GetInstances'] = function (instance, scope, hClass, maxCount, instances) {
          var useIsAssignableFrom = 0;
          getInstances(instance, scope, hClass, useIsAssignableFrom, maxCount, instances);
        };
      },
      // Android < 6 for cloneArtMethod()
      '_ZN3art6Thread14CurrentFromGdbEv': ['art::Thread::CurrentFromGdb', 'pointer', []],
      '_ZN3art6mirror6Object5CloneEPNS_6ThreadE': function _ZN3art6mirror6Object5CloneEPNS_6ThreadE(address) {
        this['art::mirror::Object::Clone'] = new NativeFunction(address, 'pointer', ['pointer', 'pointer'], nativeFunctionOptions);
      },
      '_ZN3art6mirror6Object5CloneEPNS_6ThreadEm': function _ZN3art6mirror6Object5CloneEPNS_6ThreadEm(address) {
        var nativeFn = new NativeFunction(address, 'pointer', ['pointer', 'pointer', 'pointer'], nativeFunctionOptions);

        this['art::mirror::Object::Clone'] = function (thisPtr, threadPtr) {
          var numTargetBytes = NULL;
          return nativeFn(thisPtr, threadPtr, numTargetBytes);
        };
      },
      '_ZN3art6mirror6Object5CloneEPNS_6ThreadEj': function _ZN3art6mirror6Object5CloneEPNS_6ThreadEj(address) {
        var nativeFn = new NativeFunction(address, 'pointer', ['pointer', 'pointer', 'uint'], nativeFunctionOptions);

        this['art::mirror::Object::Clone'] = function (thisPtr, threadPtr) {
          var numTargetBytes = 0;
          return nativeFn(thisPtr, threadPtr, numTargetBytes);
        };
      }
    },
    optionals: ['artInterpreterToCompiledCodeBridge', '_ZN3art9JavaVMExt12AddGlobalRefEPNS_6ThreadENS_6ObjPtrINS_6mirror6ObjectEEE', '_ZN3art9JavaVMExt12AddGlobalRefEPNS_6ThreadEPNS_6mirror6ObjectE', '_ZN3art9JavaVMExt12DecodeGlobalEPv', '_ZN3art9JavaVMExt12DecodeGlobalEPNS_6ThreadEPv', '_ZN3art10ThreadList10SuspendAllEPKcb', '_ZN3art10ThreadList10SuspendAllEv', '_ZN3art11ClassLinker12VisitClassesEPNS_12ClassVisitorE', '_ZN3art11ClassLinker12VisitClassesEPFbPNS_6mirror5ClassEPvES4_', '_ZNK3art11ClassLinker17VisitClassLoadersEPNS_18ClassLoaderVisitorE', '_ZN3art6mirror6Object5CloneEPNS_6ThreadE', '_ZN3art6mirror6Object5CloneEPNS_6ThreadEm', '_ZN3art6mirror6Object5CloneEPNS_6ThreadEj', '_ZN3art22IndirectReferenceTable3AddEjPNS_6mirror6ObjectE', '_ZN3art22IndirectReferenceTable3AddENS_15IRTSegmentStateENS_6ObjPtrINS_6mirror6ObjectEEE', '_ZN3art2gc4Heap12VisitObjectsEPFvPNS_6mirror6ObjectEPvES5_', '_ZN3art2gc4Heap12GetInstancesERNS_24VariableSizedHandleScopeENS_6HandleINS_6mirror5ClassEEEiRNSt3__16vectorINS4_INS5_6ObjectEEENS8_9allocatorISB_EEEE', '_ZN3art2gc4Heap12GetInstancesERNS_24VariableSizedHandleScopeENS_6HandleINS_6mirror5ClassEEEbiRNSt3__16vectorINS4_INS5_6ObjectEEENS8_9allocatorISB_EEEE']
  }] : [{
    module: vmModule.path,
    functions: {
      /*
       * Converts an indirect reference to to an object reference.
       */
      '_Z20dvmDecodeIndirectRefP6ThreadP8_jobject': ['dvmDecodeIndirectRef', 'pointer', ['pointer', 'pointer']],
      '_Z15dvmUseJNIBridgeP6MethodPv': ['dvmUseJNIBridge', 'void', ['pointer', 'pointer']],

      /*
       * Returns the base of the HeapSource.
       */
      '_Z20dvmHeapSourceGetBasev': ['dvmHeapSourceGetBase', 'pointer', []],

      /*
       * Returns the limit of the HeapSource.
       */
      '_Z21dvmHeapSourceGetLimitv': ['dvmHeapSourceGetLimit', 'pointer', []],

      /*
       *  Returns true if the pointer points to a valid object.
       */
      '_Z16dvmIsValidObjectPK6Object': ['dvmIsValidObject', 'uint8', ['pointer']],
      'JNI_GetCreatedJavaVMs': ['JNI_GetCreatedJavaVMs', 'int', ['pointer', 'int', 'pointer']]
    },
    variables: {
      'gDvmJni': function gDvmJni(address) {
        this.gDvmJni = address;
      },
      'gDvm': function gDvm(address) {
        this.gDvm = address;
      }
    }
  }];
  var missing = [];
  var total = 0;
  pending.forEach(function (api) {
    var functions = api.functions || {};
    var variables = api.variables || {};
    var optionals = new _set["default"](api.optionals || []);
    total += (0, _keys["default"])(functions).length + (0, _keys["default"])(variables).length;
    var exportByName = Module.enumerateExportsSync(api.module).reduce(function (result, exp) {
      result[exp.name] = exp;
      return result;
    }, {});
    (0, _keys["default"])(functions).forEach(function (name) {
      var exp = exportByName[name];

      if (exp !== undefined && exp.type === 'function') {
        var signature = functions[name];

        if (typeof signature === 'function') {
          signature.call(temporaryApi, exp.address);
        } else {
          temporaryApi[signature[0]] = new NativeFunction(exp.address, signature[1], signature[2], nativeFunctionOptions);
        }
      } else {
        if (!optionals.has(name)) {
          missing.push(name);
        }
      }
    });
    (0, _keys["default"])(variables).forEach(function (name) {
      var exp = exportByName[name];

      if (exp !== undefined && exp.type === 'variable') {
        var handler = variables[name];
        handler.call(temporaryApi, exp.address);
      } else {
        missing.push(name);
      }
    });
  });

  if (missing.length > 0) {
    throw new Error('Java API only partially available; please file a bug. Missing: ' + missing.join(', '));
  }

  var vms = Memory.alloc(pointerSize);
  var vmCount = Memory.alloc(jsizeSize);
  checkJniResult('JNI_GetCreatedJavaVMs', temporaryApi.JNI_GetCreatedJavaVMs(vms, 1, vmCount));

  if (Memory.readInt(vmCount) === 0) {
    return null;
  }

  temporaryApi.vm = Memory.readPointer(vms);

  if (isArt) {
    var artRuntime = Memory.readPointer(temporaryApi.vm.add(pointerSize));
    temporaryApi.artRuntime = artRuntime;
    var runtimeSpec = getArtRuntimeSpec(temporaryApi);
    temporaryApi.artHeap = Memory.readPointer(artRuntime.add(runtimeSpec.offset.heap));
    temporaryApi.artThreadList = Memory.readPointer(artRuntime.add(runtimeSpec.offset.threadList));
    /*
     * We must use the *correct* copy (or address) of art_quick_generic_jni_trampoline
     * in order for the stack trace to recognize the JNI stub quick frame.
     *
     * For ARTs for Android 6.x we can just use the JNI trampoline built into ART.
     */

    var classLinker = Memory.readPointer(artRuntime.add(runtimeSpec.offset.classLinker));
    temporaryApi.artClassLinker = classLinker;
    temporaryApi.artQuickGenericJniTrampoline = Memory.readPointer(classLinker.add(getArtClassLinkerSpec(temporaryApi).offset.quickGenericJniTrampoline));

    if (temporaryApi['art::JavaVMExt::AddGlobalRef'] === undefined) {
      temporaryApi['art::JavaVMExt::AddGlobalRef'] = makeAddGlobalRefFallbackForAndroid5(temporaryApi);
    }

    if (temporaryApi['art::JavaVMExt::DecodeGlobal'] === undefined) {
      temporaryApi['art::JavaVMExt::DecodeGlobal'] = makeDecodeGlobalFallbackForAndroid5(temporaryApi);
    }
  }

  var cxxImports = Module.enumerateImportsSync(vmModule.path).filter(function (imp) {
    return imp.name.indexOf('_Z') === 0;
  }).reduce(function (result, imp) {
    result[imp.name] = imp.address;
    return result;
  }, {});
  temporaryApi['$new'] = new NativeFunction(cxxImports['_Znwm'] || cxxImports['_Znwj'], 'pointer', ['ulong'], nativeFunctionOptions);
  temporaryApi['$delete'] = new NativeFunction(cxxImports['_ZdlPv'], 'void', ['pointer'], nativeFunctionOptions);
  return temporaryApi;
}

function ensureClassInitialized(env, classRef) {
  var api = getApi();

  if (api.flavor !== 'art') {
    return;
  }

  env.getFieldId(classRef, 'x', 'Z');
  env.exceptionClear();
}

function getArtVMSpec(api) {
  return {
    offset: pointerSize === 4 ? {
      globalsLock: 32,
      globals: 72
    } : {
      globalsLock: 64,
      globals: 112
    }
  };
}

function _getArtRuntimeSpec(api) {
  /*
   * class Runtime {
   * ...
   * gc::Heap* heap_;                <-- we need to find this
   * std::unique_ptr<ArenaPool> jit_arena_pool_;     <----- API level >= 24
   * std::unique_ptr<ArenaPool> arena_pool_;             __
   * std::unique_ptr<ArenaPool> low_4gb_arena_pool_; <--|__ API level >= 23
   * std::unique_ptr<LinearAlloc> linear_alloc_;         \_
   * size_t max_spins_before_thin_lock_inflation_;
   * MonitorList* monitor_list_;
   * MonitorPool* monitor_pool_;
   * ThreadList* thread_list_;        <--- and these
   * InternTable* intern_table_;      <--/
   * ClassLinker* class_linker_;      <-/
   * SignalCatcher* signal_catcher_;
   * bool use_tombstoned_traces_;     <-------------------- API level >= 27
   * std::string stack_trace_file_;
   * JavaVMExt* java_vm_;             <-- so we find this then calculate our way backwards
   * ...
   * }
   */
  var vm = api.vm;
  var runtime = api.artRuntime;
  var startOffset = pointerSize === 4 ? 200 : 384;
  var endOffset = startOffset + 100 * pointerSize;
  var apiLevel = getAndroidApiLevel();
  var spec = null;

  for (var offset = startOffset; offset !== endOffset; offset += pointerSize) {
    var value = Memory.readPointer(runtime.add(offset));

    if (value.equals(vm)) {
      var classLinkerOffset = offset - STD_STRING_SIZE - 2 * pointerSize;

      if (apiLevel >= 27) {
        classLinkerOffset -= pointerSize;
      }

      var internTableOffset = classLinkerOffset - pointerSize;
      var threadListOffset = internTableOffset - pointerSize;
      var heapOffset = threadListOffset - 4 * pointerSize;

      if (apiLevel >= 23) {
        heapOffset -= 3 * pointerSize;
      }

      if (apiLevel >= 24) {
        heapOffset -= pointerSize;
      }

      spec = {
        offset: {
          heap: heapOffset,
          threadList: threadListOffset,
          internTable: internTableOffset,
          classLinker: classLinkerOffset
        }
      };
      break;
    }
  }

  if (spec === null) {
    throw new Error('Unable to determine Runtime field offsets');
  }

  return spec;
}

function _getArtClassLinkerSpec(api) {
  /*
   * On Android 5.x:
   *
   * class ClassLinker {
   * ...
   * InternTable* intern_table_;                          <-- We find this then calculate our way forwards
   * const void* portable_resolution_trampoline_;
   * const void* quick_resolution_trampoline_;
   * const void* portable_imt_conflict_trampoline_;
   * const void* quick_imt_conflict_trampoline_;
   * const void* quick_generic_jni_trampoline_;           <-- ...to this
   * const void* quick_to_interpreter_bridge_trampoline_;
   * ...
   * }
   *
   * On Android 6.x and above:
   *
   * class ClassLinker {
   * ...
   * InternTable* intern_table_;                          <-- We find this then calculate our way forwards
   * const void* quick_resolution_trampoline_;
   * const void* quick_imt_conflict_trampoline_;
   * const void* quick_generic_jni_trampoline_;           <-- ...to this
   * const void* quick_to_interpreter_bridge_trampoline_;
   * ...
   * }
   */
  var runtime = api.artRuntime;
  var runtimeSpec = getArtRuntimeSpec(api);
  var classLinker = Memory.readPointer(runtime.add(runtimeSpec.offset.classLinker));
  var internTable = Memory.readPointer(runtime.add(runtimeSpec.offset.internTable));
  var startOffset = pointerSize === 4 ? 100 : 200;
  var endOffset = startOffset + 100 * pointerSize;
  var spec = null;

  for (var offset = startOffset; offset !== endOffset; offset += pointerSize) {
    var value = Memory.readPointer(classLinker.add(offset));

    if (value.equals(internTable)) {
      var delta = getAndroidApiLevel() >= 23 ? 3 : 5;
      spec = {
        offset: {
          quickGenericJniTrampoline: offset + delta * pointerSize
        }
      };
      break;
    }
  }

  if (spec === null) {
    throw new Error('Unable to determine ClassLinker field offsets');
  }

  return spec;
}

function _getArtMethodSpec(vm) {
  var api = getApi();
  var spec;
  vm.perform(function () {
    var env = vm.getEnv();
    var process = env.findClass('android/os/Process');
    var setArgV0 = env.getStaticMethodId(process, 'setArgV0', '(Ljava/lang/String;)V');
    var runtimeModule = Process.getModuleByName('libandroid_runtime.so');
    var runtimeStart = runtimeModule.base;
    var runtimeEnd = runtimeStart.add(runtimeModule.size);
    var apiLevel = getAndroidApiLevel();
    var entrypointFieldSize = apiLevel <= 21 ? 8 : pointerSize;
    var expectedAccessFlags = kAccPublic | kAccStatic | kAccFinal | kAccNative;
    var allFlagsExceptPublicApi = ~kAccPublicApi >>> 0;
    var jniCodeOffset = null;
    var accessFlagsOffset = null;
    var remaining = 2;

    for (var offset = 0; offset !== 64 && remaining !== 0; offset += 4) {
      var field = setArgV0.add(offset);

      if (jniCodeOffset === null) {
        var address = Memory.readPointer(field);

        if (address.compare(runtimeStart) >= 0 && address.compare(runtimeEnd) < 0) {
          jniCodeOffset = offset;
          remaining--;
        }
      }

      if (accessFlagsOffset === null) {
        var flags = Memory.readU32(field);

        if ((flags & allFlagsExceptPublicApi) === expectedAccessFlags) {
          accessFlagsOffset = offset;
          remaining--;
        }
      }
    }

    if (remaining !== 0) {
      throw new Error('Unable to determine ArtMethod field offsets');
    }

    var quickCodeOffset = jniCodeOffset + entrypointFieldSize;
    var size = apiLevel <= 21 ? quickCodeOffset + 32 : quickCodeOffset + pointerSize;
    spec = {
      size: size,
      offset: {
        jniCode: jniCodeOffset,
        quickCode: quickCodeOffset,
        accessFlags: accessFlagsOffset
      }
    };

    if ('artInterpreterToCompiledCodeBridge' in api) {
      spec.offset.interpreterCode = jniCodeOffset - entrypointFieldSize;
    }
  });
  return spec;
}

function _getArtThreadSpec(vm) {
  /*
   * bool32_t is_exception_reported_to_instrumentation_; <-- We need this on API level <= 22
   * ...
   * mirror::Throwable* exception;                       <-- ...and this on all versions
   * uint8_t* stack_end;
   * ManagedStack managed_stack;
   * uintptr_t* suspend_trigger;
   * JNIEnvExt* jni_env;                                 <-- We find this then calculate our way backwards/forwards
   * JNIEnvExt* tmp_jni_env;                             <-- API level >= 23
   * Thread* self;
   * mirror::Object* opeer;
   * jobject jpeer;
   * uint8_t* stack_begin;
   * size_t stack_size;
   * ThrowLocation throw_location;                       <-- ...and this on API level <= 22
   * union DepsOrStackTraceSample {
   *   DepsOrStackTraceSample() {
   *     verifier_deps = nullptr;
   *     stack_trace_sample = nullptr;
   *   }
   *   std::vector<ArtMethod*>* stack_trace_sample;
   *   verifier::VerifierDeps* verifier_deps;
   * } deps_or_stack_trace_sample;
   * Thread* wait_next;
   * mirror::Object* monitor_enter_object;
   * BaseHandleScope* top_handle_scope;                  <-- ...and to this on all versions
   */
  var api = getApi();
  var apiLevel = getAndroidApiLevel();
  var spec;
  vm.perform(function () {
    var env = vm.getEnv();
    var threadHandle = getArtThreadFromEnv(env);
    var envHandle = env.handle;
    var isExceptionReportedOffset = null;
    var exceptionOffset = null;
    var throwLocationOffset = null;
    var topHandleScopeOffset = null;

    for (var offset = 144; offset !== 256; offset += pointerSize) {
      var field = threadHandle.add(offset);
      var value = Memory.readPointer(field);

      if (value.equals(envHandle)) {
        exceptionOffset = offset - 6 * pointerSize;

        if (apiLevel <= 22) {
          exceptionOffset -= pointerSize;
          isExceptionReportedOffset = exceptionOffset - pointerSize - 9 * 8 - 3 * 4;
          throwLocationOffset = offset + 6 * pointerSize;
        }

        topHandleScopeOffset = offset + 9 * pointerSize;

        if (apiLevel <= 22) {
          topHandleScopeOffset += 2 * pointerSize + 4;

          if (pointerSize === 8) {
            topHandleScopeOffset += 4;
          }
        }

        if (apiLevel >= 23) {
          topHandleScopeOffset += pointerSize;
        }

        break;
      }
    }

    if (topHandleScopeOffset === null) {
      throw new Error('Unable to determine ArtThread field offsets');
    }

    spec = {
      offset: {
        isExceptionReportedToInstrumentation: isExceptionReportedOffset,
        exception: exceptionOffset,
        throwLocation: throwLocationOffset,
        topHandleScope: topHandleScopeOffset
      }
    };
  });
  return spec;
}

function getArtThreadFromEnv(env) {
  return Memory.readPointer(env.handle.add(pointerSize));
}

function _getAndroidVersion() {
  return getAndroidSystemProperty('ro.build.version.release');
}

function _getAndroidApiLevel() {
  return (0, _parseInt2["default"])(getAndroidSystemProperty('ro.build.version.sdk'), 10);
}

var systemPropertyGet = null;
var PROP_VALUE_MAX = 92;

function getAndroidSystemProperty(name) {
  if (systemPropertyGet === null) {
    systemPropertyGet = new NativeFunction(Module.findExportByName('libc.so', '__system_property_get'), 'int', ['pointer', 'pointer'], nativeFunctionOptions);
  }

  var buf = Memory.alloc(PROP_VALUE_MAX);
  systemPropertyGet(Memory.allocUtf8String(name), buf);
  return Memory.readUtf8String(buf);
}

function withRunnableArtThread(vm, env, fn) {
  var perform = getArtThreadStateTransitionImpl(vm, env);
  var id = getArtThreadFromEnv(env).toString();
  artThreadStateTransitions[id] = fn;
  perform(env.handle);

  if (artThreadStateTransitions[id] !== undefined) {
    delete artThreadStateTransitions[id];
    throw new Error('Unable to perform state transition; please file a bug at https://github.com/frida/frida-java');
  }
}

function onThreadStateTransitionComplete(thread) {
  var id = thread.toString();
  var fn = artThreadStateTransitions[id];
  delete artThreadStateTransitions[id];
  fn(thread);
}

function withAllArtThreadsSuspended(fn) {
  var api = getApi();
  var threadList = api.artThreadList;
  var longSuspend = false;
  api['art::ThreadList::SuspendAll'](threadList, Memory.allocUtf8String('frida'), longSuspend ? 1 : 0);

  try {
    fn();
  } finally {
    api['art::ThreadList::ResumeAll'](threadList);
  }
}

var ArtClassVisitor = function ArtClassVisitor(visit) {
  var visitor = Memory.alloc(4 * pointerSize);
  var vtable = visitor.add(pointerSize);
  Memory.writePointer(visitor, vtable);
  var onVisit = new NativeCallback(function (self, klass) {
    return visit(klass) === true ? 1 : 0;
  }, 'bool', ['pointer', 'pointer']);
  Memory.writePointer(vtable.add(2 * pointerSize), onVisit);
  this.handle = visitor;
  this._onVisit = onVisit;
};

function makeArtClassVisitor(visit) {
  var api = getApi();

  if (api['art::ClassLinker::VisitClasses'] instanceof NativeFunction) {
    return new ArtClassVisitor(visit);
  }

  return new NativeCallback(function (klass) {
    return visit(klass) === true ? 1 : 0;
  }, 'bool', ['pointer', 'pointer']);
}

var ArtClassLoaderVisitor = function ArtClassLoaderVisitor(visit) {
  var visitor = Memory.alloc(4 * pointerSize);
  var vtable = visitor.add(pointerSize);
  Memory.writePointer(visitor, vtable);
  var onVisit = new NativeCallback(function (self, klass) {
    visit(klass);
  }, 'void', ['pointer', 'pointer']);
  Memory.writePointer(vtable.add(2 * pointerSize), onVisit);
  this.handle = visitor;
  this._onVisit = onVisit;
};

function makeArtClassLoaderVisitor(visit) {
  return new ArtClassLoaderVisitor(visit);
}

function cloneArtMethod(method) {
  var api = getApi();

  if (getAndroidApiLevel() < 23) {
    var thread = api['art::Thread::CurrentFromGdb']();
    return api['art::mirror::Object::Clone'](method, thread);
  }

  return Memory.dup(method, getArtMethodSpec(api.vm).size);
}

function makeAddGlobalRefFallbackForAndroid5(api) {
  var offset = getArtVMSpec().offset;
  var lock = api.vm.add(offset.globalsLock);
  var table = api.vm.add(offset.globals);
  var add = api['art::IndirectReferenceTable::Add'];
  var acquire = api['art::ReaderWriterMutex::ExclusiveLock'];
  var release = api['art::ReaderWriterMutex::ExclusiveUnlock'];
  var IRT_FIRST_SEGMENT = 0;
  return function (vm, thread, obj) {
    acquire(lock, thread);

    try {
      return add(table, IRT_FIRST_SEGMENT, obj);
    } finally {
      release(lock, thread);
    }
  };
}

function makeDecodeGlobalFallbackForAndroid5(api) {
  var decode = api['art::Thread::DecodeJObject'];
  return function (vm, thread, ref) {
    return decode(thread, ref);
  };
}

var threadStateTransitionRecompilers = {
  ia32: recompileExceptionClearForX86,
  x64: recompileExceptionClearForX86,
  arm: recompileExceptionClearForArm,
  arm64: recompileExceptionClearForArm64
};

function _getArtThreadStateTransitionImpl(vm, env) {
  var exceptionClearImpl = null;
  var exceptionClearSymbol = Module.enumerateSymbolsSync('libart.so').filter(function (s) {
    return s.name === '_ZN3art3JNI14ExceptionClearEP7_JNIEnv';
  })[0];

  if (exceptionClearSymbol !== undefined) {
    exceptionClearImpl = exceptionClearSymbol.address;
  } else {
    var envVtable = Memory.readPointer(env.handle);
    exceptionClearImpl = Memory.readPointer(envVtable.add(17 * pointerSize));
  }

  var recompile = threadStateTransitionRecompilers[Process.arch];

  if (recompile === undefined) {
    throw new Error('Not yet implemented for ' + Process.arch);
  }

  var perform = null;
  var callback = new NativeCallback(onThreadStateTransitionComplete, 'void', ['pointer']);
  var threadOffsets = getArtThreadSpec(vm).offset;
  var exceptionOffset = threadOffsets.exception;
  var neuteredOffsets = new _set["default"]();
  var isReportedOffset = threadOffsets.isExceptionReportedToInstrumentation;

  if (isReportedOffset !== null) {
    neuteredOffsets.add(isReportedOffset);
  }

  var throwLocationStartOffset = threadOffsets.throwLocation;

  if (throwLocationStartOffset !== null) {
    neuteredOffsets.add(throwLocationStartOffset);
    neuteredOffsets.add(throwLocationStartOffset + pointerSize);
    neuteredOffsets.add(throwLocationStartOffset + 2 * pointerSize);
  }

  var codeSize = 65536;
  var code = Memory.alloc(codeSize);
  Memory.patchCode(code, codeSize, function (buffer) {
    perform = recompile(buffer, code, exceptionClearImpl, exceptionOffset, neuteredOffsets, callback);
  });
  perform._code = code;
  perform._callback = callback;
  return perform;
}

function recompileExceptionClearForX86(buffer, pc, exceptionClearImpl, exceptionOffset, neuteredOffsets, callback) {
  var blocks = {};
  var blockByInstruction = {};
  var branchTargets = new _set["default"]();
  var pending = [exceptionClearImpl];

  var _loop = function _loop() {
    var current = pending.shift();
    var blockAddressKey = current.toString();

    if (blockByInstruction[blockAddressKey] !== undefined) {
      return "continue";
    }

    var block = {
      begin: current
    };
    var instructionAddressIds = [];
    var reachedEndOfBlock = false;

    do {
      var insn = Instruction.parse(current);
      var insnAddressId = insn.address.toString();
      var mnemonic = insn.mnemonic;
      instructionAddressIds.push(insnAddressId);
      var existingBlock = blocks[insnAddressId];

      if (existingBlock !== undefined) {
        delete blocks[existingBlock.begin.toString()];
        blocks[blockAddressKey] = existingBlock;
        existingBlock.begin = block.begin;
        block = null;
        break;
      }

      var branchTarget = null;

      switch (mnemonic) {
        case 'jmp':
          branchTarget = ptr(insn.operands[0].value);
          reachedEndOfBlock = true;
          break;

        case 'je':
        case 'jg':
        case 'jle':
        case 'jne':
        case 'js':
          branchTarget = ptr(insn.operands[0].value);
          break;

        case 'ret':
          reachedEndOfBlock = true;
          break;
      }

      if (branchTarget !== null) {
        branchTargets.add(branchTarget.toString());
        pending.push(branchTarget);
        pending.sort(function (a, b) {
          return a.compare(b);
        });
      }

      current = insn.next;
    } while (!reachedEndOfBlock);

    if (block !== null) {
      block.end = ptr(instructionAddressIds[instructionAddressIds.length - 1]);
      blocks[blockAddressKey] = block;
      instructionAddressIds.forEach(function (id) {
        blockByInstruction[id] = block;
      });
    }
  };

  while (pending.length > 0) {
    var _ret = _loop();

    if (_ret === "continue") continue;
  }

  var blocksOrdered = (0, _keys["default"])(blocks).map(function (key) {
    return blocks[key];
  });
  blocksOrdered.sort(function (a, b) {
    return a.begin.compare(b.begin);
  });
  var entryBlock = blocks[exceptionClearImpl.toString()];
  blocksOrdered.splice(blocksOrdered.indexOf(entryBlock), 1);
  blocksOrdered.unshift(entryBlock);
  var writer = new X86Writer(buffer, {
    pc: pc
  });
  var exceptionClearInstructionFound = false;
  var threadReg = null;
  blocksOrdered.forEach(function (block) {
    var relocator = new X86Relocator(block.begin, writer);
    var offset;

    while ((offset = relocator.readOne()) !== 0) {
      var insn = relocator.input;
      var mnemonic = insn.mnemonic;
      var insnAddressId = insn.address.toString();

      if (branchTargets.has(insnAddressId)) {
        writer.putLabel(insnAddressId);
      }

      switch (mnemonic) {
        case 'jmp':
          writer.putJmpNearLabel(branchLabelFromOperand(insn.operands[0]));
          relocator.skipOne();
          break;

        case 'je':
        case 'jg':
        case 'jle':
        case 'jne':
        case 'js':
          writer.putJccNearLabel(mnemonic, branchLabelFromOperand(insn.operands[0]), 'no-hint');
          relocator.skipOne();
          break;

        case 'mov':
          {
            var _insn$operands = insn.operands,
                dst = _insn$operands[0],
                src = _insn$operands[1];

            if (dst.type === 'mem' && src.type === 'imm') {
              var dstValue = dst.value;
              var dstOffset = dstValue.disp;

              if (dstOffset === exceptionOffset && src.value.valueOf() === 0) {
                threadReg = dstValue.base;
                writer.putPushfx();
                writer.putPushax();
                writer.putMovRegReg('xbp', 'xsp');

                if (pointerSize === 4) {
                  writer.putAndRegU32('esp', 0xfffffff0);
                } else {
                  writer.putMovRegU64('rax', uint64('0xfffffffffffffff0'));
                  writer.putAndRegReg('rsp', 'rax');
                }

                writer.putCallAddressWithAlignedArguments(callback, [threadReg]);
                writer.putMovRegReg('xsp', 'xbp');
                writer.putPopax();
                writer.putPopfx();
                relocator.skipOne();
                exceptionClearInstructionFound = true;
                break;
              }

              if (neuteredOffsets.has(dstOffset) && dstValue.base === threadReg) {
                relocator.skipOne();
                break;
              }
            }
          }

        default:
          relocator.writeAll();
      }
    }

    relocator.dispose();
  });
  writer.dispose();

  if (!exceptionClearInstructionFound) {
    throwThreadStateTransitionParseError();
  }

  return new NativeFunction(pc, 'void', ['pointer'], nativeFunctionOptions);
}

function recompileExceptionClearForArm(buffer, pc, exceptionClearImpl, exceptionOffset, neuteredOffsets, callback) {
  var blocks = {};
  var blockByInstruction = {};
  var branchTargets = new _set["default"]();
  var unsupportedInstructions = {};
  var thumbBitRemovalMask = ptr(1).not();
  var pending = [exceptionClearImpl];

  var _loop2 = function _loop2() {
    var current = pending.shift();
    var begin = current.and(thumbBitRemovalMask);
    var blockId = begin.toString();
    var thumbBit = current.and(1);

    if (blockByInstruction[blockId] !== undefined) {
      return "continue";
    }

    var block = {
      begin: begin
    };
    var instructionAddressIds = [];
    var reachedEndOfBlock = false;
    var ifThenBlockRemaining = 0;

    do {
      var currentAddress = current.and(thumbBitRemovalMask);
      var insnId = currentAddress.toString();
      instructionAddressIds.push(insnId);
      var insn = void 0;

      try {
        insn = Instruction.parse(current);
      } catch (e) {
        var first = Memory.readU16(currentAddress);
        var second = Memory.readU16(currentAddress.add(2)); // TODO: fix this in Capstone

        var firstUpperBits = first & 0xfff0;
        var isLdaex = firstUpperBits === 0xe8d0 && (second & 0x0fff) === 0x0fef;
        var isStlex = firstUpperBits === 0xe8c0 && (second & 0x0ff0) === 0x0fe0;

        if (isLdaex || isStlex) {
          current = current.add(4);
          unsupportedInstructions[insnId] = [first, second];
          continue;
        }

        throw e;
      }

      var _insn = insn,
          mnemonic = _insn.mnemonic;
      var existingBlock = blocks[insnId];

      if (existingBlock !== undefined) {
        delete blocks[existingBlock.begin.toString()];
        blocks[blockId] = existingBlock;
        existingBlock.begin = block.begin;
        block = null;
        break;
      }

      var isOutsideIfThenBlock = ifThenBlockRemaining === 0;
      var branchTarget = null;

      switch (mnemonic) {
        case 'b':
          branchTarget = ptr(insn.operands[0].value);
          reachedEndOfBlock = isOutsideIfThenBlock;
          break;

        case 'beq.w':
        case 'beq':
        case 'bne':
        case 'bgt':
          branchTarget = ptr(insn.operands[0].value);
          break;

        case 'cbz':
        case 'cbnz':
          branchTarget = ptr(insn.operands[1].value);
          break;

        case 'pop.w':
          if (isOutsideIfThenBlock) {
            reachedEndOfBlock = insn.operands.filter(function (op) {
              return op.value === 'pc';
            }).length === 1;
          }

          break;
      }

      switch (mnemonic) {
        case 'it':
          ifThenBlockRemaining = 1;
          break;

        case 'itt':
          ifThenBlockRemaining = 2;
          break;

        case 'ittt':
          ifThenBlockRemaining = 3;
          break;

        case 'itttt':
          ifThenBlockRemaining = 4;
          break;

        default:
          if (ifThenBlockRemaining > 0) {
            ifThenBlockRemaining--;
          }

          break;
      }

      if (branchTarget !== null) {
        branchTargets.add(branchTarget.toString());
        pending.push(branchTarget.or(thumbBit));
        pending.sort(function (a, b) {
          return a.compare(b);
        });
      }

      current = insn.next;
    } while (!reachedEndOfBlock);

    if (block !== null) {
      block.end = ptr(instructionAddressIds[instructionAddressIds.length - 1]);
      blocks[blockId] = block;
      instructionAddressIds.forEach(function (id) {
        blockByInstruction[id] = block;
      });
    }
  };

  while (pending.length > 0) {
    var _ret2 = _loop2();

    if (_ret2 === "continue") continue;
  }

  var blocksOrdered = (0, _keys["default"])(blocks).map(function (key) {
    return blocks[key];
  });
  blocksOrdered.sort(function (a, b) {
    return a.begin.compare(b.begin);
  });
  var entryBlock = blocks[exceptionClearImpl.and(thumbBitRemovalMask).toString()];
  blocksOrdered.splice(blocksOrdered.indexOf(entryBlock), 1);
  blocksOrdered.unshift(entryBlock);
  var writer = new ThumbWriter(buffer, {
    pc: pc
  });
  var exceptionClearInstructionFound = false;
  var threadReg = null;
  blocksOrdered.forEach(function (block) {
    var relocator = new ThumbRelocator(block.begin, writer);
    var address = block.begin;
    var end = block.end;
    var size = 0;

    do {
      var offset = relocator.readOne();

      if (offset === 0) {
        var next = address.add(size);
        var instructions = unsupportedInstructions[next.toString()];

        if (instructions !== undefined) {
          instructions.forEach(function (rawInsn) {
            return writer.putInstruction(rawInsn);
          });
          relocator.reset(next.add(instructions.length * 2), writer);
          continue;
        }

        throw new Error('Unexpected end of block');
      }

      var insn = relocator.input;
      address = insn.address;
      size = insn.size;
      var mnemonic = insn.mnemonic;
      var insnAddressId = address.toString();

      if (branchTargets.has(insnAddressId)) {
        writer.putLabel(insnAddressId);
      }

      switch (mnemonic) {
        case 'b':
          writer.putBLabel(branchLabelFromOperand(insn.operands[0]));
          relocator.skipOne();
          break;

        case 'beq.w':
          writer.putBCondLabelWide('eq', branchLabelFromOperand(insn.operands[0]));
          relocator.skipOne();
          break;

        case 'beq':
        case 'bne':
        case 'bgt':
          writer.putBCondLabelWide(mnemonic.substr(1), branchLabelFromOperand(insn.operands[0]));
          relocator.skipOne();
          break;

        case 'cbz':
          {
            var ops = insn.operands;
            writer.putCbzRegLabel(ops[0].value, branchLabelFromOperand(ops[1]));
            relocator.skipOne();
            break;
          }

        case 'cbnz':
          {
            var _ops = insn.operands;
            writer.putCbnzRegLabel(_ops[0].value, branchLabelFromOperand(_ops[1]));
            relocator.skipOne();
            break;
          }

        case 'str':
        case 'str.w':
          {
            var dstValue = insn.operands[1].value;
            var dstOffset = dstValue.disp;

            if (dstOffset === exceptionOffset) {
              threadReg = dstValue.base;
              var nzcvqReg = threadReg !== 'r4' ? 'r4' : 'r5';
              var clobberedRegs = ['r0', 'r1', 'r2', 'r3', nzcvqReg, 'r9', 'r12', 'lr'];
              writer.putPushRegs(clobberedRegs);
              writer.putMrsRegReg(nzcvqReg, 'apsr_nzcvq');
              writer.putCallAddressWithArguments(callback, [threadReg]);
              writer.putMsrRegReg('apsr_nzcvq', nzcvqReg);
              writer.putPopRegs(clobberedRegs);
              relocator.skipOne();
              exceptionClearInstructionFound = true;
              break;
            }

            if (neuteredOffsets.has(dstOffset) && dstValue.base === threadReg) {
              relocator.skipOne();
              break;
            }
          }

        default:
          relocator.writeAll();
          break;
      }
    } while (!address.equals(end));

    relocator.dispose();
  });
  writer.dispose();

  if (!exceptionClearInstructionFound) {
    throwThreadStateTransitionParseError();
  }

  return new NativeFunction(pc.or(1), 'void', ['pointer'], nativeFunctionOptions);
}

function recompileExceptionClearForArm64(buffer, pc, exceptionClearImpl, exceptionOffset, neuteredOffsets, callback) {
  var blocks = {};
  var blockByInstruction = {};
  var branchTargets = new _set["default"]();
  var pending = [exceptionClearImpl];

  var _loop3 = function _loop3() {
    var current = pending.shift();
    var blockAddressKey = current.toString();

    if (blockByInstruction[blockAddressKey] !== undefined) {
      return "continue";
    }

    var block = {
      begin: current
    };
    var instructionAddressIds = [];
    var reachedEndOfBlock = false;

    do {
      var insn = Instruction.parse(current);
      var insnAddressId = insn.address.toString();
      var mnemonic = insn.mnemonic;
      instructionAddressIds.push(insnAddressId);
      var existingBlock = blocks[insnAddressId];

      if (existingBlock !== undefined) {
        delete blocks[existingBlock.begin.toString()];
        blocks[blockAddressKey] = existingBlock;
        existingBlock.begin = block.begin;
        block = null;
        break;
      }

      var branchTarget = null;

      switch (mnemonic) {
        case 'b':
          branchTarget = ptr(insn.operands[0].value);
          reachedEndOfBlock = true;
          break;

        case 'b.eq':
        case 'b.ne':
        case 'b.gt':
          branchTarget = ptr(insn.operands[0].value);
          break;

        case 'cbz':
        case 'cbnz':
          branchTarget = ptr(insn.operands[1].value);
          break;

        case 'tbz':
        case 'tbnz':
          branchTarget = ptr(insn.operands[2].value);
          break;

        case 'ret':
          reachedEndOfBlock = true;
          break;
      }

      if (branchTarget !== null) {
        branchTargets.add(branchTarget.toString());
        pending.push(branchTarget);
        pending.sort(function (a, b) {
          return a.compare(b);
        });
      }

      current = insn.next;
    } while (!reachedEndOfBlock);

    if (block !== null) {
      block.end = ptr(instructionAddressIds[instructionAddressIds.length - 1]);
      blocks[blockAddressKey] = block;
      instructionAddressIds.forEach(function (id) {
        blockByInstruction[id] = block;
      });
    }
  };

  while (pending.length > 0) {
    var _ret3 = _loop3();

    if (_ret3 === "continue") continue;
  }

  var blocksOrdered = (0, _keys["default"])(blocks).map(function (key) {
    return blocks[key];
  });
  blocksOrdered.sort(function (a, b) {
    return a.begin.compare(b.begin);
  });
  var entryBlock = blocks[exceptionClearImpl.toString()];
  blocksOrdered.splice(blocksOrdered.indexOf(entryBlock), 1);
  blocksOrdered.unshift(entryBlock);
  var writer = new Arm64Writer(buffer, {
    pc: pc
  });
  writer.putBLabel('performTransition');
  var invokeCallback = pc.add(writer.offset);
  writer.putPushAllXRegisters();
  writer.putCallAddressWithArguments(callback, ['x0']);
  writer.putPopAllXRegisters();
  writer.putRet();
  writer.putLabel('performTransition');
  var exceptionClearInstructionFound = false;
  var threadReg = null;
  blocksOrdered.forEach(function (block) {
    var relocator = new Arm64Relocator(block.begin, writer);
    var offset;

    while ((offset = relocator.readOne()) !== 0) {
      var insn = relocator.input;
      var mnemonic = insn.mnemonic;
      var insnAddressId = insn.address.toString();

      if (branchTargets.has(insnAddressId)) {
        writer.putLabel(insnAddressId);
      }

      switch (mnemonic) {
        case 'b':
          writer.putBLabel(branchLabelFromOperand(insn.operands[0]));
          relocator.skipOne();
          break;

        case 'b.eq':
        case 'b.ne':
        case 'b.gt':
          writer.putBCondLabel(mnemonic.substr(2), branchLabelFromOperand(insn.operands[0]));
          relocator.skipOne();
          break;

        case 'cbz':
          {
            var ops = insn.operands;
            writer.putCbzRegLabel(ops[0].value, branchLabelFromOperand(ops[1]));
            relocator.skipOne();
            break;
          }

        case 'cbnz':
          {
            var _ops2 = insn.operands;
            writer.putCbnzRegLabel(_ops2[0].value, branchLabelFromOperand(_ops2[1]));
            relocator.skipOne();
            break;
          }

        case 'tbz':
          {
            var _ops3 = insn.operands;
            writer.putTbzRegImmLabel(_ops3[0].value, _ops3[1].value.valueOf(), branchLabelFromOperand(_ops3[2]));
            relocator.skipOne();
            break;
          }

        case 'tbnz':
          {
            var _ops4 = insn.operands;
            writer.putTbnzRegImmLabel(_ops4[0].value, _ops4[1].value.valueOf(), branchLabelFromOperand(_ops4[2]));
            relocator.skipOne();
            break;
          }

        case 'str':
          {
            var _ops5 = insn.operands;
            var srcReg = _ops5[0].value;
            var dstValue = _ops5[1].value;
            var dstOffset = dstValue.disp;

            if (srcReg === 'xzr' && dstOffset === exceptionOffset) {
              threadReg = dstValue.base;
              writer.putPushRegReg('x0', 'lr');
              writer.putMovRegReg('x0', threadReg);
              writer.putBlImm(invokeCallback);
              writer.putPopRegReg('x0', 'lr');
              relocator.skipOne();
              exceptionClearInstructionFound = true;
              break;
            }

            if (neuteredOffsets.has(dstOffset) && dstValue.base === threadReg) {
              relocator.skipOne();
              break;
            }
          }

        default:
          relocator.writeAll();
      }
    }

    relocator.dispose();
  });
  writer.dispose();

  if (!exceptionClearInstructionFound) {
    throwThreadStateTransitionParseError();
  }

  return new NativeFunction(pc, 'void', ['pointer'], nativeFunctionOptions);
}

function throwThreadStateTransitionParseError() {
  throw new Error('Unable to parse ART internals; please file a bug at https://github.com/frida/frida-java');
}

function branchLabelFromOperand(op) {
  return ptr(op.value).toString();
}

function memoize(compute) {
  var value = null;
  var computed = false;
  return function () {
    if (!computed) {
      value = compute.apply(void 0, arguments);
      computed = true;
    }

    return value;
  };
}

function makeCxxMethodWrapperReturningPointerByValueGeneric(address, argTypes) {
  return new NativeFunction(address, 'pointer', argTypes, nativeFunctionOptions);
}

function makeCxxMethodWrapperReturningPointerByValueInFirstArg(address, argTypes) {
  var impl = new NativeFunction(address, 'void', ['pointer'].concat(argTypes), nativeFunctionOptions);
  return function () {
    var resultPtr = Memory.alloc(pointerSize);
    impl.apply(void 0, [resultPtr].concat(Array.prototype.slice.call(arguments)));
    return Memory.readPointer(resultPtr);
  };
}

module.exports = {
  getApi: getApi,
  ensureClassInitialized: ensureClassInitialized,
  getAndroidVersion: getAndroidVersion,
  getAndroidApiLevel: getAndroidApiLevel,
  getArtMethodSpec: getArtMethodSpec,
  getArtThreadSpec: getArtThreadSpec,
  getArtThreadFromEnv: getArtThreadFromEnv,
  withRunnableArtThread: withRunnableArtThread,
  withAllArtThreadsSuspended: withAllArtThreadsSuspended,
  makeArtClassVisitor: makeArtClassVisitor,
  makeArtClassLoaderVisitor: makeArtClassLoaderVisitor,
  cloneArtMethod: cloneArtMethod
};
/* global Memory, Module, NativeCallback, NativeFunction, NULL, Process */

},{"./result":154,"./vm":155,"@babel/runtime-corejs2/core-js/object/keys":13,"@babel/runtime-corejs2/core-js/parse-int":15,"@babel/runtime-corejs2/core-js/set":17,"@babel/runtime-corejs2/helpers/interopRequireDefault":22}],150:[function(require,module,exports){
'use strict';

module.exports = require('./android').getApi;

},{"./android":149}],151:[function(require,module,exports){
'use strict';

var _interopRequireDefault = require("@babel/runtime-corejs2/helpers/interopRequireDefault");

var _parseInt2 = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/parse-int"));

var _isInteger = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/number/is-integer"));

var _construct2 = _interopRequireDefault(require("@babel/runtime-corejs2/helpers/construct"));

var _getOwnPropertyNames = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/object/get-own-property-names"));

var _getPrototypeOf = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/object/get-prototype-of"));

var _defineProperties = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/object/define-properties"));

var _keys = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/object/keys"));

var _inheritsLoose2 = _interopRequireDefault(require("@babel/runtime-corejs2/helpers/inheritsLoose"));

var _createClass2 = _interopRequireDefault(require("@babel/runtime-corejs2/helpers/createClass"));

var _getIterator2 = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/get-iterator"));

var _isArray2 = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/array/is-array"));

var _defineProperty = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/object/define-property"));

var _from = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/array/from"));

var _symbol = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/symbol"));

var _set = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/set"));

var Env = require('./env'); // eslint-disable-line


var getApi = require('./api');

var _require = require('./android'),
    ensureClassInitialized = _require.ensureClassInitialized,
    getAndroidVersion = _require.getAndroidVersion,
    getArtMethodSpec = _require.getArtMethodSpec,
    getArtThreadSpec = _require.getArtThreadSpec,
    withRunnableArtThread = _require.withRunnableArtThread,
    cloneArtMethod = _require.cloneArtMethod;

var mkdex = require('./mkdex');

var _require2 = require('./result'),
    JNI_OK = _require2.JNI_OK;

var pointerSize = Process.pointerSize;
var CONSTRUCTOR_METHOD = 1;
var STATIC_METHOD = 2;
var INSTANCE_METHOD = 3;
var STATIC_FIELD = 1;
var INSTANCE_FIELD = 2;
var DVM_JNI_ENV_OFFSET_SELF = 12;
var DVM_CLASS_OBJECT_OFFSET_VTABLE_COUNT = 112;
var DVM_CLASS_OBJECT_OFFSET_VTABLE = 116;
var DVM_OBJECT_OFFSET_CLAZZ = 0;
var DVM_METHOD_SIZE = 56;
var DVM_METHOD_OFFSET_ACCESS_FLAGS = 4;
var DVM_METHOD_OFFSET_METHOD_INDEX = 8;
var DVM_METHOD_OFFSET_REGISTERS_SIZE = 10;
var DVM_METHOD_OFFSET_OUTS_SIZE = 12;
var DVM_METHOD_OFFSET_INS_SIZE = 14;
var DVM_METHOD_OFFSET_SHORTY = 28;
var DVM_METHOD_OFFSET_JNI_ARG_INFO = 36;
var DALVIK_JNI_RETURN_VOID = 0;
var DALVIK_JNI_RETURN_FLOAT = 1;
var DALVIK_JNI_RETURN_DOUBLE = 2;
var DALVIK_JNI_RETURN_S8 = 3;
var DALVIK_JNI_RETURN_S4 = 4;
var DALVIK_JNI_RETURN_S2 = 5;
var DALVIK_JNI_RETURN_U2 = 6;
var DALVIK_JNI_RETURN_S1 = 7;
var DALVIK_JNI_NO_ARG_INFO = 0x80000000;
var DALVIK_JNI_RETURN_MASK = 0x70000000;
var DALVIK_JNI_RETURN_SHIFT = 28;
var DALVIK_JNI_COUNT_MASK = 0x0f000000;
var DALVIK_JNI_COUNT_SHIFT = 24;
var kAccNative = 0x0100;
var kAccFastNative = 0x00080000;
var kAccXposedHookedMethod = 0x10000000;
var JNILocalRefType = 1;

function ClassFactory(vm) {
  var factory = this;
  var api = null;
  var classes = {};
  var patchedClasses = {};
  var patchedMethods = new _set["default"]();
  var ignoredThreads = {};
  var loader = null;
  var cachedLoaderInvoke = null;
  var cachedLoaderMethod = null;
  var cacheDir = '/data/local/tmp';
  var tempFileNaming = {
    prefix: 'frida',
    suffix: 'dat'
  };
  var PENDING_CALLS = (0, _symbol["default"])('PENDING_CALLS');

  function initialize() {
    api = getApi();
  }

  this.dispose = function (env) {
    (0, _from["default"])(patchedMethods).forEach(function (method) {
      method.implementation = null;
    });
    patchedMethods.clear();

    for (var entryId in patchedClasses) {
      if (patchedClasses.hasOwnProperty(entryId)) {
        var entry = patchedClasses[entryId];
        Memory.writePointer(entry.vtablePtr, entry.vtable);
        Memory.writeS32(entry.vtableCountPtr, entry.vtableCount);
        var targetMethods = entry.targetMethods;

        for (var methodId in targetMethods) {
          if (targetMethods.hasOwnProperty(methodId)) {
            targetMethods[methodId].implementation = null;
            delete targetMethods[methodId];
          }
        }

        delete patchedClasses[entryId];
      }
    }

    classes = {};
  };

  (0, _defineProperty["default"])(this, 'loader', {
    enumerable: true,
    get: function get() {
      return loader;
    },
    set: function set(value) {
      loader = value;
    }
  });
  (0, _defineProperty["default"])(this, 'cacheDir', {
    enumerable: true,
    get: function get() {
      return cacheDir;
    },
    set: function set(value) {
      cacheDir = value;
    }
  });
  (0, _defineProperty["default"])(this, 'tempFileNaming', {
    enumerable: true,
    get: function get() {
      return tempFileNaming;
    },
    set: function set(value) {
      tempFileNaming = value;
    }
  });

  this.use = function (className) {
    var C = classes[className];

    if (!C) {
      var env = vm.getEnv();

      if (loader !== null) {
        var usedLoader = loader;

        if (cachedLoaderMethod === null) {
          cachedLoaderInvoke = env.vaMethod('pointer', ['pointer']);
          cachedLoaderMethod = loader.loadClass.overload('java.lang.String').handle;
        }

        var getClassHandle = function getClassHandle(env) {
          var classNameValue = env.newStringUtf(className);
          var tid = Process.getCurrentThreadId();
          ignore(tid);

          try {
            return cachedLoaderInvoke(env.handle, usedLoader.$handle, cachedLoaderMethod, classNameValue);
          } finally {
            unignore(tid);
            env.deleteLocalRef(classNameValue);
          }
        };

        C = ensureClass(getClassHandle, className);
      } else {
        var canonicalClassName = className.replace(/\./g, '/');

        var _getClassHandle = function _getClassHandle(env) {
          var tid = Process.getCurrentThreadId();
          ignore(tid);

          try {
            return env.findClass(canonicalClassName);
          } finally {
            unignore(tid);
          }
        };

        C = ensureClass(_getClassHandle, className);
      }
    }

    return new C(null);
  };

  function DexFile(path, file) {
    if (file === void 0) {
      file = null;
    }

    this.path = path;
    this.file = file;
  }

  DexFile.fromBuffer = function (buffer) {
    var fileValue = createTemporaryDex();
    var filePath = fileValue.getCanonicalPath().toString();
    var file = new File(filePath, 'w');
    file.write(buffer.buffer);
    file.close();
    return new DexFile(filePath, fileValue);
  };

  DexFile.prototype = {
    load: function load() {
      var DexClassLoader = factory.use('dalvik.system.DexClassLoader');
      var file = this.file;

      if (file === null) {
        file = factory.use('java.io.File').$new(this.path);
      }

      if (!file.exists()) {
        throw new Error('File not found');
      }

      loader = DexClassLoader.$new(file.getCanonicalPath(), cacheDir, null, loader);
      vm.preventDetachDueToClassLoader();
    },
    getClassNames: function getClassNames() {
      var DexFile = factory.use('dalvik.system.DexFile');
      var optimizedDex = createTemporaryDex();
      var dx = DexFile.loadDex(this.path, optimizedDex.getCanonicalPath(), 0);
      var classNames = [];
      var enumeratorClassNames = dx.entries();

      while (enumeratorClassNames.hasMoreElements()) {
        classNames.push(enumeratorClassNames.nextElement().toString());
      }

      return classNames;
    }
  };

  function createTemporaryDex() {
    var JFile = factory.use('java.io.File');
    var cacheDirValue = JFile.$new(cacheDir);
    cacheDirValue.mkdirs();
    return JFile.createTempFile(tempFileNaming.prefix, tempFileNaming.suffix, cacheDirValue);
  }

  this.openClassFile = function (filePath) {
    return new DexFile(filePath);
  };

  this.choose = function (specifier, callbacks) {
    if (api.flavor === 'art') {
      var env = vm.getEnv();
      withRunnableArtThread(vm, env, function (thread) {
        if (api['art::gc::Heap::VisitObjects'] === undefined) {
          chooseObjectsArtModern(env, thread, specifier, callbacks);
        } else {
          chooseObjectsArtLegacy(env, thread, specifier, callbacks);
        }
      });
    } else {
      chooseObjectsDalvik(specifier, callbacks);
    }
  };

  function chooseObjectsArtModern(env, thread, className, callbacks) {
    var klass = factory.use(className);
    var scope = VariableSizedHandleScope.$new(thread);
    var localClassHandle = klass.$getClassHandle(env);
    var globalClassHandle = env.newGlobalRef(localClassHandle);
    var object = api['art::JavaVMExt::DecodeGlobal'](api.vm, thread, globalClassHandle);
    var needle = scope.newHandle(object);
    env.deleteGlobalRef(globalClassHandle);
    env.deleteLocalRef(localClassHandle);
    var maxCount = 0;
    var instances = HandleVector.$new();
    api['art::gc::Heap::GetInstances'](api.artHeap, scope, needle, maxCount, instances);
    var instanceHandles = instances.handles.map(function (handle) {
      return env.newGlobalRef(handle);
    });
    instances.$delete();
    scope.$delete();

    try {
      for (var _iterator = instanceHandles, _isArray = (0, _isArray2["default"])(_iterator), _i = 0, _iterator = _isArray ? _iterator : (0, _getIterator2["default"])(_iterator);;) {
        var _ref;

        if (_isArray) {
          if (_i >= _iterator.length) break;
          _ref = _iterator[_i++];
        } else {
          _i = _iterator.next();
          if (_i.done) break;
          _ref = _i.value;
        }

        var handle = _ref;
        var instance = factory.cast(handle, klass);
        var result = callbacks.onMatch(instance);

        if (result === 'stop') {
          break;
        }
      }

      callbacks.onComplete();
    } finally {
      instanceHandles.forEach(function (handle) {
        env.deleteGlobalRef(handle);
      });
    }
  }

  var BHS_OFFSET_LINK = 0;
  var BHS_OFFSET_NUM_REFS = pointerSize;
  var BHS_SIZE = BHS_OFFSET_NUM_REFS + 4;
  var kNumReferencesVariableSized = -1;

  var BaseHandleScope =
  /*#__PURE__*/
  function () {
    var _proto = BaseHandleScope.prototype;

    _proto.$delete = function $delete() {
      this.finalize();
      api.$delete(this);
    };

    function BaseHandleScope(storage) {
      this.handle = storage;
      this._link = storage.add(BHS_OFFSET_LINK);
      this._numberOfReferences = storage.add(BHS_OFFSET_NUM_REFS);
    }

    _proto.init = function init(link, numberOfReferences) {
      this.link = link;
      this.numberOfReferences = numberOfReferences;
    };

    _proto.finalize = function finalize() {};

    (0, _createClass2["default"])(BaseHandleScope, [{
      key: "link",
      get: function get() {
        return new BaseHandleScope(Memory.readPointer(this._link));
      },
      set: function set(value) {
        Memory.writePointer(this._link, value);
      }
    }, {
      key: "numberOfReferences",
      get: function get() {
        return Memory.readS32(this._numberOfReferences);
      },
      set: function set(value) {
        Memory.writeS32(this._numberOfReferences, value);
      }
    }]);
    return BaseHandleScope;
  }();

  var VSHS_OFFSET_SELF = alignPointerOffset(BHS_SIZE);
  var VSHS_OFFSET_CURRENT_SCOPE = VSHS_OFFSET_SELF + pointerSize;
  var VSHS_SIZE = VSHS_OFFSET_CURRENT_SCOPE + pointerSize;

  var VariableSizedHandleScope =
  /*#__PURE__*/
  function (_BaseHandleScope) {
    (0, _inheritsLoose2["default"])(VariableSizedHandleScope, _BaseHandleScope);

    VariableSizedHandleScope.$new = function $new(thread) {
      var scope = new VariableSizedHandleScope(api.$new(VSHS_SIZE));
      scope.init(thread);
      return scope;
    };

    function VariableSizedHandleScope(storage) {
      var _this;

      _this = _BaseHandleScope.call(this, storage) || this;
      _this._self = storage.add(VSHS_OFFSET_SELF);
      _this._currentScope = storage.add(VSHS_OFFSET_CURRENT_SCOPE);
      var kLocalScopeSize = 64;
      var kSizeOfReferencesPerScope = kLocalScopeSize - pointerSize - 4 - 4;
      var kNumReferencesPerScope = kSizeOfReferencesPerScope / 4;
      _this._scopeLayout = FixedSizeHandleScope.layoutForCapacity(kNumReferencesPerScope);
      _this._topHandleScopePtr = null;
      return _this;
    }

    var _proto2 = VariableSizedHandleScope.prototype;

    _proto2.init = function init(thread) {
      var topHandleScopePtr = thread.add(getArtThreadSpec(vm).offset.topHandleScope);
      this._topHandleScopePtr = topHandleScopePtr;

      _BaseHandleScope.prototype.init.call(this, Memory.readPointer(topHandleScopePtr), kNumReferencesVariableSized);

      this.self = thread;
      this.currentScope = FixedSizeHandleScope.$new(this._scopeLayout);
      Memory.writePointer(topHandleScopePtr, this);
    };

    _proto2.finalize = function finalize() {
      Memory.writePointer(this._topHandleScopePtr, this.link);
      var scope;

      while ((scope = this.currentScope) !== null) {
        var next = scope.link;
        scope.$delete();
        this.currentScope = next;
      }
    };

    _proto2.newHandle = function newHandle(object) {
      return this.currentScope.newHandle(object);
    };

    (0, _createClass2["default"])(VariableSizedHandleScope, [{
      key: "self",
      get: function get() {
        return Memory.readPointer(this._self);
      },
      set: function set(value) {
        Memory.writePointer(this._self, value);
      }
    }, {
      key: "currentScope",
      get: function get() {
        var storage = Memory.readPointer(this._currentScope);

        if (storage.isNull()) {
          return null;
        }

        return new FixedSizeHandleScope(storage, this._scopeLayout);
      },
      set: function set(value) {
        Memory.writePointer(this._currentScope, value);
      }
    }]);
    return VariableSizedHandleScope;
  }(BaseHandleScope);

  var FixedSizeHandleScope =
  /*#__PURE__*/
  function (_BaseHandleScope2) {
    (0, _inheritsLoose2["default"])(FixedSizeHandleScope, _BaseHandleScope2);

    FixedSizeHandleScope.$new = function $new(layout) {
      var scope = new FixedSizeHandleScope(api.$new(layout.size), layout);
      scope.init();
      return scope;
    };

    function FixedSizeHandleScope(storage, layout) {
      var _this2;

      _this2 = _BaseHandleScope2.call(this, storage) || this;
      var offset = layout.offset;
      _this2._refsStorage = storage.add(offset.refsStorage);
      _this2._pos = storage.add(offset.pos);
      _this2._layout = layout;
      return _this2;
    }

    var _proto3 = FixedSizeHandleScope.prototype;

    _proto3.init = function init() {
      _BaseHandleScope2.prototype.init.call(this, NULL, this._layout.numberOfReferences);

      this.pos = 0;
    };

    _proto3.newHandle = function newHandle(object) {
      var pos = this.pos;

      var handle = this._refsStorage.add(pos * 4);

      Memory.writeS32(handle, object.toInt32());
      this.pos = pos + 1;
      return handle;
    };

    FixedSizeHandleScope.layoutForCapacity = function layoutForCapacity(numRefs) {
      var refsStorage = BHS_SIZE;
      var pos = refsStorage + numRefs * 4;
      return {
        size: pos + 4,
        numberOfReferences: numRefs,
        offset: {
          refsStorage: refsStorage,
          pos: pos
        }
      };
    };

    (0, _createClass2["default"])(FixedSizeHandleScope, [{
      key: "pos",
      get: function get() {
        return Memory.readU32(this._pos);
      },
      set: function set(value) {
        Memory.writeU32(this._pos, value);
      }
    }]);
    return FixedSizeHandleScope;
  }(BaseHandleScope);

  var STD_VECTOR_SIZE = 3 * pointerSize;

  var StdVector =
  /*#__PURE__*/
  function () {
    var _proto4 = StdVector.prototype;

    _proto4.$delete = function $delete() {
      this.finalize();
      api.$delete(this);
    };

    function StdVector(storage, elementSize) {
      this.handle = storage;
      this._begin = storage;
      this._end = storage.add(pointerSize);
      this._storage = storage.add(2 * pointerSize);
      this._elementSize = elementSize;
    }

    _proto4.init = function init() {
      this.begin = NULL;
      this.end = NULL;
      this.storage = NULL;
    };

    _proto4.finalize = function finalize() {
      api.$delete(this.begin);
    };

    (0, _createClass2["default"])(StdVector, [{
      key: "begin",
      get: function get() {
        return Memory.readPointer(this._begin);
      },
      set: function set(value) {
        Memory.writePointer(this._begin, value);
      }
    }, {
      key: "end",
      get: function get() {
        return Memory.readPointer(this._end);
      },
      set: function set(value) {
        Memory.writePointer(this._end, value);
      }
    }, {
      key: "storage",
      get: function get() {
        return Memory.readPointer(this._storage);
      },
      set: function set(value) {
        Memory.writePointer(this._storage, value);
      }
    }, {
      key: "size",
      get: function get() {
        return this.end.sub(this.begin).toInt32() / this._elementSize;
      }
    }]);
    return StdVector;
  }();

  var HandleVector =
  /*#__PURE__*/
  function (_StdVector) {
    (0, _inheritsLoose2["default"])(HandleVector, _StdVector);

    HandleVector.$new = function $new() {
      var vector = new HandleVector(api.$new(STD_VECTOR_SIZE));
      vector.init();
      return vector;
    };

    function HandleVector(storage) {
      return _StdVector.call(this, storage, pointerSize) || this;
    }

    (0, _createClass2["default"])(HandleVector, [{
      key: "handles",
      get: function get() {
        var result = [];
        var cur = this.begin;
        var end = this.end;

        while (!cur.equals(end)) {
          result.push(Memory.readPointer(cur));
          cur = cur.add(pointerSize);
        }

        return result;
      }
    }]);
    return HandleVector;
  }(StdVector);

  function chooseObjectsArtLegacy(env, thread, className, callbacks) {
    var klass = factory.use(className);
    var instanceHandles = [];
    var addGlobalReference = api['art::JavaVMExt::AddGlobalRef'];
    var vmHandle = api.vm;
    var localClassHandle = klass.$getClassHandle(env);
    var globalClassHandle = env.newGlobalRef(localClassHandle);
    var needle = api['art::JavaVMExt::DecodeGlobal'](api.vm, thread, globalClassHandle).toInt32();
    env.deleteGlobalRef(globalClassHandle);
    env.deleteLocalRef(localClassHandle);
    var collectMatchingInstanceHandles = makeObjectVisitorPredicate(needle, function (object) {
      instanceHandles.push(addGlobalReference(vmHandle, thread, object));
    });
    api['art::gc::Heap::VisitObjects'](api.artHeap, collectMatchingInstanceHandles, NULL);

    try {
      for (var _i2 = 0, _instanceHandles = instanceHandles; _i2 < _instanceHandles.length; _i2++) {
        var handle = _instanceHandles[_i2];
        var instance = factory.cast(handle, klass);
        var result = callbacks.onMatch(instance);

        if (result === 'stop') {
          break;
        }
      }
    } finally {
      instanceHandles.forEach(function (handle) {
        env.deleteGlobalRef(handle);
      });
    }

    callbacks.onComplete();
  }

  var objectVisitorPredicateFactories = {
    arm: function arm(needle, onMatch) {
      var size = Process.pageSize;
      var predicate = Memory.alloc(size);
      Memory.protect(predicate, size, 'rwx');
      var onMatchCallback = new NativeCallback(onMatch, 'void', ['pointer']);
      predicate._onMatchCallback = onMatchCallback;
      var instructions = [0x6801, // ldr r1, [r0]
      0x4a03, // ldr r2, =needle
      0x4291, // cmp r1, r2
      0xd101, // bne mismatch
      0x4b02, // ldr r3, =onMatch
      0x4718, // bx r3
      0x4770, // bx lr
      0xbf00 // nop
      ];
      var needleOffset = instructions.length * 2;
      var onMatchOffset = needleOffset + 4;
      var codeSize = onMatchOffset + 4;
      Memory.patchCode(predicate, codeSize, function (address) {
        instructions.forEach(function (instruction, index) {
          Memory.writeU16(address.add(index * 2), instruction);
        });
        Memory.writeS32(address.add(needleOffset), needle);
        Memory.writePointer(address.add(onMatchOffset), onMatchCallback);
      });
      return predicate.or(1);
    },
    arm64: function arm64(needle, onMatch) {
      var size = Process.pageSize;
      var predicate = Memory.alloc(size);
      Memory.protect(predicate, size, 'rwx');
      var onMatchCallback = new NativeCallback(onMatch, 'void', ['pointer']);
      predicate._onMatchCallback = onMatchCallback;
      var instructions = [0xb9400001, // ldr w1, [x0]
      0x180000c2, // ldr w2, =needle
      0x6b02003f, // cmp w1, w2
      0x54000061, // b.ne mismatch
      0x58000083, // ldr x3, =onMatch
      0xd61f0060, // br x3
      0xd65f03c0 // ret
      ];
      var needleOffset = instructions.length * 4;
      var onMatchOffset = needleOffset + 4;
      var codeSize = onMatchOffset + 8;
      Memory.patchCode(predicate, codeSize, function (address) {
        instructions.forEach(function (instruction, index) {
          Memory.writeU32(address.add(index * 4), instruction);
        });
        Memory.writeS32(address.add(needleOffset), needle);
        Memory.writePointer(address.add(onMatchOffset), onMatchCallback);
      });
      return predicate;
    }
  };

  function makeObjectVisitorPredicate(needle, onMatch) {
    var factory = objectVisitorPredicateFactories[Process.arch] || makeGenericObjectVisitorPredicate;
    return factory(needle, onMatch);
  }

  function makeGenericObjectVisitorPredicate(needle, onMatch) {
    return new NativeCallback(function (object) {
      var klass = Memory.readS32(object);

      if (klass === needle) {
        onMatch(object);
      }
    }, 'void', ['pointer', 'pointer']);
  }

  function chooseObjectsDalvik(className, callbacks) {
    var klass = factory.use(className);

    var enumerateInstances = function enumerateInstances(className, callbacks) {
      var env = vm.getEnv();
      var thread = Memory.readPointer(env.handle.add(DVM_JNI_ENV_OFFSET_SELF));
      var classHandle = klass.$getClassHandle(env);
      var ptrClassObject = api.dvmDecodeIndirectRef(thread, classHandle);
      env.deleteLocalRef(classHandle);
      var pattern = ptrClassObject.toMatchPattern();
      var heapSourceBase = api.dvmHeapSourceGetBase();
      var heapSourceLimit = api.dvmHeapSourceGetLimit();
      var size = heapSourceLimit.sub(heapSourceBase).toInt32();
      Memory.scan(heapSourceBase, size, pattern, {
        onMatch: function onMatch(address, size) {
          if (api.dvmIsValidObject(address)) {
            vm.perform(function () {
              var env = vm.getEnv();
              var thread = Memory.readPointer(env.handle.add(DVM_JNI_ENV_OFFSET_SELF));
              var instance;
              var localReference = api.addLocalReference(thread, address);

              try {
                instance = factory.cast(localReference, klass);
              } finally {
                env.deleteLocalRef(localReference);
              }

              var result = callbacks.onMatch(instance);

              if (result === 'stop') {
                return 'stop';
              }
            });
          }
        },
        onError: function onError(reason) {},
        onComplete: function onComplete() {
          callbacks.onComplete();
        }
      });
    };

    if (api.addLocalReference === null) {
      var libdvm = Process.getModuleByName('libdvm.so');
      var pattern;

      if (getAndroidVersion(factory).indexOf('4.2.') === 0) {
        // Verified with 4.2.2
        pattern = 'F8 B5 06 46 0C 46 31 B3 43 68 00 F1 A8 07 22 46';
      } else {
        // Verified with 4.3.1 and 4.4.4
        pattern = '2D E9 F0 41 05 46 15 4E 0C 46 7E 44 11 B3 43 68';
      }

      Memory.scan(libdvm.base, libdvm.size, pattern, {
        onMatch: function onMatch(address, size) {
          if (Process.arch === 'arm') {
            address = address.or(1); // Thumb
          }

          api.addLocalReference = new NativeFunction(address, 'pointer', ['pointer', 'pointer']);
          vm.perform(function () {
            enumerateInstances(className, callbacks);
          });
          return 'stop';
        },
        onError: function onError(reason) {},
        onComplete: function onComplete() {}
      });
    } else {
      enumerateInstances(className, callbacks);
    }
  }

  this.cast = function (obj, klass) {
    var env = vm.getEnv();
    var handle = obj.hasOwnProperty('$handle') ? obj.$handle : obj;
    var classHandle = klass.$getClassHandle(env);

    try {
      var isValidCast = env.isInstanceOf(handle, classHandle);

      if (!isValidCast) {
        throw new Error("Cast from '" + env.getObjectClassName(handle) + "' to '" + env.getClassName(classHandle) + "' isn't possible");
      }
    } finally {
      env.deleteLocalRef(classHandle);
    }

    var C = klass.$classWrapper;
    return new C(handle);
  };

  this.array = function (type, elements) {
    var env = vm.getEnv();
    var primitiveType = getPrimitiveType(type);

    if (primitiveType !== undefined) {
      type = primitiveType.name;
    }

    var arrayType = getArrayType('[' + type, false, this);
    var rawArray = arrayType.toJni(elements, env);
    return arrayType.fromJni(rawArray, env);
  };

  this.registerClass = registerClass;

  function ensureClass(getClassHandle, name) {
    var klass = classes[name];

    if (klass !== undefined) {
      return klass;
    }

    var env = vm.getEnv();
    var classHandle = getClassHandle(env);
    env.checkForExceptionAndThrowIt();
    var superKlass;
    var superHandle = env.getSuperclass(classHandle);

    if (!superHandle.isNull()) {
      var getSuperClassHandle = function getSuperClassHandle(env) {
        var classHandle = getClassHandle(env);
        var superHandle = env.getSuperclass(classHandle);
        env.deleteLocalRef(classHandle);
        return superHandle;
      };

      try {
        superKlass = ensureClass(getSuperClassHandle, env.getClassName(superHandle));
      } finally {
        env.deleteLocalRef(superHandle);
      }
    } else {
      superKlass = null;
    }

    superHandle = null;
    ensureClassInitialized(env, classHandle);
    eval('klass = function (handle) {' + // eslint-disable-line
    'var env = vm.getEnv();' + 'this.$classWrapper = klass;' + 'this.$getClassHandle = getClassHandle;' + 'if (handle !== null) {' + '  this.$handle = env.newGlobalRef(handle);' + '  this.$weakRef = WeakRef.bind(this, makeHandleDestructor(vm, this.$handle));' + '}' + '};');
    (0, _defineProperty["default"])(klass, 'className', {
      enumerable: true,
      value: basename(name)
    });
    classes[name] = klass;

    function initializeClass() {
      klass.__name__ = name;
      var ctor = null;

      var getCtor = function getCtor(type) {
        if (ctor === null) {
          vm.perform(function () {
            var env = vm.getEnv();
            var classHandle = getClassHandle(env);

            try {
              ctor = makeConstructor(classHandle, env);
            } finally {
              env.deleteLocalRef(classHandle);
            }
          });
        }

        if (!ctor[type]) throw new Error('assertion !ctor[type] failed');
        return ctor[type];
      };

      (0, _defineProperty["default"])(klass.prototype, '$new', {
        get: function get() {
          return getCtor('allocAndInit');
        }
      });
      (0, _defineProperty["default"])(klass.prototype, '$alloc', {
        get: function get() {
          return function () {
            var env = vm.getEnv();
            var classHandle = this.$getClassHandle(env);

            try {
              var obj = env.allocObject(classHandle);
              return factory.cast(obj, this);
            } finally {
              env.deleteLocalRef(classHandle);
            }
          };
        }
      });
      (0, _defineProperty["default"])(klass.prototype, '$init', {
        get: function get() {
          return getCtor('initOnly');
        }
      });
      klass.prototype.$dispose = dispose;

      klass.prototype.$isSameObject = function (obj) {
        var env = vm.getEnv();
        return env.isSameObject(obj.$handle, this.$handle);
      };

      (0, _defineProperty["default"])(klass.prototype, 'class', {
        get: function get() {
          var env = vm.getEnv();
          var classHandle = this.$getClassHandle(env);

          try {
            return factory.cast(classHandle, factory.use('java.lang.Class'));
          } finally {
            env.deleteLocalRef(classHandle);
          }
        }
      });
      (0, _defineProperty["default"])(klass.prototype, '$className', {
        get: function get() {
          var env = vm.getEnv();
          var handle = this.$handle;
          if (handle !== undefined) return env.getObjectClassName(this.$handle);
          var classHandle = this.$getClassHandle(env);

          try {
            return env.getClassName(classHandle);
          } finally {
            env.deleteLocalRef(classHandle);
          }
        }
      });
      addMethodsAndFields();
    }

    function dispose() {
      /* jshint validthis: true */
      var ref = this.$weakRef;

      if (ref !== undefined) {
        delete this.$weakRef;
        WeakRef.unbind(ref);
      }
    }

    function makeConstructor(classHandle, env) {
      var Constructor = env.javaLangReflectConstructor();
      var invokeObjectMethodNoArgs = env.vaMethod('pointer', []);
      var jsCtorMethods = [];
      var jsInitMethods = [];
      var jsRetType = getTypeFromJniTypeName(name, false);
      var jsVoidType = getTypeFromJniTypeName('void', false);
      var constructors = invokeObjectMethodNoArgs(env.handle, classHandle, env.javaLangClass().getDeclaredConstructors);

      try {
        var numConstructors = env.getArrayLength(constructors);

        for (var constructorIndex = 0; constructorIndex !== numConstructors; constructorIndex++) {
          var _constructor = env.getObjectArrayElement(constructors, constructorIndex);

          try {
            var methodId = env.fromReflectedMethod(_constructor);
            var types = invokeObjectMethodNoArgs(env.handle, _constructor, Constructor.getGenericParameterTypes);
            var jsArgTypes = readTypeNames(env, types).map(function (name) {
              return getTypeFromJniTypeName(name);
            });
            env.deleteLocalRef(types);
            jsCtorMethods.push(makeMethod(basename(name), CONSTRUCTOR_METHOD, methodId, jsRetType, jsArgTypes, env));
            jsInitMethods.push(makeMethod(basename(name), INSTANCE_METHOD, methodId, jsVoidType, jsArgTypes, env));
          } finally {
            env.deleteLocalRef(_constructor);
          }
        }
      } finally {
        env.deleteLocalRef(constructors);
      }

      if (jsInitMethods.length === 0) {
        throw new Error('no supported overloads');
      }

      return {
        'allocAndInit': makeMethodDispatcher('<init>', jsCtorMethods),
        'initOnly': makeMethodDispatcher('<init>', jsInitMethods)
      };
    }

    function makeField(name, params, classHandle, env) {
      var invokeObjectMethodNoArgs = env.vaMethod('pointer', []);

      var _env$javaLangReflectF = env.javaLangReflectField(),
          getGenericType = _env$javaLangReflectF.getGenericType;

      var fieldId = params[0],
          jsType = params[1];
      var jsFieldType;
      var isStatic = jsType === STATIC_FIELD ? 1 : 0;
      var handle = env.toReflectedField(classHandle, fieldId, isStatic);

      try {
        var fieldType = invokeObjectMethodNoArgs(env.handle, handle, getGenericType);

        try {
          jsFieldType = getTypeFromJniTypeName(env.getTypeName(fieldType));
        } finally {
          env.deleteLocalRef(fieldType);
        }
      } catch (e) {
        return null;
      } finally {
        env.deleteLocalRef(handle);
      }

      return createField(name, jsType, fieldId, jsFieldType, env);
    }

    function createField(name, type, targetFieldId, fieldType, env) {
      var rawFieldType = fieldType.type;
      var invokeTarget = null; // eslint-disable-line

      if (type === STATIC_FIELD) {
        invokeTarget = env.getStaticField(rawFieldType);
      } else if (type === INSTANCE_FIELD) {
        invokeTarget = env.getField(rawFieldType);
      }

      var frameCapacity = 3;
      var callArgs = ['env.handle', type === INSTANCE_FIELD ? 'this.$handle' : 'this.$getClassHandle(env)', 'targetFieldId'];
      var returnCapture, returnStatements;

      if (fieldType.fromJni) {
        frameCapacity++;
        returnCapture = 'rawResult = ';
        returnStatements = 'try {' + 'result = fieldType.fromJni.call(this, rawResult, env);' + '} finally {' + 'env.popLocalFrame(NULL);' + '} ' + 'return result;';
      } else {
        returnCapture = 'result = ';
        returnStatements = 'env.popLocalFrame(NULL);' + 'return result;';
      }

      var getter;
      eval('getter = function () {' + // eslint-disable-line
      'var isInstance = this.$handle !== undefined;' + 'if (type === INSTANCE_FIELD && !isInstance) { ' + "throw new Error('getter of ' + name + ': cannot get an instance field without an instance.');" + '}' + 'var env = vm.getEnv();' + 'if (env.pushLocalFrame(' + frameCapacity + ') !== JNI_OK) {' + 'env.exceptionClear();' + 'throw new Error("Out of memory");' + '}' + 'var result, rawResult;' + 'try {' + returnCapture + 'invokeTarget(' + callArgs.join(', ') + ');' + '} catch (e) {' + 'env.popLocalFrame(NULL);' + 'throw e;' + '}' + 'try {' + 'env.checkForExceptionAndThrowIt();' + '} catch (e) {' + 'env.popLocalFrame(NULL); ' + 'throw e;' + '}' + returnStatements + '}');
      var setFunction = null; // eslint-disable-line

      if (type === STATIC_FIELD) {
        setFunction = env.setStaticField(rawFieldType);
      } else if (type === INSTANCE_FIELD) {
        setFunction = env.setField(rawFieldType);
      }

      var inputStatement;

      if (fieldType.toJni) {
        inputStatement = 'var input = fieldType.toJni.call(this, value, env);';
      } else {
        inputStatement = 'var input = value;';
      }

      var setter;
      eval('setter = function (value) {' + // eslint-disable-line
      'var isInstance = this.$handle !== undefined;' + 'if (type === INSTANCE_FIELD && !isInstance) { ' + "throw new Error('setter of ' + name + ': cannot set an instance field without an instance');" + '}' + 'if (!fieldType.isCompatible(value)) {' + 'throw new Error(\'Field "\' + name + \'" expected value compatible with ' + fieldType.className + ".');" + '}' + 'var env = vm.getEnv();' + 'if (env.pushLocalFrame(' + frameCapacity + ') !== JNI_OK) {' + 'env.exceptionClear();' + 'throw new Error("Out of memory");' + '}' + 'try {' + inputStatement + 'setFunction(' + callArgs.join(', ') + ', input);' + '} catch (e) {' + 'throw e;' + '} finally {' + 'env.popLocalFrame(NULL);' + '}' + 'env.checkForExceptionAndThrowIt();' + '}');
      var f = {};
      (0, _defineProperty["default"])(f, 'value', {
        enumerable: true,
        get: function get() {
          return getter.call(this.$holder);
        },
        set: function set(value) {
          setter.call(this.$holder, value);
        }
      });
      (0, _defineProperty["default"])(f, 'holder', {
        enumerable: true,
        value: klass
      });
      (0, _defineProperty["default"])(f, 'fieldType', {
        enumerable: true,
        value: type
      });
      (0, _defineProperty["default"])(f, 'fieldReturnType', {
        enumerable: true,
        value: fieldType
      });
      return [f, getter, setter];
    }

    function addMethodsAndFields() {
      var Modifier = env.javaLangReflectModifier();
      var getMethodModifiers = env.javaLangReflectMethod().getModifiers;
      var getFieldModifiers = env.javaLangReflectField().getModifiers;
      var invokeObjectMethodNoArgs = env.vaMethod('pointer', []);
      var invokeIntMethodNoArgs = env.vaMethod('int32', []);
      var methodGetName = env.javaLangReflectMethod().getName;
      var fieldGetName = env.javaLangReflectField().getName;
      var jsMethods = {};
      var jsFields = {};
      var methods = invokeObjectMethodNoArgs(env.handle, classHandle, env.javaLangClass().getDeclaredMethods);

      try {
        var numMethods = env.getArrayLength(methods);

        for (var methodIndex = 0; methodIndex !== numMethods; methodIndex++) {
          var method = env.getObjectArrayElement(methods, methodIndex);

          try {
            var methodName = invokeObjectMethodNoArgs(env.handle, method, methodGetName);

            try {
              var methodJsName = env.stringFromJni(methodName);
              var methodId = env.fromReflectedMethod(method);
              var modifiers = invokeIntMethodNoArgs(env.handle, method, getMethodModifiers);
              var jsOverloads = void 0;

              if (!jsMethods.hasOwnProperty(methodJsName)) {
                jsOverloads = [];
                jsMethods[methodJsName] = jsOverloads;
              } else {
                jsOverloads = jsMethods[methodJsName];
              }

              jsOverloads.push([methodId, modifiers]);
            } finally {
              env.deleteLocalRef(methodName);
            }
          } finally {
            env.deleteLocalRef(method);
          }
        }
      } finally {
        env.deleteLocalRef(methods);
      }

      var fields = invokeObjectMethodNoArgs(env.handle, classHandle, env.javaLangClass().getDeclaredFields);

      try {
        var numFields = env.getArrayLength(fields);

        for (var fieldIndex = 0; fieldIndex !== numFields; fieldIndex++) {
          var field = env.getObjectArrayElement(fields, fieldIndex);

          try {
            var fieldName = invokeObjectMethodNoArgs(env.handle, field, fieldGetName);

            try {
              var fieldJsName = env.stringFromJni(fieldName);

              while (jsMethods.hasOwnProperty(fieldJsName)) {
                fieldJsName = '_' + fieldJsName;
              }

              var fieldId = env.fromReflectedField(field);

              var _modifiers = invokeIntMethodNoArgs(env.handle, field, getFieldModifiers);

              var jsType = (_modifiers & Modifier.STATIC) !== 0 ? STATIC_FIELD : INSTANCE_FIELD;
              jsFields[fieldJsName] = [fieldId, jsType];
            } finally {
              env.deleteLocalRef(fieldName);
            }
          } finally {
            env.deleteLocalRef(field);
          }
        }
      } finally {
        env.deleteLocalRef(fields);
      }

      (0, _keys["default"])(jsMethods).forEach(function (name) {
        var overloads = jsMethods[name];
        var v = null;
        (0, _defineProperty["default"])(klass.prototype, name, {
          get: function get() {
            if (v === null) {
              vm.perform(function () {
                var env = vm.getEnv();
                var classHandle = getClassHandle(env);

                try {
                  v = makeMethodFromOverloads(name, overloads, classHandle, env);
                } finally {
                  env.deleteLocalRef(classHandle);
                }
              });
            }

            return v;
          }
        });
      });
      (0, _keys["default"])(jsFields).forEach(function (name) {
        var params = jsFields[name];
        var jsType = params[1];
        var v = null;
        (0, _defineProperty["default"])(klass.prototype, name, {
          get: function get() {
            var _this3 = this;

            if (v === null) {
              vm.perform(function () {
                var env = vm.getEnv();
                var classHandle = getClassHandle(env);

                try {
                  v = makeField(name, params, classHandle, env);
                } finally {
                  env.deleteLocalRef(classHandle);
                }

                if (jsType === STATIC_FIELD) {
                  v[0].$holder = _this3;
                }
              });
            }

            var _v = v,
                protoField = _v[0],
                getter = _v[1],
                setter = _v[2];
            if (jsType === STATIC_FIELD) return protoField;
            if (this.$handle === undefined) throw new Error('Unable to access instance field without an instance');
            var field = {};
            (0, _defineProperties["default"])(field, {
              value: {
                enumerable: true,
                get: function get() {
                  return getter.call(_this3);
                },
                set: function set(value) {
                  setter.call(_this3, value);
                }
              },
              holder: {
                enumerable: true,
                value: protoField.holder
              },
              fieldType: {
                enumerable: true,
                value: protoField.fieldType
              },
              fieldReturnType: {
                enumerable: true,
                value: protoField.fieldReturnType
              }
            });
            (0, _defineProperty["default"])(this, name, {
              enumerable: false,
              value: field
            });
            return field;
          }
        });
      });
    }

    function makeMethodFromOverloads(name, overloads, classHandle, env) {
      var Method = env.javaLangReflectMethod();
      var Modifier = env.javaLangReflectModifier();
      var invokeObjectMethodNoArgs = env.vaMethod('pointer', []);
      var invokeUInt8MethodNoArgs = env.vaMethod('uint8', []);
      var methods = overloads.map(function (params) {
        var methodId = params[0],
            modifiers = params[1];
        var isStatic = (modifiers & Modifier.STATIC) === 0 ? 0 : 1;
        var jsType = isStatic ? STATIC_METHOD : INSTANCE_METHOD;
        var jsRetType;
        var jsArgTypes = [];
        var handle = env.toReflectedMethod(classHandle, methodId, isStatic);

        try {
          var isVarArgs = !!invokeUInt8MethodNoArgs(env.handle, handle, Method.isVarArgs);
          var retType = invokeObjectMethodNoArgs(env.handle, handle, Method.getGenericReturnType);
          env.checkForExceptionAndThrowIt();

          try {
            jsRetType = getTypeFromJniTypeName(env.getTypeName(retType));
          } finally {
            env.deleteLocalRef(retType);
          }

          var argTypes = invokeObjectMethodNoArgs(env.handle, handle, Method.getParameterTypes);
          env.checkForExceptionAndThrowIt();

          try {
            var numArgTypes = env.getArrayLength(argTypes);

            for (var argTypeIndex = 0; argTypeIndex !== numArgTypes; argTypeIndex++) {
              var t = env.getObjectArrayElement(argTypes, argTypeIndex);

              try {
                var argClassName = isVarArgs && argTypeIndex === numArgTypes - 1 ? env.getArrayTypeName(t) : env.getTypeName(t);
                var argType = getTypeFromJniTypeName(argClassName);
                jsArgTypes.push(argType);
              } finally {
                env.deleteLocalRef(t);
              }
            }
          } finally {
            env.deleteLocalRef(argTypes);
          }
        } catch (e) {
          return null;
        } finally {
          env.deleteLocalRef(handle);
        }

        return makeMethod(name, jsType, methodId, jsRetType, jsArgTypes, env);
      }).filter(function (m) {
        return m !== null;
      });

      if (methods.length === 0) {
        throw new Error('No supported overloads');
      }

      if (name === 'valueOf') {
        var hasDefaultValueOf = methods.some(function implementsDefaultValueOf(m) {
          return m.type === INSTANCE_METHOD && m.argumentTypes.length === 0;
        });

        if (!hasDefaultValueOf) {
          var defaultValueOf = function defaultValueOf() {
            return this;
          };

          (0, _defineProperty["default"])(defaultValueOf, 'holder', {
            enumerable: true,
            value: klass
          });
          (0, _defineProperty["default"])(defaultValueOf, 'type', {
            enumerable: true,
            value: INSTANCE_METHOD
          });
          (0, _defineProperty["default"])(defaultValueOf, 'returnType', {
            enumerable: true,
            value: getTypeFromJniTypeName('int')
          });
          (0, _defineProperty["default"])(defaultValueOf, 'argumentTypes', {
            enumerable: true,
            value: []
          });
          (0, _defineProperty["default"])(defaultValueOf, 'canInvokeWith', {
            enumerable: true,
            value: function value(args) {
              return args.length === 0;
            }
          });
          methods.push(defaultValueOf);
        }
      }

      return makeMethodDispatcher(name, methods);
    }

    function makeMethodDispatcher(name, methods) {
      var candidates = {};
      methods.forEach(function (m) {
        var numArgs = m.argumentTypes.length;
        var group = candidates[numArgs];

        if (!group) {
          group = [];
          candidates[numArgs] = group;
        }

        group.push(m);
      });

      function f() {
        /* jshint validthis: true */
        var isInstance = this.$handle !== undefined;

        for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
          args[_key] = arguments[_key];
        }

        var group = candidates[args.length];

        if (!group) {
          throwOverloadError(name, methods, "argument count of " + args.length + " does not match any of:");
        }

        for (var i = 0; i !== group.length; i++) {
          var method = group[i];

          if (method.canInvokeWith(args)) {
            if (method.type === INSTANCE_METHOD && !isInstance) {
              if (name === 'toString') {
                return '<' + this.$classWrapper.__name__ + '>';
              }

              throw new Error(name + ': cannot call instance method without an instance');
            }

            return method.apply(this, args);
          }
        }

        throwOverloadError(name, methods, 'argument types do not match any of:');
      }

      (0, _defineProperty["default"])(f, 'overloads', {
        enumerable: true,
        value: methods
      });
      (0, _defineProperty["default"])(f, 'overload', {
        enumerable: true,
        value: function value() {
          for (var _len2 = arguments.length, args = new Array(_len2), _key2 = 0; _key2 < _len2; _key2++) {
            args[_key2] = arguments[_key2];
          }

          var group = candidates[args.length];

          if (!group) {
            throwOverloadError(name, methods, "argument count of " + args.length + " does not match any of:");
          }

          var signature = args.join(':');

          for (var i = 0; i !== group.length; i++) {
            var method = group[i];
            var s = method.argumentTypes.map(function (t) {
              return t.className;
            }).join(':');

            if (s === signature) {
              return method;
            }
          }

          throwOverloadError(name, methods, 'specified argument types do not match any of:');
        }
      });
      (0, _defineProperty["default"])(f, 'holder', {
        enumerable: true,
        get: methods[0].holder
      });
      (0, _defineProperty["default"])(f, 'type', {
        enumerable: true,
        value: methods[0].type
      });

      if (methods.length === 1) {
        (0, _defineProperty["default"])(f, 'implementation', {
          enumerable: true,
          get: function get() {
            return methods[0].implementation;
          },
          set: function set(imp) {
            methods[0].implementation = imp;
          }
        });
        (0, _defineProperty["default"])(f, 'returnType', {
          enumerable: true,
          value: methods[0].returnType
        });
        (0, _defineProperty["default"])(f, 'argumentTypes', {
          enumerable: true,
          value: methods[0].argumentTypes
        });
        (0, _defineProperty["default"])(f, 'canInvokeWith', {
          enumerable: true,
          value: methods[0].canInvokeWith
        });
        (0, _defineProperty["default"])(f, 'handle', {
          enumerable: true,
          value: methods[0].handle
        });
      } else {
        var throwAmbiguousError = function throwAmbiguousError() {
          throwOverloadError(name, methods, 'has more than one overload, use .overload(<signature>) to choose from:');
        };

        (0, _defineProperty["default"])(f, 'implementation', {
          enumerable: true,
          get: throwAmbiguousError,
          set: throwAmbiguousError
        });
        (0, _defineProperty["default"])(f, 'returnType', {
          enumerable: true,
          get: throwAmbiguousError
        });
        (0, _defineProperty["default"])(f, 'argumentTypes', {
          enumerable: true,
          get: throwAmbiguousError
        });
        (0, _defineProperty["default"])(f, 'canInvokeWith', {
          enumerable: true,
          get: throwAmbiguousError
        });
        (0, _defineProperty["default"])(f, 'handle', {
          enumerable: true,
          get: throwAmbiguousError
        });
      }

      return f;
    }

    function makeMethod(methodName, type, methodId, retType, argTypes, env) {
      var dalvikTargetMethodId = methodId;
      var dalvikOriginalMethod = null;
      var artHookedMethodId = methodId;
      var artOriginalMethodInfo = null;
      var rawRetType = retType.type;
      var rawArgTypes = argTypes.map(function (t) {
        return t.type;
      });
      var invokeTargetVirtually, invokeTargetDirectly; // eslint-disable-line

      if (type === CONSTRUCTOR_METHOD) {
        invokeTargetVirtually = env.constructor(rawArgTypes);
        invokeTargetDirectly = invokeTargetVirtually;
      } else if (type === STATIC_METHOD) {
        invokeTargetVirtually = env.staticVaMethod(rawRetType, rawArgTypes);
        invokeTargetDirectly = invokeTargetVirtually;
      } else if (type === INSTANCE_METHOD) {
        invokeTargetVirtually = env.vaMethod(rawRetType, rawArgTypes);
        invokeTargetDirectly = env.nonvirtualVaMethod(rawRetType, rawArgTypes);
      }

      var frameCapacity = 2;
      var argVariableNames = argTypes.map(function (t, i) {
        return 'a' + (i + 1);
      });
      var callArgsVirtual = ['env.handle', type === INSTANCE_METHOD ? 'this.$handle' : 'this.$getClassHandle(env)', api.flavor === 'art' ? 'resolveArtTargetMethodId()' : 'dalvikTargetMethodId'].concat(argTypes.map(function (t, i) {
        if (t.toJni) {
          frameCapacity++;
          return ['argTypes[', i, '].toJni.call(this, ', argVariableNames[i], ', env)'].join('');
        } else {
          return argVariableNames[i];
        }
      }));
      var callArgsDirect;

      if (type === INSTANCE_METHOD) {
        callArgsDirect = callArgsVirtual.slice();
        callArgsDirect.splice(2, 0, 'this.$getClassHandle(env)');
      } else {
        callArgsDirect = callArgsVirtual;
      }

      var returnCapture, returnStatements;

      if (rawRetType === 'void') {
        returnCapture = '';
        returnStatements = 'env.popLocalFrame(NULL);';
      } else {
        if (retType.fromJni) {
          frameCapacity++;
          returnCapture = 'rawResult = ';
          returnStatements = 'try {' + 'result = retType.fromJni.call(this, rawResult, env);' + '} finally {' + 'env.popLocalFrame(NULL);' + '}' + 'return result;';
        } else {
          returnCapture = 'result = ';
          returnStatements = 'env.popLocalFrame(NULL);' + 'return result;';
        }
      }

      var f;
      var pendingCalls = new _set["default"]();
      eval('f = function (' + argVariableNames.join(', ') + ') {' + // eslint-disable-line
      'var env = vm.getEnv();' + 'if (env.pushLocalFrame(' + frameCapacity + ') !== JNI_OK) {' + 'env.exceptionClear();' + 'throw new Error("Out of memory");' + '}' + 'var result, rawResult;' + 'try {' + (api.flavor === 'dalvik' ? 'synchronizeDalvikVtable.call(this, env, type === INSTANCE_METHOD);' + returnCapture + 'invokeTargetVirtually(' + callArgsVirtual.join(', ') + ');' : 'if (pendingCalls.has(Process.getCurrentThreadId())) {' + returnCapture + 'invokeTargetDirectly(' + callArgsDirect.join(', ') + ');' + '} else {' + returnCapture + 'invokeTargetVirtually(' + callArgsVirtual.join(', ') + ');' + '}') + '} catch (e) {' + 'env.popLocalFrame(NULL);' + 'throw e;' + '}' + 'try {' + 'env.checkForExceptionAndThrowIt();' + '} catch (e) {' + 'env.popLocalFrame(NULL); ' + 'throw e;' + '}' + returnStatements + '};');
      (0, _defineProperty["default"])(f, 'methodName', {
        enumerable: true,
        value: methodName
      });
      (0, _defineProperty["default"])(f, 'holder', {
        enumerable: true,
        value: klass
      });
      (0, _defineProperty["default"])(f, 'type', {
        enumerable: true,
        value: type
      });
      (0, _defineProperty["default"])(f, 'handle', {
        enumerable: true,
        value: methodId
      });

      function fetchMethod(methodId) {
        var artMethodSpec = getArtMethodSpec(vm);
        var artMethodOffset = artMethodSpec.offset;
        return ['jniCode', 'accessFlags', 'quickCode', 'interpreterCode'].reduce(function (original, name) {
          var offset = artMethodOffset[name];

          if (offset === undefined) {
            return original;
          }

          var address = methodId.add(offset);
          var suffix = name === 'accessFlags' ? 'U32' : 'Pointer';
          original[name] = Memory['read' + suffix](address);
          return original;
        }, {});
      }

      function patchMethod(methodId, patches) {
        var artMethodSpec = getArtMethodSpec(vm);
        var artMethodOffset = artMethodSpec.offset;
        (0, _keys["default"])(patches).forEach(function (name) {
          var offset = artMethodOffset[name];

          if (offset === undefined) {
            return;
          }

          var address = methodId.add(offset);
          var suffix = name === 'accessFlags' ? 'U32' : 'Pointer';
          Memory['write' + suffix](address, patches[name]);
        });
      }

      var implementation = null;

      function resolveArtTargetMethodId() {
        // eslint-disable-line
        if (artOriginalMethodInfo === null) {
          return methodId;
        }

        var target = cloneArtMethod(artHookedMethodId);
        patchMethod(target, artOriginalMethodInfo);
        return target;
      }

      function replaceArtImplementation(fn) {
        if (fn === null && artOriginalMethodInfo === null) {
          return;
        }

        var artMethodSpec = getArtMethodSpec(vm);
        var artMethodOffset = artMethodSpec.offset;

        if (artOriginalMethodInfo === null) {
          artOriginalMethodInfo = fetchMethod(methodId);

          if ((artOriginalMethodInfo.accessFlags & kAccXposedHookedMethod) !== 0) {
            var hookInfo = artOriginalMethodInfo.jniCode;
            artHookedMethodId = Memory.readPointer(hookInfo.add(2 * pointerSize));
            artOriginalMethodInfo = fetchMethod(artHookedMethodId);
          }
        }

        if (fn !== null) {
          implementation = implement(f, fn); // kAccFastNative so that the VM doesn't get suspended while executing JNI
          // (so that we can modify the ArtMethod on the fly)

          patchMethod(artHookedMethodId, {
            'jniCode': implementation,
            'accessFlags': (Memory.readU32(artHookedMethodId.add(artMethodOffset.accessFlags)) | kAccNative | kAccFastNative) >>> 0,
            'quickCode': api.artQuickGenericJniTrampoline,
            'interpreterCode': api.artInterpreterToCompiledCodeBridge
          });
          patchedMethods.add(f);
        } else {
          patchedMethods["delete"](f);
          patchMethod(artHookedMethodId, artOriginalMethodInfo);
          implementation = null;
        }
      }

      function replaceDalvikImplementation(fn) {
        if (fn === null && dalvikOriginalMethod === null) {
          return;
        }

        if (dalvikOriginalMethod === null) {
          dalvikOriginalMethod = Memory.dup(methodId, DVM_METHOD_SIZE);
          dalvikTargetMethodId = Memory.dup(methodId, DVM_METHOD_SIZE);
        }

        if (fn !== null) {
          implementation = implement(f, fn);
          var argsSize = argTypes.reduce(function (acc, t) {
            return acc + t.size;
          }, 0);

          if (type === INSTANCE_METHOD) {
            argsSize++;
          }
          /*
           * make method native (with kAccNative)
           * insSize and registersSize are set to arguments size
           */


          var accessFlags = (Memory.readU32(methodId.add(DVM_METHOD_OFFSET_ACCESS_FLAGS)) | kAccNative) >>> 0;
          var registersSize = argsSize;
          var outsSize = 0;
          var insSize = argsSize;
          Memory.writeU32(methodId.add(DVM_METHOD_OFFSET_ACCESS_FLAGS), accessFlags);
          Memory.writeU16(methodId.add(DVM_METHOD_OFFSET_REGISTERS_SIZE), registersSize);
          Memory.writeU16(methodId.add(DVM_METHOD_OFFSET_OUTS_SIZE), outsSize);
          Memory.writeU16(methodId.add(DVM_METHOD_OFFSET_INS_SIZE), insSize);
          Memory.writeU32(methodId.add(DVM_METHOD_OFFSET_JNI_ARG_INFO), computeDalvikJniArgInfo(methodId));
          api.dvmUseJNIBridge(methodId, implementation);
          patchedMethods.add(f);
        } else {
          patchedMethods["delete"](f);
          Memory.copy(methodId, dalvikOriginalMethod, DVM_METHOD_SIZE);
          implementation = null;
        }
      }

      function synchronizeDalvikVtable(env, instance) {
        // eslint-disable-line

        /* jshint validthis: true */
        if (dalvikOriginalMethod === null) {
          return; // nothing to do -- implementation hasn't been replaced
        }

        var thread = Memory.readPointer(env.handle.add(DVM_JNI_ENV_OFFSET_SELF));
        var objectPtr = api.dvmDecodeIndirectRef(thread, instance ? this.$handle : this.$getClassHandle(env));
        var classObject;

        if (instance) {
          classObject = Memory.readPointer(objectPtr.add(DVM_OBJECT_OFFSET_CLAZZ));
        } else {
          classObject = objectPtr;
        }

        var key = classObject.toString(16);
        var entry = patchedClasses[key];

        if (!entry) {
          var vtablePtr = classObject.add(DVM_CLASS_OBJECT_OFFSET_VTABLE);
          var vtableCountPtr = classObject.add(DVM_CLASS_OBJECT_OFFSET_VTABLE_COUNT);
          var vtable = Memory.readPointer(vtablePtr);
          var vtableCount = Memory.readS32(vtableCountPtr);
          var vtableSize = vtableCount * pointerSize;
          var shadowVtable = Memory.alloc(2 * vtableSize);
          Memory.copy(shadowVtable, vtable, vtableSize);
          Memory.writePointer(vtablePtr, shadowVtable);
          entry = {
            classObject: classObject,
            vtablePtr: vtablePtr,
            vtableCountPtr: vtableCountPtr,
            vtable: vtable,
            vtableCount: vtableCount,
            shadowVtable: shadowVtable,
            shadowVtableCount: vtableCount,
            targetMethods: {}
          };
          patchedClasses[key] = entry;
        }

        key = methodId.toString(16);
        var method = entry.targetMethods[key];

        if (!method) {
          var methodIndex = entry.shadowVtableCount++;
          Memory.writePointer(entry.shadowVtable.add(methodIndex * pointerSize), dalvikTargetMethodId);
          Memory.writeU16(dalvikTargetMethodId.add(DVM_METHOD_OFFSET_METHOD_INDEX), methodIndex);
          Memory.writeS32(entry.vtableCountPtr, entry.shadowVtableCount);
          entry.targetMethods[key] = f;
        }
      }

      (0, _defineProperty["default"])(f, 'implementation', {
        enumerable: true,
        get: function get() {
          return implementation;
        },
        set: type === CONSTRUCTOR_METHOD ? function () {
          throw new Error('Reimplementing $new is not possible. Please replace implementation of $init instead.');
        } : api.flavor === 'art' ? replaceArtImplementation : replaceDalvikImplementation
      });
      (0, _defineProperty["default"])(f, 'returnType', {
        enumerable: true,
        value: retType
      });
      (0, _defineProperty["default"])(f, 'argumentTypes', {
        enumerable: true,
        value: argTypes
      });
      (0, _defineProperty["default"])(f, 'canInvokeWith', {
        enumerable: true,
        value: function value(args) {
          if (args.length !== argTypes.length) {
            return false;
          }

          return argTypes.every(function (t, i) {
            return t.isCompatible(args[i]);
          });
        }
      });
      (0, _defineProperty["default"])(f, PENDING_CALLS, {
        enumerable: true,
        value: pendingCalls
      });
      return f;
    }

    if (superKlass !== null) {
      var Surrogate = function Surrogate() {
        this.constructor = klass;
      };

      Surrogate.prototype = superKlass.prototype;
      klass.prototype = new Surrogate();
      klass.__super__ = superKlass.prototype;
    } else {
      klass.__super__ = null;
    }

    initializeClass(); // Guard against use-after-"free"

    env.deleteLocalRef(classHandle);
    classHandle = null;
    env = null;
    return klass;
  }

  function registerClass(spec) {
    var env = vm.getEnv();
    var localHandles = [];

    try {
      var placeholder = function placeholder() {
        for (var _len3 = arguments.length, args = new Array(_len3), _key3 = 0; _key3 < _len3; _key3++) {
          args[_key3] = arguments[_key3];
        }

        return (0, _construct2["default"])(C, args);
      };

      var Method = env.javaLangReflectMethod();
      var invokeObjectMethodNoArgs = env.vaMethod('pointer', []);
      var className = spec.name;
      var interfaces = spec["implements"] || [];
      var dexMethods = [];
      var dexSpec = {
        name: makeJniObjectTypeName(className),
        sourceFileName: makeSourceFileName(className),
        superClass: 'Ljava/lang/Object;',
        interfaces: interfaces.map(function (iface) {
          return makeJniObjectTypeName(iface.$classWrapper.__name__);
        }),
        methods: dexMethods
      };
      var baseMethods = {};
      var pendingOverloads = {};
      interfaces.forEach(function (iface) {
        var ifaceHandle = iface.$getClassHandle(env);
        localHandles.push(ifaceHandle);
        var ifaceProto = (0, _getPrototypeOf["default"])(iface);
        (0, _getOwnPropertyNames["default"])(ifaceProto).filter(function (name) {
          return name[0] !== '$' && name !== 'constructor' && name !== 'class';
        }).forEach(function (name) {
          var method = iface[name];
          var overloads = method.overloads;
          var overloadIds = overloads.map(function (overload) {
            return makeOverloadId(name, overload.returnType, overload.argumentTypes);
          });
          baseMethods[name] = [method, overloadIds, ifaceHandle];
          overloads.forEach(function (overload, index) {
            var id = overloadIds[index];
            pendingOverloads[id] = [overload, ifaceHandle];
          });
        });
      });
      var methods = spec.methods || {};
      var methodNames = (0, _keys["default"])(methods);
      var methodEntries = methodNames.reduce(function (result, name) {
        var entry = methods[name];

        if (entry instanceof Array) {
          result.push.apply(result, entry.map(function (e) {
            return [name, e];
          }));
        } else {
          result.push([name, entry]);
        }

        return result;
      }, []);
      var numMethods = methodEntries.length;
      var nativeMethods = [];
      var temporaryHandles = [];
      var methodElements = null;

      if (numMethods > 0) {
        var methodElementSize = 3 * pointerSize;
        methodElements = Memory.alloc(numMethods * methodElementSize);
        methodEntries.forEach(function (_ref2, index) {
          var name = _ref2[0],
              methodValue = _ref2[1];
          var method = null;
          var returnType;
          var argumentTypes;
          var thrownTypeNames = [];
          var impl;

          if (typeof methodValue === 'function') {
            var m = baseMethods[name];

            if (m !== undefined) {
              var baseMethod = m[0],
                  overloadIds = m[1],
                  parentTypeHandle = m[2];

              if (overloadIds.length > 1) {
                throw new Error("More than one overload matching '" + name + "': signature must be specified");
              }

              delete pendingOverloads[overloadIds[0]];
              var overload = baseMethod.overloads[0];
              method = overload;
              returnType = overload.returnType;
              argumentTypes = overload.argumentTypes;
              impl = methodValue;
              var reflectedMethod = env.toReflectedMethod(parentTypeHandle, overload.handle, 0);
              var thrownTypes = invokeObjectMethodNoArgs(env.handle, reflectedMethod, Method.getGenericExceptionTypes);
              thrownTypeNames = readTypeNames(env, thrownTypes).map(makeJniObjectTypeName);
              env.deleteLocalRef(thrownTypes);
            } else {
              returnType = getTypeFromJniTypeName('void');
              argumentTypes = [];
              impl = methodValue;
            }
          } else {
            returnType = getTypeFromJniTypeName(methodValue.returnType || 'void');
            argumentTypes = (methodValue.argumentTypes || []).map(function (name) {
              return getTypeFromJniTypeName(name);
            });
            impl = methodValue.implementation;

            if (typeof impl !== 'function') {
              throw new Error('Expected a function implementation for method: ' + name);
            }

            var id = makeOverloadId(name, returnType, argumentTypes);
            var pendingOverload = pendingOverloads[id];

            if (pendingOverload !== undefined) {
              var _overload = pendingOverload[0],
                  _parentTypeHandle = pendingOverload[1];
              delete pendingOverloads[id];
              method = _overload;

              var _reflectedMethod = env.toReflectedMethod(_parentTypeHandle, _overload.handle, 0);

              var _thrownTypes = invokeObjectMethodNoArgs(env.handle, _reflectedMethod, Method.getGenericExceptionTypes);

              thrownTypeNames = readTypeNames(env, _thrownTypes).map(makeJniObjectTypeName);
              env.deleteLocalRef(_thrownTypes);
            }
          }

          if (method === null) {
            method = {
              methodName: name,
              type: INSTANCE_METHOD,
              returnType: returnType,
              argumentTypes: argumentTypes,
              holder: placeholder
            };
            method[PENDING_CALLS] = new _set["default"]();
          }

          var returnTypeName = returnType.name;
          var argumentTypeNames = argumentTypes.map(function (t) {
            return t.name;
          });
          dexMethods.push([name, returnTypeName, argumentTypeNames, thrownTypeNames]);
          var signature = '(' + argumentTypeNames.join('') + ')' + returnTypeName;
          var rawName = Memory.allocUtf8String(name);
          var rawSignature = Memory.allocUtf8String(signature);
          var rawImpl = implement(method, impl);
          Memory.writePointer(methodElements.add(index * methodElementSize), rawName);
          Memory.writePointer(methodElements.add(index * methodElementSize + pointerSize), rawSignature);
          Memory.writePointer(methodElements.add(index * methodElementSize + 2 * pointerSize), rawImpl);
          temporaryHandles.push(rawName, rawSignature);
          nativeMethods.push(rawImpl);
        });
        var unimplementedMethodIds = (0, _keys["default"])(pendingOverloads);

        if (unimplementedMethodIds.length > 0) {
          throw new Error('Missing implementation for: ' + unimplementedMethodIds.join(', '));
        }
      }

      var dex = DexFile.fromBuffer(mkdex(dexSpec));

      try {
        dex.load();
      } finally {
        dex.file["delete"]();
      }

      var Klass = factory.use(spec.name);
      Klass.$classWrapper.$nativeMethods = nativeMethods;

      if (numMethods > 0) {
        var classHandle = Klass.$getClassHandle(env);
        localHandles.push(classHandle);
        env.registerNatives(classHandle, methodElements, numMethods);
        env.checkForExceptionAndThrowIt();
      }

      var C = classes[spec.name];
      return Klass;
    } finally {
      localHandles.forEach(function (handle) {
        env.deleteLocalRef(handle);
      });
    }
  }

  function implement(method, fn) {
    if (method.hasOwnProperty('overloads')) {
      throw new Error('Only re-implementing a concrete (specific) method is possible, not a method "dispatcher"');
    }

    var C = method.holder; // eslint-disable-line

    var type = method.type;
    var retType = method.returnType;
    var argTypes = method.argumentTypes;
    var methodName = method.methodName;
    var rawRetType = retType.type;
    var rawArgTypes = argTypes.map(function (t) {
      return t.type;
    });
    var pendingCalls = method[PENDING_CALLS]; // eslint-disable-line

    var frameCapacity = 2;
    var argVariableNames = argTypes.map(function (t, i) {
      return 'a' + (i + 1);
    });
    var callArgs = argTypes.map(function (t, i) {
      if (t.fromJni) {
        frameCapacity++;
        return ['argTypes[', i, '].fromJni.call(self, ', argVariableNames[i], ', env)'].join('');
      } else {
        return argVariableNames[i];
      }
    });
    var returnCapture, returnStatements, returnNothing;

    if (rawRetType === 'void') {
      returnCapture = '';
      returnStatements = 'env.popLocalFrame(NULL);';
      returnNothing = 'return;';
    } else {
      if (retType.toJni) {
        frameCapacity++;
        returnCapture = 'result = ';
        returnStatements = 'var rawResult;' + 'try {' + 'if (retType.isCompatible.call(this, result)) {' + 'rawResult = retType.toJni.call(this, result, env);' + '} else {' + 'throw new Error("Implementation for " + methodName + " expected return value compatible with \'" + retType.className + "\'.");' + '}';

        if (retType.type === 'pointer') {
          returnStatements += '} catch (e) {' + 'env.popLocalFrame(NULL);' + 'throw e;' + '}' + 'return env.popLocalFrame(rawResult);';
          returnNothing = 'return NULL;';
        } else {
          returnStatements += '} finally {' + 'env.popLocalFrame(NULL);' + '}' + 'return rawResult;';
          returnNothing = 'return 0;';
        }
      } else {
        returnCapture = 'result = ';
        returnStatements = 'env.popLocalFrame(NULL);' + 'return result;';
        returnNothing = 'return 0;';
      }
    }

    var f;
    eval('f = function (' + ['envHandle', 'thisHandle'].concat(argVariableNames).join(', ') + ') {' + // eslint-disable-line
    'var env = new Env(envHandle, vm);' + 'if (env.pushLocalFrame(' + frameCapacity + ') !== JNI_OK) {' + 'return;' + '}' + 'var self = ' + (type === INSTANCE_METHOD ? 'new C(thisHandle);' : 'new C(null);') + 'var result;' + 'var tid = Process.getCurrentThreadId();' + 'try {' + 'pendingCalls.add(tid);' + 'if (ignoredThreads[tid] === undefined) {' + returnCapture + 'fn.call(' + ['self'].concat(callArgs).join(', ') + ');' + '} else {' + returnCapture + 'method.call(' + ['self'].concat(callArgs).join(', ') + ');' + '}' + '} catch (e) {' + 'env.popLocalFrame(NULL);' + "if (typeof e === 'object' && e.hasOwnProperty('$handle')) {" + 'env.throw(e.$handle);' + returnNothing + '} else {' + 'throw e;' + '}' + '} finally {' + 'pendingCalls.delete(tid);' + '}' + returnStatements + '};');
    (0, _defineProperty["default"])(f, 'methodName', {
      enumerable: true,
      value: methodName
    });
    (0, _defineProperty["default"])(f, 'type', {
      enumerable: true,
      value: type
    });
    (0, _defineProperty["default"])(f, 'returnType', {
      enumerable: true,
      value: retType
    });
    (0, _defineProperty["default"])(f, 'argumentTypes', {
      enumerable: true,
      value: argTypes
    });
    (0, _defineProperty["default"])(f, 'canInvokeWith', {
      enumerable: true,
      value: function value(args) {
        if (args.length !== argTypes.length) {
          return false;
        }

        return argTypes.every(function (t, i) {
          return t.isCompatible(args[i]);
        });
      }
    });
    return new NativeCallback(f, rawRetType, ['pointer', 'pointer'].concat(rawArgTypes));
  }

  function getTypeFromJniTypeName(typeName, unbox) {
    if (unbox === void 0) {
      unbox = true;
    }

    return getType(typeName, unbox, factory);
  }

  function ignore(threadId) {
    var count = ignoredThreads[threadId];

    if (count === undefined) {
      count = 0;
    }

    count++;
    ignoredThreads[threadId] = count;
  }

  function unignore(threadId) {
    var count = ignoredThreads[threadId];

    if (count === undefined) {
      throw new Error("Thread " + threadId + " is not ignored");
    }

    count--;

    if (count === 0) {
      delete ignoredThreads[threadId];
    } else {
      ignoredThreads[threadId] = count;
    }
  }

  initialize.call(this);
}

function basename(className) {
  return className.slice(className.lastIndexOf('.') + 1);
}

function makeJniObjectTypeName(typeName) {
  return 'L' + typeName.replace(/\./g, '/') + ';';
}

function readTypeNames(env, types) {
  var names = [];
  var numTypes = env.getArrayLength(types);

  for (var typeIndex = 0; typeIndex !== numTypes; typeIndex++) {
    var t = env.getObjectArrayElement(types, typeIndex);

    try {
      names.push(env.getTypeName(t));
    } finally {
      env.deleteLocalRef(t);
    }
  }

  return names;
}

function makeOverloadId(name, returnType, argumentTypes) {
  return returnType.className + " " + name + "(" + argumentTypes.map(function (t) {
    return t.className;
  }).join(', ') + ")";
}

function throwOverloadError(name, methods, message) {
  var methodsSortedByArity = methods.slice().sort(function (a, b) {
    return a.argumentTypes.length - b.argumentTypes.length;
  });
  var overloads = methodsSortedByArity.map(function (m) {
    var argTypes = m.argumentTypes;

    if (argTypes.length > 0) {
      return '.overload(\'' + m.argumentTypes.map(function (t) {
        return t.className;
      }).join('\', \'') + '\')';
    } else {
      return '.overload()';
    }
  });
  throw new Error(name + "(): " + message + "\n\t" + overloads.join('\n\t'));
}
/*
 * http://docs.oracle.com/javase/6/docs/technotes/guides/jni/spec/types.html#wp9502
 * http://www.liaohuqiu.net/posts/android-object-size-dalvik/
 */


function getType(typeName, unbox, factory) {
  var type = getPrimitiveType(typeName);

  if (!type) {
    if (typeName.indexOf('[') === 0) {
      type = getArrayType(typeName, unbox, factory);
    } else {
      if (typeName[0] === 'L' && typeName[typeName.length - 1] === ';') {
        typeName = typeName.substring(1, typeName.length - 1);
      }

      type = getObjectType(typeName, unbox, factory);
    }
  }

  var result = {
    className: typeName
  };

  for (var key in type) {
    if (type.hasOwnProperty(key)) {
      result[key] = type[key];
    }
  }

  return result;
}

var primitiveTypes = {
  "boolean": {
    name: 'Z',
    type: 'uint8',
    size: 1,
    byteSize: 1,
    isCompatible: function isCompatible(v) {
      return typeof v === 'boolean';
    },
    fromJni: function fromJni(v) {
      return !!v;
    },
    toJni: function toJni(v) {
      return v ? 1 : 0;
    },
    memoryRead: Memory.readU8,
    memoryWrite: Memory.writeU8
  },
  "byte": {
    name: 'B',
    type: 'int8',
    size: 1,
    byteSize: 1,
    isCompatible: function isCompatible(v) {
      return (0, _isInteger["default"])(v) && v >= -128 && v <= 127;
    },
    memoryRead: Memory.readS8,
    memoryWrite: Memory.writeS8
  },
  "char": {
    name: 'C',
    type: 'uint16',
    size: 1,
    byteSize: 2,
    isCompatible: function isCompatible(v) {
      if (typeof v === 'string' && v.length === 1) {
        var charCode = v.charCodeAt(0);
        return charCode >= 0 && charCode <= 65535;
      } else {
        return false;
      }
    },
    fromJni: function fromJni(c) {
      return String.fromCharCode(c);
    },
    toJni: function toJni(s) {
      return s.charCodeAt(0);
    },
    memoryRead: Memory.readU16,
    memoryWrite: Memory.writeU16
  },
  "short": {
    name: 'S',
    type: 'int16',
    size: 1,
    byteSize: 2,
    isCompatible: function isCompatible(v) {
      return (0, _isInteger["default"])(v) && v >= -32768 && v <= 32767;
    },
    memoryRead: Memory.readS16,
    memoryWrite: Memory.writeS16
  },
  "int": {
    name: 'I',
    type: 'int32',
    size: 1,
    byteSize: 4,
    isCompatible: function isCompatible(v) {
      return (0, _isInteger["default"])(v) && v >= -2147483648 && v <= 2147483647;
    },
    memoryRead: Memory.readS32,
    memoryWrite: Memory.writeS32
  },
  "long": {
    name: 'J',
    type: 'int64',
    size: 2,
    byteSize: 8,
    isCompatible: function isCompatible(v) {
      return typeof v === 'number' || v instanceof Int64;
    },
    memoryRead: Memory.readS64,
    memoryWrite: Memory.writeS64
  },
  "float": {
    name: 'F',
    type: 'float',
    size: 1,
    byteSize: 4,
    isCompatible: function isCompatible(v) {
      // TODO
      return typeof v === 'number';
    },
    memoryRead: Memory.readFloat,
    memoryWrite: Memory.writeFloat
  },
  "double": {
    name: 'D',
    type: 'double',
    size: 2,
    byteSize: 8,
    isCompatible: function isCompatible(v) {
      // TODO
      return typeof v === 'number';
    },
    memoryRead: Memory.readDouble,
    memoryWrite: Memory.writeDouble
  },
  "void": {
    name: 'V',
    type: 'void',
    size: 0,
    byteSize: 0,
    isCompatible: function isCompatible(v) {
      return v === undefined;
    }
  }
};

function getPrimitiveType(name) {
  return primitiveTypes[name];
}

var cachedObjectTypesWithUnbox = {};
var cachedObjectTypesWithoutUnbox = {};

function getObjectType(typeName, unbox, factory) {
  var cache = unbox ? cachedObjectTypesWithUnbox : cachedObjectTypesWithoutUnbox;
  var type = cache[typeName];

  if (type !== undefined) {
    return type;
  }

  if (typeName === 'java.lang.Object') {
    type = getJavaLangObjectType(factory);
  } else {
    type = getAnyObjectType(typeName, unbox, factory);
  }

  cache[typeName] = type;
  return type;
}

function getJavaLangObjectType(factory) {
  return {
    name: 'Ljava/lang/Object;',
    type: 'pointer',
    size: 1,
    isCompatible: function isCompatible(v) {
      if (v === null) {
        return true;
      }

      var jsType = typeof v;

      if (jsType === 'string') {
        return true;
      }

      return jsType === 'object' && v.hasOwnProperty('$handle');
    },
    fromJni: function fromJni(h, env) {
      if (h.isNull()) {
        return null;
      }

      if (this && this.$handle !== undefined && env.isSameObject(h, this.$handle)) {
        return this;
      }

      return factory.cast(h, factory.use('java.lang.Object'));
    },
    toJni: function toJni(o, env) {
      if (o === null) {
        return NULL;
      }

      if (typeof o === 'string') {
        return env.newStringUtf(o);
      }

      return o.$handle;
    }
  };
}

function getAnyObjectType(typeName, unbox, factory) {
  var cachedClass = null;
  var cachedIsInstance = null;
  var cachedIsDefaultString = null;

  function getClass() {
    if (cachedClass === null) {
      cachedClass = factory.use(typeName)["class"];
    }

    return cachedClass;
  }

  function isInstance(v) {
    var klass = getClass();

    if (cachedIsInstance === null) {
      cachedIsInstance = klass.isInstance.overload('java.lang.Object');
    }

    return cachedIsInstance.call(klass, v);
  }

  function typeIsDefaultString() {
    if (cachedIsDefaultString === null) {
      cachedIsDefaultString = factory.use('java.lang.String')["class"].isAssignableFrom(getClass());
    }

    return cachedIsDefaultString;
  }

  return {
    name: makeJniObjectTypeName(typeName),
    type: 'pointer',
    size: 1,
    isCompatible: function isCompatible(v) {
      if (v === null) {
        return true;
      }

      var jsType = typeof v;

      if (jsType === 'string' && typeIsDefaultString()) {
        return true;
      }

      var isWrapper = jsType === 'object' && v.hasOwnProperty('$handle');

      if (!isWrapper) {
        return false;
      }

      return isInstance(v);
    },
    fromJni: function fromJni(h, env) {
      if (h.isNull()) {
        return null;
      }

      if (typeIsDefaultString() && unbox) {
        return env.stringFromJni(h);
      }

      if (this && this.$handle !== undefined && env.isSameObject(h, this.$handle)) {
        return this;
      }

      return factory.cast(h, factory.use(typeName));
    },
    toJni: function toJni(o, env) {
      if (o === null) {
        return NULL;
      }

      if (typeof o === 'string') {
        return env.newStringUtf(o);
      }

      return o.$handle;
    }
  };
}

var primitiveArrayTypes = [['Z', 'boolean'], ['B', 'byte'], ['C', 'char'], ['D', 'double'], ['F', 'float'], ['I', 'int'], ['J', 'long'], ['S', 'short']].reduce(function (result, _ref3) {
  var shorty = _ref3[0],
      name = _ref3[1];
  result['[' + shorty] = makePrimitiveArrayType(name);
  return result;
}, {});

function makePrimitiveArrayType(name) {
  var envProto = Env.prototype;
  var nameTitled = toTitleCase(name);
  var spec = {
    typeName: name,
    newArray: envProto['new' + nameTitled + 'Array'],
    setRegion: envProto['set' + nameTitled + 'ArrayRegion'],
    getElements: envProto['get' + nameTitled + 'ArrayElements'],
    releaseElements: envProto['release' + nameTitled + 'ArrayElements']
  };
  return {
    name: name,
    type: 'pointer',
    size: 1,
    isCompatible: function isCompatible(v) {
      return isCompatiblePrimitiveArray(v, name);
    },
    fromJni: function fromJni(h, env) {
      return fromJniPrimitiveArray(h, spec, env);
    },
    toJni: function toJni(arr, env) {
      return toJniPrimitiveArray(arr, spec, env);
    }
  };
}

function getArrayType(typeName, unbox, factory) {
  var primitiveType = primitiveArrayTypes[typeName];

  if (primitiveType !== undefined) {
    return primitiveType;
  }

  if (typeName.indexOf('[') !== 0) {
    throw new Error('Unsupported type: ' + typeName);
  }

  var elementTypeName = typeName.substring(1);
  var elementType = getType(elementTypeName, unbox, factory);

  if (elementTypeName[0] === 'L' && elementTypeName[elementTypeName.length - 1] === ';') {
    elementTypeName = elementTypeName.substring(1, elementTypeName.length - 1);
  }

  return {
    name: typeName.replace(/\./g, '/'),
    type: 'pointer',
    size: 1,
    isCompatible: function isCompatible(v) {
      if (v === null) {
        return true;
      } else if (typeof v !== 'object' || !v.hasOwnProperty('length')) {
        return false;
      }

      return v.every(function (element) {
        return elementType.isCompatible(element);
      });
    },
    fromJni: function fromJni(arr, env) {
      return fromJniObjectArray.call(this, arr, env, function (self, elem) {
        return elementType.fromJni.call(self, elem, env);
      });
    },
    toJni: function toJni(elements, env) {
      var klassObj = factory.use(elementTypeName);
      var classHandle = klassObj.$getClassHandle(env);

      try {
        return toJniObjectArray(elements, env, classHandle, function (i, result) {
          var handle = elementType.toJni.call(this, elements[i], env);

          try {
            env.setObjectArrayElement(result, i, handle);
          } finally {
            if (elementType.type === 'pointer' && env.getObjectRefType(handle) === JNILocalRefType) {
              env.deleteLocalRef(handle);
            }
          }
        });
      } finally {
        env.deleteLocalRef(classHandle);
      }
    }
  };
}

function fromJniObjectArray(arr, env, convertFromJniFunc) {
  if (arr.isNull()) {
    return null;
  }

  var result = [];
  var length = env.getArrayLength(arr);

  for (var i = 0; i !== length; i++) {
    var elemHandle = env.getObjectArrayElement(arr, i); // Maybe ArrayIndexOutOfBoundsException: if 'i' does not specify a valid index in the array - should not be the case

    env.checkForExceptionAndThrowIt();

    try {
      /* jshint validthis: true */
      result.push(convertFromJniFunc(this, elemHandle));
    } finally {
      env.deleteLocalRef(elemHandle);
    }
  }

  return result;
}

function toJniObjectArray(arr, env, classHandle, setObjectArrayFunc) {
  if (arr === null) {
    return NULL;
  }

  if (!(arr instanceof Array)) {
    throw new Error("Expected an array.");
  }

  var length = arr.length;
  var result = env.newObjectArray(length, classHandle, NULL);
  env.checkForExceptionAndThrowIt();

  if (result.isNull()) {
    return NULL;
  }

  for (var i = 0; i !== length; i++) {
    setObjectArrayFunc.call(env, i, result);
    env.checkForExceptionAndThrowIt();
  }

  return result;
}

var PrimitiveArray = function PrimitiveArray(handle, type, length) {
  this.$handle = handle;
  this.type = type;
  this.length = length;
};

function fromJniPrimitiveArray(arr, spec, env) {
  if (arr.isNull()) {
    return null;
  }

  var typeName = spec.typeName;
  var type = getPrimitiveType(typeName);
  var elementSize = type.byteSize;
  var readElement = type.memoryRead;
  var writeElement = type.memoryWrite;
  var parseElementValue = type.fromJni || identity;
  var unparseElementValue = type.toJni || identity;
  var handle = env.newGlobalRef(arr);
  var length = env.getArrayLength(handle);
  var vm = env.vm;
  var storage = new PrimitiveArray(handle, typeName, length);
  var wrapper = new Proxy(storage, {
    has: function has(target, property) {
      return hasProperty.call(target, property);
    },
    get: function get(target, property, receiver) {
      switch (property) {
        case 'hasOwnProperty':
          return hasProperty.bind(target);

        case 'toJSON':
          return toJSON;

        default:
          if (typeof property === 'symbol') {
            return target[property];
          }

          var index = tryParseIndex(property);

          if (index === null) {
            return target[property];
          }

          return withElements(function (elements) {
            return parseElementValue.call(type, readElement.call(type, elements.add(index * elementSize)));
          });
      }
    },
    set: function set(target, property, value, receiver) {
      var index = tryParseIndex(property);

      if (index === null) {
        target[property] = value;
        return true;
      }

      var env = vm.getEnv();
      var element = Memory.alloc(elementSize);
      writeElement.call(type, element, unparseElementValue(value));
      spec.setRegion.call(env, handle, index, 1, element);
      return true;
    },
    ownKeys: function ownKeys(target) {
      var keys = ['$handle', 'type', 'length'];

      for (var index = 0; index !== length; index++) {
        keys.push(index.toString());
      }

      return keys;
    },
    getOwnPropertyDescriptor: function getOwnPropertyDescriptor(target, property) {
      return {
        writable: false,
        configurable: true,
        enumerable: true
      };
    }
  });
  WeakRef.bind(wrapper, makeHandleDestructor(vm, handle));
  Script.nextTick(function () {
    wrapper = null;
  });
  env = null;
  return wrapper;

  function tryParseIndex(rawIndex) {
    var index = (0, _parseInt2["default"])(rawIndex);

    if (isNaN(index) || index < 0 || index >= length) {
      return null;
    }

    return index;
  }

  function withElements(perform) {
    var env = vm.getEnv();
    var elements = spec.getElements.call(env, handle);

    if (elements.isNull()) {
      throw new Error('Unable to get array elements');
    }

    try {
      return perform(elements);
    } finally {
      spec.releaseElements.call(env, handle, elements);
    }
  }

  function hasProperty(property) {
    var index = tryParseIndex(property);

    if (index === null) {
      return this.hasOwnProperty(property);
    }

    return true;
  }

  function toJSON() {
    return withElements(function (elements) {
      var values = [];

      for (var index = 0; index !== length; index++) {
        var value = parseElementValue.call(type, readElement.call(type, elements.add(index * elementSize)));
        values.push(value);
      }

      return values;
    });
  }
}

function toJniPrimitiveArray(arr, spec, env) {
  if (arr === null) {
    return NULL;
  }

  var handle = arr.$handle;

  if (handle !== undefined) {
    return handle;
  }

  var length = arr.length;
  var type = getPrimitiveType(spec.typeName);
  var result = spec.newArray.call(env, length);

  if (result.isNull()) {
    throw new Error('Unable to construct array');
  }

  if (length > 0) {
    var elementSize = type.byteSize;
    var writeElement = type.memoryWrite;
    var unparseElementValue = type.toJni || identity;
    var elements = Memory.alloc(length * type.byteSize);

    for (var index = 0; index !== length; index++) {
      writeElement.call(type, elements.add(index * elementSize), unparseElementValue(arr[index]));
    }

    spec.setRegion.call(env, result, 0, length, elements);
    env.checkForExceptionAndThrowIt();
  }

  return result;
}

function isCompatiblePrimitiveArray(value, typeName) {
  if (value === null) {
    return true;
  }

  if (value instanceof PrimitiveArray) {
    return value.type === typeName;
  }

  var isArrayLike = typeof value === 'object' && value.hasOwnProperty('length');

  if (!isArrayLike) {
    return false;
  }

  var elementType = getPrimitiveType(typeName);
  return Array.prototype.every.call(value, function (element) {
    return elementType.isCompatible(element);
  });
}

function makeSourceFileName(className) {
  var tokens = className.split('.');
  return tokens[tokens.length - 1] + '.java';
}

function toTitleCase(str) {
  return str.charAt(0).toUpperCase() + str.slice(1);
}

function makeHandleDestructor(vm, handle) {
  return function () {
    vm.perform(function () {
      var env = vm.getEnv();
      env.deleteGlobalRef(handle);
    });
  };
}

function alignPointerOffset(offset) {
  var remainder = offset % pointerSize;

  if (remainder !== 0) {
    return offset + pointerSize - remainder;
  }

  return offset;
}

function identity(value) {
  return value;
}

function computeDalvikJniArgInfo(methodId) {
  if (Process.arch !== 'ia32') return DALVIK_JNI_NO_ARG_INFO; // For the x86 ABI, valid hints should always be generated.

  var shorty = Memory.readCString(Memory.readPointer(methodId.add(DVM_METHOD_OFFSET_SHORTY)));
  if (shorty === null || shorty.length === 0 || shorty.length > 0xffff) return DALVIK_JNI_NO_ARG_INFO;
  var returnType;

  switch (shorty[0]) {
    case 'V':
      returnType = DALVIK_JNI_RETURN_VOID;
      break;

    case 'F':
      returnType = DALVIK_JNI_RETURN_FLOAT;
      break;

    case 'D':
      returnType = DALVIK_JNI_RETURN_DOUBLE;
      break;

    case 'J':
      returnType = DALVIK_JNI_RETURN_S8;
      break;

    case 'Z':
    case 'B':
      returnType = DALVIK_JNI_RETURN_S1;
      break;

    case 'C':
      returnType = DALVIK_JNI_RETURN_U2;
      break;

    case 'S':
      returnType = DALVIK_JNI_RETURN_S2;
      break;

    default:
      returnType = DALVIK_JNI_RETURN_S4;
      break;
  }

  var hints = 0;

  for (var i = shorty.length - 1; i > 0; i--) {
    var ch = shorty[i];
    hints += ch === 'D' || ch === 'J' ? 2 : 1;
  }

  return returnType << DALVIK_JNI_RETURN_SHIFT | hints;
}

module.exports = ClassFactory;
/* global Int64, Memory, NativeCallback, NativeFunction, NULL, Process, WeakRef */

},{"./android":149,"./api":150,"./env":152,"./mkdex":153,"./result":154,"@babel/runtime-corejs2/core-js/array/from":3,"@babel/runtime-corejs2/core-js/array/is-array":4,"@babel/runtime-corejs2/core-js/get-iterator":5,"@babel/runtime-corejs2/core-js/number/is-integer":6,"@babel/runtime-corejs2/core-js/object/define-properties":9,"@babel/runtime-corejs2/core-js/object/define-property":10,"@babel/runtime-corejs2/core-js/object/get-own-property-names":11,"@babel/runtime-corejs2/core-js/object/get-prototype-of":12,"@babel/runtime-corejs2/core-js/object/keys":13,"@babel/runtime-corejs2/core-js/parse-int":15,"@babel/runtime-corejs2/core-js/set":17,"@babel/runtime-corejs2/core-js/symbol":18,"@babel/runtime-corejs2/helpers/construct":19,"@babel/runtime-corejs2/helpers/createClass":20,"@babel/runtime-corejs2/helpers/inheritsLoose":21,"@babel/runtime-corejs2/helpers/interopRequireDefault":22}],152:[function(require,module,exports){
'use strict';

function Env(handle, vm) {
  this.handle = handle;
  this.vm = vm;
}

var pointerSize = Process.pointerSize;
var JNI_ABORT = 2;
var CALL_CONSTRUCTOR_METHOD_OFFSET = 28;
var CALL_OBJECT_METHOD_OFFSET = 34;
var CALL_BOOLEAN_METHOD_OFFSET = 37;
var CALL_BYTE_METHOD_OFFSET = 40;
var CALL_CHAR_METHOD_OFFSET = 43;
var CALL_SHORT_METHOD_OFFSET = 46;
var CALL_INT_METHOD_OFFSET = 49;
var CALL_LONG_METHOD_OFFSET = 52;
var CALL_FLOAT_METHOD_OFFSET = 55;
var CALL_DOUBLE_METHOD_OFFSET = 58;
var CALL_VOID_METHOD_OFFSET = 61;
var CALL_NONVIRTUAL_OBJECT_METHOD_OFFSET = 64;
var CALL_NONVIRTUAL_BOOLEAN_METHOD_OFFSET = 67;
var CALL_NONVIRTUAL_BYTE_METHOD_OFFSET = 70;
var CALL_NONVIRTUAL_CHAR_METHOD_OFFSET = 73;
var CALL_NONVIRTUAL_SHORT_METHOD_OFFSET = 76;
var CALL_NONVIRTUAL_INT_METHOD_OFFSET = 79;
var CALL_NONVIRTUAL_LONG_METHOD_OFFSET = 82;
var CALL_NONVIRTUAL_FLOAT_METHOD_OFFSET = 85;
var CALL_NONVIRTUAL_DOUBLE_METHOD_OFFSET = 88;
var CALL_NONVIRTUAL_VOID_METHOD_OFFSET = 91;
var CALL_STATIC_OBJECT_METHOD_OFFSET = 114;
var CALL_STATIC_BOOLEAN_METHOD_OFFSET = 117;
var CALL_STATIC_BYTE_METHOD_OFFSET = 120;
var CALL_STATIC_CHAR_METHOD_OFFSET = 123;
var CALL_STATIC_SHORT_METHOD_OFFSET = 126;
var CALL_STATIC_INT_METHOD_OFFSET = 129;
var CALL_STATIC_LONG_METHOD_OFFSET = 132;
var CALL_STATIC_FLOAT_METHOD_OFFSET = 135;
var CALL_STATIC_DOUBLE_METHOD_OFFSET = 138;
var CALL_STATIC_VOID_METHOD_OFFSET = 141;
var GET_OBJECT_FIELD_OFFSET = 95;
var GET_BOOLEAN_FIELD_OFFSET = 96;
var GET_BYTE_FIELD_OFFSET = 97;
var GET_CHAR_FIELD_OFFSET = 98;
var GET_SHORT_FIELD_OFFSET = 99;
var GET_INT_FIELD_OFFSET = 100;
var GET_LONG_FIELD_OFFSET = 101;
var GET_FLOAT_FIELD_OFFSET = 102;
var GET_DOUBLE_FIELD_OFFSET = 103;
var SET_OBJECT_FIELD_OFFSET = 104;
var SET_BOOLEAN_FIELD_OFFSET = 105;
var SET_BYTE_FIELD_OFFSET = 106;
var SET_CHAR_FIELD_OFFSET = 107;
var SET_SHORT_FIELD_OFFSET = 108;
var SET_INT_FIELD_OFFSET = 109;
var SET_LONG_FIELD_OFFSET = 110;
var SET_FLOAT_FIELD_OFFSET = 111;
var SET_DOUBLE_FIELD_OFFSET = 112;
var GET_STATIC_OBJECT_FIELD_OFFSET = 145;
var GET_STATIC_BOOLEAN_FIELD_OFFSET = 146;
var GET_STATIC_BYTE_FIELD_OFFSET = 147;
var GET_STATIC_CHAR_FIELD_OFFSET = 148;
var GET_STATIC_SHORT_FIELD_OFFSET = 149;
var GET_STATIC_INT_FIELD_OFFSET = 150;
var GET_STATIC_LONG_FIELD_OFFSET = 151;
var GET_STATIC_FLOAT_FIELD_OFFSET = 152;
var GET_STATIC_DOUBLE_FIELD_OFFSET = 153;
var SET_STATIC_OBJECT_FIELD_OFFSET = 154;
var SET_STATIC_BOOLEAN_FIELD_OFFSET = 155;
var SET_STATIC_BYTE_FIELD_OFFSET = 156;
var SET_STATIC_CHAR_FIELD_OFFSET = 157;
var SET_STATIC_SHORT_FIELD_OFFSET = 158;
var SET_STATIC_INT_FIELD_OFFSET = 159;
var SET_STATIC_LONG_FIELD_OFFSET = 160;
var SET_STATIC_FLOAT_FIELD_OFFSET = 161;
var SET_STATIC_DOUBLE_FIELD_OFFSET = 162;
var callMethodOffset = {
  'pointer': CALL_OBJECT_METHOD_OFFSET,
  'uint8': CALL_BOOLEAN_METHOD_OFFSET,
  'int8': CALL_BYTE_METHOD_OFFSET,
  'uint16': CALL_CHAR_METHOD_OFFSET,
  'int16': CALL_SHORT_METHOD_OFFSET,
  'int32': CALL_INT_METHOD_OFFSET,
  'int64': CALL_LONG_METHOD_OFFSET,
  'float': CALL_FLOAT_METHOD_OFFSET,
  'double': CALL_DOUBLE_METHOD_OFFSET,
  'void': CALL_VOID_METHOD_OFFSET
};
var callNonvirtualMethodOffset = {
  'pointer': CALL_NONVIRTUAL_OBJECT_METHOD_OFFSET,
  'uint8': CALL_NONVIRTUAL_BOOLEAN_METHOD_OFFSET,
  'int8': CALL_NONVIRTUAL_BYTE_METHOD_OFFSET,
  'uint16': CALL_NONVIRTUAL_CHAR_METHOD_OFFSET,
  'int16': CALL_NONVIRTUAL_SHORT_METHOD_OFFSET,
  'int32': CALL_NONVIRTUAL_INT_METHOD_OFFSET,
  'int64': CALL_NONVIRTUAL_LONG_METHOD_OFFSET,
  'float': CALL_NONVIRTUAL_FLOAT_METHOD_OFFSET,
  'double': CALL_NONVIRTUAL_DOUBLE_METHOD_OFFSET,
  'void': CALL_NONVIRTUAL_VOID_METHOD_OFFSET
};
var callStaticMethodOffset = {
  'pointer': CALL_STATIC_OBJECT_METHOD_OFFSET,
  'uint8': CALL_STATIC_BOOLEAN_METHOD_OFFSET,
  'int8': CALL_STATIC_BYTE_METHOD_OFFSET,
  'uint16': CALL_STATIC_CHAR_METHOD_OFFSET,
  'int16': CALL_STATIC_SHORT_METHOD_OFFSET,
  'int32': CALL_STATIC_INT_METHOD_OFFSET,
  'int64': CALL_STATIC_LONG_METHOD_OFFSET,
  'float': CALL_STATIC_FLOAT_METHOD_OFFSET,
  'double': CALL_STATIC_DOUBLE_METHOD_OFFSET,
  'void': CALL_STATIC_VOID_METHOD_OFFSET
};
var getFieldOffset = {
  'pointer': GET_OBJECT_FIELD_OFFSET,
  'uint8': GET_BOOLEAN_FIELD_OFFSET,
  'int8': GET_BYTE_FIELD_OFFSET,
  'uint16': GET_CHAR_FIELD_OFFSET,
  'int16': GET_SHORT_FIELD_OFFSET,
  'int32': GET_INT_FIELD_OFFSET,
  'int64': GET_LONG_FIELD_OFFSET,
  'float': GET_FLOAT_FIELD_OFFSET,
  'double': GET_DOUBLE_FIELD_OFFSET
};
var setFieldOffset = {
  'pointer': SET_OBJECT_FIELD_OFFSET,
  'uint8': SET_BOOLEAN_FIELD_OFFSET,
  'int8': SET_BYTE_FIELD_OFFSET,
  'uint16': SET_CHAR_FIELD_OFFSET,
  'int16': SET_SHORT_FIELD_OFFSET,
  'int32': SET_INT_FIELD_OFFSET,
  'int64': SET_LONG_FIELD_OFFSET,
  'float': SET_FLOAT_FIELD_OFFSET,
  'double': SET_DOUBLE_FIELD_OFFSET
};
var getStaticFieldOffset = {
  'pointer': GET_STATIC_OBJECT_FIELD_OFFSET,
  'uint8': GET_STATIC_BOOLEAN_FIELD_OFFSET,
  'int8': GET_STATIC_BYTE_FIELD_OFFSET,
  'uint16': GET_STATIC_CHAR_FIELD_OFFSET,
  'int16': GET_STATIC_SHORT_FIELD_OFFSET,
  'int32': GET_STATIC_INT_FIELD_OFFSET,
  'int64': GET_STATIC_LONG_FIELD_OFFSET,
  'float': GET_STATIC_FLOAT_FIELD_OFFSET,
  'double': GET_STATIC_DOUBLE_FIELD_OFFSET
};
var setStaticFieldOffset = {
  'pointer': SET_STATIC_OBJECT_FIELD_OFFSET,
  'uint8': SET_STATIC_BOOLEAN_FIELD_OFFSET,
  'int8': SET_STATIC_BYTE_FIELD_OFFSET,
  'uint16': SET_STATIC_CHAR_FIELD_OFFSET,
  'int16': SET_STATIC_SHORT_FIELD_OFFSET,
  'int32': SET_STATIC_INT_FIELD_OFFSET,
  'int64': SET_STATIC_LONG_FIELD_OFFSET,
  'float': SET_STATIC_FLOAT_FIELD_OFFSET,
  'double': SET_STATIC_DOUBLE_FIELD_OFFSET
};
var nativeFunctionOptions = {
  exceptions: 'propagate'
};
var cachedVtable = null;
var globalRefs = [];

Env.dispose = function (env) {
  globalRefs.forEach(env.deleteGlobalRef, env);
  globalRefs = [];
};

function register(globalRef) {
  globalRefs.push(globalRef);
  return globalRef;
}

function vtable(instance) {
  if (cachedVtable === null) {
    cachedVtable = Memory.readPointer(instance.handle);
  }

  return cachedVtable;
}

function proxy(offset, retType, argTypes, wrapper) {
  var impl = null;
  return function () {
    if (impl === null) {
      impl = new NativeFunction(Memory.readPointer(vtable(this).add(offset * pointerSize)), retType, argTypes, nativeFunctionOptions);
    }

    var args = [impl];
    args = args.concat.apply(args, arguments);
    return wrapper.apply(this, args);
  };
}

Env.prototype.findClass = proxy(6, 'pointer', ['pointer', 'pointer'], function (impl, name) {
  var result = impl(this.handle, Memory.allocUtf8String(name));
  this.checkForExceptionAndThrowIt();
  return result;
});

Env.prototype.checkForExceptionAndThrowIt = function () {
  var throwable = this.exceptionOccurred();

  if (!throwable.isNull()) {
    try {
      this.exceptionClear();
      var description = this.vaMethod('pointer', [])(this.handle, throwable, this.javaLangObject().toString);

      try {
        var descriptionStr = this.stringFromJni(description);
        var error = new Error(descriptionStr);
        var handle = this.newGlobalRef(throwable);
        error.$handle = handle;
        WeakRef.bind(error, makeErrorHandleDestructor(this.vm, handle));
        throw error;
      } finally {
        this.deleteLocalRef(description);
      }
    } finally {
      this.deleteLocalRef(throwable);
    }
  }
};

function makeErrorHandleDestructor(vm, handle) {
  return function () {
    vm.perform(function () {
      var env = vm.getEnv();
      env.deleteGlobalRef(handle);
    });
  };
}

Env.prototype.fromReflectedMethod = proxy(7, 'pointer', ['pointer', 'pointer'], function (impl, method) {
  return impl(this.handle, method);
});
Env.prototype.fromReflectedField = proxy(8, 'pointer', ['pointer', 'pointer'], function (impl, method) {
  return impl(this.handle, method);
});
Env.prototype.toReflectedMethod = proxy(9, 'pointer', ['pointer', 'pointer', 'pointer', 'uint8'], function (impl, klass, methodId, isStatic) {
  return impl(this.handle, klass, methodId, isStatic);
});
Env.prototype.getSuperclass = proxy(10, 'pointer', ['pointer', 'pointer'], function (impl, klass) {
  return impl(this.handle, klass);
});
Env.prototype.isAssignableFrom = proxy(11, 'uint8', ['pointer', 'pointer', 'pointer'], function (impl, klass1, klass2) {
  return !!impl(this.handle, klass1, klass2);
});
Env.prototype.toReflectedField = proxy(12, 'pointer', ['pointer', 'pointer', 'pointer', 'uint8'], function (impl, klass, fieldId, isStatic) {
  return impl(this.handle, klass, fieldId, isStatic);
});
Env.prototype["throw"] = proxy(13, 'int32', ['pointer', 'pointer'], function (impl, obj) {
  return impl(this.handle, obj);
});
Env.prototype.exceptionOccurred = proxy(15, 'pointer', ['pointer'], function (impl) {
  return impl(this.handle);
});
Env.prototype.exceptionDescribe = proxy(16, 'void', ['pointer'], function (impl) {
  impl(this.handle);
});
Env.prototype.exceptionClear = proxy(17, 'void', ['pointer'], function (impl) {
  impl(this.handle);
});
Env.prototype.pushLocalFrame = proxy(19, 'int32', ['pointer', 'int32'], function (impl, capacity) {
  return impl(this.handle, capacity);
});
Env.prototype.popLocalFrame = proxy(20, 'pointer', ['pointer', 'pointer'], function (impl, result) {
  return impl(this.handle, result);
});
Env.prototype.newGlobalRef = proxy(21, 'pointer', ['pointer', 'pointer'], function (impl, obj) {
  return impl(this.handle, obj);
});
Env.prototype.deleteGlobalRef = proxy(22, 'void', ['pointer', 'pointer'], function (impl, globalRef) {
  impl(this.handle, globalRef);
});
Env.prototype.deleteLocalRef = proxy(23, 'void', ['pointer', 'pointer'], function (impl, localRef) {
  impl(this.handle, localRef);
});
Env.prototype.isSameObject = proxy(24, 'uint8', ['pointer', 'pointer', 'pointer'], function (impl, ref1, ref2) {
  return !!impl(this.handle, ref1, ref2);
});
Env.prototype.allocObject = proxy(27, 'pointer', ['pointer', 'pointer'], function (impl, clazz) {
  return impl(this.handle, clazz);
});
Env.prototype.getObjectClass = proxy(31, 'pointer', ['pointer', 'pointer'], function (impl, obj) {
  return impl(this.handle, obj);
});
Env.prototype.isInstanceOf = proxy(32, 'uint8', ['pointer', 'pointer', 'pointer'], function (impl, obj, klass) {
  return !!impl(this.handle, obj, klass);
});
Env.prototype.getMethodId = proxy(33, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer'], function (impl, klass, name, sig) {
  return impl(this.handle, klass, Memory.allocUtf8String(name), Memory.allocUtf8String(sig));
});
Env.prototype.getFieldId = proxy(94, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer'], function (impl, klass, name, sig) {
  return impl(this.handle, klass, Memory.allocUtf8String(name), Memory.allocUtf8String(sig));
});
Env.prototype.getIntField = proxy(100, 'int32', ['pointer', 'pointer', 'pointer'], function (impl, obj, fieldId) {
  return impl(this.handle, obj, fieldId);
});
Env.prototype.getStaticMethodId = proxy(113, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer'], function (impl, klass, name, sig) {
  return impl(this.handle, klass, Memory.allocUtf8String(name), Memory.allocUtf8String(sig));
});
Env.prototype.getStaticFieldId = proxy(144, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer'], function (impl, klass, name, sig) {
  return impl(this.handle, klass, Memory.allocUtf8String(name), Memory.allocUtf8String(sig));
});
Env.prototype.getStaticIntField = proxy(150, 'int32', ['pointer', 'pointer', 'pointer'], function (impl, obj, fieldId) {
  return impl(this.handle, obj, fieldId);
});
Env.prototype.newStringUtf = proxy(167, 'pointer', ['pointer', 'pointer'], function (impl, str) {
  var utf = Memory.allocUtf8String(str);
  return impl(this.handle, utf);
});
Env.prototype.getStringUtfChars = proxy(169, 'pointer', ['pointer', 'pointer', 'pointer'], function (impl, str) {
  return impl(this.handle, str, NULL);
});
Env.prototype.releaseStringUtfChars = proxy(170, 'void', ['pointer', 'pointer', 'pointer'], function (impl, str, utf) {
  impl(this.handle, str, utf);
});
Env.prototype.getArrayLength = proxy(171, 'int32', ['pointer', 'pointer'], function (impl, array) {
  return impl(this.handle, array);
});
Env.prototype.newObjectArray = proxy(172, 'pointer', ['pointer', 'int32', 'pointer', 'pointer'], function (impl, length, elementClass, initialElement) {
  return impl(this.handle, length, elementClass, initialElement);
});
Env.prototype.getObjectArrayElement = proxy(173, 'pointer', ['pointer', 'pointer', 'int32'], function (impl, array, index) {
  return impl(this.handle, array, index);
});
Env.prototype.setObjectArrayElement = proxy(174, 'void', ['pointer', 'pointer', 'int32', 'pointer'], function (impl, array, index, value) {
  impl(this.handle, array, index, value);
});
Env.prototype.newBooleanArray = proxy(175, 'pointer', ['pointer', 'int32'], function (impl, length) {
  return impl(this.handle, length);
});
Env.prototype.newByteArray = proxy(176, 'pointer', ['pointer', 'int32'], function (impl, length) {
  return impl(this.handle, length);
});
Env.prototype.newCharArray = proxy(177, 'pointer', ['pointer', 'int32'], function (impl, length) {
  return impl(this.handle, length);
});
Env.prototype.newShortArray = proxy(178, 'pointer', ['pointer', 'int32'], function (impl, length) {
  return impl(this.handle, length);
});
Env.prototype.newIntArray = proxy(179, 'pointer', ['pointer', 'int32'], function (impl, length) {
  return impl(this.handle, length);
});
Env.prototype.newLongArray = proxy(180, 'pointer', ['pointer', 'int32'], function (impl, length) {
  return impl(this.handle, length);
});
Env.prototype.newFloatArray = proxy(181, 'pointer', ['pointer', 'int32'], function (impl, length) {
  return impl(this.handle, length);
});
Env.prototype.newDoubleArray = proxy(182, 'pointer', ['pointer', 'int32'], function (impl, length) {
  return impl(this.handle, length);
});
Env.prototype.getBooleanArrayElements = proxy(183, 'pointer', ['pointer', 'pointer', 'pointer'], function (impl, array) {
  return impl(this.handle, array, NULL);
});
Env.prototype.getByteArrayElements = proxy(184, 'pointer', ['pointer', 'pointer', 'pointer'], function (impl, array) {
  return impl(this.handle, array, NULL);
});
Env.prototype.getCharArrayElements = proxy(185, 'pointer', ['pointer', 'pointer', 'pointer'], function (impl, array) {
  return impl(this.handle, array, NULL);
});
Env.prototype.getShortArrayElements = proxy(186, 'pointer', ['pointer', 'pointer', 'pointer'], function (impl, array) {
  return impl(this.handle, array, NULL);
});
Env.prototype.getIntArrayElements = proxy(187, 'pointer', ['pointer', 'pointer', 'pointer'], function (impl, array) {
  return impl(this.handle, array, NULL);
});
Env.prototype.getLongArrayElements = proxy(188, 'pointer', ['pointer', 'pointer', 'pointer'], function (impl, array) {
  return impl(this.handle, array, NULL);
});
Env.prototype.getFloatArrayElements = proxy(189, 'pointer', ['pointer', 'pointer', 'pointer'], function (impl, array) {
  return impl(this.handle, array, NULL);
});
Env.prototype.getDoubleArrayElements = proxy(190, 'pointer', ['pointer', 'pointer', 'pointer'], function (impl, array) {
  return impl(this.handle, array, NULL);
});
Env.prototype.releaseBooleanArrayElements = proxy(191, 'pointer', ['pointer', 'pointer', 'pointer', 'int32'], function (impl, array, cArray) {
  impl(this.handle, array, cArray, JNI_ABORT);
});
Env.prototype.releaseByteArrayElements = proxy(192, 'pointer', ['pointer', 'pointer', 'pointer', 'int32'], function (impl, array, cArray) {
  impl(this.handle, array, cArray, JNI_ABORT);
});
Env.prototype.releaseCharArrayElements = proxy(193, 'pointer', ['pointer', 'pointer', 'pointer', 'int32'], function (impl, array, cArray) {
  impl(this.handle, array, cArray, JNI_ABORT);
});
Env.prototype.releaseShortArrayElements = proxy(194, 'pointer', ['pointer', 'pointer', 'pointer', 'int32'], function (impl, array, cArray) {
  impl(this.handle, array, cArray, JNI_ABORT);
});
Env.prototype.releaseIntArrayElements = proxy(195, 'pointer', ['pointer', 'pointer', 'pointer', 'int32'], function (impl, array, cArray) {
  impl(this.handle, array, cArray, JNI_ABORT);
});
Env.prototype.releaseLongArrayElements = proxy(196, 'pointer', ['pointer', 'pointer', 'pointer', 'int32'], function (impl, array, cArray) {
  impl(this.handle, array, cArray, JNI_ABORT);
});
Env.prototype.releaseFloatArrayElements = proxy(197, 'pointer', ['pointer', 'pointer', 'pointer', 'int32'], function (impl, array, cArray) {
  impl(this.handle, array, cArray, JNI_ABORT);
});
Env.prototype.releaseDoubleArrayElements = proxy(198, 'pointer', ['pointer', 'pointer', 'pointer', 'int32'], function (impl, array, cArray) {
  impl(this.handle, array, cArray, JNI_ABORT);
});
Env.prototype.setBooleanArrayRegion = proxy(207, 'void', ['pointer', 'pointer', 'int32', 'int32', 'pointer'], function (impl, array, start, length, cArray) {
  impl(this.handle, array, start, length, cArray);
});
Env.prototype.setByteArrayRegion = proxy(208, 'void', ['pointer', 'pointer', 'int32', 'int32', 'pointer'], function (impl, array, start, length, cArray) {
  impl(this.handle, array, start, length, cArray);
});
Env.prototype.setCharArrayRegion = proxy(209, 'void', ['pointer', 'pointer', 'int32', 'int32', 'pointer'], function (impl, array, start, length, cArray) {
  impl(this.handle, array, start, length, cArray);
});
Env.prototype.setShortArrayRegion = proxy(210, 'void', ['pointer', 'pointer', 'int32', 'int32', 'pointer'], function (impl, array, start, length, cArray) {
  impl(this.handle, array, start, length, cArray);
});
Env.prototype.setIntArrayRegion = proxy(211, 'void', ['pointer', 'pointer', 'int32', 'int32', 'pointer'], function (impl, array, start, length, cArray) {
  impl(this.handle, array, start, length, cArray);
});
Env.prototype.setLongArrayRegion = proxy(212, 'void', ['pointer', 'pointer', 'int32', 'int32', 'pointer'], function (impl, array, start, length, cArray) {
  impl(this.handle, array, start, length, cArray);
});
Env.prototype.setFloatArrayRegion = proxy(213, 'void', ['pointer', 'pointer', 'int32', 'int32', 'pointer'], function (impl, array, start, length, cArray) {
  impl(this.handle, array, start, length, cArray);
});
Env.prototype.setDoubleArrayRegion = proxy(214, 'void', ['pointer', 'pointer', 'int32', 'int32', 'pointer'], function (impl, array, start, length, cArray) {
  impl(this.handle, array, start, length, cArray);
});
Env.prototype.registerNatives = proxy(215, 'int32', ['pointer', 'pointer', 'pointer', 'int32'], function (impl, klass, methods, numMethods) {
  return impl(this.handle, klass, methods, numMethods);
});
Env.prototype.monitorEnter = proxy(217, 'int32', ['pointer', 'pointer'], function (impl, obj) {
  return impl(this.handle, obj);
});
Env.prototype.monitorExit = proxy(218, 'int32', ['pointer', 'pointer'], function (impl, obj) {
  return impl(this.handle, obj);
});
Env.prototype.getObjectRefType = proxy(232, 'int32', ['pointer', 'pointer'], function (impl, ref) {
  return impl(this.handle, ref);
});
var cachedPlainMethods = {};
var cachedVaMethods = {};

function plainMethod(offset, retType, argTypes) {
  var key = offset + 'v' + retType + '|' + argTypes.join(':');
  var m = cachedPlainMethods[key];

  if (!m) {
    /* jshint validthis: true */
    m = new NativeFunction(Memory.readPointer(vtable(this).add(offset * pointerSize)), retType, ['pointer', 'pointer', 'pointer'].concat(argTypes), nativeFunctionOptions);
    cachedPlainMethods[key] = m;
  }

  return m;
}

function vaMethod(offset, retType, argTypes) {
  var key = offset + 'v' + retType + '|' + argTypes.join(':');
  var m = cachedVaMethods[key];

  if (!m) {
    /* jshint validthis: true */
    m = new NativeFunction(Memory.readPointer(vtable(this).add(offset * pointerSize)), retType, ['pointer', 'pointer', 'pointer', '...'].concat(argTypes), nativeFunctionOptions);
    cachedVaMethods[key] = m;
  }

  return m;
}

function nonvirtualVaMethod(offset, retType, argTypes) {
  var key = offset + 'n' + retType + '|' + argTypes.join(':');
  var m = cachedVaMethods[key];

  if (!m) {
    /* jshint validthis: true */
    m = new NativeFunction(Memory.readPointer(vtable(this).add(offset * pointerSize)), retType, ['pointer', 'pointer', 'pointer', 'pointer', '...'].concat(argTypes), nativeFunctionOptions);
    cachedVaMethods[key] = m;
  }

  return m;
}

Env.prototype.constructor = function (argTypes) {
  return vaMethod.call(this, CALL_CONSTRUCTOR_METHOD_OFFSET, 'pointer', argTypes);
};

Env.prototype.vaMethod = function (retType, argTypes) {
  var offset = callMethodOffset[retType];

  if (offset === undefined) {
    throw new Error('Unsupported type: ' + retType);
  }

  return vaMethod.call(this, offset, retType, argTypes);
};

Env.prototype.nonvirtualVaMethod = function (retType, argTypes) {
  var offset = callNonvirtualMethodOffset[retType];

  if (offset === undefined) {
    throw new Error('Unsupported type: ' + retType);
  }

  return nonvirtualVaMethod.call(this, offset, retType, argTypes);
};

Env.prototype.staticVaMethod = function (retType, argTypes) {
  var offset = callStaticMethodOffset[retType];

  if (offset === undefined) {
    throw new Error('Unsupported type: ' + retType);
  }

  return vaMethod.call(this, offset, retType, argTypes);
};

Env.prototype.getField = function (fieldType) {
  var offset = getFieldOffset[fieldType];

  if (offset === undefined) {
    throw new Error('Unsupported type: ' + fieldType);
  }

  return plainMethod.call(this, offset, fieldType, []);
};

Env.prototype.getStaticField = function (fieldType) {
  var offset = getStaticFieldOffset[fieldType];

  if (offset === undefined) {
    throw new Error('Unsupported type: ' + fieldType);
  }

  return plainMethod.call(this, offset, fieldType, []);
};

Env.prototype.setField = function (fieldType) {
  var offset = setFieldOffset[fieldType];

  if (offset === undefined) {
    throw new Error('Unsupported type: ' + fieldType);
  }

  return plainMethod.call(this, offset, 'void', [fieldType]);
};

Env.prototype.setStaticField = function (fieldType) {
  var offset = setStaticFieldOffset[fieldType];

  if (offset === undefined) {
    throw new Error('Unsupported type: ' + fieldType);
  }

  return plainMethod.call(this, offset, 'void', [fieldType]);
};

var javaLangClass = null;

Env.prototype.javaLangClass = function () {
  if (javaLangClass === null) {
    var handle = this.findClass('java/lang/Class');

    try {
      javaLangClass = {
        handle: register(this.newGlobalRef(handle)),
        getName: this.getMethodId(handle, 'getName', '()Ljava/lang/String;'),
        getSimpleName: this.getMethodId(handle, 'getSimpleName', '()Ljava/lang/String;'),
        getGenericSuperclass: this.getMethodId(handle, 'getGenericSuperclass', '()Ljava/lang/reflect/Type;'),
        getDeclaredConstructors: this.getMethodId(handle, 'getDeclaredConstructors', '()[Ljava/lang/reflect/Constructor;'),
        getDeclaredMethods: this.getMethodId(handle, 'getDeclaredMethods', '()[Ljava/lang/reflect/Method;'),
        getDeclaredFields: this.getMethodId(handle, 'getDeclaredFields', '()[Ljava/lang/reflect/Field;'),
        isArray: this.getMethodId(handle, 'isArray', '()Z'),
        isPrimitive: this.getMethodId(handle, 'isPrimitive', '()Z'),
        getComponentType: this.getMethodId(handle, 'getComponentType', '()Ljava/lang/Class;')
      };
    } finally {
      this.deleteLocalRef(handle);
    }
  }

  return javaLangClass;
};

var javaLangObject = null;

Env.prototype.javaLangObject = function () {
  if (javaLangObject === null) {
    var handle = this.findClass('java/lang/Object');

    try {
      javaLangObject = {
        toString: this.getMethodId(handle, 'toString', '()Ljava/lang/String;'),
        getClass: this.getMethodId(handle, 'getClass', '()Ljava/lang/Class;')
      };
    } finally {
      this.deleteLocalRef(handle);
    }
  }

  return javaLangObject;
};

var javaLangReflectConstructor = null;

Env.prototype.javaLangReflectConstructor = function () {
  if (javaLangReflectConstructor === null) {
    var handle = this.findClass('java/lang/reflect/Constructor');

    try {
      javaLangReflectConstructor = {
        getGenericParameterTypes: this.getMethodId(handle, 'getGenericParameterTypes', '()[Ljava/lang/reflect/Type;')
      };
    } finally {
      this.deleteLocalRef(handle);
    }
  }

  return javaLangReflectConstructor;
};

var javaLangReflectMethod = null;

Env.prototype.javaLangReflectMethod = function () {
  if (javaLangReflectMethod === null) {
    var handle = this.findClass('java/lang/reflect/Method');

    try {
      javaLangReflectMethod = {
        getName: this.getMethodId(handle, 'getName', '()Ljava/lang/String;'),
        getGenericParameterTypes: this.getMethodId(handle, 'getGenericParameterTypes', '()[Ljava/lang/reflect/Type;'),
        getParameterTypes: this.getMethodId(handle, 'getParameterTypes', '()[Ljava/lang/Class;'),
        getGenericReturnType: this.getMethodId(handle, 'getGenericReturnType', '()Ljava/lang/reflect/Type;'),
        getGenericExceptionTypes: this.getMethodId(handle, 'getGenericExceptionTypes', '()[Ljava/lang/reflect/Type;'),
        getModifiers: this.getMethodId(handle, 'getModifiers', '()I'),
        isVarArgs: this.getMethodId(handle, 'isVarArgs', '()Z')
      };
    } finally {
      this.deleteLocalRef(handle);
    }
  }

  return javaLangReflectMethod;
};

var javaLangReflectField = null;

Env.prototype.javaLangReflectField = function () {
  if (javaLangReflectField === null) {
    var handle = this.findClass('java/lang/reflect/Field');

    try {
      javaLangReflectField = {
        getName: this.getMethodId(handle, 'getName', '()Ljava/lang/String;'),
        getType: this.getMethodId(handle, 'getType', '()Ljava/lang/Class;'),
        getGenericType: this.getMethodId(handle, 'getGenericType', '()Ljava/lang/reflect/Type;'),
        getModifiers: this.getMethodId(handle, 'getModifiers', '()I'),
        toString: this.getMethodId(handle, 'toString', '()Ljava/lang/String;')
      };
    } finally {
      this.deleteLocalRef(handle);
    }
  }

  return javaLangReflectField;
};

var javaLangReflectModifier = null;

Env.prototype.javaLangReflectModifier = function () {
  if (javaLangReflectModifier === null) {
    var handle = this.findClass('java/lang/reflect/Modifier');

    try {
      javaLangReflectModifier = {
        PUBLIC: this.getStaticIntField(handle, this.getStaticFieldId(handle, 'PUBLIC', 'I')),
        PRIVATE: this.getStaticIntField(handle, this.getStaticFieldId(handle, 'PRIVATE', 'I')),
        PROTECTED: this.getStaticIntField(handle, this.getStaticFieldId(handle, 'PROTECTED', 'I')),
        STATIC: this.getStaticIntField(handle, this.getStaticFieldId(handle, 'STATIC', 'I')),
        FINAL: this.getStaticIntField(handle, this.getStaticFieldId(handle, 'FINAL', 'I')),
        SYNCHRONIZED: this.getStaticIntField(handle, this.getStaticFieldId(handle, 'SYNCHRONIZED', 'I')),
        VOLATILE: this.getStaticIntField(handle, this.getStaticFieldId(handle, 'VOLATILE', 'I')),
        TRANSIENT: this.getStaticIntField(handle, this.getStaticFieldId(handle, 'TRANSIENT', 'I')),
        NATIVE: this.getStaticIntField(handle, this.getStaticFieldId(handle, 'NATIVE', 'I')),
        INTERFACE: this.getStaticIntField(handle, this.getStaticFieldId(handle, 'INTERFACE', 'I')),
        ABSTRACT: this.getStaticIntField(handle, this.getStaticFieldId(handle, 'ABSTRACT', 'I')),
        STRICT: this.getStaticIntField(handle, this.getStaticFieldId(handle, 'STRICT', 'I'))
      };
    } finally {
      this.deleteLocalRef(handle);
    }
  }

  return javaLangReflectModifier;
};

var javaLangReflectTypeVariable = null;

Env.prototype.javaLangReflectTypeVariable = function () {
  if (javaLangReflectTypeVariable === null) {
    var handle = this.findClass('java/lang/reflect/TypeVariable');

    try {
      javaLangReflectTypeVariable = {
        handle: register(this.newGlobalRef(handle)),
        getName: this.getMethodId(handle, 'getName', '()Ljava/lang/String;'),
        getBounds: this.getMethodId(handle, 'getBounds', '()[Ljava/lang/reflect/Type;'),
        getGenericDeclaration: this.getMethodId(handle, 'getGenericDeclaration', '()Ljava/lang/reflect/GenericDeclaration;')
      };
    } finally {
      this.deleteLocalRef(handle);
    }
  }

  return javaLangReflectTypeVariable;
};

var javaLangReflectWildcardType = null;

Env.prototype.javaLangReflectWildcardType = function () {
  if (javaLangReflectWildcardType === null) {
    var handle = this.findClass('java/lang/reflect/WildcardType');

    try {
      javaLangReflectWildcardType = {
        handle: register(this.newGlobalRef(handle)),
        getLowerBounds: this.getMethodId(handle, 'getLowerBounds', '()[Ljava/lang/reflect/Type;'),
        getUpperBounds: this.getMethodId(handle, 'getUpperBounds', '()[Ljava/lang/reflect/Type;')
      };
    } finally {
      this.deleteLocalRef(handle);
    }
  }

  return javaLangReflectWildcardType;
};

var javaLangReflectGenericArrayType = null;

Env.prototype.javaLangReflectGenericArrayType = function () {
  if (javaLangReflectGenericArrayType === null) {
    var handle = this.findClass('java/lang/reflect/GenericArrayType');

    try {
      javaLangReflectGenericArrayType = {
        handle: register(this.newGlobalRef(handle)),
        getGenericComponentType: this.getMethodId(handle, 'getGenericComponentType', '()Ljava/lang/reflect/Type;')
      };
    } finally {
      this.deleteLocalRef(handle);
    }
  }

  return javaLangReflectGenericArrayType;
};

var javaLangReflectParameterizedType = null;

Env.prototype.javaLangReflectParameterizedType = function () {
  if (javaLangReflectParameterizedType === null) {
    var handle = this.findClass('java/lang/reflect/ParameterizedType');

    try {
      javaLangReflectParameterizedType = {
        handle: register(this.newGlobalRef(handle)),
        getActualTypeArguments: this.getMethodId(handle, 'getActualTypeArguments', '()[Ljava/lang/reflect/Type;'),
        getRawType: this.getMethodId(handle, 'getRawType', '()Ljava/lang/reflect/Type;'),
        getOwnerType: this.getMethodId(handle, 'getOwnerType', '()Ljava/lang/reflect/Type;')
      };
    } finally {
      this.deleteLocalRef(handle);
    }
  }

  return javaLangReflectParameterizedType;
};

var javaLangString = null;

Env.prototype.javaLangString = function () {
  if (javaLangString === null) {
    var handle = this.findClass('java/lang/String');

    try {
      javaLangString = {
        handle: register(this.newGlobalRef(handle))
      };
    } finally {
      this.deleteLocalRef(handle);
    }
  }

  return javaLangString;
};

Env.prototype.getClassName = function (classHandle) {
  var name = this.vaMethod('pointer', [])(this.handle, classHandle, this.javaLangClass().getName);

  try {
    return this.stringFromJni(name);
  } finally {
    this.deleteLocalRef(name);
  }
};

Env.prototype.getObjectClassName = function (objHandle) {
  var jklass = this.getObjectClass(objHandle);

  try {
    return this.getClassName(jklass);
  } finally {
    this.deleteLocalRef(jklass);
  }
};

Env.prototype.getActualTypeArgument = function (type) {
  var actualTypeArguments = this.vaMethod('pointer', [])(this.handle, type, this.javaLangReflectParameterizedType().getActualTypeArguments);
  this.checkForExceptionAndThrowIt();

  if (!actualTypeArguments.isNull()) {
    try {
      return this.getTypeNameFromFirstTypeElement(actualTypeArguments);
    } finally {
      this.deleteLocalRef(actualTypeArguments);
    }
  }
};

Env.prototype.getTypeNameFromFirstTypeElement = function (typeArray) {
  var length = this.getArrayLength(typeArray);

  if (length > 0) {
    var typeArgument0 = this.getObjectArrayElement(typeArray, 0);

    try {
      return this.getTypeName(typeArgument0);
    } finally {
      this.deleteLocalRef(typeArgument0);
    }
  } else {
    // TODO
    return 'java.lang.Object';
  }
};

Env.prototype.getTypeName = function (type, getGenericsInformation) {
  var invokeObjectMethodNoArgs = this.vaMethod('pointer', []);

  if (this.isInstanceOf(type, this.javaLangClass().handle)) {
    return this.getClassName(type);
  } else if (this.isInstanceOf(type, this.javaLangReflectParameterizedType().handle)) {
    var rawType = invokeObjectMethodNoArgs(this.handle, type, this.javaLangReflectParameterizedType().getRawType);
    this.checkForExceptionAndThrowIt();
    var result;

    try {
      result = this.getTypeName(rawType);
    } finally {
      this.deleteLocalRef(rawType);
    }

    if (result === 'java.lang.Class' && !getGenericsInformation) {
      return this.getActualTypeArgument(type);
    }

    if (getGenericsInformation) {
      result += '<' + this.getActualTypeArgument(type) + '>';
    }

    return result;
  } else if (this.isInstanceOf(type, this.javaLangReflectTypeVariable().handle)) {
    // TODO
    return 'java.lang.Object';
  } else if (this.isInstanceOf(type, this.javaLangReflectWildcardType().handle)) {
    // TODO
    return 'java.lang.Object';
  } else {
    return 'java.lang.Object';
  }
};

Env.prototype.getArrayTypeName = function (type) {
  var invokeObjectMethodNoArgs = this.vaMethod('pointer', []);

  if (this.isInstanceOf(type, this.javaLangClass().handle)) {
    return this.getClassName(type);
  } else if (this.isInstanceOf(type, this.javaLangReflectGenericArrayType().handle)) {
    var componentType = invokeObjectMethodNoArgs(this.handle, type, this.javaLangReflectGenericArrayType().getGenericComponentType); // check for TypeNotPresentException and MalformedParameterizedTypeException

    this.checkForExceptionAndThrowIt();

    try {
      return '[L' + this.getTypeName(componentType) + ';';
    } finally {
      this.deleteLocalRef(componentType);
    }
  } else {
    return '[Ljava.lang.Object;';
  }
};

Env.prototype.stringFromJni = function (str) {
  var utf = this.getStringUtfChars(str);

  if (utf.isNull()) {
    throw new Error("Can't access the string.");
  }

  try {
    return Memory.readUtf8String(utf);
  } finally {
    this.releaseStringUtfChars(str, utf);
  }
};

module.exports = Env;
/* global Memory, NativeFunction, NULL, Process, WeakRef */

},{}],153:[function(require,module,exports){
(function (Buffer){
'use strict';

var _interopRequireDefault = require("@babel/runtime-corejs2/helpers/interopRequireDefault");

var _keys = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/object/keys"));

var _from = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/array/from"));

var _set = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/set"));

var _assign = _interopRequireDefault(require("@babel/runtime-corejs2/core-js/object/assign"));

module.exports = mkdex;

var SHA1 = require('jssha/src/sha1');

var kAccPublic = 0x0001;
var kAccNative = 0x0100;
var kAccConstructor = 0x00010000;
var kEndianTag = 0x12345678;
var kClassDefSize = 32;
var kProtoIdSize = 12;
var kMethodIdSize = 8;
var kTypeIdSize = 4;
var kStringIdSize = 4;
var kMapItemSize = 12;
var TYPE_HEADER_ITEM = 0;
var TYPE_STRING_ID_ITEM = 1;
var TYPE_TYPE_ID_ITEM = 2;
var TYPE_PROTO_ID_ITEM = 3;
var TYPE_METHOD_ID_ITEM = 5;
var TYPE_CLASS_DEF_ITEM = 6;
var TYPE_MAP_LIST = 0x1000;
var TYPE_TYPE_LIST = 0x1001;
var TYPE_ANNOTATION_SET_ITEM = 0x1003;
var TYPE_CLASS_DATA_ITEM = 0x2000;
var TYPE_CODE_ITEM = 0x2001;
var TYPE_STRING_DATA_ITEM = 0x2002;
var TYPE_DEBUG_INFO_ITEM = 0x2003;
var TYPE_ANNOTATION_ITEM = 0x2004;
var TYPE_ANNOTATIONS_DIRECTORY_ITEM = 0x2006;
var VALUE_TYPE = 0x18;
var VALUE_ARRAY = 0x1c;
var VISIBILITY_SYSTEM = 2;
var kDefaultConstructorSize = 24;
var kDefaultConstructorDebugInfo = Buffer.from([0x03, 0x00, 0x07, 0x0e, 0x00]);
var kDalvikAnnotationTypeThrows = 'Ldalvik/annotation/Throws;';
var kNullTerminator = Buffer.from([0]);

function mkdex(spec) {
  var builder = new DexBuilder();
  var fullSpec = (0, _assign["default"])({}, spec);
  fullSpec.methods.splice(0, 0, ['<init>', 'V', []]);
  builder.addClass(fullSpec);
  return builder.build();
}

var DexBuilder =
/*#__PURE__*/
function () {
  function DexBuilder() {
    this.classes = [];
  }

  var _proto = DexBuilder.prototype;

  _proto.addClass = function addClass(spec) {
    this.classes.push(spec);
  };

  _proto.build = function build() {
    var model = computeModel(this.classes);
    var classes = model.classes,
        interfaces = model.interfaces,
        methods = model.methods,
        protos = model.protos,
        parameters = model.parameters,
        annotationDirectories = model.annotationDirectories,
        annotationSets = model.annotationSets,
        throwsAnnotations = model.throwsAnnotations,
        types = model.types,
        strings = model.strings;
    var offset = 0;
    var headerOffset = 0;
    var checksumOffset = 8;
    var signatureOffset = 12;
    var signatureSize = 20;
    var headerSize = 0x70;
    offset += headerSize;
    var stringIdsOffset = offset;
    var stringIdsSize = strings.length * kStringIdSize;
    offset += stringIdsSize;
    var typeIdsOffset = offset;
    var typeIdsSize = types.length * kTypeIdSize;
    offset += typeIdsSize;
    var protoIdsOffset = offset;
    var protoIdsSize = protos.length * kProtoIdSize;
    offset += protoIdsSize;
    var fieldIdsOffset = 0;
    var fieldIdsCount = 0;
    var methodIdsOffset = offset;
    var methodIdsSize = methods.length * kMethodIdSize;
    offset += methodIdsSize;
    var classDefsOffset = offset;
    var classDefsSize = classes.length * kClassDefSize;
    offset += classDefsSize;
    var dataOffset = offset;
    var annotationSetOffsets = annotationSets.map(function (set) {
      var setOffset = offset;
      set.offset = setOffset;
      offset += 4 + set.items.length * 4;
      return setOffset;
    });
    var constructorOffsets = classes.map(function (klass) {
      var ctorOffset = offset;
      offset += kDefaultConstructorSize;
      return ctorOffset;
    });
    annotationDirectories.forEach(function (dir) {
      dir.offset = offset;
      offset += 16 + dir.methods.length * 8;
    });
    var interfaceOffsets = interfaces.map(function (iface) {
      offset = align(offset, 4);
      var ifaceOffset = offset;
      iface.offset = ifaceOffset;
      offset += 4 + 2 * iface.types.length;
      return ifaceOffset;
    });
    var parameterOffsets = parameters.map(function (param) {
      offset = align(offset, 4);
      var paramOffset = offset;
      param.offset = paramOffset;
      offset += 4 + 2 * param.types.length;
      return paramOffset;
    });
    var stringChunks = [];
    var stringOffsets = strings.map(function (str) {
      var strOffset = offset;
      var header = Buffer.from(createUleb128(str.length));
      var data = Buffer.from(str, 'utf8');
      var chunk = Buffer.concat([header, data, kNullTerminator]);
      stringChunks.push(chunk);
      offset += chunk.length;
      return strOffset;
    });
    var debugInfoOffsets = classes.map(function (klass) {
      var debugOffset = offset;
      offset += kDefaultConstructorDebugInfo.length;
      return debugOffset;
    });
    var throwsAnnotationBlobs = throwsAnnotations.map(function (annotation) {
      var blob = makeThrowsAnnotation(annotation);
      annotation.offset = offset;
      offset += blob.length;
      return blob;
    });
    var classDataBlobs = classes.map(function (klass, index) {
      klass.classData.offset = offset;
      var blob = makeClassData(klass, constructorOffsets[index]);
      offset += blob.length;
      return blob;
    });
    var linkSize = 0;
    var linkOffset = 0;
    offset = align(offset, 4);
    var mapOffset = offset;
    var typeListLength = interfaces.length + parameters.length;
    var mapNumItems = 8 + 3 * classes.length + (typeListLength > 0 ? 1 : 0) + annotationDirectories.length + annotationSets.length + throwsAnnotations.length;
    var mapSize = 4 + mapNumItems * kMapItemSize;
    offset += mapSize;
    var dataSize = offset - dataOffset;
    var fileSize = offset;
    var dex = Buffer.alloc(fileSize);
    dex.write('dex\n035');
    dex.writeUInt32LE(fileSize, 0x20);
    dex.writeUInt32LE(headerSize, 0x24);
    dex.writeUInt32LE(kEndianTag, 0x28);
    dex.writeUInt32LE(linkSize, 0x2c);
    dex.writeUInt32LE(linkOffset, 0x30);
    dex.writeUInt32LE(mapOffset, 0x34);
    dex.writeUInt32LE(strings.length, 0x38);
    dex.writeUInt32LE(stringIdsOffset, 0x3c);
    dex.writeUInt32LE(types.length, 0x40);
    dex.writeUInt32LE(typeIdsOffset, 0x44);
    dex.writeUInt32LE(protos.length, 0x48);
    dex.writeUInt32LE(protoIdsOffset, 0x4c);
    dex.writeUInt32LE(fieldIdsCount, 0x50);
    dex.writeUInt32LE(fieldIdsOffset, 0x54);
    dex.writeUInt32LE(methods.length, 0x58);
    dex.writeUInt32LE(methodIdsOffset, 0x5c);
    dex.writeUInt32LE(classes.length, 0x60);
    dex.writeUInt32LE(classDefsOffset, 0x64);
    dex.writeUInt32LE(dataSize, 0x68);
    dex.writeUInt32LE(dataOffset, 0x6c);
    stringOffsets.forEach(function (offset, index) {
      dex.writeUInt32LE(offset, stringIdsOffset + index * kStringIdSize);
    });
    types.forEach(function (id, index) {
      dex.writeUInt32LE(id, typeIdsOffset + index * kTypeIdSize);
    });
    protos.forEach(function (proto, index) {
      var shortyIndex = proto[0],
          returnTypeIndex = proto[1],
          params = proto[2];
      var protoOffset = protoIdsOffset + index * kProtoIdSize;
      dex.writeUInt32LE(shortyIndex, protoOffset);
      dex.writeUInt32LE(returnTypeIndex, protoOffset + 4);
      dex.writeUInt32LE(params !== null ? params.offset : 0, protoOffset + 8);
    });
    methods.forEach(function (method, index) {
      var classIndex = method[0],
          protoIndex = method[1],
          nameIndex = method[2];
      var methodOffset = methodIdsOffset + index * kMethodIdSize;
      dex.writeUInt16LE(classIndex, methodOffset);
      dex.writeUInt16LE(protoIndex, methodOffset + 2);
      dex.writeUInt32LE(nameIndex, methodOffset + 4);
    });
    classes.forEach(function (klass, index) {
      var interfaces = klass.interfaces,
          annotationsDirectory = klass.annotationsDirectory;
      var interfacesOffset = interfaces !== null ? interfaces.offset : 0;
      var annotationsOffset = annotationsDirectory !== null ? annotationsDirectory.offset : 0;
      var staticValuesOffset = 0;
      var classOffset = classDefsOffset + index * kClassDefSize;
      dex.writeUInt32LE(klass.index, classOffset);
      dex.writeUInt32LE(klass.accessFlags, classOffset + 4);
      dex.writeUInt32LE(klass.superClassIndex, classOffset + 8);
      dex.writeUInt32LE(interfacesOffset, classOffset + 12);
      dex.writeUInt32LE(klass.sourceFileIndex, classOffset + 16);
      dex.writeUInt32LE(annotationsOffset, classOffset + 20);
      dex.writeUInt32LE(klass.classData.offset, classOffset + 24);
      dex.writeUInt32LE(staticValuesOffset, classOffset + 28);
    });
    annotationSets.forEach(function (set, index) {
      var items = set.items;
      var setOffset = annotationSetOffsets[index];
      dex.writeUInt32LE(items.length, setOffset);
      items.forEach(function (item, index) {
        dex.writeUInt32LE(item.offset, setOffset + 4 + index * 4);
      });
    });
    constructorOffsets.forEach(function (constructorOffset, index) {
      var _classes$index$classD = classes[index].classData.superConstructorMethod,
          superConstructor = _classes$index$classD[0];
      var registersSize = 1;
      var insSize = 1;
      var outsSize = 1;
      var triesSize = 0;
      var insnsSize = 4;
      dex.writeUInt16LE(registersSize, constructorOffset);
      dex.writeUInt16LE(insSize, constructorOffset + 2);
      dex.writeUInt16LE(outsSize, constructorOffset + 4);
      dex.writeUInt16LE(triesSize, constructorOffset + 6);
      dex.writeUInt32LE(debugInfoOffsets[index], constructorOffset + 8);
      dex.writeUInt32LE(insnsSize, constructorOffset + 12);
      dex.writeUInt16LE(0x1070, constructorOffset + 16);
      dex.writeUInt16LE(superConstructor, constructorOffset + 18);
      dex.writeUInt16LE(0x0000, constructorOffset + 20);
      dex.writeUInt16LE(0x000e, constructorOffset + 22);
    });
    annotationDirectories.forEach(function (dir) {
      var dirOffset = dir.offset;
      var classAnnotationsOffset = 0;
      var fieldsSize = 0;
      var annotatedMethodsSize = dir.methods.length;
      var annotatedParametersSize = 0;
      dex.writeUInt32LE(classAnnotationsOffset, dirOffset);
      dex.writeUInt32LE(fieldsSize, dirOffset + 4);
      dex.writeUInt32LE(annotatedMethodsSize, dirOffset + 8);
      dex.writeUInt32LE(annotatedParametersSize, dirOffset + 12);
      dir.methods.forEach(function (method, index) {
        var entryOffset = dirOffset + 16 + index * 8;
        var methodIndex = method[0],
            annotationSet = method[1];
        dex.writeUInt32LE(methodIndex, entryOffset);
        dex.writeUInt32LE(annotationSet.offset, entryOffset + 4);
      });
    });
    interfaces.forEach(function (iface, index) {
      var ifaceOffset = interfaceOffsets[index];
      dex.writeUInt32LE(iface.types.length, ifaceOffset);
      iface.types.forEach(function (type, typeIndex) {
        dex.writeUInt16LE(type, ifaceOffset + 4 + typeIndex * 2);
      });
    });
    parameters.forEach(function (param, index) {
      var paramOffset = parameterOffsets[index];
      dex.writeUInt32LE(param.types.length, paramOffset);
      param.types.forEach(function (type, typeIndex) {
        dex.writeUInt16LE(type, paramOffset + 4 + typeIndex * 2);
      });
    });
    stringChunks.forEach(function (chunk, index) {
      chunk.copy(dex, stringOffsets[index]);
    });
    debugInfoOffsets.forEach(function (debugInfoOffset) {
      kDefaultConstructorDebugInfo.copy(dex, debugInfoOffset);
    });
    throwsAnnotationBlobs.forEach(function (annotationBlob, index) {
      annotationBlob.copy(dex, throwsAnnotations[index].offset);
    });
    classDataBlobs.forEach(function (classDataBlob, index) {
      classDataBlob.copy(dex, classes[index].classData.offset);
    });
    dex.writeUInt32LE(mapNumItems, mapOffset);
    var mapItems = [[TYPE_HEADER_ITEM, 1, headerOffset], [TYPE_STRING_ID_ITEM, strings.length, stringIdsOffset], [TYPE_TYPE_ID_ITEM, types.length, typeIdsOffset], [TYPE_PROTO_ID_ITEM, protos.length, protoIdsOffset], [TYPE_METHOD_ID_ITEM, methods.length, methodIdsOffset], [TYPE_CLASS_DEF_ITEM, classes.length, classDefsOffset]];
    annotationSets.forEach(function (set, index) {
      mapItems.push([TYPE_ANNOTATION_SET_ITEM, set.items.length, annotationSetOffsets[index]]);
    });
    classes.forEach(function (klass, index) {
      mapItems.push([TYPE_CODE_ITEM, 1, constructorOffsets[index]]);
    });
    annotationDirectories.forEach(function (dir) {
      mapItems.push([TYPE_ANNOTATIONS_DIRECTORY_ITEM, 1, dir.offset]);
    });

    if (typeListLength > 0) {
      mapItems.push([TYPE_TYPE_LIST, typeListLength, interfaceOffsets.concat(parameterOffsets)[0]]);
    }

    mapItems.push([TYPE_STRING_DATA_ITEM, strings.length, stringOffsets[0]]);
    debugInfoOffsets.forEach(function (debugInfoOffset) {
      mapItems.push([TYPE_DEBUG_INFO_ITEM, 1, debugInfoOffset]);
    });
    throwsAnnotations.forEach(function (annotation) {
      mapItems.push([TYPE_ANNOTATION_ITEM, 1, annotation.offset]);
    });
    classes.forEach(function (klass) {
      mapItems.push([TYPE_CLASS_DATA_ITEM, 1, klass.classData.offset]);
    });
    mapItems.push([TYPE_MAP_LIST, 1, mapOffset]);
    mapItems.forEach(function (item, index) {
      var type = item[0],
          size = item[1],
          offset = item[2];
      var itemOffset = mapOffset + 4 + index * kMapItemSize;
      dex.writeUInt16LE(type, itemOffset);
      dex.writeUInt32LE(size, itemOffset + 4);
      dex.writeUInt32LE(offset, itemOffset + 8);
    });
    var hash = new SHA1('SHA-1', 'ARRAYBUFFER');
    hash.update(dex.slice(signatureOffset + signatureSize));
    Buffer.from(hash.getHash('ARRAYBUFFER')).copy(dex, signatureOffset);
    dex.writeUInt32LE(adler32(dex, signatureOffset), checksumOffset);
    return dex;
  };

  return DexBuilder;
}();

function makeClassData(klass, constructorCodeOffset) {
  var _klass$classData = klass.classData,
      constructorMethod = _klass$classData.constructorMethod,
      virtualMethods = _klass$classData.virtualMethods;
  var staticFieldsSize = 0;
  var instanceFieldsSize = 0;
  var directMethodsSize = 1;
  var constructorIndex = constructorMethod[0],
      constructorAccessFlags = constructorMethod[1];
  return Buffer.from([staticFieldsSize, instanceFieldsSize, directMethodsSize].concat(createUleb128(virtualMethods.length)).concat(createUleb128(constructorIndex)).concat(createUleb128(constructorAccessFlags)).concat(createUleb128(constructorCodeOffset)).concat(virtualMethods.reduce(function (result, _ref) {
    var indexDiff = _ref[0],
        accessFlags = _ref[1];
    var codeOffset = 0;
    return result.concat(createUleb128(indexDiff)).concat(createUleb128(accessFlags)).concat([codeOffset]);
  }, [])));
}

function makeThrowsAnnotation(annotation) {
  var thrownTypes = annotation.thrownTypes;
  return Buffer.from([VISIBILITY_SYSTEM].concat(createUleb128(annotation.type)).concat([1]).concat(createUleb128(annotation.value)).concat([VALUE_ARRAY, thrownTypes.length]).concat(thrownTypes.reduce(function (result, type) {
    result.push(VALUE_TYPE, type);
    return result;
  }, [])));
}

function computeModel(classes) {
  var strings = new _set["default"]();
  var types = new _set["default"]();
  var protos = {};
  var methods = [];
  var throwsAnnotations = {};
  var superConstructors = new _set["default"]();
  classes.forEach(function (klass) {
    var name = klass.name,
        superClass = klass.superClass,
        sourceFileName = klass.sourceFileName;
    strings.add('this');
    strings.add(name);
    types.add(name);
    strings.add(superClass);
    types.add(superClass);
    strings.add(sourceFileName);
    klass.interfaces.forEach(function (iface) {
      strings.add(iface);
      types.add(iface);
    });
    klass.methods.forEach(function (method) {
      var methodName = method[0],
          retType = method[1],
          argTypes = method[2],
          _method$ = method[3],
          thrownTypes = _method$ === void 0 ? [] : _method$;
      strings.add(methodName);
      var protoId = addProto(retType, argTypes);
      var throwsAnnotationId = null;

      if (thrownTypes.length > 0) {
        var typesNormalized = thrownTypes.slice();
        typesNormalized.sort();
        throwsAnnotationId = typesNormalized.join('|');
        var throwsAnnotation = throwsAnnotations[throwsAnnotationId];

        if (throwsAnnotation === undefined) {
          throwsAnnotation = {
            id: throwsAnnotationId,
            types: typesNormalized
          };
          throwsAnnotations[throwsAnnotationId] = throwsAnnotation;
        }

        strings.add(kDalvikAnnotationTypeThrows);
        types.add(kDalvikAnnotationTypeThrows);
        thrownTypes.forEach(function (type) {
          strings.add(type);
          types.add(type);
        });
        strings.add('value');
      }

      methods.push([klass.name, protoId, methodName, throwsAnnotationId]);

      if (methodName === '<init>') {
        var superConstructorId = superClass + '|' + protoId;

        if (!superConstructors.has(superConstructorId)) {
          methods.push([superClass, protoId, methodName, null]);
          superConstructors.add(superConstructorId);
        }
      }
    });
  });

  function addProto(retType, argTypes) {
    var signature = [retType].concat(argTypes);
    var id = signature.join('|');

    if (protos[id] !== undefined) {
      return id;
    }

    strings.add(retType);
    types.add(retType);
    argTypes.forEach(function (argType) {
      strings.add(argType);
      types.add(argType);
    });
    var shorty = signature.map(typeToShorty).join('');
    strings.add(shorty);
    protos[id] = [id, shorty, retType, argTypes];
    return id;
  }

  var stringItems = (0, _from["default"])(strings);
  stringItems.sort();
  var stringToIndex = stringItems.reduce(function (result, string, index) {
    result[string] = index;
    return result;
  }, {});
  var typeItems = (0, _from["default"])(types).map(function (name) {
    return stringToIndex[name];
  });
  typeItems.sort(compareNumbers);
  var typeToIndex = typeItems.reduce(function (result, stringIndex, typeIndex) {
    result[stringItems[stringIndex]] = typeIndex;
    return result;
  }, {});
  var literalProtoItems = (0, _keys["default"])(protos).map(function (id) {
    return protos[id];
  });
  literalProtoItems.sort(compareProtoItems);
  var parameters = {};
  var protoItems = literalProtoItems.map(function (item) {
    var shorty = item[1],
        retType = item[2],
        argTypes = item[3];
    var params;

    if (argTypes.length > 0) {
      var argTypesSig = argTypes.join('|');
      params = parameters[argTypesSig];

      if (params === undefined) {
        params = {
          types: argTypes.map(function (type) {
            return typeToIndex[type];
          }),
          offset: -1
        };
        parameters[argTypesSig] = params;
      }
    } else {
      params = null;
    }

    return [stringToIndex[shorty], typeToIndex[retType], params];
  });
  var protoToIndex = literalProtoItems.reduce(function (result, item, index) {
    var id = item[0];
    result[id] = index;
    return result;
  }, {});
  var parameterItems = (0, _keys["default"])(parameters).map(function (id) {
    return parameters[id];
  });
  var methodItems = methods.map(function (method) {
    var klass = method[0],
        protoId = method[1],
        name = method[2],
        annotationsId = method[3];
    return [typeToIndex[klass], protoToIndex[protoId], stringToIndex[name], annotationsId];
  });
  methodItems.sort(compareMethodItems);
  var throwsAnnotationItems = (0, _keys["default"])(throwsAnnotations).map(function (id) {
    return throwsAnnotations[id];
  }).map(function (item) {
    var id = item.id,
        types = item.types;
    return {
      id: item.id,
      type: typeToIndex[kDalvikAnnotationTypeThrows],
      value: stringToIndex['value'],
      thrownTypes: item.types.map(function (type) {
        return typeToIndex[type];
      }),
      offset: -1
    };
  });
  var annotationSetItems = throwsAnnotationItems.map(function (item) {
    return {
      id: item.id,
      items: [item],
      offset: -1
    };
  });
  var annotationSetIdToIndex = annotationSetItems.reduce(function (result, item, index) {
    result[item.id] = index;
    return result;
  }, {});
  var interfaceLists = {};
  var annotationDirectories = [];
  var classItems = classes.map(function (klass) {
    var classIndex = typeToIndex[klass.name];
    var accessFlags = kAccPublic;
    var superClassIndex = typeToIndex[klass.superClass];
    var ifaceList;
    var ifaces = klass.interfaces.map(function (type) {
      return typeToIndex[type];
    });

    if (ifaces.length > 0) {
      ifaces.sort(compareNumbers);
      var ifacesId = ifaces.join('|');
      ifaceList = interfaceLists[ifacesId];

      if (ifaceList === undefined) {
        ifaceList = {
          types: ifaces,
          offset: -1
        };
        interfaceLists[ifacesId] = ifaceList;
      }
    } else {
      ifaceList = null;
    }

    var sourceFileIndex = stringToIndex[klass.sourceFileName];
    var classMethods = methodItems.map(function (method, index) {
      return [index].concat(method);
    }).filter(function (method) {
      var holder = method[1];
      return holder === classIndex;
    }).map(function (method) {
      var index = method[0],
          name = method[3],
          annotationsId = method[4];
      return [index, name, annotationsId];
    });
    var annotationsDirectory = null;
    var methodAnnotations = classMethods.filter(function (_ref2) {
      var annotationsId = _ref2[2];
      return annotationsId !== null;
    }).map(function (_ref3) {
      var index = _ref3[0],
          annotationsId = _ref3[2];
      return [index, annotationSetItems[annotationSetIdToIndex[annotationsId]]];
    });

    if (methodAnnotations.length > 0) {
      annotationsDirectory = {
        methods: methodAnnotations,
        offset: -1
      };
      annotationDirectories.push(annotationsDirectory);
    }

    var constructorNameIndex = stringToIndex['<init>'];
    var constructorMethod = classMethods.filter(function (_ref4) {
      var name = _ref4[1];
      return name === constructorNameIndex;
    }).map(function (_ref5) {
      var index = _ref5[0];
      return [index, kAccPublic | kAccConstructor];
    })[0];
    var superConstructorMethod = methodItems.map(function (method, index) {
      return [index].concat(method);
    }).filter(function (method) {
      var holder = method[1],
          name = method[3];
      return holder === superClassIndex && name === constructorNameIndex;
    })[0];
    var virtualMethods = compressClassMethodIndexes(classMethods.filter(function (_ref6) {
      var name = _ref6[1];
      return name !== constructorNameIndex;
    }).map(function (_ref7) {
      var index = _ref7[0];
      return [index, kAccPublic | kAccNative];
    }));
    var classData = {
      constructorMethod: constructorMethod,
      superConstructorMethod: superConstructorMethod,
      virtualMethods: virtualMethods,
      offset: -1
    };
    return {
      index: classIndex,
      accessFlags: accessFlags,
      superClassIndex: superClassIndex,
      interfaces: ifaceList,
      sourceFileIndex: sourceFileIndex,
      annotationsDirectory: annotationsDirectory,
      classData: classData
    };
  });
  var interfaceItems = (0, _keys["default"])(interfaceLists).map(function (id) {
    return interfaceLists[id];
  });
  return {
    classes: classItems,
    interfaces: interfaceItems,
    methods: methodItems,
    protos: protoItems,
    parameters: parameterItems,
    annotationDirectories: annotationDirectories,
    annotationSets: annotationSetItems,
    throwsAnnotations: throwsAnnotationItems,
    types: typeItems,
    strings: stringItems
  };
}

function compressClassMethodIndexes(items) {
  var previousIndex = 0;
  return items.map(function (_ref8, elementIndex) {
    var index = _ref8[0],
        accessFlags = _ref8[1];
    var result;

    if (elementIndex === 0) {
      result = [index, accessFlags];
    } else {
      result = [index - previousIndex, accessFlags];
    }

    previousIndex = index;
    return result;
  });
}

function compareNumbers(a, b) {
  return a - b;
}

function compareProtoItems(a, b) {
  var aRetType = a[2],
      aArgTypes = a[3];
  var bRetType = b[2],
      bArgTypes = b[3];

  if (aRetType < bRetType) {
    return -1;
  }

  if (aRetType > bRetType) {
    return 1;
  }

  var aArgTypesSig = aArgTypes.join('|');
  var bArgTypesSig = bArgTypes.join('|');

  if (aArgTypesSig < bArgTypesSig) {
    return -1;
  }

  if (aArgTypesSig > bArgTypesSig) {
    return 1;
  }

  return 0;
}

function compareMethodItems(a, b) {
  var aClass = a[0],
      aProto = a[1],
      aName = a[2];
  var bClass = b[0],
      bProto = b[1],
      bName = b[2];

  if (aClass !== bClass) {
    return aClass - bClass;
  }

  if (aName !== bName) {
    return aName - bName;
  }

  return aProto - bProto;
}

function typeToShorty(type) {
  var firstCharacter = type[0];
  return firstCharacter === 'L' || firstCharacter === '[' ? 'L' : type;
}

function createUleb128(value) {
  if (value <= 0x7f) {
    return [value];
  }

  var result = [];
  var moreSlicesNeeded = false;

  do {
    var slice = value & 0x7f;
    value >>= 7;
    moreSlicesNeeded = value !== 0;

    if (moreSlicesNeeded) {
      slice |= 0x80;
    }

    result.push(slice);
  } while (moreSlicesNeeded);

  return result;
}

function align(value, alignment) {
  var alignmentDelta = value % alignment;

  if (alignmentDelta === 0) {
    return value;
  }

  return value + alignment - alignmentDelta;
}

function adler32(buffer, offset) {
  var a = 1;
  var b = 0;
  var length = buffer.length;

  for (var i = offset; i < length; i++) {
    a = (a + buffer[i]) % 65521;
    b = (b + a) % 65521;
  }

  return (b << 16 | a) >>> 0;
}

}).call(this,require("buffer").Buffer)

},{"@babel/runtime-corejs2/core-js/array/from":3,"@babel/runtime-corejs2/core-js/object/assign":7,"@babel/runtime-corejs2/core-js/object/keys":13,"@babel/runtime-corejs2/core-js/set":17,"@babel/runtime-corejs2/helpers/interopRequireDefault":22,"buffer":159,"jssha/src/sha1":156}],154:[function(require,module,exports){
'use strict';

var JNI_OK = 0;

function checkJniResult(name, result) {
  if (result !== JNI_OK) {
    throw new Error(name + ' failed: ' + result);
  }
}

module.exports = {
  checkJniResult: checkJniResult,
  JNI_OK: 0
};

},{}],155:[function(require,module,exports){
'use strict';

var Env = require('./env');

var _require = require('./result'),
    JNI_OK = _require.JNI_OK,
    checkJniResult = _require.checkJniResult;

var JNI_VERSION_1_6 = 0x00010006;
var pointerSize = Process.pointerSize;

function VM(api) {
  var handle = null;
  var attachCurrentThread = null;
  var detachCurrentThread = null;
  var getEnv = null;
  var attachedThreads = {};

  function initialize() {
    handle = api.vm;
    var vtable = Memory.readPointer(handle);
    var options = {
      exceptions: 'propagate'
    };
    attachCurrentThread = new NativeFunction(Memory.readPointer(vtable.add(4 * pointerSize)), 'int32', ['pointer', 'pointer', 'pointer'], options);
    detachCurrentThread = new NativeFunction(Memory.readPointer(vtable.add(5 * pointerSize)), 'int32', ['pointer'], options);
    getEnv = new NativeFunction(Memory.readPointer(vtable.add(6 * pointerSize)), 'int32', ['pointer', 'pointer', 'int32'], options);
  }

  this.perform = function (fn) {
    var threadId = null;
    var env = this.tryGetEnv();
    var alreadyAttached = env !== null;

    if (!alreadyAttached) {
      env = this.attachCurrentThread();
      threadId = Process.getCurrentThreadId();
      attachedThreads[threadId] = true;
    }

    try {
      fn();
    } finally {
      if (!alreadyAttached) {
        var allowedToDetach = attachedThreads[threadId];
        delete attachedThreads[threadId];

        if (allowedToDetach) {
          this.detachCurrentThread();
        }
      }
    }
  };

  this.attachCurrentThread = function () {
    var envBuf = Memory.alloc(pointerSize);
    checkJniResult('VM::AttachCurrentThread', attachCurrentThread(handle, envBuf, NULL));
    return new Env(Memory.readPointer(envBuf), this);
  };

  this.detachCurrentThread = function () {
    checkJniResult('VM::DetachCurrentThread', detachCurrentThread(handle));
  };

  this.preventDetachDueToClassLoader = function () {
    var threadId = Process.getCurrentThreadId();

    if (threadId in attachedThreads) {
      attachedThreads[threadId] = false;
    }
  };

  this.getEnv = function () {
    var envBuf = Memory.alloc(pointerSize);
    checkJniResult('VM::GetEnv', getEnv(handle, envBuf, JNI_VERSION_1_6));
    return new Env(Memory.readPointer(envBuf), this);
  };

  this.tryGetEnv = function () {
    var envBuf = Memory.alloc(pointerSize);
    var result = getEnv(handle, envBuf, JNI_VERSION_1_6);

    if (result !== JNI_OK) {
      return null;
    }

    return new Env(Memory.readPointer(envBuf), this);
  };

  initialize.call(this);
}

module.exports = VM;
/* global Memory, NativeFunction, NULL, Process */

},{"./env":152,"./result":154}],156:[function(require,module,exports){
/*
 A JavaScript implementation of the SHA family of hashes, as
 defined in FIPS PUB 180-4 and FIPS PUB 202, as well as the corresponding
 HMAC implementation as defined in FIPS PUB 198a

 Copyright Brian Turek 2008-2017
 Distributed under the BSD License
 See http://caligatio.github.com/jsSHA/ for more information

 Several functions taken from Paul Johnston
*/
'use strict';(function(G){function r(d,b,c){var h=0,a=[],f=0,g,m,k,e,l,p,q,t,w=!1,n=[],u=[],v,r=!1;c=c||{};g=c.encoding||"UTF8";v=c.numRounds||1;if(v!==parseInt(v,10)||1>v)throw Error("numRounds must a integer >= 1");if("SHA-1"===d)l=512,p=z,q=H,e=160,t=function(a){return a.slice()};else throw Error("Chosen SHA variant is not supported");k=A(b,g);m=x(d);this.setHMACKey=function(a,f,b){var c;if(!0===w)throw Error("HMAC key already set");if(!0===r)throw Error("Cannot set HMAC key after calling update");
g=(b||{}).encoding||"UTF8";f=A(f,g)(a);a=f.binLen;f=f.value;c=l>>>3;b=c/4-1;if(c<a/8){for(f=q(f,a,0,x(d),e);f.length<=b;)f.push(0);f[b]&=4294967040}else if(c>a/8){for(;f.length<=b;)f.push(0);f[b]&=4294967040}for(a=0;a<=b;a+=1)n[a]=f[a]^909522486,u[a]=f[a]^1549556828;m=p(n,m);h=l;w=!0};this.update=function(b){var e,g,c,d=0,q=l>>>5;e=k(b,a,f);b=e.binLen;g=e.value;e=b>>>5;for(c=0;c<e;c+=q)d+l<=b&&(m=p(g.slice(c,c+q),m),d+=l);h+=d;a=g.slice(d>>>5);f=b%l;r=!0};this.getHash=function(b,g){var c,k,l,p;if(!0===
w)throw Error("Cannot call getHash after setting HMAC key");l=B(g);switch(b){case "HEX":c=function(a){return C(a,e,l)};break;case "B64":c=function(a){return D(a,e,l)};break;case "BYTES":c=function(a){return E(a,e)};break;case "ARRAYBUFFER":try{k=new ArrayBuffer(0)}catch(I){throw Error("ARRAYBUFFER not supported by this environment");}c=function(a){return F(a,e)};break;default:throw Error("format must be HEX, B64, BYTES, or ARRAYBUFFER");}p=q(a.slice(),f,h,t(m),e);for(k=1;k<v;k+=1)p=q(p,e,0,x(d),e);
return c(p)};this.getHMAC=function(b,g){var c,k,n,r;if(!1===w)throw Error("Cannot call getHMAC without first setting HMAC key");n=B(g);switch(b){case "HEX":c=function(a){return C(a,e,n)};break;case "B64":c=function(a){return D(a,e,n)};break;case "BYTES":c=function(a){return E(a,e)};break;case "ARRAYBUFFER":try{c=new ArrayBuffer(0)}catch(I){throw Error("ARRAYBUFFER not supported by this environment");}c=function(a){return F(a,e)};break;default:throw Error("outputFormat must be HEX, B64, BYTES, or ARRAYBUFFER");
}k=q(a.slice(),f,h,t(m),e);r=p(u,x(d));r=q(k,e,l,r,e);return c(r)}}function C(d,b,c){var h="";b/=8;var a,f;for(a=0;a<b;a+=1)f=d[a>>>2]>>>8*(3+a%4*-1),h+="0123456789abcdef".charAt(f>>>4&15)+"0123456789abcdef".charAt(f&15);return c.outputUpper?h.toUpperCase():h}function D(d,b,c){var h="",a=b/8,f,g,m;for(f=0;f<a;f+=3)for(g=f+1<a?d[f+1>>>2]:0,m=f+2<a?d[f+2>>>2]:0,m=(d[f>>>2]>>>8*(3+f%4*-1)&255)<<16|(g>>>8*(3+(f+1)%4*-1)&255)<<8|m>>>8*(3+(f+2)%4*-1)&255,g=0;4>g;g+=1)8*f+6*g<=b?h+="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".charAt(m>>>
6*(3-g)&63):h+=c.b64Pad;return h}function E(d,b){var c="",h=b/8,a,f;for(a=0;a<h;a+=1)f=d[a>>>2]>>>8*(3+a%4*-1)&255,c+=String.fromCharCode(f);return c}function F(d,b){var c=b/8,h,a=new ArrayBuffer(c),f;f=new Uint8Array(a);for(h=0;h<c;h+=1)f[h]=d[h>>>2]>>>8*(3+h%4*-1)&255;return a}function B(d){var b={outputUpper:!1,b64Pad:"=",shakeLen:-1};d=d||{};b.outputUpper=d.outputUpper||!1;!0===d.hasOwnProperty("b64Pad")&&(b.b64Pad=d.b64Pad);if("boolean"!==typeof b.outputUpper)throw Error("Invalid outputUpper formatting option");
if("string"!==typeof b.b64Pad)throw Error("Invalid b64Pad formatting option");return b}function A(d,b){var c;switch(b){case "UTF8":case "UTF16BE":case "UTF16LE":break;default:throw Error("encoding must be UTF8, UTF16BE, or UTF16LE");}switch(d){case "HEX":c=function(b,a,f){var g=b.length,c,d,e,l,p;if(0!==g%2)throw Error("String of HEX type must be in byte increments");a=a||[0];f=f||0;p=f>>>3;for(c=0;c<g;c+=2){d=parseInt(b.substr(c,2),16);if(isNaN(d))throw Error("String of HEX type contains invalid characters");
l=(c>>>1)+p;for(e=l>>>2;a.length<=e;)a.push(0);a[e]|=d<<8*(3+l%4*-1)}return{value:a,binLen:4*g+f}};break;case "TEXT":c=function(c,a,f){var g,d,k=0,e,l,p,q,t,n;a=a||[0];f=f||0;p=f>>>3;if("UTF8"===b)for(n=3,e=0;e<c.length;e+=1)for(g=c.charCodeAt(e),d=[],128>g?d.push(g):2048>g?(d.push(192|g>>>6),d.push(128|g&63)):55296>g||57344<=g?d.push(224|g>>>12,128|g>>>6&63,128|g&63):(e+=1,g=65536+((g&1023)<<10|c.charCodeAt(e)&1023),d.push(240|g>>>18,128|g>>>12&63,128|g>>>6&63,128|g&63)),l=0;l<d.length;l+=1){t=k+
p;for(q=t>>>2;a.length<=q;)a.push(0);a[q]|=d[l]<<8*(n+t%4*-1);k+=1}else if("UTF16BE"===b||"UTF16LE"===b)for(n=2,d="UTF16LE"===b&&!0||"UTF16LE"!==b&&!1,e=0;e<c.length;e+=1){g=c.charCodeAt(e);!0===d&&(l=g&255,g=l<<8|g>>>8);t=k+p;for(q=t>>>2;a.length<=q;)a.push(0);a[q]|=g<<8*(n+t%4*-1);k+=2}return{value:a,binLen:8*k+f}};break;case "B64":c=function(b,a,f){var c=0,d,k,e,l,p,q,n;if(-1===b.search(/^[a-zA-Z0-9=+\/]+$/))throw Error("Invalid character in base-64 string");k=b.indexOf("=");b=b.replace(/\=/g,
"");if(-1!==k&&k<b.length)throw Error("Invalid '=' found in base-64 string");a=a||[0];f=f||0;q=f>>>3;for(k=0;k<b.length;k+=4){p=b.substr(k,4);for(e=l=0;e<p.length;e+=1)d="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".indexOf(p[e]),l|=d<<18-6*e;for(e=0;e<p.length-1;e+=1){n=c+q;for(d=n>>>2;a.length<=d;)a.push(0);a[d]|=(l>>>16-8*e&255)<<8*(3+n%4*-1);c+=1}}return{value:a,binLen:8*c+f}};break;case "BYTES":c=function(b,a,c){var d,m,k,e,l;a=a||[0];c=c||0;k=c>>>3;for(m=0;m<b.length;m+=
1)d=b.charCodeAt(m),l=m+k,e=l>>>2,a.length<=e&&a.push(0),a[e]|=d<<8*(3+l%4*-1);return{value:a,binLen:8*b.length+c}};break;case "ARRAYBUFFER":try{c=new ArrayBuffer(0)}catch(h){throw Error("ARRAYBUFFER not supported by this environment");}c=function(b,a,c){var d,m,k,e,l;a=a||[0];c=c||0;m=c>>>3;l=new Uint8Array(b);for(d=0;d<b.byteLength;d+=1)e=d+m,k=e>>>2,a.length<=k&&a.push(0),a[k]|=l[d]<<8*(3+e%4*-1);return{value:a,binLen:8*b.byteLength+c}};break;default:throw Error("format must be HEX, TEXT, B64, BYTES, or ARRAYBUFFER");
}return c}function n(d,b){return d<<b|d>>>32-b}function u(d,b){var c=(d&65535)+(b&65535);return((d>>>16)+(b>>>16)+(c>>>16)&65535)<<16|c&65535}function y(d,b,c,h,a){var f=(d&65535)+(b&65535)+(c&65535)+(h&65535)+(a&65535);return((d>>>16)+(b>>>16)+(c>>>16)+(h>>>16)+(a>>>16)+(f>>>16)&65535)<<16|f&65535}function x(d){var b=[];if("SHA-1"===d)b=[1732584193,4023233417,2562383102,271733878,3285377520];else throw Error("No SHA variants supported");return b}function z(d,b){var c=[],h,a,f,g,m,k,e;h=b[0];a=b[1];
f=b[2];g=b[3];m=b[4];for(e=0;80>e;e+=1)c[e]=16>e?d[e]:n(c[e-3]^c[e-8]^c[e-14]^c[e-16],1),k=20>e?y(n(h,5),a&f^~a&g,m,1518500249,c[e]):40>e?y(n(h,5),a^f^g,m,1859775393,c[e]):60>e?y(n(h,5),a&f^a&g^f&g,m,2400959708,c[e]):y(n(h,5),a^f^g,m,3395469782,c[e]),m=g,g=f,f=n(a,30),a=h,h=k;b[0]=u(h,b[0]);b[1]=u(a,b[1]);b[2]=u(f,b[2]);b[3]=u(g,b[3]);b[4]=u(m,b[4]);return b}function H(d,b,c,h){var a;for(a=(b+65>>>9<<4)+15;d.length<=a;)d.push(0);d[b>>>5]|=128<<24-b%32;b+=c;d[a]=b&4294967295;d[a-1]=b/4294967296|0;
b=d.length;for(a=0;a<b;a+=16)h=z(d.slice(a,a+16),h);return h}"function"===typeof define&&define.amd?define(function(){return r}):"undefined"!==typeof exports?("undefined"!==typeof module&&module.exports&&(module.exports=r),exports=r):G.jsSHA=r})(this);

},{}],157:[function(require,module,exports){
'use strict'

exports.byteLength = byteLength
exports.toByteArray = toByteArray
exports.fromByteArray = fromByteArray

var lookup = []
var revLookup = []
var Arr = typeof Uint8Array !== 'undefined' ? Uint8Array : Array

var code = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
for (var i = 0, len = code.length; i < len; ++i) {
  lookup[i] = code[i]
  revLookup[code.charCodeAt(i)] = i
}

// Support decoding URL-safe base64 strings, as Node.js does.
// See: https://en.wikipedia.org/wiki/Base64#URL_applications
revLookup['-'.charCodeAt(0)] = 62
revLookup['_'.charCodeAt(0)] = 63

function getLens (b64) {
  var len = b64.length

  if (len % 4 > 0) {
    throw new Error('Invalid string. Length must be a multiple of 4')
  }

  // Trim off extra bytes after placeholder bytes are found
  // See: https://github.com/beatgammit/base64-js/issues/42
  var validLen = b64.indexOf('=')
  if (validLen === -1) validLen = len

  var placeHoldersLen = validLen === len
    ? 0
    : 4 - (validLen % 4)

  return [validLen, placeHoldersLen]
}

// base64 is 4/3 + up to two characters of the original data
function byteLength (b64) {
  var lens = getLens(b64)
  var validLen = lens[0]
  var placeHoldersLen = lens[1]
  return ((validLen + placeHoldersLen) * 3 / 4) - placeHoldersLen
}

function _byteLength (b64, validLen, placeHoldersLen) {
  return ((validLen + placeHoldersLen) * 3 / 4) - placeHoldersLen
}

function toByteArray (b64) {
  var tmp
  var lens = getLens(b64)
  var validLen = lens[0]
  var placeHoldersLen = lens[1]

  var arr = new Arr(_byteLength(b64, validLen, placeHoldersLen))

  var curByte = 0

  // if there are placeholders, only get up to the last complete 4 chars
  var len = placeHoldersLen > 0
    ? validLen - 4
    : validLen

  var i
  for (i = 0; i < len; i += 4) {
    tmp =
      (revLookup[b64.charCodeAt(i)] << 18) |
      (revLookup[b64.charCodeAt(i + 1)] << 12) |
      (revLookup[b64.charCodeAt(i + 2)] << 6) |
      revLookup[b64.charCodeAt(i + 3)]
    arr[curByte++] = (tmp >> 16) & 0xFF
    arr[curByte++] = (tmp >> 8) & 0xFF
    arr[curByte++] = tmp & 0xFF
  }

  if (placeHoldersLen === 2) {
    tmp =
      (revLookup[b64.charCodeAt(i)] << 2) |
      (revLookup[b64.charCodeAt(i + 1)] >> 4)
    arr[curByte++] = tmp & 0xFF
  }

  if (placeHoldersLen === 1) {
    tmp =
      (revLookup[b64.charCodeAt(i)] << 10) |
      (revLookup[b64.charCodeAt(i + 1)] << 4) |
      (revLookup[b64.charCodeAt(i + 2)] >> 2)
    arr[curByte++] = (tmp >> 8) & 0xFF
    arr[curByte++] = tmp & 0xFF
  }

  return arr
}

function tripletToBase64 (num) {
  return lookup[num >> 18 & 0x3F] +
    lookup[num >> 12 & 0x3F] +
    lookup[num >> 6 & 0x3F] +
    lookup[num & 0x3F]
}

function encodeChunk (uint8, start, end) {
  var tmp
  var output = []
  for (var i = start; i < end; i += 3) {
    tmp =
      ((uint8[i] << 16) & 0xFF0000) +
      ((uint8[i + 1] << 8) & 0xFF00) +
      (uint8[i + 2] & 0xFF)
    output.push(tripletToBase64(tmp))
  }
  return output.join('')
}

function fromByteArray (uint8) {
  var tmp
  var len = uint8.length
  var extraBytes = len % 3 // if we have 1 byte left, pad 2 bytes
  var parts = []
  var maxChunkLength = 16383 // must be multiple of 3

  // go through the array every three bytes, we'll deal with trailing stuff later
  for (var i = 0, len2 = len - extraBytes; i < len2; i += maxChunkLength) {
    parts.push(encodeChunk(
      uint8, i, (i + maxChunkLength) > len2 ? len2 : (i + maxChunkLength)
    ))
  }

  // pad the end with zeros, but make sure to not forget the extra bytes
  if (extraBytes === 1) {
    tmp = uint8[len - 1]
    parts.push(
      lookup[tmp >> 2] +
      lookup[(tmp << 4) & 0x3F] +
      '=='
    )
  } else if (extraBytes === 2) {
    tmp = (uint8[len - 2] << 8) + uint8[len - 1]
    parts.push(
      lookup[tmp >> 10] +
      lookup[(tmp >> 4) & 0x3F] +
      lookup[(tmp << 2) & 0x3F] +
      '='
    )
  }

  return parts.join('')
}

},{}],158:[function(require,module,exports){
(function (Buffer){
/*!
 * The buffer module from node.js, for the browser.
 *
 * @author   Feross Aboukhadijeh <https://feross.org>
 * @license  MIT
 */
/* eslint-disable no-proto */

'use strict'

var base64 = require('base64-js')
var ieee754 = require('ieee754')
var customInspectSymbol =
  (typeof Symbol === 'function' && typeof Symbol.for === 'function')
    ? Symbol.for('nodejs.util.inspect.custom')
    : null

exports.Buffer = Buffer
exports.SlowBuffer = SlowBuffer
exports.INSPECT_MAX_BYTES = 50

var K_MAX_LENGTH = 0x7fffffff
exports.kMaxLength = K_MAX_LENGTH

/**
 * If `Buffer.TYPED_ARRAY_SUPPORT`:
 *   === true    Use Uint8Array implementation (fastest)
 *   === false   Print warning and recommend using `buffer` v4.x which has an Object
 *               implementation (most compatible, even IE6)
 *
 * Browsers that support typed arrays are IE 10+, Firefox 4+, Chrome 7+, Safari 5.1+,
 * Opera 11.6+, iOS 4.2+.
 *
 * We report that the browser does not support typed arrays if the are not subclassable
 * using __proto__. Firefox 4-29 lacks support for adding new properties to `Uint8Array`
 * (See: https://bugzilla.mozilla.org/show_bug.cgi?id=695438). IE 10 lacks support
 * for __proto__ and has a buggy typed array implementation.
 */
Buffer.TYPED_ARRAY_SUPPORT = typedArraySupport()

if (!Buffer.TYPED_ARRAY_SUPPORT && typeof console !== 'undefined' &&
    typeof console.error === 'function') {
  console.error(
    'This browser lacks typed array (Uint8Array) support which is required by ' +
    '`buffer` v5.x. Use `buffer` v4.x if you require old browser support.'
  )
}

function typedArraySupport () {
  // Can typed array instances can be augmented?
  try {
    var arr = new Uint8Array(1)
    var proto = { foo: function () { return 42 } }
    Object.setPrototypeOf(proto, Uint8Array.prototype)
    Object.setPrototypeOf(arr, proto)
    return arr.foo() === 42
  } catch (e) {
    return false
  }
}

Object.defineProperty(Buffer.prototype, 'parent', {
  enumerable: true,
  get: function () {
    if (!Buffer.isBuffer(this)) return undefined
    return this.buffer
  }
})

Object.defineProperty(Buffer.prototype, 'offset', {
  enumerable: true,
  get: function () {
    if (!Buffer.isBuffer(this)) return undefined
    return this.byteOffset
  }
})

function createBuffer (length) {
  if (length > K_MAX_LENGTH) {
    throw new RangeError('The value "' + length + '" is invalid for option "size"')
  }
  // Return an augmented `Uint8Array` instance
  var buf = new Uint8Array(length)
  Object.setPrototypeOf(buf, Buffer.prototype)
  return buf
}

/**
 * The Buffer constructor returns instances of `Uint8Array` that have their
 * prototype changed to `Buffer.prototype`. Furthermore, `Buffer` is a subclass of
 * `Uint8Array`, so the returned instances will have all the node `Buffer` methods
 * and the `Uint8Array` methods. Square bracket notation works as expected -- it
 * returns a single octet.
 *
 * The `Uint8Array` prototype remains unmodified.
 */

function Buffer (arg, encodingOrOffset, length) {
  // Common case.
  if (typeof arg === 'number') {
    if (typeof encodingOrOffset === 'string') {
      throw new TypeError(
        'The "string" argument must be of type string. Received type number'
      )
    }
    return allocUnsafe(arg)
  }
  return from(arg, encodingOrOffset, length)
}

// Fix subarray() in ES2016. See: https://github.com/feross/buffer/pull/97
if (typeof Symbol !== 'undefined' && Symbol.species != null &&
    Buffer[Symbol.species] === Buffer) {
  Object.defineProperty(Buffer, Symbol.species, {
    value: null,
    configurable: true,
    enumerable: false,
    writable: false
  })
}

Buffer.poolSize = 8192 // not used by this implementation

function from (value, encodingOrOffset, length) {
  if (typeof value === 'string') {
    return fromString(value, encodingOrOffset)
  }

  if (ArrayBuffer.isView(value)) {
    return fromArrayLike(value)
  }

  if (value == null) {
    throw new TypeError(
      'The first argument must be one of type string, Buffer, ArrayBuffer, Array, ' +
      'or Array-like Object. Received type ' + (typeof value)
    )
  }

  if (isInstance(value, ArrayBuffer) ||
      (value && isInstance(value.buffer, ArrayBuffer))) {
    return fromArrayBuffer(value, encodingOrOffset, length)
  }

  if (typeof value === 'number') {
    throw new TypeError(
      'The "value" argument must not be of type number. Received type number'
    )
  }

  var valueOf = value.valueOf && value.valueOf()
  if (valueOf != null && valueOf !== value) {
    return Buffer.from(valueOf, encodingOrOffset, length)
  }

  var b = fromObject(value)
  if (b) return b

  if (typeof Symbol !== 'undefined' && Symbol.toPrimitive != null &&
      typeof value[Symbol.toPrimitive] === 'function') {
    return Buffer.from(
      value[Symbol.toPrimitive]('string'), encodingOrOffset, length
    )
  }

  throw new TypeError(
    'The first argument must be one of type string, Buffer, ArrayBuffer, Array, ' +
    'or Array-like Object. Received type ' + (typeof value)
  )
}

/**
 * Functionally equivalent to Buffer(arg, encoding) but throws a TypeError
 * if value is a number.
 * Buffer.from(str[, encoding])
 * Buffer.from(array)
 * Buffer.from(buffer)
 * Buffer.from(arrayBuffer[, byteOffset[, length]])
 **/
Buffer.from = function (value, encodingOrOffset, length) {
  return from(value, encodingOrOffset, length)
}

// Note: Change prototype *after* Buffer.from is defined to workaround Chrome bug:
// https://github.com/feross/buffer/pull/148
Object.setPrototypeOf(Buffer.prototype, Uint8Array.prototype)
Object.setPrototypeOf(Buffer, Uint8Array)

function assertSize (size) {
  if (typeof size !== 'number') {
    throw new TypeError('"size" argument must be of type number')
  } else if (size < 0) {
    throw new RangeError('The value "' + size + '" is invalid for option "size"')
  }
}

function alloc (size, fill, encoding) {
  assertSize(size)
  if (size <= 0) {
    return createBuffer(size)
  }
  if (fill !== undefined) {
    // Only pay attention to encoding if it's a string. This
    // prevents accidentally sending in a number that would
    // be interpretted as a start offset.
    return typeof encoding === 'string'
      ? createBuffer(size).fill(fill, encoding)
      : createBuffer(size).fill(fill)
  }
  return createBuffer(size)
}

/**
 * Creates a new filled Buffer instance.
 * alloc(size[, fill[, encoding]])
 **/
Buffer.alloc = function (size, fill, encoding) {
  return alloc(size, fill, encoding)
}

function allocUnsafe (size) {
  assertSize(size)
  return createBuffer(size < 0 ? 0 : checked(size) | 0)
}

/**
 * Equivalent to Buffer(num), by default creates a non-zero-filled Buffer instance.
 * */
Buffer.allocUnsafe = function (size) {
  return allocUnsafe(size)
}
/**
 * Equivalent to SlowBuffer(num), by default creates a non-zero-filled Buffer instance.
 */
Buffer.allocUnsafeSlow = function (size) {
  return allocUnsafe(size)
}

function fromString (string, encoding) {
  if (typeof encoding !== 'string' || encoding === '') {
    encoding = 'utf8'
  }

  if (!Buffer.isEncoding(encoding)) {
    throw new TypeError('Unknown encoding: ' + encoding)
  }

  var length = byteLength(string, encoding) | 0
  var buf = createBuffer(length)

  var actual = buf.write(string, encoding)

  if (actual !== length) {
    // Writing a hex string, for example, that contains invalid characters will
    // cause everything after the first invalid character to be ignored. (e.g.
    // 'abxxcd' will be treated as 'ab')
    buf = buf.slice(0, actual)
  }

  return buf
}

function fromArrayLike (array) {
  var length = array.length < 0 ? 0 : checked(array.length) | 0
  var buf = createBuffer(length)
  for (var i = 0; i < length; i += 1) {
    buf[i] = array[i] & 255
  }
  return buf
}

function fromArrayBuffer (array, byteOffset, length) {
  if (byteOffset < 0 || array.byteLength < byteOffset) {
    throw new RangeError('"offset" is outside of buffer bounds')
  }

  if (array.byteLength < byteOffset + (length || 0)) {
    throw new RangeError('"length" is outside of buffer bounds')
  }

  var buf
  if (byteOffset === undefined && length === undefined) {
    buf = new Uint8Array(array)
  } else if (length === undefined) {
    buf = new Uint8Array(array, byteOffset)
  } else {
    buf = new Uint8Array(array, byteOffset, length)
  }

  // Return an augmented `Uint8Array` instance
  Object.setPrototypeOf(buf, Buffer.prototype)

  return buf
}

function fromObject (obj) {
  if (Buffer.isBuffer(obj)) {
    var len = checked(obj.length) | 0
    var buf = createBuffer(len)

    if (buf.length === 0) {
      return buf
    }

    obj.copy(buf, 0, 0, len)
    return buf
  }

  if (obj.length !== undefined) {
    if (typeof obj.length !== 'number' || numberIsNaN(obj.length)) {
      return createBuffer(0)
    }
    return fromArrayLike(obj)
  }

  if (obj.type === 'Buffer' && Array.isArray(obj.data)) {
    return fromArrayLike(obj.data)
  }
}

function checked (length) {
  // Note: cannot use `length < K_MAX_LENGTH` here because that fails when
  // length is NaN (which is otherwise coerced to zero.)
  if (length >= K_MAX_LENGTH) {
    throw new RangeError('Attempt to allocate Buffer larger than maximum ' +
                         'size: 0x' + K_MAX_LENGTH.toString(16) + ' bytes')
  }
  return length | 0
}

function SlowBuffer (length) {
  if (+length != length) { // eslint-disable-line eqeqeq
    length = 0
  }
  return Buffer.alloc(+length)
}

Buffer.isBuffer = function isBuffer (b) {
  return b != null && b._isBuffer === true &&
    b !== Buffer.prototype // so Buffer.isBuffer(Buffer.prototype) will be false
}

Buffer.compare = function compare (a, b) {
  if (isInstance(a, Uint8Array)) a = Buffer.from(a, a.offset, a.byteLength)
  if (isInstance(b, Uint8Array)) b = Buffer.from(b, b.offset, b.byteLength)
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) {
    throw new TypeError(
      'The "buf1", "buf2" arguments must be one of type Buffer or Uint8Array'
    )
  }

  if (a === b) return 0

  var x = a.length
  var y = b.length

  for (var i = 0, len = Math.min(x, y); i < len; ++i) {
    if (a[i] !== b[i]) {
      x = a[i]
      y = b[i]
      break
    }
  }

  if (x < y) return -1
  if (y < x) return 1
  return 0
}

Buffer.isEncoding = function isEncoding (encoding) {
  switch (String(encoding).toLowerCase()) {
    case 'hex':
    case 'utf8':
    case 'utf-8':
    case 'ascii':
    case 'latin1':
    case 'binary':
    case 'base64':
    case 'ucs2':
    case 'ucs-2':
    case 'utf16le':
    case 'utf-16le':
      return true
    default:
      return false
  }
}

Buffer.concat = function concat (list, length) {
  if (!Array.isArray(list)) {
    throw new TypeError('"list" argument must be an Array of Buffers')
  }

  if (list.length === 0) {
    return Buffer.alloc(0)
  }

  var i
  if (length === undefined) {
    length = 0
    for (i = 0; i < list.length; ++i) {
      length += list[i].length
    }
  }

  var buffer = Buffer.allocUnsafe(length)
  var pos = 0
  for (i = 0; i < list.length; ++i) {
    var buf = list[i]
    if (isInstance(buf, Uint8Array)) {
      buf = Buffer.from(buf)
    }
    if (!Buffer.isBuffer(buf)) {
      throw new TypeError('"list" argument must be an Array of Buffers')
    }
    buf.copy(buffer, pos)
    pos += buf.length
  }
  return buffer
}

function byteLength (string, encoding) {
  if (Buffer.isBuffer(string)) {
    return string.length
  }
  if (ArrayBuffer.isView(string) || isInstance(string, ArrayBuffer)) {
    return string.byteLength
  }
  if (typeof string !== 'string') {
    throw new TypeError(
      'The "string" argument must be one of type string, Buffer, or ArrayBuffer. ' +
      'Received type ' + typeof string
    )
  }

  var len = string.length
  var mustMatch = (arguments.length > 2 && arguments[2] === true)
  if (!mustMatch && len === 0) return 0

  // Use a for loop to avoid recursion
  var loweredCase = false
  for (;;) {
    switch (encoding) {
      case 'ascii':
      case 'latin1':
      case 'binary':
        return len
      case 'utf8':
      case 'utf-8':
        return utf8ToBytes(string).length
      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return len * 2
      case 'hex':
        return len >>> 1
      case 'base64':
        return base64ToBytes(string).length
      default:
        if (loweredCase) {
          return mustMatch ? -1 : utf8ToBytes(string).length // assume utf8
        }
        encoding = ('' + encoding).toLowerCase()
        loweredCase = true
    }
  }
}
Buffer.byteLength = byteLength

function slowToString (encoding, start, end) {
  var loweredCase = false

  // No need to verify that "this.length <= MAX_UINT32" since it's a read-only
  // property of a typed array.

  // This behaves neither like String nor Uint8Array in that we set start/end
  // to their upper/lower bounds if the value passed is out of range.
  // undefined is handled specially as per ECMA-262 6th Edition,
  // Section 13.3.3.7 Runtime Semantics: KeyedBindingInitialization.
  if (start === undefined || start < 0) {
    start = 0
  }
  // Return early if start > this.length. Done here to prevent potential uint32
  // coercion fail below.
  if (start > this.length) {
    return ''
  }

  if (end === undefined || end > this.length) {
    end = this.length
  }

  if (end <= 0) {
    return ''
  }

  // Force coersion to uint32. This will also coerce falsey/NaN values to 0.
  end >>>= 0
  start >>>= 0

  if (end <= start) {
    return ''
  }

  if (!encoding) encoding = 'utf8'

  while (true) {
    switch (encoding) {
      case 'hex':
        return hexSlice(this, start, end)

      case 'utf8':
      case 'utf-8':
        return utf8Slice(this, start, end)

      case 'ascii':
        return asciiSlice(this, start, end)

      case 'latin1':
      case 'binary':
        return latin1Slice(this, start, end)

      case 'base64':
        return base64Slice(this, start, end)

      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return utf16leSlice(this, start, end)

      default:
        if (loweredCase) throw new TypeError('Unknown encoding: ' + encoding)
        encoding = (encoding + '').toLowerCase()
        loweredCase = true
    }
  }
}

// This property is used by `Buffer.isBuffer` (and the `is-buffer` npm package)
// to detect a Buffer instance. It's not possible to use `instanceof Buffer`
// reliably in a browserify context because there could be multiple different
// copies of the 'buffer' package in use. This method works even for Buffer
// instances that were created from another copy of the `buffer` package.
// See: https://github.com/feross/buffer/issues/154
Buffer.prototype._isBuffer = true

function swap (b, n, m) {
  var i = b[n]
  b[n] = b[m]
  b[m] = i
}

Buffer.prototype.swap16 = function swap16 () {
  var len = this.length
  if (len % 2 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 16-bits')
  }
  for (var i = 0; i < len; i += 2) {
    swap(this, i, i + 1)
  }
  return this
}

Buffer.prototype.swap32 = function swap32 () {
  var len = this.length
  if (len % 4 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 32-bits')
  }
  for (var i = 0; i < len; i += 4) {
    swap(this, i, i + 3)
    swap(this, i + 1, i + 2)
  }
  return this
}

Buffer.prototype.swap64 = function swap64 () {
  var len = this.length
  if (len % 8 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 64-bits')
  }
  for (var i = 0; i < len; i += 8) {
    swap(this, i, i + 7)
    swap(this, i + 1, i + 6)
    swap(this, i + 2, i + 5)
    swap(this, i + 3, i + 4)
  }
  return this
}

Buffer.prototype.toString = function toString () {
  var length = this.length
  if (length === 0) return ''
  if (arguments.length === 0) return utf8Slice(this, 0, length)
  return slowToString.apply(this, arguments)
}

Buffer.prototype.toLocaleString = Buffer.prototype.toString

Buffer.prototype.equals = function equals (b) {
  if (!Buffer.isBuffer(b)) throw new TypeError('Argument must be a Buffer')
  if (this === b) return true
  return Buffer.compare(this, b) === 0
}

Buffer.prototype.inspect = function inspect () {
  var str = ''
  var max = exports.INSPECT_MAX_BYTES
  str = this.toString('hex', 0, max).replace(/(.{2})/g, '$1 ').trim()
  if (this.length > max) str += ' ... '
  return '<Buffer ' + str + '>'
}
if (customInspectSymbol) {
  Buffer.prototype[customInspectSymbol] = Buffer.prototype.inspect
}

Buffer.prototype.compare = function compare (target, start, end, thisStart, thisEnd) {
  if (isInstance(target, Uint8Array)) {
    target = Buffer.from(target, target.offset, target.byteLength)
  }
  if (!Buffer.isBuffer(target)) {
    throw new TypeError(
      'The "target" argument must be one of type Buffer or Uint8Array. ' +
      'Received type ' + (typeof target)
    )
  }

  if (start === undefined) {
    start = 0
  }
  if (end === undefined) {
    end = target ? target.length : 0
  }
  if (thisStart === undefined) {
    thisStart = 0
  }
  if (thisEnd === undefined) {
    thisEnd = this.length
  }

  if (start < 0 || end > target.length || thisStart < 0 || thisEnd > this.length) {
    throw new RangeError('out of range index')
  }

  if (thisStart >= thisEnd && start >= end) {
    return 0
  }
  if (thisStart >= thisEnd) {
    return -1
  }
  if (start >= end) {
    return 1
  }

  start >>>= 0
  end >>>= 0
  thisStart >>>= 0
  thisEnd >>>= 0

  if (this === target) return 0

  var x = thisEnd - thisStart
  var y = end - start
  var len = Math.min(x, y)

  var thisCopy = this.slice(thisStart, thisEnd)
  var targetCopy = target.slice(start, end)

  for (var i = 0; i < len; ++i) {
    if (thisCopy[i] !== targetCopy[i]) {
      x = thisCopy[i]
      y = targetCopy[i]
      break
    }
  }

  if (x < y) return -1
  if (y < x) return 1
  return 0
}

// Finds either the first index of `val` in `buffer` at offset >= `byteOffset`,
// OR the last index of `val` in `buffer` at offset <= `byteOffset`.
//
// Arguments:
// - buffer - a Buffer to search
// - val - a string, Buffer, or number
// - byteOffset - an index into `buffer`; will be clamped to an int32
// - encoding - an optional encoding, relevant is val is a string
// - dir - true for indexOf, false for lastIndexOf
function bidirectionalIndexOf (buffer, val, byteOffset, encoding, dir) {
  // Empty buffer means no match
  if (buffer.length === 0) return -1

  // Normalize byteOffset
  if (typeof byteOffset === 'string') {
    encoding = byteOffset
    byteOffset = 0
  } else if (byteOffset > 0x7fffffff) {
    byteOffset = 0x7fffffff
  } else if (byteOffset < -0x80000000) {
    byteOffset = -0x80000000
  }
  byteOffset = +byteOffset // Coerce to Number.
  if (numberIsNaN(byteOffset)) {
    // byteOffset: it it's undefined, null, NaN, "foo", etc, search whole buffer
    byteOffset = dir ? 0 : (buffer.length - 1)
  }

  // Normalize byteOffset: negative offsets start from the end of the buffer
  if (byteOffset < 0) byteOffset = buffer.length + byteOffset
  if (byteOffset >= buffer.length) {
    if (dir) return -1
    else byteOffset = buffer.length - 1
  } else if (byteOffset < 0) {
    if (dir) byteOffset = 0
    else return -1
  }

  // Normalize val
  if (typeof val === 'string') {
    val = Buffer.from(val, encoding)
  }

  // Finally, search either indexOf (if dir is true) or lastIndexOf
  if (Buffer.isBuffer(val)) {
    // Special case: looking for empty string/buffer always fails
    if (val.length === 0) {
      return -1
    }
    return arrayIndexOf(buffer, val, byteOffset, encoding, dir)
  } else if (typeof val === 'number') {
    val = val & 0xFF // Search for a byte value [0-255]
    if (typeof Uint8Array.prototype.indexOf === 'function') {
      if (dir) {
        return Uint8Array.prototype.indexOf.call(buffer, val, byteOffset)
      } else {
        return Uint8Array.prototype.lastIndexOf.call(buffer, val, byteOffset)
      }
    }
    return arrayIndexOf(buffer, [val], byteOffset, encoding, dir)
  }

  throw new TypeError('val must be string, number or Buffer')
}

function arrayIndexOf (arr, val, byteOffset, encoding, dir) {
  var indexSize = 1
  var arrLength = arr.length
  var valLength = val.length

  if (encoding !== undefined) {
    encoding = String(encoding).toLowerCase()
    if (encoding === 'ucs2' || encoding === 'ucs-2' ||
        encoding === 'utf16le' || encoding === 'utf-16le') {
      if (arr.length < 2 || val.length < 2) {
        return -1
      }
      indexSize = 2
      arrLength /= 2
      valLength /= 2
      byteOffset /= 2
    }
  }

  function read (buf, i) {
    if (indexSize === 1) {
      return buf[i]
    } else {
      return buf.readUInt16BE(i * indexSize)
    }
  }

  var i
  if (dir) {
    var foundIndex = -1
    for (i = byteOffset; i < arrLength; i++) {
      if (read(arr, i) === read(val, foundIndex === -1 ? 0 : i - foundIndex)) {
        if (foundIndex === -1) foundIndex = i
        if (i - foundIndex + 1 === valLength) return foundIndex * indexSize
      } else {
        if (foundIndex !== -1) i -= i - foundIndex
        foundIndex = -1
      }
    }
  } else {
    if (byteOffset + valLength > arrLength) byteOffset = arrLength - valLength
    for (i = byteOffset; i >= 0; i--) {
      var found = true
      for (var j = 0; j < valLength; j++) {
        if (read(arr, i + j) !== read(val, j)) {
          found = false
          break
        }
      }
      if (found) return i
    }
  }

  return -1
}

Buffer.prototype.includes = function includes (val, byteOffset, encoding) {
  return this.indexOf(val, byteOffset, encoding) !== -1
}

Buffer.prototype.indexOf = function indexOf (val, byteOffset, encoding) {
  return bidirectionalIndexOf(this, val, byteOffset, encoding, true)
}

Buffer.prototype.lastIndexOf = function lastIndexOf (val, byteOffset, encoding) {
  return bidirectionalIndexOf(this, val, byteOffset, encoding, false)
}

function hexWrite (buf, string, offset, length) {
  offset = Number(offset) || 0
  var remaining = buf.length - offset
  if (!length) {
    length = remaining
  } else {
    length = Number(length)
    if (length > remaining) {
      length = remaining
    }
  }

  var strLen = string.length

  if (length > strLen / 2) {
    length = strLen / 2
  }
  for (var i = 0; i < length; ++i) {
    var parsed = parseInt(string.substr(i * 2, 2), 16)
    if (numberIsNaN(parsed)) return i
    buf[offset + i] = parsed
  }
  return i
}

function utf8Write (buf, string, offset, length) {
  return blitBuffer(utf8ToBytes(string, buf.length - offset), buf, offset, length)
}

function asciiWrite (buf, string, offset, length) {
  return blitBuffer(asciiToBytes(string), buf, offset, length)
}

function latin1Write (buf, string, offset, length) {
  return asciiWrite(buf, string, offset, length)
}

function base64Write (buf, string, offset, length) {
  return blitBuffer(base64ToBytes(string), buf, offset, length)
}

function ucs2Write (buf, string, offset, length) {
  return blitBuffer(utf16leToBytes(string, buf.length - offset), buf, offset, length)
}

Buffer.prototype.write = function write (string, offset, length, encoding) {
  // Buffer#write(string)
  if (offset === undefined) {
    encoding = 'utf8'
    length = this.length
    offset = 0
  // Buffer#write(string, encoding)
  } else if (length === undefined && typeof offset === 'string') {
    encoding = offset
    length = this.length
    offset = 0
  // Buffer#write(string, offset[, length][, encoding])
  } else if (isFinite(offset)) {
    offset = offset >>> 0
    if (isFinite(length)) {
      length = length >>> 0
      if (encoding === undefined) encoding = 'utf8'
    } else {
      encoding = length
      length = undefined
    }
  } else {
    throw new Error(
      'Buffer.write(string, encoding, offset[, length]) is no longer supported'
    )
  }

  var remaining = this.length - offset
  if (length === undefined || length > remaining) length = remaining

  if ((string.length > 0 && (length < 0 || offset < 0)) || offset > this.length) {
    throw new RangeError('Attempt to write outside buffer bounds')
  }

  if (!encoding) encoding = 'utf8'

  var loweredCase = false
  for (;;) {
    switch (encoding) {
      case 'hex':
        return hexWrite(this, string, offset, length)

      case 'utf8':
      case 'utf-8':
        return utf8Write(this, string, offset, length)

      case 'ascii':
        return asciiWrite(this, string, offset, length)

      case 'latin1':
      case 'binary':
        return latin1Write(this, string, offset, length)

      case 'base64':
        // Warning: maxLength not taken into account in base64Write
        return base64Write(this, string, offset, length)

      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return ucs2Write(this, string, offset, length)

      default:
        if (loweredCase) throw new TypeError('Unknown encoding: ' + encoding)
        encoding = ('' + encoding).toLowerCase()
        loweredCase = true
    }
  }
}

Buffer.prototype.toJSON = function toJSON () {
  return {
    type: 'Buffer',
    data: Array.prototype.slice.call(this._arr || this, 0)
  }
}

function base64Slice (buf, start, end) {
  if (start === 0 && end === buf.length) {
    return base64.fromByteArray(buf)
  } else {
    return base64.fromByteArray(buf.slice(start, end))
  }
}

function utf8Slice (buf, start, end) {
  end = Math.min(buf.length, end)
  var res = []

  var i = start
  while (i < end) {
    var firstByte = buf[i]
    var codePoint = null
    var bytesPerSequence = (firstByte > 0xEF) ? 4
      : (firstByte > 0xDF) ? 3
        : (firstByte > 0xBF) ? 2
          : 1

    if (i + bytesPerSequence <= end) {
      var secondByte, thirdByte, fourthByte, tempCodePoint

      switch (bytesPerSequence) {
        case 1:
          if (firstByte < 0x80) {
            codePoint = firstByte
          }
          break
        case 2:
          secondByte = buf[i + 1]
          if ((secondByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0x1F) << 0x6 | (secondByte & 0x3F)
            if (tempCodePoint > 0x7F) {
              codePoint = tempCodePoint
            }
          }
          break
        case 3:
          secondByte = buf[i + 1]
          thirdByte = buf[i + 2]
          if ((secondByte & 0xC0) === 0x80 && (thirdByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0xF) << 0xC | (secondByte & 0x3F) << 0x6 | (thirdByte & 0x3F)
            if (tempCodePoint > 0x7FF && (tempCodePoint < 0xD800 || tempCodePoint > 0xDFFF)) {
              codePoint = tempCodePoint
            }
          }
          break
        case 4:
          secondByte = buf[i + 1]
          thirdByte = buf[i + 2]
          fourthByte = buf[i + 3]
          if ((secondByte & 0xC0) === 0x80 && (thirdByte & 0xC0) === 0x80 && (fourthByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0xF) << 0x12 | (secondByte & 0x3F) << 0xC | (thirdByte & 0x3F) << 0x6 | (fourthByte & 0x3F)
            if (tempCodePoint > 0xFFFF && tempCodePoint < 0x110000) {
              codePoint = tempCodePoint
            }
          }
      }
    }

    if (codePoint === null) {
      // we did not generate a valid codePoint so insert a
      // replacement char (U+FFFD) and advance only 1 byte
      codePoint = 0xFFFD
      bytesPerSequence = 1
    } else if (codePoint > 0xFFFF) {
      // encode to utf16 (surrogate pair dance)
      codePoint -= 0x10000
      res.push(codePoint >>> 10 & 0x3FF | 0xD800)
      codePoint = 0xDC00 | codePoint & 0x3FF
    }

    res.push(codePoint)
    i += bytesPerSequence
  }

  return decodeCodePointsArray(res)
}

// Based on http://stackoverflow.com/a/22747272/680742, the browser with
// the lowest limit is Chrome, with 0x10000 args.
// We go 1 magnitude less, for safety
var MAX_ARGUMENTS_LENGTH = 0x1000

function decodeCodePointsArray (codePoints) {
  var len = codePoints.length
  if (len <= MAX_ARGUMENTS_LENGTH) {
    return String.fromCharCode.apply(String, codePoints) // avoid extra slice()
  }

  // Decode in chunks to avoid "call stack size exceeded".
  var res = ''
  var i = 0
  while (i < len) {
    res += String.fromCharCode.apply(
      String,
      codePoints.slice(i, i += MAX_ARGUMENTS_LENGTH)
    )
  }
  return res
}

function asciiSlice (buf, start, end) {
  var ret = ''
  end = Math.min(buf.length, end)

  for (var i = start; i < end; ++i) {
    ret += String.fromCharCode(buf[i] & 0x7F)
  }
  return ret
}

function latin1Slice (buf, start, end) {
  var ret = ''
  end = Math.min(buf.length, end)

  for (var i = start; i < end; ++i) {
    ret += String.fromCharCode(buf[i])
  }
  return ret
}

function hexSlice (buf, start, end) {
  var len = buf.length

  if (!start || start < 0) start = 0
  if (!end || end < 0 || end > len) end = len

  var out = ''
  for (var i = start; i < end; ++i) {
    out += hexSliceLookupTable[buf[i]]
  }
  return out
}

function utf16leSlice (buf, start, end) {
  var bytes = buf.slice(start, end)
  var res = ''
  for (var i = 0; i < bytes.length; i += 2) {
    res += String.fromCharCode(bytes[i] + (bytes[i + 1] * 256))
  }
  return res
}

Buffer.prototype.slice = function slice (start, end) {
  var len = this.length
  start = ~~start
  end = end === undefined ? len : ~~end

  if (start < 0) {
    start += len
    if (start < 0) start = 0
  } else if (start > len) {
    start = len
  }

  if (end < 0) {
    end += len
    if (end < 0) end = 0
  } else if (end > len) {
    end = len
  }

  if (end < start) end = start

  var newBuf = this.subarray(start, end)
  // Return an augmented `Uint8Array` instance
  Object.setPrototypeOf(newBuf, Buffer.prototype)

  return newBuf
}

/*
 * Need to make sure that buffer isn't trying to write out of bounds.
 */
function checkOffset (offset, ext, length) {
  if ((offset % 1) !== 0 || offset < 0) throw new RangeError('offset is not uint')
  if (offset + ext > length) throw new RangeError('Trying to access beyond buffer length')
}

Buffer.prototype.readUIntLE = function readUIntLE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  var val = this[offset]
  var mul = 1
  var i = 0
  while (++i < byteLength && (mul *= 0x100)) {
    val += this[offset + i] * mul
  }

  return val
}

Buffer.prototype.readUIntBE = function readUIntBE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) {
    checkOffset(offset, byteLength, this.length)
  }

  var val = this[offset + --byteLength]
  var mul = 1
  while (byteLength > 0 && (mul *= 0x100)) {
    val += this[offset + --byteLength] * mul
  }

  return val
}

Buffer.prototype.readUInt8 = function readUInt8 (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 1, this.length)
  return this[offset]
}

Buffer.prototype.readUInt16LE = function readUInt16LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  return this[offset] | (this[offset + 1] << 8)
}

Buffer.prototype.readUInt16BE = function readUInt16BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  return (this[offset] << 8) | this[offset + 1]
}

Buffer.prototype.readUInt32LE = function readUInt32LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return ((this[offset]) |
      (this[offset + 1] << 8) |
      (this[offset + 2] << 16)) +
      (this[offset + 3] * 0x1000000)
}

Buffer.prototype.readUInt32BE = function readUInt32BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset] * 0x1000000) +
    ((this[offset + 1] << 16) |
    (this[offset + 2] << 8) |
    this[offset + 3])
}

Buffer.prototype.readIntLE = function readIntLE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  var val = this[offset]
  var mul = 1
  var i = 0
  while (++i < byteLength && (mul *= 0x100)) {
    val += this[offset + i] * mul
  }
  mul *= 0x80

  if (val >= mul) val -= Math.pow(2, 8 * byteLength)

  return val
}

Buffer.prototype.readIntBE = function readIntBE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  var i = byteLength
  var mul = 1
  var val = this[offset + --i]
  while (i > 0 && (mul *= 0x100)) {
    val += this[offset + --i] * mul
  }
  mul *= 0x80

  if (val >= mul) val -= Math.pow(2, 8 * byteLength)

  return val
}

Buffer.prototype.readInt8 = function readInt8 (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 1, this.length)
  if (!(this[offset] & 0x80)) return (this[offset])
  return ((0xff - this[offset] + 1) * -1)
}

Buffer.prototype.readInt16LE = function readInt16LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  var val = this[offset] | (this[offset + 1] << 8)
  return (val & 0x8000) ? val | 0xFFFF0000 : val
}

Buffer.prototype.readInt16BE = function readInt16BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  var val = this[offset + 1] | (this[offset] << 8)
  return (val & 0x8000) ? val | 0xFFFF0000 : val
}

Buffer.prototype.readInt32LE = function readInt32LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset]) |
    (this[offset + 1] << 8) |
    (this[offset + 2] << 16) |
    (this[offset + 3] << 24)
}

Buffer.prototype.readInt32BE = function readInt32BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset] << 24) |
    (this[offset + 1] << 16) |
    (this[offset + 2] << 8) |
    (this[offset + 3])
}

Buffer.prototype.readFloatLE = function readFloatLE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)
  return ieee754.read(this, offset, true, 23, 4)
}

Buffer.prototype.readFloatBE = function readFloatBE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)
  return ieee754.read(this, offset, false, 23, 4)
}

Buffer.prototype.readDoubleLE = function readDoubleLE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 8, this.length)
  return ieee754.read(this, offset, true, 52, 8)
}

Buffer.prototype.readDoubleBE = function readDoubleBE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 8, this.length)
  return ieee754.read(this, offset, false, 52, 8)
}

function checkInt (buf, value, offset, ext, max, min) {
  if (!Buffer.isBuffer(buf)) throw new TypeError('"buffer" argument must be a Buffer instance')
  if (value > max || value < min) throw new RangeError('"value" argument is out of bounds')
  if (offset + ext > buf.length) throw new RangeError('Index out of range')
}

Buffer.prototype.writeUIntLE = function writeUIntLE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) {
    var maxBytes = Math.pow(2, 8 * byteLength) - 1
    checkInt(this, value, offset, byteLength, maxBytes, 0)
  }

  var mul = 1
  var i = 0
  this[offset] = value & 0xFF
  while (++i < byteLength && (mul *= 0x100)) {
    this[offset + i] = (value / mul) & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeUIntBE = function writeUIntBE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) {
    var maxBytes = Math.pow(2, 8 * byteLength) - 1
    checkInt(this, value, offset, byteLength, maxBytes, 0)
  }

  var i = byteLength - 1
  var mul = 1
  this[offset + i] = value & 0xFF
  while (--i >= 0 && (mul *= 0x100)) {
    this[offset + i] = (value / mul) & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeUInt8 = function writeUInt8 (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 1, 0xff, 0)
  this[offset] = (value & 0xff)
  return offset + 1
}

Buffer.prototype.writeUInt16LE = function writeUInt16LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0xffff, 0)
  this[offset] = (value & 0xff)
  this[offset + 1] = (value >>> 8)
  return offset + 2
}

Buffer.prototype.writeUInt16BE = function writeUInt16BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0xffff, 0)
  this[offset] = (value >>> 8)
  this[offset + 1] = (value & 0xff)
  return offset + 2
}

Buffer.prototype.writeUInt32LE = function writeUInt32LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0xffffffff, 0)
  this[offset + 3] = (value >>> 24)
  this[offset + 2] = (value >>> 16)
  this[offset + 1] = (value >>> 8)
  this[offset] = (value & 0xff)
  return offset + 4
}

Buffer.prototype.writeUInt32BE = function writeUInt32BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0xffffffff, 0)
  this[offset] = (value >>> 24)
  this[offset + 1] = (value >>> 16)
  this[offset + 2] = (value >>> 8)
  this[offset + 3] = (value & 0xff)
  return offset + 4
}

Buffer.prototype.writeIntLE = function writeIntLE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    var limit = Math.pow(2, (8 * byteLength) - 1)

    checkInt(this, value, offset, byteLength, limit - 1, -limit)
  }

  var i = 0
  var mul = 1
  var sub = 0
  this[offset] = value & 0xFF
  while (++i < byteLength && (mul *= 0x100)) {
    if (value < 0 && sub === 0 && this[offset + i - 1] !== 0) {
      sub = 1
    }
    this[offset + i] = ((value / mul) >> 0) - sub & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeIntBE = function writeIntBE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    var limit = Math.pow(2, (8 * byteLength) - 1)

    checkInt(this, value, offset, byteLength, limit - 1, -limit)
  }

  var i = byteLength - 1
  var mul = 1
  var sub = 0
  this[offset + i] = value & 0xFF
  while (--i >= 0 && (mul *= 0x100)) {
    if (value < 0 && sub === 0 && this[offset + i + 1] !== 0) {
      sub = 1
    }
    this[offset + i] = ((value / mul) >> 0) - sub & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeInt8 = function writeInt8 (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 1, 0x7f, -0x80)
  if (value < 0) value = 0xff + value + 1
  this[offset] = (value & 0xff)
  return offset + 1
}

Buffer.prototype.writeInt16LE = function writeInt16LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0x7fff, -0x8000)
  this[offset] = (value & 0xff)
  this[offset + 1] = (value >>> 8)
  return offset + 2
}

Buffer.prototype.writeInt16BE = function writeInt16BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0x7fff, -0x8000)
  this[offset] = (value >>> 8)
  this[offset + 1] = (value & 0xff)
  return offset + 2
}

Buffer.prototype.writeInt32LE = function writeInt32LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0x7fffffff, -0x80000000)
  this[offset] = (value & 0xff)
  this[offset + 1] = (value >>> 8)
  this[offset + 2] = (value >>> 16)
  this[offset + 3] = (value >>> 24)
  return offset + 4
}

Buffer.prototype.writeInt32BE = function writeInt32BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0x7fffffff, -0x80000000)
  if (value < 0) value = 0xffffffff + value + 1
  this[offset] = (value >>> 24)
  this[offset + 1] = (value >>> 16)
  this[offset + 2] = (value >>> 8)
  this[offset + 3] = (value & 0xff)
  return offset + 4
}

function checkIEEE754 (buf, value, offset, ext, max, min) {
  if (offset + ext > buf.length) throw new RangeError('Index out of range')
  if (offset < 0) throw new RangeError('Index out of range')
}

function writeFloat (buf, value, offset, littleEndian, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    checkIEEE754(buf, value, offset, 4, 3.4028234663852886e+38, -3.4028234663852886e+38)
  }
  ieee754.write(buf, value, offset, littleEndian, 23, 4)
  return offset + 4
}

Buffer.prototype.writeFloatLE = function writeFloatLE (value, offset, noAssert) {
  return writeFloat(this, value, offset, true, noAssert)
}

Buffer.prototype.writeFloatBE = function writeFloatBE (value, offset, noAssert) {
  return writeFloat(this, value, offset, false, noAssert)
}

function writeDouble (buf, value, offset, littleEndian, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    checkIEEE754(buf, value, offset, 8, 1.7976931348623157E+308, -1.7976931348623157E+308)
  }
  ieee754.write(buf, value, offset, littleEndian, 52, 8)
  return offset + 8
}

Buffer.prototype.writeDoubleLE = function writeDoubleLE (value, offset, noAssert) {
  return writeDouble(this, value, offset, true, noAssert)
}

Buffer.prototype.writeDoubleBE = function writeDoubleBE (value, offset, noAssert) {
  return writeDouble(this, value, offset, false, noAssert)
}

// copy(targetBuffer, targetStart=0, sourceStart=0, sourceEnd=buffer.length)
Buffer.prototype.copy = function copy (target, targetStart, start, end) {
  if (!Buffer.isBuffer(target)) throw new TypeError('argument should be a Buffer')
  if (!start) start = 0
  if (!end && end !== 0) end = this.length
  if (targetStart >= target.length) targetStart = target.length
  if (!targetStart) targetStart = 0
  if (end > 0 && end < start) end = start

  // Copy 0 bytes; we're done
  if (end === start) return 0
  if (target.length === 0 || this.length === 0) return 0

  // Fatal error conditions
  if (targetStart < 0) {
    throw new RangeError('targetStart out of bounds')
  }
  if (start < 0 || start >= this.length) throw new RangeError('Index out of range')
  if (end < 0) throw new RangeError('sourceEnd out of bounds')

  // Are we oob?
  if (end > this.length) end = this.length
  if (target.length - targetStart < end - start) {
    end = target.length - targetStart + start
  }

  var len = end - start

  if (this === target && typeof Uint8Array.prototype.copyWithin === 'function') {
    // Use built-in when available, missing from IE11
    this.copyWithin(targetStart, start, end)
  } else if (this === target && start < targetStart && targetStart < end) {
    // descending copy from end
    for (var i = len - 1; i >= 0; --i) {
      target[i + targetStart] = this[i + start]
    }
  } else {
    Uint8Array.prototype.set.call(
      target,
      this.subarray(start, end),
      targetStart
    )
  }

  return len
}

// Usage:
//    buffer.fill(number[, offset[, end]])
//    buffer.fill(buffer[, offset[, end]])
//    buffer.fill(string[, offset[, end]][, encoding])
Buffer.prototype.fill = function fill (val, start, end, encoding) {
  // Handle string cases:
  if (typeof val === 'string') {
    if (typeof start === 'string') {
      encoding = start
      start = 0
      end = this.length
    } else if (typeof end === 'string') {
      encoding = end
      end = this.length
    }
    if (encoding !== undefined && typeof encoding !== 'string') {
      throw new TypeError('encoding must be a string')
    }
    if (typeof encoding === 'string' && !Buffer.isEncoding(encoding)) {
      throw new TypeError('Unknown encoding: ' + encoding)
    }
    if (val.length === 1) {
      var code = val.charCodeAt(0)
      if ((encoding === 'utf8' && code < 128) ||
          encoding === 'latin1') {
        // Fast path: If `val` fits into a single byte, use that numeric value.
        val = code
      }
    }
  } else if (typeof val === 'number') {
    val = val & 255
  } else if (typeof val === 'boolean') {
    val = Number(val)
  }

  // Invalid ranges are not set to a default, so can range check early.
  if (start < 0 || this.length < start || this.length < end) {
    throw new RangeError('Out of range index')
  }

  if (end <= start) {
    return this
  }

  start = start >>> 0
  end = end === undefined ? this.length : end >>> 0

  if (!val) val = 0

  var i
  if (typeof val === 'number') {
    for (i = start; i < end; ++i) {
      this[i] = val
    }
  } else {
    var bytes = Buffer.isBuffer(val)
      ? val
      : Buffer.from(val, encoding)
    var len = bytes.length
    if (len === 0) {
      throw new TypeError('The value "' + val +
        '" is invalid for argument "value"')
    }
    for (i = 0; i < end - start; ++i) {
      this[i + start] = bytes[i % len]
    }
  }

  return this
}

// HELPER FUNCTIONS
// ================

var INVALID_BASE64_RE = /[^+/0-9A-Za-z-_]/g

function base64clean (str) {
  // Node takes equal signs as end of the Base64 encoding
  str = str.split('=')[0]
  // Node strips out invalid characters like \n and \t from the string, base64-js does not
  str = str.trim().replace(INVALID_BASE64_RE, '')
  // Node converts strings with length < 2 to ''
  if (str.length < 2) return ''
  // Node allows for non-padded base64 strings (missing trailing ===), base64-js does not
  while (str.length % 4 !== 0) {
    str = str + '='
  }
  return str
}

function utf8ToBytes (string, units) {
  units = units || Infinity
  var codePoint
  var length = string.length
  var leadSurrogate = null
  var bytes = []

  for (var i = 0; i < length; ++i) {
    codePoint = string.charCodeAt(i)

    // is surrogate component
    if (codePoint > 0xD7FF && codePoint < 0xE000) {
      // last char was a lead
      if (!leadSurrogate) {
        // no lead yet
        if (codePoint > 0xDBFF) {
          // unexpected trail
          if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
          continue
        } else if (i + 1 === length) {
          // unpaired lead
          if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
          continue
        }

        // valid lead
        leadSurrogate = codePoint

        continue
      }

      // 2 leads in a row
      if (codePoint < 0xDC00) {
        if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
        leadSurrogate = codePoint
        continue
      }

      // valid surrogate pair
      codePoint = (leadSurrogate - 0xD800 << 10 | codePoint - 0xDC00) + 0x10000
    } else if (leadSurrogate) {
      // valid bmp char, but last char was a lead
      if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
    }

    leadSurrogate = null

    // encode utf8
    if (codePoint < 0x80) {
      if ((units -= 1) < 0) break
      bytes.push(codePoint)
    } else if (codePoint < 0x800) {
      if ((units -= 2) < 0) break
      bytes.push(
        codePoint >> 0x6 | 0xC0,
        codePoint & 0x3F | 0x80
      )
    } else if (codePoint < 0x10000) {
      if ((units -= 3) < 0) break
      bytes.push(
        codePoint >> 0xC | 0xE0,
        codePoint >> 0x6 & 0x3F | 0x80,
        codePoint & 0x3F | 0x80
      )
    } else if (codePoint < 0x110000) {
      if ((units -= 4) < 0) break
      bytes.push(
        codePoint >> 0x12 | 0xF0,
        codePoint >> 0xC & 0x3F | 0x80,
        codePoint >> 0x6 & 0x3F | 0x80,
        codePoint & 0x3F | 0x80
      )
    } else {
      throw new Error('Invalid code point')
    }
  }

  return bytes
}

function asciiToBytes (str) {
  var byteArray = []
  for (var i = 0; i < str.length; ++i) {
    // Node's code seems to be doing this and not & 0x7F..
    byteArray.push(str.charCodeAt(i) & 0xFF)
  }
  return byteArray
}

function utf16leToBytes (str, units) {
  var c, hi, lo
  var byteArray = []
  for (var i = 0; i < str.length; ++i) {
    if ((units -= 2) < 0) break

    c = str.charCodeAt(i)
    hi = c >> 8
    lo = c % 256
    byteArray.push(lo)
    byteArray.push(hi)
  }

  return byteArray
}

function base64ToBytes (str) {
  return base64.toByteArray(base64clean(str))
}

function blitBuffer (src, dst, offset, length) {
  for (var i = 0; i < length; ++i) {
    if ((i + offset >= dst.length) || (i >= src.length)) break
    dst[i + offset] = src[i]
  }
  return i
}

// ArrayBuffer or Uint8Array objects from other contexts (i.e. iframes) do not pass
// the `instanceof` check but they should be treated as of that type.
// See: https://github.com/feross/buffer/issues/166
function isInstance (obj, type) {
  return obj instanceof type ||
    (obj != null && obj.constructor != null && obj.constructor.name != null &&
      obj.constructor.name === type.name)
}
function numberIsNaN (obj) {
  // For IE11 support
  return obj !== obj // eslint-disable-line no-self-compare
}

// Create lookup table for `toString('hex')`
// See: https://github.com/feross/buffer/issues/219
var hexSliceLookupTable = (function () {
  var alphabet = '0123456789abcdef'
  var table = new Array(256)
  for (var i = 0; i < 16; ++i) {
    var i16 = i * 16
    for (var j = 0; j < 16; ++j) {
      table[i16 + j] = alphabet[i] + alphabet[j]
    }
  }
  return table
})()

}).call(this,require("buffer").Buffer)

},{"base64-js":157,"buffer":159,"ieee754":160}],159:[function(require,module,exports){
(function (global){
/*
 * Short-circuit auto-detection in the buffer module to avoid a Duktape
 * compatibility issue with __proto__.
 */
global.TYPED_ARRAY_SUPPORT = true;

module.exports = require('buffer/');

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})

},{"buffer/":158}],160:[function(require,module,exports){
exports.read = function (buffer, offset, isLE, mLen, nBytes) {
  var e, m
  var eLen = (nBytes * 8) - mLen - 1
  var eMax = (1 << eLen) - 1
  var eBias = eMax >> 1
  var nBits = -7
  var i = isLE ? (nBytes - 1) : 0
  var d = isLE ? -1 : 1
  var s = buffer[offset + i]

  i += d

  e = s & ((1 << (-nBits)) - 1)
  s >>= (-nBits)
  nBits += eLen
  for (; nBits > 0; e = (e * 256) + buffer[offset + i], i += d, nBits -= 8) {}

  m = e & ((1 << (-nBits)) - 1)
  e >>= (-nBits)
  nBits += mLen
  for (; nBits > 0; m = (m * 256) + buffer[offset + i], i += d, nBits -= 8) {}

  if (e === 0) {
    e = 1 - eBias
  } else if (e === eMax) {
    return m ? NaN : ((s ? -1 : 1) * Infinity)
  } else {
    m = m + Math.pow(2, mLen)
    e = e - eBias
  }
  return (s ? -1 : 1) * m * Math.pow(2, e - mLen)
}

exports.write = function (buffer, value, offset, isLE, mLen, nBytes) {
  var e, m, c
  var eLen = (nBytes * 8) - mLen - 1
  var eMax = (1 << eLen) - 1
  var eBias = eMax >> 1
  var rt = (mLen === 23 ? Math.pow(2, -24) - Math.pow(2, -77) : 0)
  var i = isLE ? 0 : (nBytes - 1)
  var d = isLE ? 1 : -1
  var s = value < 0 || (value === 0 && 1 / value < 0) ? 1 : 0

  value = Math.abs(value)

  if (isNaN(value) || value === Infinity) {
    m = isNaN(value) ? 1 : 0
    e = eMax
  } else {
    e = Math.floor(Math.log(value) / Math.LN2)
    if (value * (c = Math.pow(2, -e)) < 1) {
      e--
      c *= 2
    }
    if (e + eBias >= 1) {
      value += rt / c
    } else {
      value += rt * Math.pow(2, 1 - eBias)
    }
    if (value * c >= 2) {
      e++
      c /= 2
    }

    if (e + eBias >= eMax) {
      m = 0
      e = eMax
    } else if (e + eBias >= 1) {
      m = ((value * c) - 1) * Math.pow(2, mLen)
      e = e + eBias
    } else {
      m = value * Math.pow(2, eBias - 1) * Math.pow(2, mLen)
      e = 0
    }
  }

  for (; mLen >= 8; buffer[offset + i] = m & 0xff, i += d, m /= 256, mLen -= 8) {}

  e = (e << mLen) | m
  eLen += mLen
  for (; eLen > 0; buffer[offset + i] = e & 0xff, i += d, e /= 256, eLen -= 8) {}

  buffer[offset + i - d] |= s * 128
}

},{}]},{},[2])
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uLy4uLy4uLy4uLy4uL3Vzci9sb2NhbC9saWIvbm9kZV9tb2R1bGVzL2ZyaWRhLWNvbXBpbGUvbm9kZV9tb2R1bGVzL2Jyb3dzZXItcGFjay9fcHJlbHVkZS5qcyIsImZyaWRhLmpzIiwiamF2YV9ob29rcy5qcyIsIi4uLy4uLy4uL25vZGVfbW9kdWxlcy9AYmFiZWwvcnVudGltZS1jb3JlanMyL2NvcmUtanMvYXJyYXkvZnJvbS5qcyIsIi4uLy4uLy4uL25vZGVfbW9kdWxlcy9AYmFiZWwvcnVudGltZS1jb3JlanMyL2NvcmUtanMvYXJyYXkvaXMtYXJyYXkuanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvQGJhYmVsL3J1bnRpbWUtY29yZWpzMi9jb3JlLWpzL2dldC1pdGVyYXRvci5qcyIsIi4uLy4uLy4uL25vZGVfbW9kdWxlcy9AYmFiZWwvcnVudGltZS1jb3JlanMyL2NvcmUtanMvbnVtYmVyL2lzLWludGVnZXIuanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvQGJhYmVsL3J1bnRpbWUtY29yZWpzMi9jb3JlLWpzL29iamVjdC9hc3NpZ24uanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvQGJhYmVsL3J1bnRpbWUtY29yZWpzMi9jb3JlLWpzL29iamVjdC9jcmVhdGUuanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvQGJhYmVsL3J1bnRpbWUtY29yZWpzMi9jb3JlLWpzL29iamVjdC9kZWZpbmUtcHJvcGVydGllcy5qcyIsIi4uLy4uLy4uL25vZGVfbW9kdWxlcy9AYmFiZWwvcnVudGltZS1jb3JlanMyL2NvcmUtanMvb2JqZWN0L2RlZmluZS1wcm9wZXJ0eS5qcyIsIi4uLy4uLy4uL25vZGVfbW9kdWxlcy9AYmFiZWwvcnVudGltZS1jb3JlanMyL2NvcmUtanMvb2JqZWN0L2dldC1vd24tcHJvcGVydHktbmFtZXMuanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvQGJhYmVsL3J1bnRpbWUtY29yZWpzMi9jb3JlLWpzL29iamVjdC9nZXQtcHJvdG90eXBlLW9mLmpzIiwiLi4vLi4vLi4vbm9kZV9tb2R1bGVzL0BiYWJlbC9ydW50aW1lLWNvcmVqczIvY29yZS1qcy9vYmplY3Qva2V5cy5qcyIsIi4uLy4uLy4uL25vZGVfbW9kdWxlcy9AYmFiZWwvcnVudGltZS1jb3JlanMyL2NvcmUtanMvb2JqZWN0L3NldC1wcm90b3R5cGUtb2YuanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvQGJhYmVsL3J1bnRpbWUtY29yZWpzMi9jb3JlLWpzL3BhcnNlLWludC5qcyIsIi4uLy4uLy4uL25vZGVfbW9kdWxlcy9AYmFiZWwvcnVudGltZS1jb3JlanMyL2NvcmUtanMvcmVmbGVjdC9jb25zdHJ1Y3QuanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvQGJhYmVsL3J1bnRpbWUtY29yZWpzMi9jb3JlLWpzL3NldC5qcyIsIi4uLy4uLy4uL25vZGVfbW9kdWxlcy9AYmFiZWwvcnVudGltZS1jb3JlanMyL2NvcmUtanMvc3ltYm9sLmpzIiwiLi4vLi4vLi4vbm9kZV9tb2R1bGVzL0BiYWJlbC9ydW50aW1lLWNvcmVqczIvaGVscGVycy9jb25zdHJ1Y3QuanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvQGJhYmVsL3J1bnRpbWUtY29yZWpzMi9oZWxwZXJzL2NyZWF0ZUNsYXNzLmpzIiwiLi4vLi4vLi4vbm9kZV9tb2R1bGVzL0BiYWJlbC9ydW50aW1lLWNvcmVqczIvaGVscGVycy9pbmhlcml0c0xvb3NlLmpzIiwiLi4vLi4vLi4vbm9kZV9tb2R1bGVzL0BiYWJlbC9ydW50aW1lLWNvcmVqczIvaGVscGVycy9pbnRlcm9wUmVxdWlyZURlZmF1bHQuanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvQGJhYmVsL3J1bnRpbWUtY29yZWpzMi9oZWxwZXJzL3NldFByb3RvdHlwZU9mLmpzIiwiLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9mbi9hcnJheS9mcm9tLmpzIiwiLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9mbi9hcnJheS9pcy1hcnJheS5qcyIsIi4uLy4uLy4uL25vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvZm4vZ2V0LWl0ZXJhdG9yLmpzIiwiLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9mbi9udW1iZXIvaXMtaW50ZWdlci5qcyIsIi4uLy4uLy4uL25vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvZm4vb2JqZWN0L2Fzc2lnbi5qcyIsIi4uLy4uLy4uL25vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvZm4vb2JqZWN0L2NyZWF0ZS5qcyIsIi4uLy4uLy4uL25vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvZm4vb2JqZWN0L2RlZmluZS1wcm9wZXJ0aWVzLmpzIiwiLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9mbi9vYmplY3QvZGVmaW5lLXByb3BlcnR5LmpzIiwiLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9mbi9vYmplY3QvZ2V0LW93bi1wcm9wZXJ0eS1uYW1lcy5qcyIsIi4uLy4uLy4uL25vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvZm4vb2JqZWN0L2dldC1wcm90b3R5cGUtb2YuanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L2ZuL29iamVjdC9rZXlzLmpzIiwiLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9mbi9vYmplY3Qvc2V0LXByb3RvdHlwZS1vZi5qcyIsIi4uLy4uLy4uL25vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvZm4vcGFyc2UtaW50LmpzIiwiLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9mbi9yZWZsZWN0L2NvbnN0cnVjdC5qcyIsIi4uLy4uLy4uL25vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvZm4vc2V0LmpzIiwiLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9mbi9zeW1ib2wvaW5kZXguanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX2EtZnVuY3Rpb24uanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX2FkZC10by11bnNjb3BhYmxlcy5qcyIsIi4uLy4uLy4uL25vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9fYW4taW5zdGFuY2UuanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX2FuLW9iamVjdC5qcyIsIi4uLy4uLy4uL25vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9fYXJyYXktZnJvbS1pdGVyYWJsZS5qcyIsIi4uLy4uLy4uL25vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9fYXJyYXktaW5jbHVkZXMuanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX2FycmF5LW1ldGhvZHMuanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX2FycmF5LXNwZWNpZXMtY29uc3RydWN0b3IuanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX2FycmF5LXNwZWNpZXMtY3JlYXRlLmpzIiwiLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19iaW5kLmpzIiwiLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19jbGFzc29mLmpzIiwiLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19jb2YuanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX2NvbGxlY3Rpb24tc3Ryb25nLmpzIiwiLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19jb2xsZWN0aW9uLXRvLWpzb24uanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX2NvbGxlY3Rpb24uanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX2NvcmUuanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX2NyZWF0ZS1wcm9wZXJ0eS5qcyIsIi4uLy4uLy4uL25vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9fY3R4LmpzIiwiLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19kZWZpbmVkLmpzIiwiLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19kZXNjcmlwdG9ycy5qcyIsIi4uLy4uLy4uL25vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9fZG9tLWNyZWF0ZS5qcyIsIi4uLy4uLy4uL25vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9fZW51bS1idWcta2V5cy5qcyIsIi4uLy4uLy4uL25vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9fZW51bS1rZXlzLmpzIiwiLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19leHBvcnQuanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX2ZhaWxzLmpzIiwiLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19mb3Itb2YuanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX2dsb2JhbC5qcyIsIi4uLy4uLy4uL25vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9faGFzLmpzIiwiLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19oaWRlLmpzIiwiLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19odG1sLmpzIiwiLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19pZTgtZG9tLWRlZmluZS5qcyIsIi4uLy4uLy4uL25vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9faW52b2tlLmpzIiwiLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19pb2JqZWN0LmpzIiwiLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19pcy1hcnJheS1pdGVyLmpzIiwiLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19pcy1hcnJheS5qcyIsIi4uLy4uLy4uL25vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9faXMtaW50ZWdlci5qcyIsIi4uLy4uLy4uL25vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9faXMtb2JqZWN0LmpzIiwiLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19pdGVyLWNhbGwuanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX2l0ZXItY3JlYXRlLmpzIiwiLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19pdGVyLWRlZmluZS5qcyIsIi4uLy4uLy4uL25vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9faXRlci1kZXRlY3QuanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX2l0ZXItc3RlcC5qcyIsIi4uLy4uLy4uL25vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9faXRlcmF0b3JzLmpzIiwiLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19saWJyYXJ5LmpzIiwiLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19tZXRhLmpzIiwiLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19vYmplY3QtYXNzaWduLmpzIiwiLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19vYmplY3QtY3JlYXRlLmpzIiwiLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19vYmplY3QtZHAuanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX29iamVjdC1kcHMuanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX29iamVjdC1nb3BkLmpzIiwiLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19vYmplY3QtZ29wbi1leHQuanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX29iamVjdC1nb3BuLmpzIiwiLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19vYmplY3QtZ29wcy5qcyIsIi4uLy4uLy4uL25vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9fb2JqZWN0LWdwby5qcyIsIi4uLy4uLy4uL25vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9fb2JqZWN0LWtleXMtaW50ZXJuYWwuanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX29iamVjdC1rZXlzLmpzIiwiLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19vYmplY3QtcGllLmpzIiwiLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19vYmplY3Qtc2FwLmpzIiwiLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19wYXJzZS1pbnQuanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX3Byb3BlcnR5LWRlc2MuanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX3JlZGVmaW5lLWFsbC5qcyIsIi4uLy4uLy4uL25vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9fcmVkZWZpbmUuanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX3NldC1jb2xsZWN0aW9uLWZyb20uanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX3NldC1jb2xsZWN0aW9uLW9mLmpzIiwiLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19zZXQtcHJvdG8uanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX3NldC1zcGVjaWVzLmpzIiwiLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19zZXQtdG8tc3RyaW5nLXRhZy5qcyIsIi4uLy4uLy4uL25vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9fc2hhcmVkLWtleS5qcyIsIi4uLy4uLy4uL25vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9fc2hhcmVkLmpzIiwiLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19zdHJpbmctYXQuanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX3N0cmluZy10cmltLmpzIiwiLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL19zdHJpbmctd3MuanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX3RvLWFic29sdXRlLWluZGV4LmpzIiwiLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL190by1pbnRlZ2VyLmpzIiwiLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL190by1pb2JqZWN0LmpzIiwiLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL190by1sZW5ndGguanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX3RvLW9iamVjdC5qcyIsIi4uLy4uLy4uL25vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9fdG8tcHJpbWl0aXZlLmpzIiwiLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL191aWQuanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX3ZhbGlkYXRlLWNvbGxlY3Rpb24uanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX3drcy1kZWZpbmUuanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX3drcy1leHQuanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvX3drcy5qcyIsIi4uLy4uLy4uL25vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9jb3JlLmdldC1pdGVyYXRvci1tZXRob2QuanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvY29yZS5nZXQtaXRlcmF0b3IuanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvZXM2LmFycmF5LmZyb20uanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvZXM2LmFycmF5LmlzLWFycmF5LmpzIiwiLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL2VzNi5hcnJheS5pdGVyYXRvci5qcyIsIi4uLy4uLy4uL25vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9lczYubnVtYmVyLmlzLWludGVnZXIuanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvZXM2Lm9iamVjdC5hc3NpZ24uanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvZXM2Lm9iamVjdC5jcmVhdGUuanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvZXM2Lm9iamVjdC5kZWZpbmUtcHJvcGVydGllcy5qcyIsIi4uLy4uLy4uL25vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9lczYub2JqZWN0LmRlZmluZS1wcm9wZXJ0eS5qcyIsIi4uLy4uLy4uL25vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9lczYub2JqZWN0LmdldC1vd24tcHJvcGVydHktbmFtZXMuanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvZXM2Lm9iamVjdC5nZXQtcHJvdG90eXBlLW9mLmpzIiwiLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL2VzNi5vYmplY3Qua2V5cy5qcyIsIi4uLy4uLy4uL25vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9lczYub2JqZWN0LnNldC1wcm90b3R5cGUtb2YuanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvZXM2Lm9iamVjdC50by1zdHJpbmcuanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvZXM2LnBhcnNlLWludC5qcyIsIi4uLy4uLy4uL25vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9lczYucmVmbGVjdC5jb25zdHJ1Y3QuanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvZXM2LnNldC5qcyIsIi4uLy4uLy4uL25vZGVfbW9kdWxlcy9jb3JlLWpzL2xpYnJhcnkvbW9kdWxlcy9lczYuc3RyaW5nLml0ZXJhdG9yLmpzIiwiLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL2VzNi5zeW1ib2wuanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvZXM3LnNldC5mcm9tLmpzIiwiLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL2VzNy5zZXQub2YuanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvZXM3LnNldC50by1qc29uLmpzIiwiLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL2VzNy5zeW1ib2wuYXN5bmMtaXRlcmF0b3IuanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvY29yZS1qcy9saWJyYXJ5L21vZHVsZXMvZXM3LnN5bWJvbC5vYnNlcnZhYmxlLmpzIiwiLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2NvcmUtanMvbGlicmFyeS9tb2R1bGVzL3dlYi5kb20uaXRlcmFibGUuanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvZnJpZGEtamF2YS9saWIvYW5kcm9pZC5qcyIsIi4uLy4uLy4uL25vZGVfbW9kdWxlcy9mcmlkYS1qYXZhL2xpYi9hcGkuanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvZnJpZGEtamF2YS9saWIvY2xhc3MtZmFjdG9yeS5qcyIsIi4uLy4uLy4uL25vZGVfbW9kdWxlcy9mcmlkYS1qYXZhL2xpYi9lbnYuanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvZnJpZGEtamF2YS9saWIvbWtkZXguanMiLCIuLi8uLi8uLi9ub2RlX21vZHVsZXMvZnJpZGEtamF2YS9saWIvcmVzdWx0LmpzIiwiLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2ZyaWRhLWphdmEvbGliL3ZtLmpzIiwiLi4vLi4vLi4vbm9kZV9tb2R1bGVzL2pzc2hhL3NyYy9zaGExLmpzIiwiLi4vLi4vLi4vLi4vLi4vdXNyL2xvY2FsL2xpYi9ub2RlX21vZHVsZXMvZnJpZGEtY29tcGlsZS9ub2RlX21vZHVsZXMvYmFzZTY0LWpzL2luZGV4LmpzIiwiLi4vLi4vLi4vLi4vLi4vdXNyL2xvY2FsL2xpYi9ub2RlX21vZHVsZXMvZnJpZGEtY29tcGlsZS9ub2RlX21vZHVsZXMvYnVmZmVyL2luZGV4LmpzIiwiLi4vLi4vLi4vLi4vLi4vdXNyL2xvY2FsL2xpYi9ub2RlX21vZHVsZXMvZnJpZGEtY29tcGlsZS9ub2RlX21vZHVsZXMvZnJpZGEtYnVmZmVyL2luZGV4LmpzIiwiLi4vLi4vLi4vLi4vLi4vdXNyL2xvY2FsL2xpYi9ub2RlX21vZHVsZXMvZnJpZGEtY29tcGlsZS9ub2RlX21vZHVsZXMvaWVlZTc1NC9pbmRleC5qcyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQTtBQ0FBOzs7Ozs7Ozs7Ozs7Ozs7OztBQWtCQTtBQUNBLE1BQU0sT0FBTyxHQUFHLENBQWhCO0FBQ0EsTUFBTSxRQUFRLEdBQUcsRUFBakI7QUFFQSxNQUFNLFVBQVUsR0FBRyxDQUFuQjtBQUNBLE1BQU0sT0FBTyxHQUFHLENBQWhCO0FBQ0EsTUFBTSxXQUFXLEdBQUcsQ0FBcEI7QUFDQSxNQUFNLFVBQVUsR0FBRyxDQUFuQjtBQUVBOztBQUNBLE1BQU0sUUFBUSxHQUFHLENBQWpCO0FBRUE7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QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDbENBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDbkJBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNSQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNOQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDWEE7QUFDQTtBQUNBO0FBQ0E7O0FDSEE7QUFDQTtBQUNBOztBQ0ZBO0FBQ0E7QUFDQTtBQUNBOztBQ0hBO0FBQ0E7QUFDQTs7QUNGQTtBQUNBO0FBQ0E7O0FDRkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ0xBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNMQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDTEE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ0xBO0FBQ0E7QUFDQTs7QUNGQTtBQUNBO0FBQ0E7O0FDRkE7QUFDQTtBQUNBOztBQ0ZBO0FBQ0E7QUFDQTs7QUNGQTtBQUNBO0FBQ0E7O0FDRkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ1JBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNMQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ0pBO0FBQ0E7O0FDREE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ0xBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNMQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ1BBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUN2QkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQzVDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ2hCQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNOQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ3pCQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDdkJBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNMQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNoSkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDVEE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQzNEQTtBQUNBO0FBQ0E7O0FDRkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ1JBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNwQkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ0xBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDSkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNQQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ0pBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ2ZBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUM5REE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNQQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ3pCQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNOQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ0pBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNSQTtBQUNBO0FBQ0E7O0FDRkE7QUFDQTtBQUNBO0FBQ0E7O0FDSEE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNoQkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDTkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ1JBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNMQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNOQTtBQUNBO0FBQ0E7QUFDQTs7QUNIQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNaQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ2JBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ3JFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ3RCQTtBQUNBO0FBQ0E7QUFDQTs7QUNIQTtBQUNBOztBQ0RBO0FBQ0E7O0FDREE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ3JEQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDdENBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUN6Q0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNoQkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNiQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ2hCQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ25CQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ1BBO0FBQ0E7O0FDREE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNiQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDakJBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDUEE7QUFDQTs7QUNEQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ1ZBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ1RBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNSQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ1BBO0FBQ0E7O0FDREE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUM1QkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDWkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUN6QkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ2RBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDUEE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ0xBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ1pBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNqQkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDOUJBO0FBQ0E7QUFDQTs7QUNGQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ1BBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ05BO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ05BO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ05BO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNMQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNaQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDTEE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ0xBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ1RBO0FBQ0E7O0FDREE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ1hBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNSQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ1BBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDckNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDSkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNsQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNKQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ0pBO0FBQ0E7QUFDQTtBQUNBOztBQ0hBO0FBQ0E7QUFDQTtBQUNBOztBQ0hBO0FBQ0E7QUFDQTtBQUNBOztBQ0hBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDSkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDVEE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDVEE7QUFDQTtBQUNBO0FBQ0E7O0FDSEE7O0FDQUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNKQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDL0NBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNkQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDakJBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ3RQQTtBQUNBO0FBQ0E7O0FDRkE7QUFDQTtBQUNBOztBQ0ZBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDSkE7QUFDQTs7QUNEQTtBQUNBOztBQ0RBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7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QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOzs7QUN4SkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOzs7OztBQ3Z3REE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7OztBQ1BBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBIiwiZmlsZSI6ImdlbmVyYXRlZC5qcyIsInNvdXJjZVJvb3QiOiIifQ==
