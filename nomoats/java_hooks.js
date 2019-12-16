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
var JAVA_EXCEPTION;

// TODO: ideally all msg types should be in a separate module
const TYPE_LIB  = "lib";

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
            var res = classLoaders[i].findClass(classOfInterest); 
            //console.log("Done: " + classLoaders[i]);
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
        const ContentsClientAdapter = customClassFactory.use(classOfInterest);

        // TODO: if app crashes - restart with Frida
        ContentsClientAdapter.shouldInterceptRequest.implementation = function(params) {
            //console.log("shouldInterceptRequest: " + this.mWebViewClient.value);
            
            const retVal = ContentsClientAdapter.shouldInterceptRequest.call(this, params);
            
            // We only care about network requests:
            const url = params.url.value.toString();            
            if (!url.startsWith("http")) {
                //mf.sendInfoToPython("Skipping resource: " + url);
                return retVal;
            }
            
            const headersMap = params.requestHeaders.value;
            const keySet = headersMap.keySet().toArray();
            var headers = {};
            for (var i = 0; i < keySet.length; i++)
                headers[keySet[i]] = headersMap.get(keySet[i]).toString();
            
            var message = new mf.PythonMsg(TYPE_WEB_INTC);
            message.url = url;
            message.headers = headers;
            message.method = params.method.value.toString();
            
            if (webViewClients[this.mWebViewClient.value] == null)
                mf.sendInfoToPython("NO TRACE for: " + this.mWebViewClient.value);
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
    message.containsSSL = false;
    
    
    // Check if the library contains SSL functions, and if so, attach
    var sslWriteCustom = Module.findExportByName(moduleName, mf.sslWrite);       
    if (sslWriteCustom != null && !sslWriteCustom.equals(Module.findExportByName(mf.libSSL, mf.sslWrite))) {
        Interceptor.attach(sslWriteCustom, new mf.SSLcallback(moduleName + ":" + mf.sslWrite));
        mf.sendInfoToPython(moduleName + " contains SSL");
        message.containsSSL = true;
    }
    
    send(message);
}

// Catch any early NDK libraries loading
// using performNow - see note on https://github.com/frida/frida-java/issues/89
Java.performNow(function() {    
    // Prepare Java objects for future use:
    JAVA_LOG = Java.use("android.util.Log");
    JAVA_EXCEPTION = Java.use("java.lang.Exception");    
    mf.init(Java.use("java.lang.Thread"));
    
    // Catch native library loading
    // TODO: possibly hook dlopen as well
    // See https://github.com/frida/frida/issues/448
    const System = Java.use('java.lang.System');
    const Runtime = Java.use('java.lang.Runtime');
    const VMStack = Java.use('dalvik.system.VMStack');
    
    System.load.implementation = function(pathName) {
        var loaded = false;
        try {
            loaded = Runtime.getRuntime().load0(VMStack.getStackClass1(), pathName);
        } catch(ex) {
            console.log(ex);
            return loaded;
        }
        
        const Java_File = Java.use("java.io.File");
        const moduleName = Java_File.$new(pathName).getName();
        processNativeLib(moduleName);
        return loaded;
    };

    System.loadLibrary.implementation = function(library) {
        var loaded = false;
        try {
            loaded = Runtime.getRuntime().loadLibrary0(VMStack.getCallingClassLoader(), library);            
        } catch(ex) {
            console.log(ex);
            return loaded;
        }
        
        // Libraries get prefixed with 'lib' and suffixed with the .so extension:
        const moduleName = "lib" + library + ".so";
        processNativeLib(moduleName);
        return loaded;
    };  
    
    const webViewClientClass = 'android.webkit.WebViewClient';
    const WebViewClient = Java.use(webViewClientClass);
    WebViewClient.$init.implementation = function() {
        
        const trace = JAVA_LOG.getStackTraceString(JAVA_EXCEPTION.$new());
        const res = this.$init();
        console.log("Constructor called " + this.$className + ":" + (this in webViewClients));
        webViewClients[this] = trace;
        
        if (!WEB_VIEW_INIT_DONE)
            interceptRequest();
    
        return res;
    }; 
    
    mf.sendInfoToPython("Java loaded");
});
