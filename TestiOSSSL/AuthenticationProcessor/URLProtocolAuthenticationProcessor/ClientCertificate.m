/*
 Licensed to the Apache Software Foundation (ASF) under one
 or more contributor license agreements.  See the NOTICE file
 distributed with this work for additional information
 regarding copyright ownership.  The ASF licenses this file
 to you under the Apache License, Version 2.0 (the
 "License"); you may not use this file except in compliance
 with the License.  You may obtain a copy of the License at
 
 http://www.apache.org/licenses/LICENSE-2.0
 
 Unless required by applicable law or agreed to in writing,
 software distributed under the License is distributed on an
 "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 KIND, either express or implied.  See the License for the
 specific language governing permissions and limitations
 under the License.
 */

#include <sys/types.h>
#include <sys/sysctl.h>
#include "TargetConditionals.h"

#import <Cordova/CDV.h>
#import "ClientCertificate.h"

#import "FDTURLProtocolAuthenticationProcessor.h"

@interface ClientCertificate ()

@end

@implementation ClientCertificate {
    FDTURLProtocolAuthenticationProcessor *authenticationProcessor;
}

- (void)pluginInitialize {
    authenticationProcessor = [[FDTURLProtocolAuthenticationProcessor alloc] init];
}

- (void)registerAuthenticationCertificate:(CDVInvokedUrlCommand*)command {
    
    NSString* path = [command argumentAtIndex:0];
    NSString* password = [command argumentAtIndex:1];

    if ([[NSFileManager defaultManager] fileExistsAtPath:path]) {
        NSData *PKCS12Data = [NSData dataWithContentsOfFile:path];
        authenticationProcessor.clientPKCS12CertificateData = PKCS12Data;
    } else {
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR
                                                          messageAsString:@"Client certificate not exists!"];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
        return;
    }

    authenticationProcessor.clientCertificatePassphrase = password;
    
    NSString *errMsg = [authenticationProcessor registerAuthenticationCertificate];

    if (errMsg) {
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR
                                                          messageAsString:errMsg];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
        return;
    }
    
    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

- (void)validateSslChain:(CDVInvokedUrlCommand*)command {
    BOOL validateSslChain = [command argumentAtIndex:0];
    [authenticationProcessor validateSSlChain:validateSslChain];

    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}


@end
