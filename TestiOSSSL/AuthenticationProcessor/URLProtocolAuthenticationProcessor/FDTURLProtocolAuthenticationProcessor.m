//
//  FDTURLProtocolAuthenticationProcessor.m
//  TestiOSSSL
//
//  Created by 巴宏斌 on 2018/4/7.
//  Copyright © 2018年 巴宏斌. All rights reserved.
//

#include <sys/types.h>
#include <sys/sysctl.h>
#include <TargetConditionals.h>

#import "FDTURLProtocolAuthenticationProcessor.h"




@interface FDTURLProtocolAuthenticationProcessor () <CustomHTTPProtocolDelegate>

@end


@implementation FDTURLProtocolAuthenticationProcessor {
    BOOL validateSslChain;
    NSString* certificatePassword;
}


- (instancetype)init {
    if (self = [super init]) {
        
        validateSslChain = YES;

        // TODO: Check for keychain item, set self as delegate if so

        [CustomHTTPProtocol setDelegate:self];
        [CustomHTTPProtocol start];
    }
    return self;
}


- (NSString *)registerAuthenticationCertificate {

    NSString *retErrMsg = nil;

    //check certificate and password
    SecIdentityRef myIdentity;
    SecTrustRef myTrust;
    OSStatus status = extractIdentityAndTrust(self.clientPKCS12CertificateData,
                                              self.clientCertificatePassphrase,
                                              &myIdentity,
                                              &myTrust);
    if(status != noErr) {
        retErrMsg = @"reading certificate failed.";
        return retErrMsg;
    }

    certificatePassword = self.clientCertificatePassphrase;

    //resgister custom protocol
    [CustomHTTPProtocol setDelegate:self];
    [CustomHTTPProtocol start];

    return retErrMsg;
}



- (void)validateSSlChain:(BOOL)bValidateSSlChain {
    validateSslChain = bValidateSSlChain;
}

- (BOOL)customHTTPProtocol:(CustomHTTPProtocol *)protocol canAuthenticateAgainstProtectionSpace:(NSURLProtectionSpace *)protectionSpace
{
    NSLog(@"canAuthenticateAgainstProtectionSpace: %@", protectionSpace.authenticationMethod);

    if ([protectionSpace authenticationMethod] == NSURLAuthenticationMethodServerTrust) {
        return !validateSslChain;
    } else if ([protectionSpace authenticationMethod] == NSURLAuthenticationMethodClientCertificate) {
        return YES;
    }

    return NO;
}

- (void)customHTTPProtocol:(CustomHTTPProtocol *)protocol didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
{
    if([challenge previousFailureCount] == 0) {

        NSURLCredential *credential = nil;

        if ([self isAuthenticationMethodServerTrust:challenge]) {
            [self processAuthenticationChallengeForServerTrust:challenge
                                                          forCredential:&credential];
        } else if ([self isAuthenticationMethodClientCertificate:challenge]) {

            [self processAuthenticationChallengeForClientCertificate:challenge
                                                                forCredential:&credential];
        }

        [protocol resolveAuthenticationChallenge:challenge withCredential:credential];

    }
}

OSStatus extractIdentityAndTrust(NSData *certData, NSString *pwd, SecIdentityRef *identity, SecTrustRef *trust)
{
    OSStatus securityError = errSecSuccess;
    NSData *PKCS12Data = certData;
    CFDataRef inPKCS12Data = (__bridge CFDataRef)PKCS12Data;
    CFStringRef passwordRef = (__bridge CFStringRef)pwd; // Password for Certificate which client have given

    const void *keys[] =   { kSecImportExportPassphrase };
    const void *values[] = { passwordRef };

    CFDictionaryRef optionsDictionary = CFDictionaryCreate(NULL, keys, values, 1, NULL, NULL);
    CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
    securityError = SecPKCS12Import(inPKCS12Data, optionsDictionary, &items);

    if (securityError == 0) {
        CFDictionaryRef myIdentityAndTrust = CFArrayGetValueAtIndex (items, 0);
        const void *tempIdentity = NULL;
        tempIdentity = CFDictionaryGetValue (myIdentityAndTrust, kSecImportItemIdentity);

        *identity = (SecIdentityRef)tempIdentity;

        const void *tempTrust = NULL;
        tempTrust = CFDictionaryGetValue (myIdentityAndTrust, kSecImportItemTrust);
        *trust = (SecTrustRef)tempTrust;

        SecTrustResultType trustResult;
        OSStatus status = SecTrustEvaluate(*trust, &trustResult);
        if (status == errSecSuccess) {

            // Clear app keychain
            void (^deleteAllKeysForSecClass)(CFTypeRef) = ^(CFTypeRef secClass) {
                id dict = @{(__bridge id)kSecClass: (__bridge id)secClass};
                SecItemDelete((__bridge CFDictionaryRef) dict);
            };
            deleteAllKeysForSecClass(kSecClassIdentity);

            // Persist identity to keychain
            NSMutableDictionary *secIdentityParams = [[NSMutableDictionary alloc] init];
            [secIdentityParams setObject:(__bridge id)tempIdentity forKey:(id)kSecValueRef];
            status = SecItemAdd((CFDictionaryRef) secIdentityParams, NULL);
        }
    }

    if (optionsDictionary) {
        CFRelease(optionsDictionary);
    }

    if (items)
        CFRelease(items);

    return securityError;
}

CFDataRef persistentRefForIdentity(SecIdentityRef identity)
{
    OSStatus status = errSecSuccess;

    CFTypeRef  persistent_ref = NULL;
    const void *keys[] =   { kSecReturnPersistentRef, kSecValueRef };
    const void *values[] = { kCFBooleanTrue,          identity };
    CFDictionaryRef dict = CFDictionaryCreate(NULL, keys, values,
                                              2, NULL, NULL);
    status = SecItemAdd(dict, &persistent_ref);

    if (dict)
        CFRelease(dict);

    return (CFDataRef)persistent_ref;
}

SecIdentityRef identityForPersistentRef(CFDataRef persistent_ref)
{
    CFTypeRef   identity_ref     = NULL;
    const void *keys[] =   { kSecClass, kSecReturnRef,  kSecValuePersistentRef };
    const void *values[] = { kSecClassIdentity, kCFBooleanTrue, persistent_ref };
    CFDictionaryRef dict = CFDictionaryCreate(NULL, keys, values,
                                              3, NULL, NULL);
    SecItemCopyMatching(dict, &identity_ref);

    if (dict)
        CFRelease(dict);

    return (SecIdentityRef)identity_ref;
}


@end
