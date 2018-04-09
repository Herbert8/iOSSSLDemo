//
//  FDTURLSessionAuthenticationProcessor.m
//  TestiOSSSL
//
//  Created by 巴宏斌 on 2018/4/7.
//  Copyright © 2018年 巴宏斌. All rights reserved.
//

#import "FDTAuthenticationProcessor.h"

@implementation FDTAuthenticationProcessor


- (instancetype)init {
    if (self = [super init]) {
        self.clientCertificatePassphrase = @"";
    }
    return self;
}

#pragma mark 判断是否为服务端授权质询
/**
 challenge.protectionSpace.authenticationMethod 包含认证方式：
 NSURLAuthenticationMethodClientCertificate  表示认证方式为客户端认证
 NSURLAuthenticationMethodServerTrust  表示认证方式为服务端认证
 */
- (BOOL)isAuthenticationMethodServerTrust:(NSURLAuthenticationChallenge *)challenge {
    return [NSURLAuthenticationMethodServerTrust isEqualToString:challenge.protectionSpace.authenticationMethod];
}

#pragma mark 判断是否为客户端授权质询
- (BOOL)isAuthenticationMethodClientCertificate:(NSURLAuthenticationChallenge *)challenge {
    return [NSURLAuthenticationMethodClientCertificate isEqualToString:challenge.protectionSpace.authenticationMethod];
}

#pragma mark 处理服务端授权质询
- (NSURLSessionAuthChallengeDisposition)processAuthenticationChallengeForServerTrust:(NSURLAuthenticationChallenge *)challenge
                                                                    forCredential:(NSURLCredential *__autoreleasing *)credential {

    NSURLSessionAuthChallengeDisposition disposition = NSURLSessionAuthChallengePerformDefaultHandling;
    NSURLCredential *credentialRet = nil;

    if ([self isAuthenticationMethodServerTrust:challenge]) {
        //创建并返回 NSURLCredential 对象，以使用给定的接受信任进行服务器信任认证。
        credentialRet = [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust];

        if (credentialRet) {
            // 如果创建 Credential（凭证）成功，则使用
            disposition = NSURLSessionAuthChallengeUseCredential;
        } else {
            // 如果创建 Credential（凭证）失败，则使用默认值
            disposition = NSURLSessionAuthChallengePerformDefaultHandling;
        }
    }

    *credential = credentialRet;
    return disposition;
}

# pragma mark 从 P12 证书中提取 Identity 和 Trust
- (BOOL)extractIdentity:(SecIdentityRef *)outIdentity
               andTrust:(SecTrustRef *)outTrust
         fromPKCS12Data:(NSData *)inPKCS12Data {

    OSStatus securityError = errSecSuccess;

    // 创建包含客户端证书密码的 字典
    NSDictionary *optionsDictionary = @{(__bridge id)kSecImportExportPassphrase: self.clientCertificatePassphrase};


    // 创建 items 数组，将证书中的信息存到数组中
    CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
    securityError = SecPKCS12Import((__bridge CFDataRef)inPKCS12Data,
                                    (__bridge CFDictionaryRef)optionsDictionary,
                                    &items);
    // 如果从证书中获取信息成功
    if (securityError == 0) {
        // 从包含证书信息的数组中，获取第一项，类型为一个字典，其中包含 Identity 与 Trust 信息
        CFDictionaryRef identityAndTrustDictRef = CFArrayGetValueAtIndex(items, 0);
        // 从字典中获取 Identity 信息
        *outIdentity = (SecIdentityRef)CFDictionaryGetValue(identityAndTrustDictRef, kSecImportItemIdentity);
        // 从字典中获取 Trust 信息
        *outTrust = (SecTrustRef)CFDictionaryGetValue(identityAndTrustDictRef, kSecImportItemTrust);
    } else {
        NSLog(@"Failed with error code %d", (int)securityError);
        return NO;
    }

    return YES;
}

#pragma mark 处理客户端授权质询
- (NSURLSessionAuthChallengeDisposition)processAuthenticationChallengeForClientCertificate:(NSURLAuthenticationChallenge *)challenge
                                                                             forCredential:(NSURLCredential *__autoreleasing *)credential {

    NSURLSessionAuthChallengeDisposition disposition = NSURLSessionAuthChallengePerformDefaultHandling;
    NSURLCredential *credentialRet = nil;

    if ([self isAuthenticationMethodClientCertificate:challenge]) {

        SecIdentityRef identity = NULL;
        SecTrustRef trust = NULL;

        NSAssert(self.clientPKCS12CertificateData, @"客户端证书不存在");
        
        NSData *PKCS12Data = self.clientPKCS12CertificateData;

        // 从 P12 证书中，获取 Identify 和 Trust 信息
        if ([self extractIdentity:&identity
                         andTrust:&trust
                   fromPKCS12Data:PKCS12Data]) {

            // 通过 Identify 获取 Certificate
            SecCertificateRef certificate = NULL;
            SecIdentityCopyCertificate(identity, &certificate);
            // 将 Certificate 放入数组
            const void *certs[] = {certificate};
            CFArrayRef certArray = CFArrayCreate(kCFAllocatorDefault, certs, 1, NULL);
            // 使用 Identify 和 Certificate 数组 得到 Credentia
            credentialRet = [NSURLCredential credentialWithIdentity:identity
                                                       certificates:(__bridge  NSArray*)certArray
                                                        persistence:NSURLCredentialPersistencePermanent];
            disposition = NSURLSessionAuthChallengeUseCredential;
        }
    }

    *credential = credentialRet;
    return disposition;
}

#pragma mark 伪造一个经过认证的凭据
- (NSURLSessionAuthChallengeDisposition)fakeAuthorizedCredential:(NSURLCredential * __autoreleasing *)credential {

    NSURLCredential *retCredential = nil;

    NSDictionary *query = @{(__bridge id)kSecClass: (__bridge id)kSecClassIdentity,
                            (__bridge id)kSecReturnRef: (__bridge id)kCFBooleanTrue,
                            (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitOne
                            };

    CFTypeRef result = NULL;
    SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    SecIdentityRef myIdentity = (SecIdentityRef)result;

    SecCertificateRef myCertificate;
    if (myIdentity) {
        SecIdentityCopyCertificate(myIdentity, &myCertificate);
        const void *certs[] = { myCertificate };
        CFArrayRef certsArray = CFArrayCreate(NULL, certs, 1, NULL);
        retCredential = [NSURLCredential credentialWithIdentity:myIdentity
                                                   certificates:(__bridge NSArray*)certsArray
                                                    persistence:NSURLCredentialPersistencePermanent];
    }

    *credential = retCredential;

    return NSURLSessionAuthChallengeUseCredential;
}


#pragma mark 处理 URLSession 收到 授权质询 时的回调
- (void)URLSession:(NSURLSession *)session
didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
 completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential * _Nullable))completionHandler {

    NSURLSessionAuthChallengeDisposition disposition = NSURLSessionAuthChallengePerformDefaultHandling;
    NSURLCredential *credential = nil;

    if ([self isAuthenticationMethodServerTrust:challenge]) {
        disposition = [self processAuthenticationChallengeForServerTrust:challenge
                                                           forCredential:&credential];

    } else if ([self isAuthenticationMethodClientCertificate:challenge]) {
        disposition = [self processAuthenticationChallengeForClientCertificate:challenge
                                                                 forCredential:&credential];
    }

    if (completionHandler) {
        completionHandler(disposition, credential);
    }

}


@end
