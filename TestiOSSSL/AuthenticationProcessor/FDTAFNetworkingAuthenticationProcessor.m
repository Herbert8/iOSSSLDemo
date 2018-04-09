//
//  FDTAuthenticationProcessor.m
//  TestiOSSSL
//
//  Created by 巴宏斌 on 2018/4/7.
//  Copyright © 2018年 巴宏斌. All rights reserved.
//

#import "FDTAFNetworkingAuthenticationProcessor.h"


@interface FDTAFNetworkingAuthenticationProcessor ()


@end

@implementation FDTAFNetworkingAuthenticationProcessor



- (NSURLSessionAuthChallengeDisposition)sessionManager:(AFHTTPSessionManager *)sessionManager
                                   didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
                                            credential:(NSURLCredential *__autoreleasing *)credential {

    // 初始化返回值
    NSURLSessionAuthChallengeDisposition disposition = NSURLSessionAuthChallengePerformDefaultHandling;
    NSURLCredential *credentialRet = nil;


    // 通过标识，判断是服务端认证的话，处理服务端认证
    if ([self isAuthenticationMethodServerTrust:challenge]) {

        NSURLProtectionSpace *protectionSpace = challenge.protectionSpace;

        // 根据安全策略是否接受指定的服务器信任。响应来自服务器的身份验证质询时应使用此方法。
        if ([sessionManager.securityPolicy evaluateServerTrust:protectionSpace.serverTrust
                                                     forDomain:protectionSpace.host]) {

            disposition = [self processAuthenticationChallengeForServerTrust:challenge
                                                               forCredential:&credentialRet];
        } else {
            // 如果不接受服务端凭证，则取消
            // 认证失败会走这个分支
            disposition = NSURLSessionAuthChallengeCancelAuthenticationChallenge;
        }

    } else if ([self isAuthenticationMethodClientCertificate:challenge]) {
        // 处理客户端认证
        disposition = [self processAuthenticationChallengeForClientCertificate:challenge
                                                                 forCredential:&credentialRet];
    }

    *credential = credentialRet;

    return disposition;
}

@end
