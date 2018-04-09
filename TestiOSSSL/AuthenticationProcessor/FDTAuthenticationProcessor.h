//
//  FDTURLSessionAuthenticationProcessor.h
//  TestiOSSSL
//
//  Created by 巴宏斌 on 2018/4/7.
//  Copyright © 2018年 巴宏斌. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface FDTAuthenticationProcessor : NSObject


/**
 P12 证书数据
 */
@property (nonatomic, strong, nonnull) NSData *clientPKCS12CertificateData;


/**
 P12 证书密码
 */
@property (nonatomic, copy, nonnull) NSString *clientCertificatePassphrase;


/**
 判断是否为服务端授权质询

 @param challenge 授权质询
 @return 是否为服务端授权质询
 */
- (BOOL)isAuthenticationMethodServerTrust:(nonnull NSURLAuthenticationChallenge *)challenge;



/**
 判断是否为客户端授权质询

 @param challenge 授权质询
 @return 是否为客户端授权质询
 */
- (BOOL)isAuthenticationMethodClientCertificate:(nonnull NSURLAuthenticationChallenge *)challenge;


/**
 伪造一个经过认证的凭据

 @param credential 凭据变量指针，接受方法内部指定的凭据对象
 @return 授权质询的处置方式
 */
- (NSURLSessionAuthChallengeDisposition)fakeAuthorizedCredential:(NSURLCredential * _Nullable __autoreleasing * _Nullable)credential;

/**
 处理服务端证书引发的授权质询

 @param challenge 授权质询
 @param credential 凭据变量指针，接受方法内部指定的凭据对象
 @return 授权质询的处置方式
 */
- (NSURLSessionAuthChallengeDisposition)processAuthenticationChallengeForServerTrust:(nonnull NSURLAuthenticationChallenge *)challenge
                                                                       forCredential:(NSURLCredential * _Nullable __autoreleasing * _Nullable)credential;

/**
 处理客户端证书引发的授权质询

 @param challenge 授权质询
 @param credential 凭据变量指针，接受方法内部指定的凭据对象
 @return 授权质询的处置方式
 */
- (NSURLSessionAuthChallengeDisposition)processAuthenticationChallengeForClientCertificate:(nonnull NSURLAuthenticationChallenge *)challenge
                                                                             forCredential:(NSURLCredential * _Nullable __autoreleasing * _Nullable)credential;


/**
 处理 URLSession 收到 授权质询 时的回调

 @param session URLSession
 @param challenge 授权质询
 @param completionHandler 回调块，这个回调块由系统提供。完成其他处理后，调用一下即可。
 */
- (void)URLSession:(nonnull NSURLSession *)session
didReceiveChallenge:(nonnull NSURLAuthenticationChallenge *)challenge
 completionHandler:(nonnull void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential * _Nullable))completionHandler;

@end


