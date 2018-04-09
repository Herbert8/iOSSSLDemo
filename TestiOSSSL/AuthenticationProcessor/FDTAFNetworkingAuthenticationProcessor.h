//
//  FDTAuthenticationProcessor.h
//  TestiOSSSL
//
//  Created by 巴宏斌 on 2018/4/7.
//  Copyright © 2018年 巴宏斌. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <AFNetworking.h>
#import "FDTAuthenticationProcessor.h"

@interface FDTAFNetworkingAuthenticationProcessor : FDTAuthenticationProcessor



/**
 AFHTTPSessionManager 收到授权质询时的处理

 @param sessionManager AFHTTPSessionManager
 @param challenge 授权质询
 @param credential 凭据变量指针，接受方法内部指定的凭据对象
 @return 授权质询的处置方式
 */
- (NSURLSessionAuthChallengeDisposition)sessionManager:(AFHTTPSessionManager *)sessionManager
                                   didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
                                            credential:(NSURLCredential * __autoreleasing *)credential;

@end
