//
//  FDTURLProtocolAuthenticationProcessor.h
//  TestiOSSSL
//
//  Created by 巴宏斌 on 2018/4/7.
//  Copyright © 2018年 巴宏斌. All rights reserved.
//

#import <Foundation/Foundation.h>

#import "CustomHTTPProtocol.h"
#import "FDTAuthenticationProcessor.h"

@interface FDTURLProtocolAuthenticationProcessor : FDTAuthenticationProcessor

- (NSString *)registerAuthenticationCertificate;

- (void)validateSSlChain:(BOOL)bValidateSSlChain;

@end
