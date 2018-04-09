//
//  ViewController.m
//  TestiOSSSL
//
//  Created by 巴宏斌 on 2017/8/13.
//  Copyright © 2017年 巴宏斌. All rights reserved.
//

#import "ViewController.h"
#import <AFNetworking.h>

#import "FDTAFNetworkingAuthenticationProcessor.h"
#import "FDTAuthenticationProcessor.h"
#import "FDTURLProtocolAuthenticationProcessor.h"

@interface NSURLRequest (SSL)

@end

@implementation NSURLRequest (SSL)

+ (BOOL)allowsAnyHTTPSCertificateForHost:(NSString *)host {
    return YES;
}

@end

@interface ViewController () <NSURLSessionDelegate>

@end

@implementation ViewController {
    __weak IBOutlet UIWebView *myWebView;
    FDTURLProtocolAuthenticationProcessor *urlProtocolAuthenticationProcessor;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.

    urlProtocolAuthenticationProcessor = [[FDTURLProtocolAuthenticationProcessor alloc] init];
    urlProtocolAuthenticationProcessor.clientPKCS12CertificateData = [self dataFromPKCS12CertificateFile];
    urlProtocolAuthenticationProcessor.clientCertificatePassphrase = @"123456";
    [urlProtocolAuthenticationProcessor registerAuthenticationCertificate];
//    [urlProtocolAuthenticationProcessor validateSSlChain:NO];
}

- (NSString *)genUrlStr {
    NSString *sUrl = @"https://www.sslpoc.com/t.json";
    //        sUrl = @"https://www.httpbin.org/get";
    //    sUrl = @"https://www.sslpoc.com/get";
    sUrl = @"https://192.168.51.133:28082";
    sUrl = @"https://192.168.199.158:28082";


    sUrl = @"https://httpbin.org/get";
    sUrl = @"https://httpbin.org/basic-auth/user/passwd";
    sUrl = @"https://sslpoc.com:28082";
    sUrl = @"https://test.com:28082";



    NSString *url = [NSString stringWithFormat:@"%@?ts=%f",
                     sUrl,
                     [[NSDate date] timeIntervalSince1970]];

    url = sUrl;
    NSLog(@"url = %@", url);
    return url;
}

- (AFSecurityPolicy *)genPolicy {
    AFSecurityPolicy *policy = [AFSecurityPolicy policyWithPinningMode:AFSSLPinningModeCertificate];

    policy.validatesDomainName = YES;
    policy.allowInvalidCertificates = YES;

    NSString *caCerFile = [[NSBundle mainBundle] pathForResource:@"ca" ofType:@"cer"];
    NSData *data = [NSData dataWithContentsOfFile:caCerFile];
    NSLog(@"data len = %lu", data.length);
    policy.pinnedCertificates = [NSSet setWithObject:data];

    return policy;
}

- (NSData *)dataFromPKCS12CertificateFile {
    NSString *p12CerFile = [[NSBundle mainBundle] pathForResource:@"client"ofType:@"p12"];
    NSData *retData = [NSData dataWithContentsOfFile:p12CerFile];
    return retData;
}

- (IBAction)onAFNClk:(UIButton *)sender {
    [self testAFN];
    [self testWebView];
}

- (IBAction)onSessionClk:(UIButton *)sender {
    [self testSession];
}

- (void)testWebView {
    NSString *url = [self genUrlStr];
    NSURLRequest *req = [NSURLRequest requestWithURL:[NSURL URLWithString:url]];
    [myWebView loadRequest:req];
}


- (void)testAFN {
    NSString *url = [self genUrlStr];

    __block AFHTTPSessionManager *mgr = [AFHTTPSessionManager manager];
    __weak typeof(mgr) weakMgr = mgr;

//    NSURLSessionConfiguration *cfg = [NSURLSessionConfiguration defaultSessionConfiguration];
//    NSMutableArray *arr = [cfg.protocolClasses mutableCopy];
//    [arr insertObject:[CustomHTTPProtocol class] atIndex:0];
//    cfg.protocolClasses = [arr copy];
//
//    mgr = [[AFHTTPSessionManager alloc] initWithSessionConfiguration:cfg];

    mgr.responseSerializer = [[AFHTTPResponseSerializer alloc] init];
    mgr.securityPolicy = [self genPolicy];


    FDTAFNetworkingAuthenticationProcessor *authProcessor = [[FDTAFNetworkingAuthenticationProcessor alloc] init];
    authProcessor.clientPKCS12CertificateData = [self dataFromPKCS12CertificateFile];
    authProcessor.clientCertificatePassphrase = @"123456";

    // 指定处理 认证 的回调
    [mgr setSessionDidReceiveAuthenticationChallengeBlock:^NSURLSessionAuthChallengeDisposition(NSURLSession *session, NSURLAuthenticationChallenge *challenge, NSURLCredential *__autoreleasing*_credential) {
        return [authProcessor sessionManager:weakMgr
                         didReceiveChallenge:challenge
                                  credential:_credential];
    }];

    [mgr GET:url
  parameters:nil progress:nil success:^(NSURLSessionDataTask * _Nonnull task, id _Nullable responseObject) {

      NSString *s = [NSString stringWithFormat:@"rep = %@", responseObject];

      s = [[NSString alloc] initWithData:responseObject encoding:NSUTF8StringEncoding];
      //      txtView.text = s;

      NSLog(@"rep = %@", s);
  } failure:^(NSURLSessionDataTask * _Nullable task, NSError * _Nonnull error) {
      NSLog(@"err = %@", error.localizedDescription);
  }];

}

- (void)testSession {

    NSString *urlStr = [self genUrlStr];
    NSURL *url = [NSURL URLWithString:urlStr];

    NSDictionary *headers = @{ @"Cache-Control": @"no-cache" };

    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url
                                                           cachePolicy:NSURLRequestUseProtocolCachePolicy
                                                       timeoutInterval:10.0];
    [request setHTTPMethod:@"GET"];
    [request setAllHTTPHeaderFields:headers];

    NSURLSessionConfiguration *cfg = [NSURLSessionConfiguration defaultSessionConfiguration];
    //    NSMutableArray *arr = [cfg.protocolClasses mutableCopy];
    //    [arr insertObject:[CustomHTTPProtocol class] atIndex:0];
    ////    [arr addObject:[CustomHTTPProtocol class]];
    //    cfg.protocolClasses = [arr copy];

    NSURLSession *session = [NSURLSession sessionWithConfiguration:cfg
                                                          delegate:self
                                                     delegateQueue:[NSOperationQueue mainQueue]];

    NSURLSessionDataTask *dataTask = [session dataTaskWithRequest:request
                                                completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
                                                    if (error) {
                                                        NSLog(@"Exec HTTP HEAD error = %@", error);
                                                    } else {
                                                        NSString *s = [[NSString alloc] initWithData:data
                                                                                            encoding:NSUTF8StringEncoding];
                                                        NSLog(@"data str = %@", s);
                                                    }
                                                }];
    [dataTask resume];
}

- (void)URLSession:(NSURLSession *)session
didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
 completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential * _Nullable))completionHandler {

    FDTAuthenticationProcessor *authProcessor = [[FDTAuthenticationProcessor alloc] init];
    authProcessor.clientPKCS12CertificateData = [self dataFromPKCS12CertificateFile];
    authProcessor.clientCertificatePassphrase = @"123456";

    [authProcessor URLSession:session
          didReceiveChallenge:challenge
            completionHandler:completionHandler];

}


@end
