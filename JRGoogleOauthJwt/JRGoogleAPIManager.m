//
//  JRGoogleAPIManager.m
//  JRGoogleOauthJwtDemo
//
//  Created by Julien Regnauld on 08/09/2015.
//  Copyright (c) 2015 Julien. All rights reserved.
//

#import "JRGoogleAPIManager.h"


static NSString *const kGoogleGrantType =
@"urn:ietf:params:oauth:grant-type:jwt-bearer";
static NSString *const kGoogleAuthentificationUrl =
@"https://www.googleapis.com/oauth2/v3/token";

@interface JRGoogleAPIManager ()
@end
@implementation JRGoogleAPIManager
+ (instancetype)sharedManager {
    static JRGoogleAPIManager *_sharedManager = nil;
    static dispatch_once_t oncePredicate;
    dispatch_once(&oncePredicate, ^{
        _sharedManager = [[self alloc] init];
    });
    return _sharedManager;
}
@end
