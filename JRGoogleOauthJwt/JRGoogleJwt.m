//
//  JRGoogleJwt.m
//  JRGoogleOauthJwtDemo
//
//  Created by Julien on 2015-08-22.
//  Copyright (c) 2015 Julien. All rights reserved.
//

#import "JRGoogleJwt.h"


static NSString *const kGoogleAud =
@"https://www.googleapis.com/oauth2/v3/token";
static NSString *const kGooglePassPhrasePrivateKey = @"notasecret";
static int const kOneHourInsec = 3600;

@interface JRGoogleJwt ()
@property(nonatomic, strong) NSString *privateKeyName;
@property(nonatomic, strong) NSString *iss;
@property(nonatomic, strong) NSArray *scope;
@property(nonatomic, strong) NSString *aud;
@property(nonatomic, assign) int exp;
@property(nonatomic, assign) int iat;
@property(nonatomic, strong) NSString *jwtHeaderBase64Encoded ;
@end

@implementation JRGoogleJwt
- (instancetype)initWithIss:(NSString *)iss
                   andScope:(NSArray *)scope
          andPrivateKeyName:(NSString *)privateKeyName{
    self = [super init];
    if (self) {
        _iss = iss;
        _scope = [scope copy];
        _privateKeyName = privateKeyName;
        _aud = kGoogleAud;
        NSTimeInterval currentTimeInSec = [[NSDate date] timeIntervalSince1970];
        _iat = (int)currentTimeInSec;
        _exp = _iat + kOneHourInsec;
    }
    return self;
}

@end
