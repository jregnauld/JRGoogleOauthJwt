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

static NSString *const kGoogleHeaderJSON = @"{\"alg\":\"RS256\",\"typ\":\"JWT\"}";


@interface JRGoogleJwt ()
@property(nonatomic, strong) NSString *privateKeyName;
@property(nonatomic, strong) NSString *iss;
@property(nonatomic, strong) NSArray *scope;
@property(nonatomic, strong) NSString *aud;
@property(nonatomic, assign) int exp;
@property(nonatomic, assign) int iat;
@property(nonatomic, strong) NSString *jwtHeaderBase64Encoded;
@property(nonatomic, strong) NSString *jwtClaimBase64Encoded;

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
        _jwtHeaderBase64Encoded = [self encodeToBase64:kGoogleHeaderJSON];
        _jwtClaimBase64Encoded = [self generateJwtClaimJsonBase64Encoded];
    }
    return self;
}
-(NSString*)generateJwtClaimJsonBase64Encoded{
    NSString *scopeStr = [_scope componentsJoinedByString:@" "];
    NSDictionary *jsonDico = @{ @"iss":self.iss,
                            @"scope": scopeStr,
                            @"aud": self.aud,
                            @"exp": [NSString stringWithFormat:@"%d", self.exp],
                            @"iat": [NSString stringWithFormat:@"%d", self.iat],
                           };
    NSError *error = nil;
    NSData *jsonObject =
    [NSJSONSerialization dataWithJSONObject:jsonDico
                                    options:NSJSONWritingPrettyPrinted
                                      error:&error];
    NSString *jsonStr =
    [[NSString alloc] initWithData:jsonObject encoding:NSUTF8StringEncoding];
    return [self encodeToBase64:jsonStr];
}
-(NSString *)encodeToBase64:(NSString*)str{
    NSData *data = [str dataUsingEncoding:NSUTF8StringEncoding];
    return [data base64EncodedStringWithOptions:0];
}

-(void)generateSignedGoogleJwt:(SignedGoogleJwtCompletionBlock)block{
    
    NSString *signedGoogleJwt = = [NSString
                                   stringWithFormat:@"%@.%@.%@", self.jwtClaimBase64Encoded, self.jwtClaimBase64Encoded,
                                   @""];
    
    block(signedGoogleJwt);

}
@end
