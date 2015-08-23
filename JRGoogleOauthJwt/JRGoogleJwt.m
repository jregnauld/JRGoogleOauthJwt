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

/**
 * Creates the signature for the passed plain data.
 * Signature is created by encrypting the SHA256 hash value of the plain data.
 *
 * @param plainData Any raw data of which the signature should get created.
 * @param privateKey The private key used to encrypt the data.
 * @return Create signature bytes.
 * Thanks Michael Hohl for sharing that! 
 * https://github.com/hohl/PKCS-Universal
 */
NSData* PKCSSignBytesSHA256withRSA(NSData* plainData, SecKeyRef privateKey)
{
    if (!privateKey) {
        @throw [NSException exceptionWithName:NSInvalidArgumentException
                                       reason:@"Passed private key of PKCSSignBytesSHA256withRSA must not be NULL!"
                                     userInfo:nil];
    }
    
    size_t signedHashBytesSize = SecKeyGetBlockSize(privateKey);
    uint8_t* signedHashBytes = malloc(signedHashBytesSize);
    memset(signedHashBytes, 0x0, signedHashBytesSize);
    
    size_t hashBytesSize = CC_SHA256_DIGEST_LENGTH;
    uint8_t* hashBytes = malloc(hashBytesSize);
    if (!CC_SHA256([plainData bytes], (CC_LONG)[plainData length], hashBytes)) {
        return nil;
    }
    
    SecKeyRawSign(privateKey,
                  kSecPaddingPKCS1SHA256,
                  hashBytes,
                  hashBytesSize,
                  signedHashBytes,
                  &signedHashBytesSize);
    
    NSData* signedHash = [NSData dataWithBytes:signedHashBytes
                                        length:(NSUInteger)signedHashBytesSize];
    
    if (hashBytes)
        free(hashBytes);
    if (signedHashBytes)
        free(signedHashBytes);
    
    return signedHash;
}
