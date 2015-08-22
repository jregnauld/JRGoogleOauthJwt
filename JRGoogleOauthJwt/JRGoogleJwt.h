//
//  JRGoogleJwt.h
//  JRGoogleOauthJwtDemo
//
//  Created by Julien on 2015-08-22.
//  Copyright (c) 2015 Julien. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface JRGoogleJwt : NSObject
- (instancetype)initWithIss:(NSString *)iss
         andScope:(NSArray *)scope
andPrivateKeyName:(NSString *)privateKeyName;
@end
