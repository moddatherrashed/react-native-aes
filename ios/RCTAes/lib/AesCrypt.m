//
//  AesCrypt.m
//
//  Created by tectiv3 on 10/02/17.
//  Copyright © 2017 tectiv3. All rights reserved.
//

#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonKeyDerivation.h>

#import "AesCrypt.h"

static NSMutableDictionary *cryptorDict = nil;

@implementation AesCrypt

+ (void) initialize {
    if (cryptorDict == nil) {
        cryptorDict = [NSMutableDictionary dictionary];
    }
}

+ (NSString *) toHex:(NSData *)nsdata {
    NSString * hexStr = [NSString stringWithFormat:@"%@", nsdata];
    for(NSString * toRemove in [NSArray arrayWithObjects:@"<", @">", @" ", nil])
        hexStr = [hexStr stringByReplacingOccurrencesOfString:toRemove withString:@""];
    return hexStr;
}

+ (NSData *) fromHex: (NSString *)string {
    NSMutableData *data = [[NSMutableData alloc] init];
    unsigned char whole_byte;
    char byte_chars[3] = {'\0','\0','\0'};
    for (int i = 0; i < ([string length] / 2); i++) {
        byte_chars[0] = [string characterAtIndex:i*2];
        byte_chars[1] = [string characterAtIndex:i*2+1];
        whole_byte = strtol(byte_chars, NULL, 16);
        [data appendBytes:&whole_byte length:1];
    }
    return data;
}

+ (NSString *) pbkdf2:(NSString *)password salt: (NSString *)salt cost: (NSInteger)cost length: (NSInteger)length {
    // Data of String to generate Hash key(hexa decimal string).
    NSData *passwordData = [password dataUsingEncoding:NSUTF8StringEncoding];
    NSData *saltData = [salt dataUsingEncoding:NSUTF8StringEncoding];
    
    // Hash key (hexa decimal) string data length.
    NSMutableData *hashKeyData = [NSMutableData dataWithLength:length/8];
    
    // Key Derivation using PBKDF2 algorithm.
    int status = CCKeyDerivationPBKDF(
                                      kCCPBKDF2,
                                      passwordData.bytes,
                                      passwordData.length,
                                      saltData.bytes,
                                      saltData.length,
                                      kCCPRFHmacAlgSHA512,
                                      cost,
                                      hashKeyData.mutableBytes,
                                      hashKeyData.length);
    
    if (status == kCCParamError) {
        NSLog(@"Key derivation error");
        return @"";
    }
    
    return [self toHex:hashKeyData];
}

+ (NSData *) AES128CBC: (NSString *)operation data: (NSData *)data key: (NSString *)key iv: (NSString *)iv {
    //convert hex string to hex data
    NSData *keyData = [self fromHex:key];
    NSData *ivData = [self fromHex:iv];
    //    NSData *keyData = [key dataUsingEncoding:NSUTF8StringEncoding];
    size_t numBytes = 0;
    
    NSMutableData * buffer = [[NSMutableData alloc] initWithLength:[data length] + kCCBlockSizeAES128];
    
    CCCryptorStatus cryptStatus = CCCrypt(
                                          [operation isEqualToString:@"encrypt"] ? kCCEncrypt : kCCDecrypt,
                                          kCCAlgorithmAES128,
                                          kCCOptionPKCS7Padding,
                                          keyData.bytes, kCCKeySizeAES128,
                                          ivData.bytes,
                                          data.bytes, data.length,
                                          buffer.mutableBytes,  buffer.length,
                                          &numBytes);
    
    if (cryptStatus == kCCSuccess) {
        [buffer setLength:numBytes];
        return buffer;
    }
    NSLog(@"AES error, %d", cryptStatus);
    return nil;
}

+ (NSString *) initCipher: (NSString *)mode key: (NSString *)key iv: (NSString *)iv {
    //convert hex string to hex data
    NSData *keyData = [self fromHex:key];
    NSData *ivData = [self fromHex:iv];
    
    CCCryptorRef cryptor;
    CCCryptorCreate(
                    [mode isEqualToString:@"encrypt"] ? kCCEncrypt : kCCDecrypt,
                    kCCAlgorithmAES,
                    kCCOptionPKCS7Padding,
                    keyData.bytes, kCCKeySizeAES256,
                    ivData.bytes,
                    &cryptor);
    NSString *uniqueID = [self randomUuid];
    [cryptorDict setObject: [NSValue valueWithPointer:cryptor] forKey: uniqueID];
    
    return uniqueID;
}

+ (NSData *) encrypt: (NSString *)uniqueID data: (NSData *)data {
    CCCryptorRef cryptor = [[cryptorDict objectForKey: uniqueID] pointerValue];
    uniqueID = nil;
    
    NSMutableData * buffer = [[NSMutableData alloc] initWithLength:[data length] + kCCBlockSizeAES128];
    size_t updateLength;
    CCCryptorStatus result = CCCryptorUpdate(cryptor,
                                             [data bytes],
                                             [data length],
                                             [buffer mutableBytes],
                                             [buffer length],
                                             &updateLength);
    
    data = nil;
    if (result == kCCSuccess) {
        [buffer setLength:updateLength];
        return buffer;
    }
    else {
        return nil;
    }
}

+ (NSString *) update: (NSString *)uniqueID data: (NSString *)data {
    @autoreleasepool {
        return [[NSString alloc] initWithString:[[[NSData alloc] initWithData:[self encrypt:uniqueID data:[[NSData alloc] initWithBase64EncodedString:data options:0]]] base64EncodedStringWithOptions:0]];
    }
}

+ (NSString *) doFinal: (NSString *)uniqueID data: (NSString *)data {
    CCCryptorRef cryptor = [[cryptorDict objectForKey: uniqueID] pointerValue];
    NSData *decodedData = [[NSData alloc] initWithBase64EncodedString:data options:0];
    
    NSMutableData *finalData = [NSMutableData data];
    NSMutableData *buffer = [NSMutableData dataWithLength:decodedData.length + kCCBlockSizeAES128];
    size_t finalLength;
    
    CCCryptorStatus result1 = CCCryptorUpdate(cryptor,
                                              [decodedData bytes],
                                              [decodedData length],
                                              [buffer mutableBytes],
                                              [buffer length],
                                              &finalLength);
    
    [finalData appendBytes:buffer.bytes length:finalLength];
    
    CCCryptorStatus result2 = CCCryptorFinal(cryptor,
                                             [buffer mutableBytes],
                                             [buffer length],
                                             &finalLength);
    
    [finalData appendBytes:buffer.bytes length:finalLength];

    CCCryptorRelease(cryptor);
    [cryptorDict removeObjectForKey: uniqueID];
    
    if (result2 == kCCSuccess) {
        NSData *result = [NSData dataWithData:finalData];
        return [result base64EncodedStringWithOptions:0];
    }
    else {
        return nil;
    }
}

+ (NSString *) hmac256: (NSString *)input key: (NSString *)key {
    NSData *keyData = [self fromHex:key];
    NSData* inputData = [input dataUsingEncoding:NSUTF8StringEncoding];
    void* buffer = malloc(CC_SHA256_DIGEST_LENGTH);
    CCHmac(kCCHmacAlgSHA256, [keyData bytes], [keyData length], [inputData bytes], [inputData length], buffer);
    NSData *nsdata = [NSData dataWithBytesNoCopy:buffer length:CC_SHA256_DIGEST_LENGTH freeWhenDone:YES];
    return [self toHex:nsdata];
}

+ (NSString *) sha1: (NSString *)input {
    NSData* inputData = [input dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableData *result = [[NSMutableData alloc] initWithLength:CC_SHA1_DIGEST_LENGTH];
    CC_SHA1([inputData bytes], (CC_LONG)[inputData length], result.mutableBytes);
    return [self toHex:result];
}

+ (NSString *) sha256: (NSString *)input {
    NSData* inputData = [input dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char* buffer = malloc(CC_SHA256_DIGEST_LENGTH);
    CC_SHA256([inputData bytes], (CC_LONG)[inputData length], buffer);
    NSData *result = [NSData dataWithBytesNoCopy:buffer length:CC_SHA256_DIGEST_LENGTH freeWhenDone:YES];
    return [self toHex:result];
}

+ (NSString *) sha512: (NSString *)input {
    NSData* inputData = [input dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char* buffer = malloc(CC_SHA512_DIGEST_LENGTH);
    CC_SHA512([inputData bytes], (CC_LONG)[inputData length], buffer);
    NSData *result = [NSData dataWithBytesNoCopy:buffer length:CC_SHA512_DIGEST_LENGTH freeWhenDone:YES];
    return [self toHex:result];
}

+ (NSString *) randomUuid {
    return [[NSUUID UUID] UUIDString];
}

+ (NSString *) randomKey: (NSInteger)length {
    NSMutableData *data = [NSMutableData dataWithLength:length];
    int result = SecRandomCopyBytes(kSecRandomDefault, length, data.mutableBytes);
    if (result != noErr) {
        return nil;
    }
    return [self toHex:data];
}

@end