// SM_AFSecurityPolicy.m
// Copyright (c) 2011–2016 Alamofire Software Foundation ( http://alamofire.org/ )
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#import "SM_AFSecurityPolicy.h"

#import <Security/Security.h>

@interface SM_AFSecurityPolicy()

@property (nonatomic, strong) NSString *publicKeyContent;

@end

@implementation SM_AFSecurityPolicy

- (instancetype)init {
    self = [super init];
    if (self) {
        // Initialize the publicKeyContent as an empty string
        self.publicKeyContent = @"";
    }
    return self;
}

- (void)configurePublicKey {
    // Path to the public key file in the app bundle
    NSString *publicKeyPath = [[NSBundle mainBundle] pathForResource:@"public_key" ofType:@"pem"];
    if (!publicKeyPath) {
        NSLog(@" [SM_AFSecurityPolicy] Public key file not found in app bundle.");
        return;
    }

    // Read and process the public key
    NSError *error = nil;
    NSString *publicKeyString = [NSString stringWithContentsOfFile:publicKeyPath encoding:NSUTF8StringEncoding error:&error];
    if (error || publicKeyString == nil) {
        NSLog(@"⚠️ [SM_AFSecurityPolicy] Failed to read public key: %@", error.localizedDescription);
        return;
    }

    // Remove PEM headers and footers
    publicKeyString = [publicKeyString stringByReplacingOccurrencesOfString:@"-----BEGIN PUBLIC KEY-----" withString:@""];
    publicKeyString = [publicKeyString stringByReplacingOccurrencesOfString:@"-----END PUBLIC KEY-----" withString:@""];
    publicKeyString = [publicKeyString stringByReplacingOccurrencesOfString:@"\n" withString:@""];

    self.publicKeyContent = publicKeyString;
}

- (SecKeyRef)getPublicKey {
    if (self.publicKeyContent.length == 0) {
        [self configurePublicKey];
        NSLog(@" [SM_AFSecurityPolicy] No public key content loaded. Skipping key generation.");
        return nil;
    }

    NSData *publicKeyData = [[NSData alloc] initWithBase64EncodedString:self.publicKeyContent options:0];
    if (!publicKeyData) {
        NSLog(@" [SM_AFSecurityPolicy] Failed to decode Base64 public key.");
        return nil;
    }

    NSDictionary *options = @{
        (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeRSA,
        (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPublic,
        (__bridge id)kSecAttrKeySizeInBits: @(2048),
    };

    CFErrorRef error = NULL;
    SecKeyRef publicKey = SecKeyCreateWithData((__bridge CFDataRef)publicKeyData, (__bridge CFDictionaryRef)options, &error);
    if (!publicKey || error) {
        NSLog(@" [SM_AFSecurityPolicy] Failed to create SecKeyRef for public key. Error: %@", error);
        if (error) CFRelease(error);
        return nil;
    }

    return publicKey;
}

- (BOOL)verifyCertificate:(NSData *)encryptedData {
    SecKeyRef publicKey = [self getPublicKey];
    if (!publicKey) {
        NSLog(@" [SM_AFSecurityPolicy] Public key is missing. Certificate verification failed.");
        return NO;
    }

    size_t cipherBufferSize = SecKeyGetBlockSize(publicKey);
    uint8_t *cipherBuffer = malloc(cipherBufferSize);

    if (!cipherBuffer) {
        NSLog(@" [SM_AFSecurityPolicy] Memory allocation failed for cipher buffer.");
        return NO;
    }

    OSStatus status = SecKeyDecrypt(publicKey, kSecPaddingPKCS1, encryptedData.bytes, encryptedData.length, cipherBuffer, &cipherBufferSize);

    BOOL success = NO;
    if (status == errSecSuccess) {
        success = YES;
        NSLog(@" [SM_AFSecurityPolicy] Certificate verified successfully.");
    } else {
        NSLog(@" [SM_AFSecurityPolicy] Certificate verification failed with error: %d", (int)status);
    }

    free(cipherBuffer);
    CFRelease(publicKey);

    return success;
}

- (void)showAlertAndCloseApp {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@""
                                                                       message:@"An error occurred while configuring SSL cert mode"
                                                                preferredStyle:UIAlertControllerStyleAlert];

        UIAlertAction *okAction = [UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
            exit(0); // Close the app
        }];
        [alert addAction:okAction];
        [[UIApplication sharedApplication].keyWindow.rootViewController presentViewController:alert animated:YES completion:nil];
    });
}

@end

#import <AssertMacros.h>

#if !TARGET_OS_IOS && !TARGET_OS_WATCH && !TARGET_OS_TV
static NSData * AFSecKeyGetData(SecKeyRef key) {
    CFDataRef data = NULL;

    __Require_noErr_Quiet(SecItemExport(key, kSecFormatUnknown, kSecItemPemArmour, NULL, &data), _out);

    return (__bridge_transfer NSData *)data;

_out:
    if (data) {
        CFRelease(data);
    }

    return nil;
}
#endif

static BOOL AFSecKeyIsEqualToKey(SecKeyRef key1, SecKeyRef key2) {
#if TARGET_OS_IOS || TARGET_OS_WATCH || TARGET_OS_TV
    return [(__bridge id)key1 isEqual:(__bridge id)key2];
#else
    return [AFSecKeyGetData(key1) isEqual:AFSecKeyGetData(key2)];
#endif
}

static id AFPublicKeyForCertificate(NSData *certificate) {
    id allowedPublicKey = nil;
    SecCertificateRef allowedCertificate;
    SecCertificateRef allowedCertificates[1];
    CFArrayRef tempCertificates = nil;
    SecPolicyRef policy = nil;
    SecTrustRef allowedTrust = nil;
    SecTrustResultType result;

    allowedCertificate = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)certificate);
    __Require_Quiet(allowedCertificate != NULL, _out);

    allowedCertificates[0] = allowedCertificate;
    tempCertificates = CFArrayCreate(NULL, (const void **)allowedCertificates, 1, NULL);

    policy = SecPolicyCreateBasicX509();
    __Require_noErr_Quiet(SecTrustCreateWithCertificates(tempCertificates, policy, &allowedTrust), _out);
    __Require_noErr_Quiet(SecTrustEvaluate(allowedTrust, &result), _out);

    allowedPublicKey = (__bridge_transfer id)SecTrustCopyPublicKey(allowedTrust);

_out:
    if (allowedTrust) {
        CFRelease(allowedTrust);
    }

    if (policy) {
        CFRelease(policy);
    }

    if (tempCertificates) {
        CFRelease(tempCertificates);
    }

    if (allowedCertificate) {
        CFRelease(allowedCertificate);
    }

    return allowedPublicKey;
}

static BOOL AFServerTrustIsValid(SecTrustRef serverTrust) {
    BOOL isValid = NO;
    SecTrustResultType result;
    __Require_noErr_Quiet(SecTrustEvaluate(serverTrust, &result), _out);

    isValid = (result == kSecTrustResultUnspecified || result == kSecTrustResultProceed);

_out:
    return isValid;
}

static NSArray * AFCertificateTrustChainForServerTrust(SecTrustRef serverTrust) {
    CFIndex certificateCount = SecTrustGetCertificateCount(serverTrust);
    NSMutableArray *trustChain = [NSMutableArray arrayWithCapacity:(NSUInteger)certificateCount];

    for (CFIndex i = 0; i < certificateCount; i++) {
        SecCertificateRef certificate = SecTrustGetCertificateAtIndex(serverTrust, i);
        [trustChain addObject:(__bridge_transfer NSData *)SecCertificateCopyData(certificate)];
    }

    return [NSArray arrayWithArray:trustChain];
}

static NSArray * AFPublicKeyTrustChainForServerTrust(SecTrustRef serverTrust) {
    SecPolicyRef policy = SecPolicyCreateBasicX509();
    CFIndex certificateCount = SecTrustGetCertificateCount(serverTrust);
    NSMutableArray *trustChain = [NSMutableArray arrayWithCapacity:(NSUInteger)certificateCount];
    for (CFIndex i = 0; i < certificateCount; i++) {
        SecCertificateRef certificate = SecTrustGetCertificateAtIndex(serverTrust, i);

        SecCertificateRef someCertificates[] = {certificate};
        CFArrayRef certificates = CFArrayCreate(NULL, (const void **)someCertificates, 1, NULL);

        SecTrustRef trust;
        __Require_noErr_Quiet(SecTrustCreateWithCertificates(certificates, policy, &trust), _out);

        SecTrustResultType result;
        __Require_noErr_Quiet(SecTrustEvaluate(trust, &result), _out);

        [trustChain addObject:(__bridge_transfer id)SecTrustCopyPublicKey(trust)];

    _out:
        if (trust) {
            CFRelease(trust);
        }

        if (certificates) {
            CFRelease(certificates);
        }

        continue;
    }
    CFRelease(policy);

    return [NSArray arrayWithArray:trustChain];
}

#pragma mark -

@interface SM_AFSecurityPolicy()
@property (readwrite, nonatomic, assign) AFSSLPinningMode SSLPinningMode;
@property (readwrite, nonatomic, strong) NSSet *pinnedPublicKeys;
@end

@implementation SM_AFSecurityPolicy

+ (NSSet *)certificatesInBundle:(NSBundle *)bundle {
    NSArray *paths = [bundle pathsForResourcesOfType:@"cer" inDirectory:@"www/certificates"];
    NSMutableSet *certificates = [NSMutableSet setWithCapacity:[paths count]];

    for (NSString *path in paths) {
        NSData *certificateData = [NSData dataWithContentsOfFile:path];
        [certificates addObject:certificateData];
    }

    return [NSSet setWithSet:certificates];
}

+ (NSSet *)defaultPinnedCertificates {
    static NSSet *_defaultPinnedCertificates = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSBundle *bundle = [NSBundle bundleForClass:[self class]];
        _defaultPinnedCertificates = [self certificatesInBundle:bundle];
    });

    return _defaultPinnedCertificates;
}

+ (instancetype)defaultPolicy {
    SM_AFSecurityPolicy *securityPolicy = [[self alloc] init];
    securityPolicy.SSLPinningMode = AFSSLPinningModeNone;

    return securityPolicy;
}

+ (instancetype)policyWithPinningMode:(AFSSLPinningMode)pinningMode {
    return [self policyWithPinningMode:pinningMode withPinnedCertificates:[self defaultPinnedCertificates]];
}

+ (instancetype)policyWithPinningMode:(AFSSLPinningMode)pinningMode withPinnedCertificates:(NSSet *)pinnedCertificates {
    SM_AFSecurityPolicy *securityPolicy = [[self alloc] init];
    securityPolicy.SSLPinningMode = pinningMode;

    [securityPolicy setPinnedCertificates:pinnedCertificates];

    return securityPolicy;
}

- (instancetype)init {
    self = [super init];
    if (!self) {
        return nil;
    }

    self.validatesDomainName = YES;

    return self;
}

- (void)setPinnedCertificates:(NSSet *)pinnedCertificates {
    _pinnedCertificates = pinnedCertificates;

    if (self.pinnedCertificates) {
        NSMutableSet *mutablePinnedPublicKeys = [NSMutableSet setWithCapacity:[self.pinnedCertificates count]];
        for (NSData *certificate in self.pinnedCertificates) {
            id publicKey = AFPublicKeyForCertificate(certificate);
            if (!publicKey) {
                continue;
            }
            [mutablePinnedPublicKeys addObject:publicKey];
        }
        self.pinnedPublicKeys = [NSSet setWithSet:mutablePinnedPublicKeys];
    } else {
        self.pinnedPublicKeys = nil;
    }
}

#pragma mark -

- (BOOL)evaluateServerTrust:(SecTrustRef)serverTrust
                  forDomain:(NSString *)domain
{
    if (domain && self.allowInvalidCertificates && self.validatesDomainName && (self.SSLPinningMode == AFSSLPinningModeNone || [self.pinnedCertificates count] == 0)) {
        // https://developer.apple.com/library/mac/documentation/NetworkingInternet/Conceptual/NetworkingTopics/Articles/OverridingSSLChainValidationCorrectly.html
        //  According to the docs, you should only trust your provided certs for evaluation.
        //  Pinned certificates are added to the trust. Without pinned certificates,
        //  there is nothing to evaluate against.
        //
        //  From Apple Docs:
        //          "Do not implicitly trust self-signed certificates as anchors (kSecTrustOptionImplicitAnchors).
        //           Instead, add your own (self-signed) CA certificate to the list of trusted anchors."
        NSLog(@"In order to validate a domain name for self signed certificates, you MUST use pinning.");
        return NO;
    }

    NSMutableArray *policies = [NSMutableArray array];
    if (self.validatesDomainName) {
        [policies addObject:(__bridge_transfer id)SecPolicyCreateSSL(true, (__bridge CFStringRef)domain)];
    } else {
        [policies addObject:(__bridge_transfer id)SecPolicyCreateBasicX509()];
    }

    SecTrustSetPolicies(serverTrust, (__bridge CFArrayRef)policies);

    if (self.SSLPinningMode == AFSSLPinningModeNone) {
        return self.allowInvalidCertificates || AFServerTrustIsValid(serverTrust);
    } else if (!AFServerTrustIsValid(serverTrust) && !self.allowInvalidCertificates) {
        return NO;
    }

    switch (self.SSLPinningMode) {
        case AFSSLPinningModeNone:
        default:
            return NO;
        case AFSSLPinningModeCertificate: {
            NSMutableArray *pinnedCertificates = [NSMutableArray array];
            for (NSData *certificateData in self.pinnedCertificates) {
                [pinnedCertificates addObject:(__bridge_transfer id)SecCertificateCreateWithData(NULL, (__bridge CFDataRef)certificateData)];
            }
            SecTrustSetAnchorCertificates(serverTrust, (__bridge CFArrayRef)pinnedCertificates);

            if (!AFServerTrustIsValid(serverTrust)) {
                return NO;
            }

            // obtain the chain after being validated, which *should* contain the pinned certificate in the last position (if it's the Root CA)
            NSArray *serverCertificates = AFCertificateTrustChainForServerTrust(serverTrust);

            for (NSData *trustChainCertificate in [serverCertificates reverseObjectEnumerator]) {
                if ([self.pinnedCertificates containsObject:trustChainCertificate]) {
                    return YES;
                }
            }

            return NO;
        }
        case AFSSLPinningModePublicKey: {
            NSUInteger trustedPublicKeyCount = 0;
            NSArray *publicKeys = AFPublicKeyTrustChainForServerTrust(serverTrust);

            for (id trustChainPublicKey in publicKeys) {
                for (id pinnedPublicKey in self.pinnedPublicKeys) {
                    if (AFSecKeyIsEqualToKey((__bridge SecKeyRef)trustChainPublicKey, (__bridge SecKeyRef)pinnedPublicKey)) {
                        trustedPublicKeyCount += 1;
                    }
                }
            }
            return trustedPublicKeyCount > 0;
        }
    }

    return NO;
}

#pragma mark - NSKeyValueObserving

+ (NSSet *)keyPathsForValuesAffectingPinnedPublicKeys {
    return [NSSet setWithObject:@"pinnedCertificates"];
}

#pragma mark - NSSecureCoding

+ (BOOL)supportsSecureCoding {
    return YES;
}

- (instancetype)initWithCoder:(NSCoder *)decoder {

    self = [self init];
    if (!self) {
        return nil;
    }

    self.SSLPinningMode = [[decoder decodeObjectOfClass:[NSNumber class] forKey:NSStringFromSelector(@selector(SSLPinningMode))] unsignedIntegerValue];
    self.allowInvalidCertificates = [decoder decodeBoolForKey:NSStringFromSelector(@selector(allowInvalidCertificates))];
    self.validatesDomainName = [decoder decodeBoolForKey:NSStringFromSelector(@selector(validatesDomainName))];
    self.pinnedCertificates = [decoder decodeObjectOfClass:[NSArray class] forKey:NSStringFromSelector(@selector(pinnedCertificates))];

    return self;
}

- (void)encodeWithCoder:(NSCoder *)coder {
    [coder encodeObject:[NSNumber numberWithUnsignedInteger:self.SSLPinningMode] forKey:NSStringFromSelector(@selector(SSLPinningMode))];
    [coder encodeBool:self.allowInvalidCertificates forKey:NSStringFromSelector(@selector(allowInvalidCertificates))];
    [coder encodeBool:self.validatesDomainName forKey:NSStringFromSelector(@selector(validatesDomainName))];
    [coder encodeObject:self.pinnedCertificates forKey:NSStringFromSelector(@selector(pinnedCertificates))];
}

#pragma mark - NSCopying

- (instancetype)copyWithZone:(NSZone *)zone {
    SM_AFSecurityPolicy *securityPolicy = [[[self class] allocWithZone:zone] init];
    securityPolicy.SSLPinningMode = self.SSLPinningMode;
    securityPolicy.allowInvalidCertificates = self.allowInvalidCertificates;
    securityPolicy.validatesDomainName = self.validatesDomainName;
    securityPolicy.pinnedCertificates = [self.pinnedCertificates copyWithZone:zone];

    return securityPolicy;
}

@end
