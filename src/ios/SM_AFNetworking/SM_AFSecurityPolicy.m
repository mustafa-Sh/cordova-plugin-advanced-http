#import "SM_AFSecurityPolicy.h"
#import <Security/Security.h>
#import <UIKit/UIKit.h>

@interface SM_AFSecurityPolicy()
@property (readwrite, nonatomic, assign) AFSSLPinningMode SSLPinningMode;
@property (nonatomic, strong) NSString *publicKeyContent;
@property (nonatomic, strong) NSArray *decryptedCertificates;
@end

@implementation SM_AFSecurityPolicy

- (instancetype)init {
    self = [super init];
    if (self) {
        self.publicKeyContent = @"";
        self.decryptedCertificates = @[];
    }
    return self;
}

// Load & decrypt encrypted certificates (only when SSL pinning is enabled)
- (NSArray *)loadEncryptedCertificates {
    NSMutableArray *certificates = [NSMutableArray array];

    NSBundle *bundle = [NSBundle mainBundle];
    NSArray *paths = [bundle pathsForResourcesOfType:@"cer" inDirectory:@"www/certificates"];

    for (NSString *path in paths) {
        NSError *error;
        NSString *encryptedContent = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:&error];

        if (error) {
            [self showAlert:[NSString stringWithFormat:@"Failed to read encrypted certificate file: %@", path]];
            continue;
        }

        NSData *decryptedCert = [self decryptCertificate:encryptedContent];
        if (decryptedCert) {
            [certificates addObject:decryptedCert];
        } else {
            [self showAlert:[NSString stringWithFormat:@"Failed to decrypt certificate: %@", path]];
        }
    }

    return [certificates copy];
}

// Decrypt each chunk and reconstruct the certificate
- (NSData *)decryptCertificate:(NSString *)encryptedCertificate {
    SecKeyRef publicKey = [self getPublicKey];
    if (!publicKey) {
        [self showAlert:@"No public key available for decryption."];
        return nil;
    }

    NSMutableData *decryptedData = [NSMutableData data];

	// Remove JSON-like formatting and split into chunks
    NSString *cleanedCertificate = [encryptedCertificate stringByReplacingOccurrencesOfString:@"[" withString:@""];
    cleanedCertificate = [cleanedCertificate stringByReplacingOccurrencesOfString:@"]" withString:@""];
    cleanedCertificate = [cleanedCertificate stringByReplacingOccurrencesOfString:@"\"" withString:@""];
    NSArray *chunks = [cleanedCertificate componentsSeparatedByString:@","];

    for (NSString *chunk in chunks) {
        NSData *chunkData = [[NSData alloc] initWithBase64EncodedString:chunk options:0];
        if (!chunkData) {
            [self showAlert:@"Invalid base64 chunk found."];
            continue;
        }

        size_t decryptedSize = SecKeyGetBlockSize(publicKey);
        uint8_t *decryptedBuffer = malloc(decryptedSize);
        size_t actualDecryptedSize = decryptedSize;

        OSStatus status = SecKeyDecrypt(publicKey, kSecPaddingPKCS1, chunkData.bytes, chunkData.length, decryptedBuffer, &actualDecryptedSize);
        if (status == errSecSuccess) {
            [decryptedData appendBytes:decryptedBuffer length:actualDecryptedSize];
        } else {
            [self showAlert:[NSString stringWithFormat:@"Decryption failed with error: %d", (int)status]];
        }

        free(decryptedBuffer);
    }

    return [decryptedData copy];
}

// Retrieves the RSA public key used for decryption
- (SecKeyRef)getPublicKey {
    if (self.publicKeyContent.length == 0) {
        [self showAlert:@"Public key content is empty!"];
        return nil;
    }

    NSData *publicKeyData = [[NSData alloc] initWithBase64EncodedString:self.publicKeyContent options:0];
    if (!publicKeyData) {
        [self showAlert:@"Failed to decode public key content."];
        return nil;
    }

    NSDictionary *options = @{
        (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeRSA,
        (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPublic,
        (__bridge id)kSecAttrKeySizeInBits: @(2048),
    };

    SecKeyRef publicKey = SecKeyCreateWithData((__bridge CFDataRef)publicKeyData, (__bridge CFDictionaryRef)options, nil);
    if (!publicKey) {
        [self showAlert:@"Failed to create SecKeyRef for public key."];
    }

    return publicKey;
}

// Now loads decrypted certificates ONLY when SSL pinning is active
+ (instancetype)policyWithPinningMode:(AFSSLPinningMode)pinningMode {
    return [self policyWithPinningMode:pinningMode withPinnedCertificates:[self defaultPinnedCertificates]];
}

+ (instancetype)policyWithPinningMode:(AFSSLPinningMode)pinningMode withPinnedCertificates:(NSSet *)pinnedCertificates {
    SM_AFSecurityPolicy *securityPolicy = [[self alloc] init];
    securityPolicy.SSLPinningMode = pinningMode;

    if (pinningMode == AFSSLPinningModeCertificate) {
        securityPolicy.decryptedCertificates = [securityPolicy loadEncryptedCertificates]; // Loads only when needed
    }

    return securityPolicy;
}

// Default pinned certificates now correctly loads encrypted certificates
+ (NSSet *)defaultPinnedCertificates {
    static NSSet *_defaultPinnedCertificates = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        SM_AFSecurityPolicy *policy = [[SM_AFSecurityPolicy alloc] init];
        _defaultPinnedCertificates = [NSSet setWithArray:[policy loadEncryptedCertificates]];
    });

    return _defaultPinnedCertificates;
}

// Improved showAlert() function
- (void)showAlert:(NSString *)message {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindow *window = UIApplication.sharedApplication.keyWindow;
        if (!window) return;

        UIViewController *rootViewController = window.rootViewController;
        if (!rootViewController) return;

        if (rootViewController.presentedViewController) return;

        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Security Alert"
                                                                       message:message
                                                                preferredStyle:UIAlertControllerStyleAlert];

        UIAlertAction *okAction = [UIAlertAction actionWithTitle:@"OK" 
                                                           style:UIAlertActionStyleDefault 
                                                         handler:nil];
        [alert addAction:okAction];

        [rootViewController presentViewController:alert animated:YES completion:nil];
    });
}

@end
