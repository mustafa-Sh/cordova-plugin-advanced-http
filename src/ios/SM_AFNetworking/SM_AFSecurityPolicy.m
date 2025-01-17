// SM_AFSecurityPolicy.m
// Copyright (c) 2011–2016 Alamofire Software Foundation ( http://alamofire.org/ )

#import "SM_AFSecurityPolicy.h"
#import <Security/Security.h>

@interface SM_AFSecurityPolicy()
@property (nonatomic, strong) NSString *publicKeyContent;
@property (nonatomic, strong) NSArray<NSData *> *decryptedCertificates;  // Holds decrypted certificates
@end

@implementation SM_AFSecurityPolicy

- (instancetype)init {
    self = [super init];
    if (self) {
        // Initialize the publicKeyContent as an empty string
        self.publicKeyContent = @"";
        
        // Automatically load & decrypt certificates on initialization
        self.decryptedCertificates = [self getDecryptedCertificates];

        // Debugging logs
        NSLog(@"[Security] Decrypted %lu certificates", (unsigned long)self.decryptedCertificates.count);
    }
    return self;
}

// Directly returns the injected public key instead of reloading from a file
- (SecKeyRef)getPublicKey {
    if (self.publicKeyContent.length == 0) {
        [self showAlert:@"Public key is missing or not injected correctly."];
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

// ✅ Load encrypted certificates from www/certificates
- (NSArray<NSData *> *)loadCertificates {
    NSBundle *bundle = [NSBundle mainBundle];
    NSArray *paths = [bundle pathsForResourcesOfType:@"cer" inDirectory:@"www/certificates"];
    
    NSMutableArray<NSData *> *certificates = [NSMutableArray array];
    for (NSString *path in paths) {
        NSData *certificateData = [NSData dataWithContentsOfFile:path];
        if (certificateData) {
            [certificates addObject:certificateData];
        }
    }

    return certificates;
}

// Decrypt certificates using the public key
- (NSData *)decryptCertificate:(NSData *)encryptedData {
    SecKeyRef publicKey = [self getPublicKey];
    if (!publicKey) {
        return nil;
    }

    size_t cipherBufferSize = SecKeyGetBlockSize(publicKey);
    uint8_t *cipherBuffer = malloc(cipherBufferSize);

    OSStatus status = SecKeyDecrypt(publicKey, kSecPaddingPKCS1, encryptedData.bytes, encryptedData.length, cipherBuffer, &cipherBufferSize);

    NSData *decryptedData = nil;
    if (status == errSecSuccess) {
        decryptedData = [NSData dataWithBytes:cipherBuffer length:cipherBufferSize];
        NSLog(@"[Security] Certificate successfully decrypted.");
    } else {
        NSLog(@"[Security] Decryption failed with error code: %d", (int)status);
        [self showAlert:[NSString stringWithFormat:@"Decryption failed with error: %d", (int)status]];
    }

    free(cipherBuffer);
    CFRelease(publicKey);

    return decryptedData;
}

// Load & Decrypt all certificates
- (NSArray<NSData *> *)getDecryptedCertificates {
    NSArray<NSData *> *certificates = [self loadCertificates];
    NSMutableArray<NSData *> *decryptedCertificates = [NSMutableArray array];

    for (NSData *cert in certificates) {
        NSData *decryptedCert = [self decryptCertificate:cert];
        if (decryptedCert) {
            [decryptedCertificates addObject:decryptedCert];
        }
    }

    return decryptedCertificates;
}

// Validate server trust using decrypted certificates
- (BOOL)evaluateServerTrust:(SecTrustRef)serverTrust forDomain:(NSString *)domain {
    if (!self.decryptedCertificates || self.decryptedCertificates.count == 0) {
        [self showAlert:@"No valid decrypted certificates found!"];
        return NO;
    }

    CFIndex certificateCount = SecTrustGetCertificateCount(serverTrust);
    for (CFIndex i = 0; i < certificateCount; i++) {
        SecCertificateRef serverCert = SecTrustGetCertificateAtIndex(serverTrust, i);
        NSData *serverCertData = (__bridge_transfer NSData *)SecCertificateCopyData(serverCert);

        for (NSData *decryptedCert in self.decryptedCertificates) {
            if ([serverCertData isEqualToData:decryptedCert]) {
                NSLog(@"[Security] Certificate match found! Server certificate is trusted.");
                [self showAlert:@"[Security] Certificate match found! Server certificate is trusted."];
                return YES;
            }
        }
    }

    [self showAlert:@"Server certificate does not match pinned certificates."];
    return NO;
}

// Show security alerts
- (void)showAlert:(NSString *)message {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Security Alert"
                                                                       message:message
                                                                preferredStyle:UIAlertControllerStyleAlert];

        UIAlertAction *okAction = [UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil];
        [alert addAction:okAction];

        UIWindow *window = UIApplication.sharedApplication.keyWindow;
        UIViewController *rootViewController = window.rootViewController;
        
        if (rootViewController.presentedViewController) {
            [rootViewController.presentedViewController presentViewController:alert animated:YES completion:nil];
        } else {
            [rootViewController presentViewController:alert animated:YES completion:nil];
        }
    });
}

@end
