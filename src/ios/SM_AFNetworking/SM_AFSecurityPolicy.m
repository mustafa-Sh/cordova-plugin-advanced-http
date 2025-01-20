#import "SM_AFSecurityPolicy.h"
#import <Security/Security.h>
#import <UIKit/UIKit.h>

@interface SM_AFSecurityPolicy()
@property (nonatomic, strong) NSString *publicKeyContent;
@property (nonatomic, strong) NSArray *decryptedCertificates;
@end

@implementation SM_AFSecurityPolicy

- (instancetype)init {
    self = [super init];
    if (self) {
        self.publicKeyContent = @"";
        self.decryptedCertificates = [self getDecryptedCertificates]; // Now it initializes on creation
    }
    return self;
}

// Show alert for debugging messages instead of NSLog
- (void)showAlert:(NSString *)message {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindow *window = UIApplication.sharedApplication.keyWindow;
        if (!window) {
            return; // Prevents crashing if the window is nil
        }
        
        UIViewController *rootViewController = window.rootViewController;
        if (!rootViewController) {
            return; // Prevents crashing if there's no rootViewController
        }
        
        // Check if an alert is already being presented to avoid stacking
        if (rootViewController.presentedViewController) {
            return;
        }

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


// Load the public key from the pre-injected value
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

// Reads encrypted .cer files from www/certificates and decrypts them
- (NSArray *)getDecryptedCertificates {
    NSMutableArray *decryptedCerts = [NSMutableArray array];

    NSBundle *bundle = [NSBundle mainBundle];
    NSArray *paths = [bundle pathsForResourcesOfType:@"cer" inDirectory:@"www/certificates"];
    
    for (NSString *path in paths) {
        NSError *error;
        NSString *encryptedCertContent = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:&error];

        if (error) {
            [self showAlert:[NSString stringWithFormat:@"Failed to read certificate file: %@", path]];
            continue;
        }

        NSData *decryptedCert = [self decryptCertificate:encryptedCertContent];
        if (decryptedCert) {
            [decryptedCerts addObject:decryptedCert];
        }
    }

    return [decryptedCerts copy];
}

// Decrypts an encrypted certificate (split into chunks)
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

        size_t cipherBufferSize = SecKeyGetBlockSize(publicKey);
        uint8_t *cipherBuffer = malloc(cipherBufferSize);
        size_t decryptedBufferSize = cipherBufferSize;

        OSStatus status = SecKeyDecrypt(publicKey, kSecPaddingPKCS1, [chunkData bytes], chunkData.length, cipherBuffer, &decryptedBufferSize);

        if (status == errSecSuccess) {
            [decryptedData appendBytes:cipherBuffer length:decryptedBufferSize];
        } else {
            [self showAlert:[NSString stringWithFormat:@"Decryption failed for chunk with error: %d", (int)status]];
        }

        free(cipherBuffer);
    }

    return [decryptedData copy];
}

// Evaluate server certificates against decrypted pinned certificates
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
                [self showAlert:@"Certificate match found! Server certificate is trusted."];
                return YES;
            }
        }
    }

    [self showAlert:@"Server certificate does not match pinned certificates."];
    return NO;
}

@end
