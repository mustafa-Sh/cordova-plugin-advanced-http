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
        NSLog(@"Public key file not found.");
        [self showAlert:@"Public key file not found."];
        return;
    }

    // Read and process the public key
    NSError *error = nil;
    NSString *publicKeyString = [NSString stringWithContentsOfFile:publicKeyPath encoding:NSUTF8StringEncoding error:&error];

    if (error) {
         NSLog(@"Failed to read public key: %@", error.localizedDescription);
        [self showAlert:[NSString stringWithFormat:@"Failed to read public key: %@", error.localizedDescription]];
        return;
    }

    // Remove PEM headers and footers
    publicKeyString = [publicKeyString stringByReplacingOccurrencesOfString:@"-----BEGIN PUBLIC KEY-----" withString:@""];
    publicKeyString = [publicKeyString stringByReplacingOccurrencesOfString:@"-----END PUBLIC KEY-----" withString:@""];
    publicKeyString = [publicKeyString stringByReplacingOccurrencesOfString:@"\n" withString:@""];

    self.publicKeyContent = publicKeyString;
    NSLog(@"PublicKeyContent: %@", self.publicKeyContent);
}

- (SecKeyRef)getPublicKey {
    if (self.publicKeyContent.length == 0) {
        [self configurePublicKey];
    }

    NSData *publicKeyData = [[NSData alloc] initWithBase64EncodedString:self.publicKeyContent options:0];
    
    if (!publicKeyData) {
        NSLog(@"Failed to decode public key content.");
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
        NSLog(@"Failed to create SecKeyRef for public key.");
         [self showAlert:@"Failed to create SecKeyRef for public key."];
    }

    return publicKey;
}

- (BOOL)verifyCertificate:(NSData *)encryptedData {
    SecKeyRef publicKey = [self getPublicKey];
    if (!publicKey) {
        NSLog(@"No public key available for verification.");
        return NO;
    }

    NSData *decryptedData = nil;
    size_t cipherBufferSize = SecKeyGetBlockSize(publicKey);
    uint8_t *cipherBuffer = malloc(cipherBufferSize);

    OSStatus status = SecKeyDecrypt(publicKey, kSecPaddingPKCS1, encryptedData.bytes, encryptedData.length, cipherBuffer, &cipherBufferSize);

    if (status == errSecSuccess) {
        decryptedData = [NSData dataWithBytes:cipherBuffer length:cipherBufferSize];
        NSLog(@"Certificate successfully decrypted.");
    } else {
        NSLog(@"Decryption failed with error code: %d", (int)status);
        [self showAlert:[NSString stringWithFormat:@"Decryption failed with error: %d", (int)status]];
    }

    free(cipherBuffer);
    CFRelease(publicKey);

    return (decryptedData != nil);
}

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
