#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <Foundation/Foundation.h>

#define SERVER_URL @"http://dy.slios.cn/api/verify/index.php"
#define KEYCHAIN_SERVICE @"com.dt.authhook.card"

static NSString *loadCard() {
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: KEYCHAIN_SERVICE,
        (__bridge id)kSecReturnData: (__bridge id)kCFBooleanTrue,
        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitOne
    };
    CFDataRef data = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&data);
    if (status == errSecSuccess && data) {
        NSString *card = [[NSString alloc] initWithData:(__bridge NSData *)data encoding:NSUTF8StringEncoding];
        CFRelease(data);
        return card;
    }
    return nil;
}

static void saveCard(NSString *card) {
    NSData *data = [card dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: KEYCHAIN_SERVICE
    };
    SecItemDelete((__bridge CFDictionaryRef)query);
    NSDictionary *add = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: KEYCHAIN_SERVICE,
        (__bridge id)kSecValueData: data
    };
    SecItemAdd((__bridge CFDictionaryRef)add, NULL);
}

static void showAlert(NSString *title, NSString *msg, BOOL exitAfter) {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:title message:msg preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
            if (exitAfter) exit(0);
        }]];
        UIViewController *root = [UIApplication sharedApplication].keyWindow.rootViewController;
        while (root.presentedViewController) root = root.presentedViewController;
        [root presentViewController:alert animated:YES completion:nil];
    });
}

static void showCardInput(void (^onSubmit)(NSString *card)) {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"卡密激活" message:@"请输入卡密" preferredStyle:UIAlertControllerStyleAlert];
        [alert addTextFieldWithConfigurationHandler:^(UITextField *tf) {
            tf.placeholder = @"请输入卡密";
            tf.clearButtonMode = UITextFieldViewModeWhileEditing;
        }];
        [alert addAction:[UIAlertAction actionWithTitle:@"激活" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
            NSString *card = alert.textFields.firstObject.text;
            if (card.length > 0) {
                onSubmit(card);
            } else {
                showAlert(@"错误", @"卡密不能为空", NO);
            }
        }]];
        [alert addAction:[UIAlertAction actionWithTitle:@"退出" style:UIAlertActionStyleCancel handler:^(UIAlertAction *action) {
            exit(0);
        }]];
        UIViewController *root = [UIApplication sharedApplication].keyWindow.rootViewController;
        while (root.presentedViewController) root = root.presentedViewController;
        [root presentViewController:alert animated:YES completion:nil];
    });
}

static void verifyCard(NSString *card, void (^onSuccess)(NSDictionary *resp), void (^onFail)(NSString *msg)) {
    NSString *urlStr = [NSString stringWithFormat:@"%@?card=%@", SERVER_URL,
                        [card stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet URLQueryAllowedCharacterSet]]];
    NSURL *url = [NSURL URLWithString:urlStr];
    NSURLRequest *req = [NSURLRequest requestWithURL:url cachePolicy:NSURLRequestReloadIgnoringCacheData timeoutInterval:10];

    NSURLSessionDataTask *task = [[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:^(NSData *data, NSURLResponse *resp, NSError *error) {
        if (error) {
            onFail([NSString stringWithFormat:@"网络错误: %@", error.localizedDescription]);
            return;
        }
        if (!data) {
            onFail(@"服务器无响应");
            return;
        }
        NSError *jsonErr = nil;
        NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:&jsonErr];
        if (!json || jsonErr) {
            onFail([NSString stringWithFormat:@"服务器返回格式错误"]);
            return;
        }
        NSInteger code = [json[@"code"] integerValue];
        if (code == 0) {
            onSuccess(json);
        } else {
            onFail(json[@"msg"] ?: @"验证失败");
        }
    }];
    [task resume];
}

static void startAuthFlow() {
    NSString *savedCard = loadCard();

    if (savedCard) {
        verifyCard(savedCard, ^(NSDictionary *resp) {
            NSLog(@"[AuthHook] 卡密验证成功: %@", resp[@"expireDate"] ?: @"永久");
        }, ^(NSString *msg) {
            NSDictionary *query = @{(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword, (__bridge id)kSecAttrService: KEYCHAIN_SERVICE};
            SecItemDelete((__bridge CFDictionaryRef)query);
            showAlert(@"授权失效", msg, NO);
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                showCardInput(^(NSString *card) {
                    verifyCard(card, ^(NSDictionary *resp) {
                        saveCard(card);
                        showAlert(@"激活成功", [NSString stringWithFormat:@"到期时间: %@", resp[@"expireDate"] ?: @"未知"], NO);
                    }, ^(NSString *msg) {
                        showAlert(@"激活失败", msg, YES);
                    });
                });
            });
        });
    } else {
        showCardInput(^(NSString *card) {
            verifyCard(card, ^(NSDictionary *resp) {
                saveCard(card);
                showAlert(@"激活成功", [NSString stringWithFormat:@"到期时间: %@", resp[@"expireDate"] ?: @"未知"], NO);
            }, ^(NSString *msg) {
                showAlert(@"激活失败", msg, YES);
            });
        });
    }
}

__attribute__((constructor))
static void initializer() {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        startAuthFlow();
    });
}


