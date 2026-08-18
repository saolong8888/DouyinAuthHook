#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <Foundation/Foundation.h>

#define SERVER_URL @"http://dy.slios.cn/api/verify/index.php"
#define KEYCHAIN_SERVICE @"com.dt.authhook.card"

static UIWindow *g_alertWindow = nil;

static UIWindow *getKeyWindow() {
    if (@available(iOS 13.0, *)) {
        for (UIScene *scene in [UIApplication sharedApplication].connectedScenes) {
            if (![scene isKindOfClass:[UIWindowScene class]]) continue;
            UIWindowScene *ws = (UIWindowScene *)scene;
            if (ws.activationState != UISceneActivationStateForegroundActive) continue;
            for (UIWindow *w in ws.windows) {
                if (w.isKeyWindow) return w;
            }
        }
    }
    return [UIApplication sharedApplication].keyWindow;
}

static void presentAlert(UIAlertController *alert) {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindow *keyWin = getKeyWindow();
        if (!keyWin) {
            if (@available(iOS 13.0, *)) {
                for (UIScene *scene in [UIApplication sharedApplication].connectedScenes) {
                    if ([scene isKindOfClass:[UIWindowScene class]]) {
                        g_alertWindow = [[UIWindow alloc] initWithWindowScene:(UIWindowScene *)scene];
                        break;
                    }
                }
            }
            if (!g_alertWindow) {
                g_alertWindow = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
            }
            g_alertWindow.rootViewController = [UIViewController new];
            g_alertWindow.windowLevel = UIWindowLevelAlert + 1;
            [g_alertWindow makeKeyAndVisible];
            keyWin = g_alertWindow;
        }
        UIViewController *root = keyWin.rootViewController;
        while (root.presentedViewController) root = root.presentedViewController;
        [root presentViewController:alert animated:YES completion:nil];
    });
}

static void dismissAlertWindow() {
    if (g_alertWindow) {
        [g_alertWindow setHidden:YES];
        g_alertWindow = nil;
    }
}

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

static void deleteCard() {
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: KEYCHAIN_SERVICE
    };
    SecItemDelete((__bridge CFDictionaryRef)query);
}

static void showAlert(NSString *title, NSString *msg, BOOL exitAfter) {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:title message:msg preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        dismissAlertWindow();
        if (exitAfter) exit(0);
    }]];
    presentAlert(alert);
}

static void showCardInput(void (^onSubmit)(NSString *card)) {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"卡密激活" message:@"请输入卡密" preferredStyle:UIAlertControllerStyleAlert];
    [alert addTextFieldWithConfigurationHandler:^(UITextField *tf) {
        tf.placeholder = @"请输入卡密";
        tf.clearButtonMode = UITextFieldViewModeWhileEditing;
    }];
    __weak UIAlertController *weakAlert = alert;
    [alert addAction:[UIAlertAction actionWithTitle:@"激活" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        NSString *card = weakAlert.textFields.firstObject.text;
        dismissAlertWindow();
        if (card.length > 0) {
            onSubmit(card);
        } else {
            showAlert(@"错误", @"卡密不能为空", NO);
        }
    }]];
    [alert addAction:[UIAlertAction actionWithTitle:@"退出" style:UIAlertActionStyleCancel handler:^(UIAlertAction *action) {
        dismissAlertWindow();
        exit(0);
    }]];
    presentAlert(alert);
}

static void verifyCard(NSString *card, void (^onSuccess)(NSDictionary *resp), void (^onFail)(NSString *msg)) {
    NSString *urlStr = [NSString stringWithFormat:@"%@?card=%@", SERVER_URL,
                        [card stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet URLQueryAllowedCharacterSet]]];
    NSURL *url = [NSURL URLWithString:urlStr];
    NSURLRequest *req = [NSURLRequest requestWithURL:url cachePolicy:NSURLRequestReloadIgnoringCacheData timeoutInterval:10];
    NSLog(@"[AuthHook] 请求: %@", urlStr);

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
        NSLog(@"[AuthHook] 响应: %@", [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]);
        if (!json || jsonErr) {
            onFail(@"服务器返回格式错误");
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
    NSLog(@"[AuthHook] === 开始验证流程 ===");
    NSString *savedCard = loadCard();
    NSLog(@"[AuthHook] 已保存卡密: %@", savedCard ?: @"无");

    if (savedCard) {
        verifyCard(savedCard, ^(NSDictionary *resp) {
            NSLog(@"[AuthHook] 卡密验证成功, 到期: %@", resp[@"expireDate"] ?: @"永久");
        }, ^(NSString *msg) {
            NSLog(@"[AuthHook] 卡密验证失败: %@", msg);
            deleteCard();
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
    NSLog(@"[AuthHook] === dylib 已加载 ===");
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        startAuthFlow();
    });
}


