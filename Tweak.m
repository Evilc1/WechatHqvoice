#import <UIKit/UIKit.h>
#import <AVFoundation/AVFoundation.h>
#import <AudioToolbox/AudioToolbox.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <string.h>
#import <stdlib.h>

// ==========================================
// 1. 内置轻量级 Fishhook（非越狱环境安全 Hook C 函数）
// ==========================================
struct rebinding {
    const char *name;
    void *replacement;
    void **replaced;
};

struct rebindings_entry {
    struct rebinding *rebindings;
    size_t rebindings_nel;
    struct rebindings_entry *next;
};

static struct rebindings_entry *_rebindings_head;

static int prepend_rebindings(struct rebindings_entry **rebindings_head, struct rebinding rebindings[], size_t nel) {
    struct rebindings_entry *new_entry = (struct rebindings_entry *)malloc(sizeof(struct rebindings_entry));
    if (!new_entry) return -1;
    new_entry->rebindings = (struct rebinding *)malloc(sizeof(struct rebinding) * nel);
    if (!new_entry->rebindings) {
        free(new_entry);
        return -1;
    }
    memcpy(new_entry->rebindings, rebindings, sizeof(struct rebinding) * nel);
    new_entry->rebindings_nel = nel;
    new_entry->next = *rebindings_head;
    *rebindings_head = new_entry;
    return 0;
}

static void perform_rebinding_with_section(struct rebindings_entry *rebindings, struct section_64 *section, intptr_t slide, struct nlist_64 *symtab, char *strtab, uint32_t *indirect_symtab) {
    uint32_t *indirect_symbol_indices = indirect_symtab + section->reserved1;
    void **indirect_symbol_bindings = (void **)((uintptr_t)slide + section->addr);
    for (uint i = 0; i < section->size / sizeof(void *); i++) {
        uint32_t symtab_index = indirect_symbol_indices[i];
        if (symtab_index == INDIRECT_SYMBOL_ABS || symtab_index == INDIRECT_SYMBOL_LOCAL ||
            symtab_index == (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS)) {
            continue;
        }
        uint32_t strtab_offset = symtab[symtab_index].n_un.n_strx;
        char *symbol_name = strtab + strtab_offset;
        if (strnlen(symbol_name, 2) < 2) continue;

        struct rebindings_entry *cur = rebindings;
        while (cur) {
            for (size_t j = 0; j < cur->rebindings_nel; j++) {
                if (strcmp(&symbol_name[1], cur->rebindings[j].name) == 0) {
                    if (cur->rebindings[j].replaced != NULL && indirect_symbol_bindings[i] != cur->rebindings[j].replacement) {
                        *(cur->rebindings[j].replaced) = indirect_symbol_bindings[i];
                    }
                    indirect_symbol_bindings[i] = cur->rebindings[j].replacement;
                    goto symbol_loop;
                }
            }
            cur = cur->next;
        }
    symbol_loop:;
    }
}

static void rebind_symbols_for_image(struct rebindings_entry *rebindings, const struct mach_header *header, intptr_t slide) {
    Dl_info info;
    if (dladdr(header, &info) == 0) return;

    struct segment_command_64 *cur_seg_cmd;
    struct segment_command_64 *linkedit_segment = NULL;
    struct symtab_command *symtab_cmd = NULL;
    struct dysymtab_command *dysymtab_cmd = NULL;

    uintptr_t cur = (uintptr_t)header + sizeof(struct mach_header_64);
    for (uint i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize) {
        cur_seg_cmd = (struct segment_command_64 *)cur;
        if (cur_seg_cmd->cmd == LC_SEGMENT_64) {
            if (strcmp(cur_seg_cmd->segname, SEG_LINKEDIT) == 0) {
                linkedit_segment = cur_seg_cmd;
            }
        } else if (cur_seg_cmd->cmd == LC_SYMTAB) {
            symtab_cmd = (struct symtab_command *)cur_seg_cmd;
        } else if (cur_seg_cmd->cmd == LC_DYSYMTAB) {
            dysymtab_cmd = (struct dysymtab_command *)cur_seg_cmd;
        }
    }

    if (!symtab_cmd || !dysymtab_cmd || !linkedit_segment || !dysymtab_cmd->nindirectsyms) return;

    uintptr_t linkedit_base = (uintptr_t)slide + linkedit_segment->vmaddr - linkedit_segment->fileoff;
    struct nlist_64 *symtab = (struct nlist_64 *)(linkedit_base + symtab_cmd->symoff);
    char *strtab = (char *)(linkedit_base + symtab_cmd->stroff);
    uint32_t *indirect_symtab = (uint32_t *)(linkedit_base + dysymtab_cmd->indirectsymoff);

    cur = (uintptr_t)header + sizeof(struct mach_header_64);
    for (uint i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize) {
        cur_seg_cmd = (struct segment_command_64 *)cur;
        if (cur_seg_cmd->cmd == LC_SEGMENT_64) {
            if (strcmp(cur_seg_cmd->segname, SEG_DATA) != 0 && strcmp(cur_seg_cmd->segname, "__DATA_CONST") != 0) {
                continue;
            }
            for (uint j = 0; j < cur_seg_cmd->nsects; j++) {
                struct section_64 *sect = (struct section_64 *)(cur + sizeof(struct segment_command_64)) + j;
                if ((sect->flags & SECTION_TYPE) == S_LAZY_SYMBOL_POINTERS ||
                    (sect->flags & SECTION_TYPE) == S_NON_LAZY_SYMBOL_POINTERS) {
                    perform_rebinding_with_section(rebindings, sect, slide, symtab, strtab, indirect_symtab);
                }
            }
        }
    }
}

static void _rebind_symbols_for_image(const struct mach_header *header, intptr_t slide) {
    rebind_symbols_for_image(_rebindings_head, header, slide);
}

static int rebind_symbols(struct rebinding rebindings[], size_t nel) {
    int retval = prepend_rebindings(&_rebindings_head, rebindings, nel);
    if (retval < 0) return retval;
    if (!_rebindings_head->next) {
        _dyld_register_func_for_add_image(_rebind_symbols_for_image);
    } else {
        uint32_t c = _dyld_image_count();
        for (uint32_t i = 0; i < c; i++) {
            _rebind_symbols_for_image(_dyld_get_image_header(i), _dyld_get_image_vmaddr_slide(i));
        }
    }
    return retval;
}

// ==========================================
// 2. 档位配置与持久化存储
// ==========================================
static NSString * const kHQVoiceLevelKey = @"com.custom.wechat.hqvoice.level";
static NSString * const kHQVoiceLevelChangedNotification = @"HQVoiceLevelDidChangeNotification";

typedef NS_ENUM(NSInteger, HQVoiceLevel) {
    HQVoiceLevelOff    = 0, // 关闭（微信原生）
    HQVoiceLevelLow    = 1, // 小等（24kHz / 24kbps 清晰）
    HQVoiceLevelMedium = 2, // 中等（24kHz / 32kbps 均衡）
    HQVoiceLevelHigh   = 3  // 最高（24kHz / 40kbps 极限）
};

static HQVoiceLevel GetCurrentVoiceLevel(void) {
    return (HQVoiceLevel)[[NSUserDefaults standardUserDefaults] integerForKey:kHQVoiceLevelKey];
}

static void SetCurrentVoiceLevel(HQVoiceLevel level) {
    [[NSUserDefaults standardUserDefaults] setInteger:level forKey:kHQVoiceLevelKey];
    [[NSUserDefaults standardUserDefaults] synchronize];
    [[NSNotificationCenter defaultCenter] postNotificationName:kHQVoiceLevelChangedNotification object:nil];
}

static NSString *GetVoiceLevelFullName(HQVoiceLevel level) {
    switch (level) {
        case HQVoiceLevelLow:    return @"小等 (24kHz / 24kbps 清晰)";
        case HQVoiceLevelMedium: return @"中等 (24kHz / 32kbps 均衡)";
        case HQVoiceLevelHigh:   return @"最高 (24kHz / 40kbps 极限)";
        default:                 return @"已关闭 (微信原生音质)";
    }
}

static NSString *GetVoiceLevelShortTag(HQVoiceLevel level) {
    switch (level) {
        case HQVoiceLevelLow:    return @"小等音质";
        case HQVoiceLevelMedium: return @"中等音质";
        case HQVoiceLevelHigh:   return @"最高音质";
        default:                 return @"";
    }
}

static int GetTargetBitRate(HQVoiceLevel level) {
    switch (level) {
        case HQVoiceLevelLow:    return 24000;
        case HQVoiceLevelMedium: return 32000;
        case HQVoiceLevelHigh:   return 40000;
        default:                 return 16000;
    }
}

// ==========================================
// 3. 音质选择弹窗 UI
// ==========================================
static UIViewController *FindTopViewController(void) {
    UIWindow *keyWindow = nil;
    for (UIScene *scene in [UIApplication sharedApplication].connectedScenes) {
        if (scene.activationState == UISceneActivationStateForegroundActive && [scene isKindOfClass:[UIWindowScene class]]) {
            UIWindowScene *windowScene = (UIWindowScene *)scene;
            for (UIWindow *w in windowScene.windows) {
                if (w.isKeyWindow) {
                    keyWindow = w;
                    break;
                }
            }
        }
    }
    UIViewController *topVC = keyWindow.rootViewController;
    while (topVC.presentedViewController) {
        topVC = topVC.presentedViewController;
    }
    return topVC;
}

static void ShowHQVoiceControlMenu(void) {
    HQVoiceLevel current = GetCurrentVoiceLevel();
    NSString *title = [NSString stringWithFormat:@"语音条音质调节\n当前：%@", GetVoiceLevelFullName(current)];

    UIAlertController *sheet = [UIAlertController alertControllerWithTitle:title
                                                                   message:@"安静房间或接声卡建议选「最高」；刮风马路/地铁建议选「关闭」以保留系统降噪。"
                                                            preferredStyle:UIAlertControllerStyleActionSheet];

    NSArray<NSNumber *> *levels = @[
        @(HQVoiceLevelHigh),
        @(HQVoiceLevelMedium),
        @(HQVoiceLevelLow),
        @(HQVoiceLevelOff)
    ];

    for (NSNumber *num in levels) {
        HQVoiceLevel lvl = (HQVoiceLevel)[num integerValue];
        NSString *prefix = (lvl == current) ? @"✓ " : @"";
        NSString *btnTitle = [NSString stringWithFormat:@"%@%@", prefix, GetVoiceLevelFullName(lvl)];

        UIAlertActionStyle style = (lvl == HQVoiceLevelOff) ? UIAlertActionStyleDestructive : UIAlertActionStyleDefault;
        [sheet addAction:[UIAlertAction actionWithTitle:btnTitle style:style handler:^(UIAlertAction * _Nonnull action) {
            SetCurrentVoiceLevel(lvl);
        }]];
    }

    [sheet addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];

    UIViewController *topVC = FindTopViewController();
    if (topVC) {
        if (sheet.popoverPresentationController) {
            sheet.popoverPresentationController.sourceView = topVC.view;
            sheet.popoverPresentationController.sourceRect = CGRectMake(topVC.view.bounds.size.width / 2.0, topVC.view.bounds.size.height - 100, 1, 1);
        }
        [topVC presentViewController:sheet animated:YES completion:nil];
    }
}

// ==========================================
// 4. Objective-C 运行时安全交换工具
// ==========================================
static void SwizzleInstanceMethod(Class cls, SEL origSel, SEL newSel) {
    if (!cls) return;
    Method origMethod = class_getInstanceMethod(cls, origSel);
    Method newMethod = class_getInstanceMethod(cls, newSel);
    if (!origMethod || !newMethod) return;

    if (class_addMethod(cls, origSel, method_getImplementation(newMethod), method_getTypeEncoding(newMethod))) {
        class_replaceMethod(cls, newSel, method_getImplementation(origMethod), method_getTypeEncoding(origMethod));
    } else {
        method_exchangeImplementations(origMethod, newMethod);
    }
}

// ==========================================
// 5. 硬件采集与会话模式 Hook（适配 8.0.75）
// ==========================================
static OSStatus (*orig_AudioQueueNewInput)(const AudioStreamBasicDescription *inFormat, AudioQueueInputCallback inCallbackProc, void *inUserData, CFRunLoopRef inCallbackRunLoop, CFStringRef inCallbackRunLoopMode, UInt32 inFlags, AudioQueueRef *outAQ);

static OSStatus my_AudioQueueNewInput(const AudioStreamBasicDescription *inFormat, AudioQueueInputCallback inCallbackProc, void *inUserData, CFRunLoopRef inCallbackRunLoop, CFStringRef inCallbackRunLoopMode, UInt32 inFlags, AudioQueueRef *outAQ) {
    HQVoiceLevel level = GetCurrentVoiceLevel();
    if (level != HQVoiceLevelOff && inFormat != NULL && inFormat->mFormatID == kAudioFormatLinearPCM) {
        AudioStreamBasicDescription customFormat = *inFormat;
        if (customFormat.mSampleRate == 16000.0) {
            customFormat.mSampleRate = 24000.0;
        }
        return orig_AudioQueueNewInput(&customFormat, inCallbackProc, inUserData, inCallbackRunLoop, inCallbackRunLoopMode, inFlags, outAQ);
    }
    return orig_AudioQueueNewInput(inFormat, inCallbackProc, inUserData, inCallbackRunLoop, inCallbackRunLoopMode, inFlags, outAQ);
}

static AVAudioSessionMode ResolveMappedAudioMode(AVAudioSessionMode mode) {
    HQVoiceLevel level = GetCurrentVoiceLevel();
    if (level != HQVoiceLevelOff && [mode isEqualToString:AVAudioSessionModeVoiceChat]) {
        switch (level) {
            case HQVoiceLevelLow:    return AVAudioSessionModeDefault;
            case HQVoiceLevelMedium: return AVAudioSessionModeVideoRecording;
            case HQVoiceLevelHigh:   return AVAudioSessionModeMeasurement;
            default: break;
        }
    }
    return mode;
}

@implementation AVAudioSession (HQVoiceHook)

- (BOOL)hq_setMode:(AVAudioSessionMode)mode error:(NSError **)outError {
    return [self hq_setMode:ResolveMappedAudioMode(mode) error:outError];
}

- (BOOL)hq_setCategory:(AVAudioSessionCategory)category mode:(AVAudioSessionMode)mode options:(AVAudioSessionCategoryOptions)options error:(NSError **)outError {
    return [self hq_setCategory:category mode:ResolveMappedAudioMode(mode) options:options error:outError];
}

@end

// ==========================================
// 6. 微信 8.0.75 SilkAudioRecorder 码率动态注入
// ==========================================
static void ApplySilkRecorderParams(id recorderObj) {
    HQVoiceLevel level = GetCurrentVoiceLevel();
    if (level == HQVoiceLevelOff || !recorderObj) return;

    int targetBitRate = GetTargetBitRate(level);
    unsigned int ivarCount = 0;
    Ivar *ivars = class_copyIvarList([recorderObj class], &ivarCount);
    if (!ivars) return;

    for (unsigned int i = 0; i < ivarCount; i++) {
        const char *rawName = ivar_getName(ivars[i]);
        const char *typeEnc = ivar_getTypeEncoding(ivars[i]);
        if (!rawName || !typeEnc) continue;

        NSString *name = [[NSString stringWithUTF8String:rawName] lowercaseString];
        ptrdiff_t offset = ivar_getOffset(ivars[i]);
        uint8_t *basePtr = (uint8_t *)(__bridge void *)recorderObj;

        if ([name containsString:@"bitrate"]) {
            if (strcmp(typeEnc, "i") == 0 || strcmp(typeEnc, "I") == 0) {
                *(int *)(basePtr + offset) = targetBitRate;
            }
        } else if ([name containsString:@"samplerate"]) {
            if (strcmp(typeEnc, "i") == 0 || strcmp(typeEnc, "I") == 0) {
                if (*(int *)(basePtr + offset) == 16000) {
                    *(int *)(basePtr + offset) = 24000;
                }
            } else if (strcmp(typeEnc, "d") == 0) {
                if (*(double *)(basePtr + offset) == 16000.0) {
                    *(double *)(basePtr + offset) = 24000.0;
                }
            }
        }
    }
    free(ivars);
}

@implementation NSObject (HQSilkRecorderHook)

- (BOOL)hq_prepareRecord {
    ApplySilkRecorderParams(self);
    BOOL ret = [self hq_prepareRecord];
    ApplySilkRecorderParams(self);
    return ret;
}

- (BOOL)hq_prepareRecordWithNotify:(BOOL)notify {
    ApplySilkRecorderParams(self);
    BOOL ret = [self hq_prepareRecordWithNotify:notify];
    ApplySilkRecorderParams(self);
    return ret;
}

@end

// ==========================================
// 7. 语音条快捷呼出菜单交互挂载
// ==========================================
static const void *kHQVoiceBarBoundKey = &kHQVoiceBarBoundKey;

@implementation UIButton (HQVoiceUIHook)

- (void)hq_setTitle:(NSString *)title forState:(UIControlState)state {
    if (state == UIControlStateNormal && [title hasPrefix:@"按住 说话"]) {
        NSString *tag = GetVoiceLevelShortTag(GetCurrentVoiceLevel());
        NSString *displayTitle = (tag.length > 0) ? [NSString stringWithFormat:@"按住 说话 · %@", tag] : @"按住 说话";
        [self hq_setTitle:displayTitle forState:state];

        if (![objc_getAssociatedObject(self, kHQVoiceBarBoundKey) boolValue]) {
            objc_setAssociatedObject(self, kHQVoiceBarBoundKey, @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);

            UITapGestureRecognizer *doubleTap = [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(hq_onVoiceBarDoubleTap:)];
            doubleTap.numberOfTapsRequired = 2;
            [self addGestureRecognizer:doubleTap];

            [[NSNotificationCenter defaultCenter] addObserver:self
                                                     selector:@selector(hq_refreshVoiceBarTitle)
                                                         name:kHQVoiceLevelChangedNotification
                                                       object:nil];
        }
        return;
    }
    [self hq_setTitle:title forState:state];
}

- (void)hq_didMoveToWindow {
    [self hq_didMoveToWindow];
    if (self.window && [self.accessibilityLabel containsString:@"语音"] && ![objc_getAssociatedObject(self, kHQVoiceBarBoundKey) boolValue]) {
        objc_setAssociatedObject(self, kHQVoiceBarBoundKey, @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        UILongPressGestureRecognizer *longPress = [[UILongPressGestureRecognizer alloc] initWithTarget:self action:@selector(hq_onVoiceIconLongPress:)];
        longPress.minimumPressDuration = 0.5;
        [self addGestureRecognizer:longPress];
    }
}

- (void)hq_onVoiceBarDoubleTap:(UITapGestureRecognizer *)gesture {
    if (gesture.state == UIGestureRecognizerStateRecognized) {
        ShowHQVoiceControlMenu();
    }
}

- (void)hq_onVoiceIconLongPress:(UILongPressGestureRecognizer *)gesture {
    if (gesture.state == UIGestureRecognizerStateBegan) {
        UIImpactFeedbackGenerator *feedback = [[UIImpactFeedbackGenerator alloc] initWithStyle:UIImpactFeedbackStyleMedium];
        [feedback impactOccurred];
        ShowHQVoiceControlMenu();
    }
}

- (void)hq_refreshVoiceBarTitle {
    NSString *currentTitle = [self titleForState:UIControlStateNormal];
    if ([currentTitle hasPrefix:@"按住 说话"]) {
        [self setTitle:@"按住 说话" forState:UIControlStateNormal];
    }
}

@end

// ==========================================
// 8. 动态库入口初始化
// ==========================================
__attribute__((constructor))
static void HQVoicePluginInit(void) {
    @autoreleasepool {
        // 1. Fishhook 绑定 AudioQueueNewInput 同步 24kHz 采样率
        struct rebinding reb = { "AudioQueueNewInput", (void *)my_AudioQueueNewInput, (void **)&orig_AudioQueueNewInput };
        rebind_symbols(&reb, 1);

        // 2. Hook AVAudioSession 解除通话窄带滤波
        Class sessionCls = [AVAudioSession class];
        SwizzleInstanceMethod(sessionCls, @selector(setMode:error:), @selector(hq_setMode:error:));
        SwizzleInstanceMethod(sessionCls, @selector(setCategory:mode:options:error:), @selector(hq_setCategory:mode:options:error:));

        // 3. Hook 微信 8.0.75 SilkAudioRecorder
        Class silkRecorderCls = NSClassFromString(@"SilkAudioRecorder");
        if (silkRecorderCls) {
            SwizzleInstanceMethod(silkRecorderCls, NSSelectorFromString(@"prepareRecord"), @selector(hq_prepareRecord));
            SwizzleInstanceMethod(silkRecorderCls, NSSelectorFromString(@"prepareRecordWithNotify:"), @selector(hq_prepareRecordWithNotify:));
        }

        // 4. Hook UIButton 挂载菜单呼出与状态展示
        Class btnCls = [UIButton class];
        SwizzleInstanceMethod(btnCls, @selector(setTitle:forState:), @selector(hq_setTitle:forState:));
        SwizzleInstanceMethod(btnCls, @selector(didMoveToWindow), @selector(hq_didMoveToWindow));
    }
}
