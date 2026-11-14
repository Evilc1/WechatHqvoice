#import <UIKit/UIKit.h>
#import <AVFoundation/AVFoundation.h>
#import <AudioToolbox/AudioToolbox.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <stdatomic.h>
#import <string.h>
#import <stdlib.h>

// ==========================================
// 1. 内置轻量级 Fishhook
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
// 2. 档位配置（原子缓存，保证音频线程零延迟安全读取）
// ==========================================
static NSString * const kHQVoiceLevelKey = @"com.custom.wechat.hqvoice.level";
static NSString * const kHQVoiceLevelChangedNotification = @"HQVoiceLevelDidChangeNotification";

typedef NS_ENUM(NSInteger, HQVoiceLevel) {
    HQVoiceLevelOff    = 0, // 关闭（微信原生）
    HQVoiceLevelLow    = 1, // 小等（解除电话滤波 + 轻度清晰增强）
    HQVoiceLevelMedium = 2, // 中等（近场人声模式 + 通透空气感增强）
    HQVoiceLevelHigh   = 3  // 最高（硬件无滤波直采 + 棚感人声激励）
};

static _Atomic(NSInteger) gCachedVoiceLevel = HQVoiceLevelOff;

static HQVoiceLevel GetCurrentVoiceLevel(void) {
    return (HQVoiceLevel)atomic_load(&gCachedVoiceLevel);
}

static void SetCurrentVoiceLevel(HQVoiceLevel level) {
    atomic_store(&gCachedVoiceLevel, level);
    [[NSUserDefaults standardUserDefaults] setInteger:level forKey:kHQVoiceLevelKey];
    [[NSUserDefaults standardUserDefaults] synchronize];
    [[NSNotificationCenter defaultCenter] postNotificationName:kHQVoiceLevelChangedNotification object:nil];
}

static NSString *GetVoiceLevelFullName(HQVoiceLevel level) {
    switch (level) {
        case HQVoiceLevelLow:    return @"小等 (清晰原声 · 去闷感)";
        case HQVoiceLevelMedium: return @"中等 (播客饱满 · 通透人声)";
        case HQVoiceLevelHigh:   return @"最高 (棚感直采 · 声卡/清唱)";
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
// 5. 实时 PCM 人声清晰度与动态 DSP 处理器（不改采样率，零变调）
// ==========================================
typedef struct {
    AudioQueueInputCallback origCallback;
    void *origUserData;
    BOOL is16BitMonoPCM;
    float prevIn;
    float dcPrevX;
    float dcPrevY;
} HQAudioContext;

#define kMaxHQContexts 32
static HQAudioContext gAudioContexts[kMaxHQContexts];
static _Atomic(uint32_t) gContextCursor = 0;

static inline int16_t SoftLimitPCM(float sample) {
    // 超过 24000 启用平滑软限幅，保证人声饱满且大声说话/唱歌绝不破音
    const float threshold = 24000.0f;
    const float maxVal = 32500.0f;
    float absVal = fabsf(sample);
    if (absVal > threshold) {
        float excess = absVal - threshold;
        float compressed = threshold + (maxVal - threshold) * (excess / (excess + 8500.0f));
        sample = (sample >= 0.0f) ? compressed : -compressed;
    }
    if (sample > 32767.0f) return 32767;
    if (sample < -32768.0f) return -32768;
    return (int16_t)sample;
}

static void ProcessVocalPCMBuffer(HQAudioContext *ctx, AudioQueueBufferRef inBuffer, HQVoiceLevel level) {
    if (level == HQVoiceLevelOff || !ctx->is16BitMonoPCM || !inBuffer || !inBuffer->mAudioData) return;

    UInt32 sampleCount = inBuffer->mAudioDataByteSize / sizeof(int16_t);
    if (sampleCount == 0) return;

    // 按档位配置人声激励参数（抵消 SILK 压缩导致的发闷感，同时补偿硬件直采音量）
    float gain = 1.0f;
    float clarityBoost = 0.0f; // 高频清晰度/齿音还原系数
    switch (level) {
        case HQVoiceLevelLow:
            gain = 1.12f;
            clarityBoost = 0.25f;
            break;
        case HQVoiceLevelMedium:
            gain = 1.28f;
            clarityBoost = 0.45f;
            break;
        case HQVoiceLevelHigh:
            gain = 1.45f;
            clarityBoost = 0.62f;
            break;
        default:
            return;
    }

    int16_t *samples = (int16_t *)inBuffer->mAudioData;
    float prevIn = ctx->prevIn;
    float dcPrevX = ctx->dcPrevX;
    float dcPrevY = ctx->dcPrevY;

    for (UInt32 i = 0; i < sampleCount; i++) {
        float x = (float)samples[i];

        // 1) 去除硬件直采时的低频直流偏移与喷麦轰鸣
        float cleanX = x - dcPrevX + 0.992f * dcPrevY;
        dcPrevX = x;
        dcPrevY = cleanX;

        // 2) 高频清晰度预加重（保留原始低频胸腔共鸣，同时提亮高频细节）
        float enhanced = cleanX + clarityBoost * (cleanX - prevIn);
        prevIn = cleanX;

        // 3) 增益补偿 + 软限幅防爆音
        samples[i] = SoftLimitPCM(enhanced * gain);
    }

    ctx->prevIn = prevIn;
    ctx->dcPrevX = dcPrevX;
    ctx->dcPrevY = dcPrevY;
}

static void HQ_AudioQueueInputCallback(void *inUserData, AudioQueueRef inAQ, AudioQueueBufferRef inBuffer, const AudioTimeStamp *inStartTime, UInt32 inNumberPacketDescriptions, const AudioStreamPacketDescription *inPacketDescs) {
    HQAudioContext *ctx = (HQAudioContext *)inUserData;
    if (!ctx || !ctx->origCallback) return;

    HQVoiceLevel level = GetCurrentVoiceLevel();
    if (level != HQVoiceLevelOff) {
        ProcessVocalPCMBuffer(ctx, inBuffer, level);
    }

    ctx->origCallback(ctx->origUserData, inAQ, inBuffer, inStartTime, inNumberPacketDescriptions, inPacketDescs);
}

static OSStatus (*orig_AudioQueueNewInput)(const AudioStreamBasicDescription *inFormat, AudioQueueInputCallback inCallbackProc, void *inUserData, CFRunLoopRef inCallbackRunLoop, CFStringRef inCallbackRunLoopMode, UInt32 inFlags, AudioQueueRef *outAQ);

static OSStatus my_AudioQueueNewInput(const AudioStreamBasicDescription *inFormat, AudioQueueInputCallback inCallbackProc, void *inUserData, CFRunLoopRef inCallbackRunLoop, CFStringRef inCallbackRunLoopMode, UInt32 inFlags, AudioQueueRef *outAQ) {
    // 关键：完全保留原始 inFormat（不改 mSampleRate），保证语速与音调 100% 正常！
    if (inCallbackProc != NULL && inFormat != NULL) {
        uint32_t idx = atomic_fetch_add(&gContextCursor, 1) % kMaxHQContexts;
        HQAudioContext *ctx = &gAudioContexts[idx];
        ctx->origCallback = inCallbackProc;
        ctx->origUserData = inUserData;
        ctx->is16BitMonoPCM = (inFormat->mFormatID == kAudioFormatLinearPCM &&
                               inFormat->mBitsPerChannel == 16 &&
                               inFormat->mChannelsPerFrame == 1);
        ctx->prevIn = 0.0f;
        ctx->dcPrevX = 0.0f;
        ctx->dcPrevY = 0.0f;

        return orig_AudioQueueNewInput(inFormat, HQ_AudioQueueInputCallback, ctx, inCallbackRunLoop, inCallbackRunLoopMode, inFlags, outAQ);
    }
    return orig_AudioQueueNewInput(inFormat, inCallbackProc, inUserData, inCallbackRunLoop, inCallbackRunLoopMode, inFlags, outAQ);
}

// ==========================================
// 6. 解除系统通话模式滤波（打开硬件全频段麦克风）
// ==========================================
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
        NSInteger savedLevel = [[NSUserDefaults standardUserDefaults] integerForKey:kHQVoiceLevelKey];
        atomic_store(&gCachedVoiceLevel, savedLevel);

        struct rebinding reb = { "AudioQueueNewInput", (void *)my_AudioQueueNewInput, (void **)&orig_AudioQueueNewInput };
        rebind_symbols(&reb, 1);

        Class sessionCls = [AVAudioSession class];
        SwizzleInstanceMethod(sessionCls, @selector(setMode:error:), @selector(hq_setMode:error:));
        SwizzleInstanceMethod(sessionCls, @selector(setCategory:mode:options:error:), @selector(hq_setCategory:mode:options:error:));

        Class btnCls = [UIButton class];
        SwizzleInstanceMethod(btnCls, @selector(setTitle:forState:), @selector(hq_setTitle:forState:));
        SwizzleInstanceMethod(btnCls, @selector(didMoveToWindow), @selector(hq_didMoveToWindow));
    }
}
