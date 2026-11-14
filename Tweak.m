#import <UIKit/UIKit.h>
#import <AVFoundation/AVFoundation.h>
#import <AudioToolbox/AudioToolbox.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <stdatomic.h>
#import <math.h>
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
// 2. 档位配置（原子缓存，音频线程实时读取）
// ==========================================
static NSString * const kHQVoiceLevelKey = @"com.custom.wechat.hqvoice.level";
static NSString * const kHQVoiceLevelChangedNotification = @"HQVoiceLevelDidChangeNotification";

typedef NS_ENUM(NSInteger, HQVoiceLevel) {
    HQVoiceLevelOff    = 0, // 关闭（微信原生）
    HQVoiceLevelLow    = 1, // 小等（轻度清晰去闷）
    HQVoiceLevelMedium = 2, // 中等（播客磁性人声）
    HQVoiceLevelHigh   = 3  // 最高（电台棚感 · 声卡/清唱）
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
        case HQVoiceLevelLow:    return @"小等 (自然清晰 · 去电话闷感)";
        case HQVoiceLevelMedium: return @"中等 (播客磁性 · 饱满人声)";
        case HQVoiceLevelHigh:   return @"最高 (电台棚感 · 声卡/清唱)";
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
// 5. 播客级双频段 Biquad 均衡器 + 动态压缩 DSP（不改采样率，零变调）
// ==========================================
typedef struct {
    float b0, b1, b2, a1, a2;
    float x1, x2, y1, y2;
} BiquadFilter;

typedef struct {
    AudioQueueInputCallback origCallback;
    void *origUserData;
    BOOL is16BitMonoPCM;
    double sampleRate;
    HQVoiceLevel configuredLevel;
    BiquadFilter warmthShelf;   // 180Hz 胸腔厚度补偿
    BiquadFilter presencePeak;  // 3.8kHz 齿音与通透度提亮
    float hpPrevX;
    float hpPrevY;
    float envFollower;
} HQAudioContext;

#define kMaxHQContexts 32
static HQAudioContext gAudioContexts[kMaxHQContexts];
static _Atomic(uint32_t) gContextCursor = 0;

static void SetupLowShelfFilter(BiquadFilter *f, float fs, float f0, float dBgain) {
    float A = powf(10.0f, dBgain / 40.0f);
    float w0 = 2.0f * (float)M_PI * f0 / fs;
    float cosw0 = cosf(w0);
    float sinw0 = sinf(w0);
    float alpha = sinw0 * 0.5f * sqrtf((A + 1.0f / A) * (1.0f / 0.85f - 1.0f) + 2.0f);
    float beta = 2.0f * sqrtf(A) * alpha;

    float a0 = (A + 1.0f) + (A - 1.0f) * cosw0 + beta;
    f->b0 = (A * ((A + 1.0f) - (A - 1.0f) * cosw0 + beta)) / a0;
    f->b1 = (2.0f * A * ((A - 1.0f) - (A + 1.0f) * cosw0)) / a0;
    f->b2 = (A * ((A + 1.0f) - (A - 1.0f) * cosw0 - beta)) / a0;
    f->a1 = (-2.0f * ((A - 1.0f) + (A + 1.0f) * cosw0)) / a0;
    f->a2 = ((A + 1.0f) + (A - 1.0f) * cosw0 - beta) / a0;
}

static void SetupPeakingFilter(BiquadFilter *f, float fs, float f0, float Q, float dBgain) {
    if (f0 > fs * 0.42f) f0 = fs * 0.42f;
    float A = powf(10.0f, dBgain / 40.0f);
    float w0 = 2.0f * (float)M_PI * f0 / fs;
    float cosw0 = cosf(w0);
    float alpha = sinf(w0) / (2.0f * Q);

    float a0 = 1.0f + alpha / A;
    f->b0 = (1.0f + alpha * A) / a0;
    f->b1 = (-2.0f * cosw0) / a0;
    f->b2 = (1.0f - alpha * A) / a0;
    f->a1 = (-2.0f * cosw0) / a0;
    f->a2 = (1.0f - alpha / A) / a0;
}

static inline float ProcessBiquad(BiquadFilter *f, float x) {
    float y = f->b0 * x + f->b1 * f->x1 + f->b2 * f->x2 - f->a1 * f->y1 - f->a2 * f->y2;
    f->x2 = f->x1;
    f->x1 = x;
    f->y2 = f->y1;
    f->y1 = y;
    return y;
}

static inline int16_t SoftLimitPCM(float sample) {
    const float threshold = 25000.0f;
    const float maxVal = 32600.0f;
    float absVal = fabsf(sample);
    if (absVal > threshold) {
        float excess = absVal - threshold;
        float compressed = threshold + (maxVal - threshold) * (excess / (excess + 7600.0f));
        sample = (sample >= 0.0f) ? compressed : -compressed;
    }
    if (sample > 32767.0f) return 32767;
    if (sample < -32768.0f) return -32768;
    return (int16_t)sample;
}

static void ConfigureFiltersForLevel(HQAudioContext *ctx, HQVoiceLevel level) {
    float fs = (ctx->sampleRate > 0.0) ? (float)ctx->sampleRate : 16000.0f;
    float warmthDb = 0.0f;
    float presenceDb = 0.0f;

    switch (level) {
        case HQVoiceLevelLow:
            warmthDb = 1.8f;
            presenceDb = 2.8f;
            break;
        case HQVoiceLevelMedium:
            warmthDb = 3.2f;
            presenceDb = 4.8f;
            break;
        case HQVoiceLevelHigh:
            warmthDb = 4.2f;
            presenceDb = 6.5f;
            break;
        default:
            break;
    }

    SetupLowShelfFilter(&ctx->warmthShelf, fs, 185.0f, warmthDb);
    SetupPeakingFilter(&ctx->presencePeak, fs, 3800.0f, 1.15f, presenceDb);
    ctx->configuredLevel = level;
}

static void ProcessBroadcastVocalPCM(HQAudioContext *ctx, AudioQueueBufferRef inBuffer, HQVoiceLevel level) {
    if (level == HQVoiceLevelOff || !ctx->is16BitMonoPCM || !inBuffer || !inBuffer->mAudioData) return;

    UInt32 sampleCount = inBuffer->mAudioDataByteSize / sizeof(int16_t);
    if (sampleCount == 0) return;

    if (ctx->configuredLevel != level) {
        ConfigureFiltersForLevel(ctx, level);
    }

    // 补偿关闭 iOS 通话 AGC 后的音量损失，让电台感与气声细节充分展现
    float baseMakeupGain = 1.0f;
    float compStrength = 0.0f;
    switch (level) {
        case HQVoiceLevelLow:
            baseMakeupGain = 1.45f;
            compStrength = 0.20f;
            break;
        case HQVoiceLevelMedium:
            baseMakeupGain = 2.05f;
            compStrength = 0.35f;
            break;
        case HQVoiceLevelHigh:
            baseMakeupGain = 2.75f; // +8.8dB，补偿 Measurement 无 AGC 衰减，人声饱满有磁性
            compStrength = 0.50f;
            break;
        default:
            return;
    }

    int16_t *samples = (int16_t *)inBuffer->mAudioData;
    float hpPrevX = ctx->hpPrevX;
    float hpPrevY = ctx->hpPrevY;
    float env = ctx->envFollower;

    for (UInt32 i = 0; i < sampleCount; i++) {
        float x = (float)samples[i];

        // 1) 70Hz 高通滤波：滤除喷麦低频轰鸣与手持摩擦底噪
        float hp = x - hpPrevX + 0.972f * hpPrevY;
        hpPrevX = x;
        hpPrevY = hp;

        // 2) 双频段电台 EQ：补足 185Hz 胸腔磁性 + 提亮 3.8kHz 齿音通透度
        float warmed = ProcessBiquad(&ctx->warmthShelf, hp);
        float bright = ProcessBiquad(&ctx->presencePeak, warmed);

        // 3) 播客级动态包络压缩：托起轻声细节，防止大声炸麦
        float absSig = fabsf(bright);
        env = 0.996f * env + 0.004f * absSig;
        float dynamicRatio = 1.0f;
        if (env > 3500.0f) {
            dynamicRatio = 1.0f - compStrength * ((env - 3500.0f) / (env + 6000.0f));
        }

        samples[i] = SoftLimitPCM(bright * baseMakeupGain * dynamicRatio);
    }

    ctx->hpPrevX = hpPrevX;
    ctx->hpPrevY = hpPrevY;
    ctx->envFollower = env;
}

static void HQ_AudioQueueInputCallback(void *inUserData, AudioQueueRef inAQ, AudioQueueBufferRef inBuffer, const AudioTimeStamp *inStartTime, UInt32 inNumberPacketDescriptions, const AudioStreamPacketDescription *inPacketDescs) {
    HQAudioContext *ctx = (HQAudioContext *)inUserData;
    if (!ctx || !ctx->origCallback) return;

    HQVoiceLevel level = GetCurrentVoiceLevel();
    if (level != HQVoiceLevelOff) {
        ProcessBroadcastVocalPCM(ctx, inBuffer, level);
    }

    ctx->origCallback(ctx->origUserData, inAQ, inBuffer, inStartTime, inNumberPacketDescriptions, inPacketDescs);
}

static OSStatus (*orig_AudioQueueNewInput)(const AudioStreamBasicDescription *inFormat, AudioQueueInputCallback inCallbackProc, void *inUserData, CFRunLoopRef inCallbackRunLoop, CFStringRef inCallbackRunLoopMode, UInt32 inFlags, AudioQueueRef *outAQ);

static OSStatus my_AudioQueueNewInput(const AudioStreamBasicDescription *inFormat, AudioQueueInputCallback inCallbackProc, void *inUserData, CFRunLoopRef inCallbackRunLoop, CFStringRef inCallbackRunLoopMode, UInt32 inFlags, AudioQueueRef *outAQ) {
    if (inCallbackProc != NULL && inFormat != NULL) {
        uint32_t idx = atomic_fetch_add(&gContextCursor, 1) % kMaxHQContexts;
        HQAudioContext *ctx = &gAudioContexts[idx];
        memset(ctx, 0, sizeof(HQAudioContext));
        ctx->origCallback = inCallbackProc;
        ctx->origUserData = inUserData;
        ctx->sampleRate = inFormat->mSampleRate;
        ctx->configuredLevel = HQVoiceLevelOff;
        ctx->is16BitMonoPCM = (inFormat->mFormatID == kAudioFormatLinearPCM &&
                               inFormat->mBitsPerChannel == 16 &&
                               inFormat->mChannelsPerFrame == 1);

        return orig_AudioQueueNewInput(inFormat, HQ_AudioQueueInputCallback, ctx, inCallbackRunLoop, inCallbackRunLoopMode, inFlags, outAQ);
    }
    return orig_AudioQueueNewInput(inFormat, inCallbackProc, inUserData, inCallbackRunLoop, inCallbackRunLoopMode, inFlags, outAQ);
}

// ==========================================
// 6. 解除系统通话模式滤波
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
// 7. 安全扫描 SilkAudioRecorder 内存控制块（不改采样率，只提码率）
// ==========================================
static void PatchSilkControlStructSafely(id recorderObj) {
    HQVoiceLevel level = GetCurrentVoiceLevel();
    if (level == HQVoiceLevelOff || !recorderObj) return;

    int targetBitRate = (level == HQVoiceLevelHigh) ? 40000 : ((level == HQVoiceLevelMedium) ? 32000 : 24000);
    size_t instSize = class_getInstanceSize([recorderObj class]);
    if (instSize < 32 || instSize > 4096) return;

    int32_t *words = (int32_t *)(__bridge void *)recorderObj;
    size_t wordCount = instSize / sizeof(int32_t);

    // 匹配 SKP_Silk_SDK_EncControlStruct 连续内存特征: [API_sampleRate, maxInternalSampleRate, packetSize, bitRate, ...]
    for (size_t i = 0; i + 7 < wordCount; i++) {
        int32_t apiSr = words[i];
        int32_t maxSr = words[i + 1];
        int32_t pktSz = words[i + 2];
        int32_t br    = words[i + 3];

        BOOL validSr = (apiSr == 16000 || apiSr == 24000);
        BOOL validMaxSr = (maxSr == 16000 || maxSr == 24000);
        BOOL validPkt = (pktSz == 320 || pktSz == 480);
        BOOL validBr = (br >= 8000 && br <= 32000);

        if (validSr && validMaxSr && validPkt && validBr) {
            // 保持 apiSr 和 pktSz 不变（绝对不变调），只拉高内部采样率、码率并关闭静音吞音
            words[i + 1] = 24000;
            words[i + 3] = targetBitRate;
            words[i + 5] = 2; // complexity = 2
            words[i + 6] = 0; // useInBandFEC = 0
            words[i + 7] = 0; // useDTX = 0
            break;
        }
    }
}

@implementation NSObject (HQSilkRecorderMemoryHook)

- (BOOL)hq_prepareRecord {
    BOOL ret = [self hq_prepareRecord];
    PatchSilkControlStructSafely(self);
    return ret;
}

- (BOOL)hq_prepareRecordWithNotify:(BOOL)notify {
    BOOL ret = [self hq_prepareRecordWithNotify:notify];
    PatchSilkControlStructSafely(self);
    return ret;
}

@end

// ==========================================
// 8. 语音条快捷呼出菜单交互挂载
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
// 9. 动态库入口初始化
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

        Class silkRecorderCls = NSClassFromString(@"SilkAudioRecorder");
        if (silkRecorderCls) {
            SwizzleInstanceMethod(silkRecorderCls, NSSelectorFromString(@"prepareRecord"), @selector(hq_prepareRecord));
            SwizzleInstanceMethod(silkRecorderCls, NSSelectorFromString(@"prepareRecordWithNotify:"), @selector(hq_prepareRecordWithNotify:));
        }

        Class btnCls = [UIButton class];
        SwizzleInstanceMethod(btnCls, @selector(setTitle:forState:), @selector(hq_setTitle:forState:));
        SwizzleInstanceMethod(btnCls, @selector(didMoveToWindow), @selector(hq_didMoveToWindow));
    }
}
