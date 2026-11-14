#import <UIKit/UIKit.h>
#import <AVFoundation/AVFoundation.h>
#import <AudioToolbox/AudioToolbox.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <mach/mach.h>
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
// 2. 档位与实时命中状态统计
// ==========================================
static NSString * const kHQVoiceLevelKey = @"com.custom.wechat.hqvoice.level";
static NSString * const kHQVoiceLevelChangedNotification = @"HQVoiceLevelDidChangeNotification";

typedef NS_ENUM(NSInteger, HQVoiceLevel) {
    HQVoiceLevelOff    = 0,
    HQVoiceLevelLow    = 1,
    HQVoiceLevelMedium = 2,
    HQVoiceLevelHigh   = 3
};

static _Atomic(NSInteger) gCachedVoiceLevel = HQVoiceLevelOff;
static _Atomic(uint64_t) gHitPacketsCount = 0;
static _Atomic(uint32_t) gDetectedSampleRate = 0;
static _Atomic(BOOL) gSilkPatched = NO;

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
        case HQVoiceLevelLow:    return @"小等 (自然通透 · 去闷感)";
        case HQVoiceLevelMedium: return @"中等 (清脆播客 · 降底噪)";
        case HQVoiceLevelHigh:   return @"最高 (极致清透 · 空气感拉满)";
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
    uint64_t hits = atomic_load(&gHitPacketsCount);
    uint32_t sr = atomic_load(&gDetectedSampleRate);
    BOOL silkOk = atomic_load(&gSilkPatched);

    NSString *statusLine = (sr > 0)
        ? [NSString stringWithFormat:@"已接管音频包：%llu 次（%uHz | 码率解锁:%@）", hits, sr, silkOk ? @"是" : @"软件增强"]
        : [NSString stringWithFormat:@"已接管音频包：%llu 次（录音后刷新可见）", hits];

    NSString *title = [NSString stringWithFormat:@"语音条音质调节\n当前：%@\n%@", GetVoiceLevelFullName(current), statusLine];

    UIAlertController *sheet = [UIAlertController alertControllerWithTitle:title
                                                                   message:@"切换档位后，下一次按住说话立即生效。"
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
// 5. 专攻“清透空气感”的混音级 DSP（砍闷声 + 提空气 + 智能底噪门限）
// ==========================================
typedef struct {
    float b0, b1, b2, a1, a2;
    float x1, x2, y1, y2;
} BiquadFilter;

typedef struct {
    AudioQueueInputCallback origCallback;
    void *origUserData;
    double sampleRate;
    uint32_t bitsPerChannel;
    uint32_t bytesPerFrame;
    BOOL isFloat32;
    HQVoiceLevel configuredLevel;
    BiquadFilter highPass115Hz;   // 115Hz 高通：切掉手持闷声与低频浑浊
    BiquadFilter deMud260Hz;      // 260Hz 陷波：消除“电话听筒/捂嘴闷罐感”
    BiquadFilter airSparkle5kHz;  // 5.2kHz 空气感提亮：拉满唇齿通透度
    BiquadFilter exciterBand;     // 3.2kHz 以上高频谐波激励带通
    float envFollower;
    float gateGain;
} HQAudioContext;

#define kMaxHQContexts 32
static HQAudioContext gAudioContexts[kMaxHQContexts];
static _Atomic(uint32_t) gContextCursor = 0;

static void SetupPeakingFilter(BiquadFilter *f, float fs, float f0, float Q, float dBgain) {
    if (f0 > fs * 0.43f) f0 = fs * 0.43f;
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

static void SetupHighPassFilter(BiquadFilter *f, float fs, float f0, float Q) {
    if (f0 > fs * 0.43f) f0 = fs * 0.43f;
    float w0 = 2.0f * (float)M_PI * f0 / fs;
    float cosw0 = cosf(w0);
    float alpha = sinf(w0) / (2.0f * Q);

    float a0 = 1.0f + alpha;
    f->b0 = ((1.0f + cosw0) * 0.5f) / a0;
    f->b1 = (-(1.0f + cosw0)) / a0;
    f->b2 = ((1.0f + cosw0) * 0.5f) / a0;
    f->a1 = (-2.0f * cosw0) / a0;
    f->a2 = (1.0f - alpha) / a0;
}

static inline float ProcessBiquad(BiquadFilter *f, float x) {
    float y = f->b0 * x + f->b1 * f->x1 + f->b2 * f->x2 - f->a1 * f->y1 - f->a2 * f->y2;
    f->x2 = f->x1;
    f->x1 = x;
    f->y2 = f->y1;
    f->y1 = y;
    return y;
}

static void ConfigureCrystalClearChain(HQAudioContext *ctx, HQVoiceLevel level) {
    float fs = (ctx->sampleRate > 0.0) ? (float)ctx->sampleRate : 16000.0f;
    float deMudDb = 0.0f;
    float airDb = 0.0f;

    switch (level) {
        case HQVoiceLevelLow:
            deMudDb = -2.0f;
            airDb = 4.5f;
            break;
        case HQVoiceLevelMedium:
            deMudDb = -3.2f;
            airDb = 7.2f;
            break;
        case HQVoiceLevelHigh:
            deMudDb = -4.5f; // 砍掉 260Hz 闷罐浑浊感，人声立刻变干净
            airDb = 9.8f;    // 大幅提亮 5.2kHz 空气感与唇齿细节
            break;
        default:
            break;
    }

    memset(&ctx->highPass115Hz, 0, sizeof(BiquadFilter));
    memset(&ctx->deMud260Hz, 0, sizeof(BiquadFilter));
    memset(&ctx->airSparkle5kHz, 0, sizeof(BiquadFilter));
    memset(&ctx->exciterBand, 0, sizeof(BiquadFilter));

    SetupHighPassFilter(&ctx->highPass115Hz, fs, 115.0f, 0.707f);
    SetupPeakingFilter(&ctx->deMud260Hz, fs, 260.0f, 1.25f, deMudDb);
    SetupPeakingFilter(&ctx->airSparkle5kHz, fs, 5200.0f, 0.90f, airDb);
    SetupHighPassFilter(&ctx->exciterBand, fs, 3200.0f, 0.85f);

    ctx->gateGain = 1.0f;
    ctx->configuredLevel = level;
}

static void ProcessCrystalVocalBuffer(HQAudioContext *ctx, AudioQueueBufferRef inBuffer, HQVoiceLevel level) {
    if (level == HQVoiceLevelOff || !inBuffer || !inBuffer->mAudioData || inBuffer->mAudioDataByteSize == 0) return;

    if (ctx->configuredLevel != level) {
        ConfigureCrystalClearChain(ctx, level);
    }

    float makeupGain = 1.0f;
    float airHarmonicMix = 0.0f;
    float compStrength = 0.0f;
    float gateThreshold = 0.008f;

    switch (level) {
        case HQVoiceLevelLow:
            makeupGain = 1.65f;
            airHarmonicMix = 0.12f;
            compStrength = 0.25f;
            gateThreshold = 0.007f;
            break;
        case HQVoiceLevelMedium:
            makeupGain = 2.40f;
            airHarmonicMix = 0.24f;
            compStrength = 0.40f;
            gateThreshold = 0.010f;
            break;
        case HQVoiceLevelHigh:
            makeupGain = 3.20f;
            airHarmonicMix = 0.36f; // 仅对 3.2kHz 以上高频做空气感谐波激励，绝不浑浊
            compStrength = 0.55f;
            gateThreshold = 0.013f; // 说话间隙压低房间底噪，衬托人声清透度
            break;
        default:
            return;
    }

    float env = ctx->envFollower;
    float gateGain = ctx->gateGain;

    if (ctx->isFloat32) {
        float *samples = (float *)inBuffer->mAudioData;
        UInt32 count = inBuffer->mAudioDataByteSize / sizeof(float);
        for (UInt32 i = 0; i < count; i++) {
            float x = samples[i];
            float hp = ProcessBiquad(&ctx->highPass115Hz, x);
            float clean = ProcessBiquad(&ctx->deMud260Hz, hp);
            float crisp = ProcessBiquad(&ctx->airSparkle5kHz, clean);

            // 高频空气感谐波激励（不碰低频，保持声音干净晶莹）
            float hiOnly = ProcessBiquad(&ctx->exciterBand, clean);
            float excited = crisp + airHarmonicMix * tanhf(hiOnly * 4.5f) * 0.20f;

            float absSig = fabsf(excited);
            env = (absSig > env) ? (0.92f * env + 0.08f * absSig) : (0.996f * env + 0.004f * absSig);

            // 自适应底噪门限：无人说话时平滑压低底噪，说话瞬间立刻打开
            float targetGate = (env < gateThreshold) ? 0.18f : 1.0f;
            gateGain = (targetGate > gateGain) ? (0.90f * gateGain + 0.10f * targetGate) : (0.995f * gateGain + 0.005f * targetGate);

            float compRatio = (env > 0.09f) ? (1.0f - compStrength * ((env - 0.09f) / (env + 0.18f))) : 1.0f;
            samples[i] = tanhf(excited * makeupGain * gateGain * compRatio) * 0.96f;
        }
    } else {
        int16_t *samples = (int16_t *)inBuffer->mAudioData;
        UInt32 count = inBuffer->mAudioDataByteSize / sizeof(int16_t);
        for (UInt32 i = 0; i < count; i++) {
            float x = (float)samples[i] / 32768.0f;

            // 1) 115Hz 高通去低频闷声
            float hp = ProcessBiquad(&ctx->highPass115Hz, x);
            // 2) 260Hz 削减浑浊共振（消除电话听筒闷罐感）
            float clean = ProcessBiquad(&ctx->deMud260Hz, hp);
            // 3) 5.2kHz 拉满清透空气感
            float crisp = ProcessBiquad(&ctx->airSparkle5kHz, clean);

            // 4) 纯高频空气谐波激励
            float hiOnly = ProcessBiquad(&ctx->exciterBand, clean);
            float excited = crisp + airHarmonicMix * tanhf(hiOnly * 4.5f) * 0.20f;

            // 5) 包络追踪 + 智能底噪门限 + 动态压缩
            float absSig = fabsf(excited);
            env = (absSig > env) ? (0.92f * env + 0.08f * absSig) : (0.996f * env + 0.004f * absSig);

            float targetGate = (env < gateThreshold) ? 0.18f : 1.0f;
            gateGain = (targetGate > gateGain) ? (0.90f * gateGain + 0.10f * targetGate) : (0.995f * gateGain + 0.005f * targetGate);

            float compRatio = (env > 0.09f) ? (1.0f - compStrength * ((env - 0.09f) / (env + 0.18f))) : 1.0f;
            float out = tanhf(excited * makeupGain * gateGain * compRatio) * 0.96f;

            int32_t pcmOut = (int32_t)(out * 32767.0f);
            if (pcmOut > 32767) pcmOut = 32767;
            if (pcmOut < -32768) pcmOut = -32768;
            samples[i] = (int16_t)pcmOut;
        }
    }

    ctx->envFollower = env;
    ctx->gateGain = gateGain;
}

// ==========================================
// 6. AudioQueue 拦截（完全同步采样率，零变调）
// ==========================================
static void HQ_AudioQueueInputCallback(void *inUserData, AudioQueueRef inAQ, AudioQueueBufferRef inBuffer, const AudioTimeStamp *inStartTime, UInt32 inNumberPacketDescriptions, const AudioStreamPacketDescription *inPacketDescs) {
    HQAudioContext *ctx = (HQAudioContext *)inUserData;
    if (!ctx || !ctx->origCallback) return;

    atomic_fetch_add(&gHitPacketsCount, 1);
    if (ctx->sampleRate > 0.0) {
        atomic_store(&gDetectedSampleRate, (uint32_t)ctx->sampleRate);
    }

    HQVoiceLevel level = GetCurrentVoiceLevel();
    if (level != HQVoiceLevelOff) {
        ProcessCrystalVocalBuffer(ctx, inBuffer, level);
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
        ctx->sampleRate = (inFormat->mSampleRate > 0.0) ? inFormat->mSampleRate : 16000.0;
        ctx->bitsPerChannel = inFormat->mBitsPerChannel;
        ctx->bytesPerFrame = inFormat->mBytesPerFrame;
        ctx->isFloat32 = ((inFormat->mFormatFlags & kAudioFormatFlagIsFloat) != 0);
        ctx->configuredLevel = HQVoiceLevelOff;

        return orig_AudioQueueNewInput(inFormat, HQ_AudioQueueInputCallback, ctx, inCallbackRunLoop, inCallbackRunLoopMode, inFlags, outAQ);
    }
    return orig_AudioQueueNewInput(inFormat, inCallbackProc, inUserData, inCallbackRunLoop, inCallbackRunLoopMode, inFlags, outAQ);
}

// ==========================================
// 7. 解除系统通话模式滤波
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
// 8. 同步解锁 SilkAudioRecorder 24kHz 采样率与 40kbps 码率（防变调）
// ==========================================
static void SyncUpgradeSilkRecorderObjC(id recorderObj, BOOL allow24kSampleRate) {
    HQVoiceLevel level = GetCurrentVoiceLevel();
    if (level == HQVoiceLevelOff || !recorderObj) return;

    int targetBitRate = (level == HQVoiceLevelHigh) ? 40000 : ((level == HQVoiceLevelMedium) ? 32000 : 24000);
    unsigned int ivarCount = 0;
    Ivar *ivars = class_copyIvarList([recorderObj class], &ivarCount);
    if (!ivars) return;

    uint8_t *basePtr = (uint8_t *)(__bridge void *)recorderObj;
    for (unsigned int i = 0; i < ivarCount; i++) {
        const char *rawName = ivar_getName(ivars[i]);
        const char *typeEnc = ivar_getTypeEncoding(ivars[i]);
        if (!rawName || !typeEnc) continue;

        NSString *name = [[NSString stringWithUTF8String:rawName] lowercaseString];
        ptrdiff_t offset = ivar_getOffset(ivars[i]);

        // 仅在 prepareRecord 执行前同步拉高采样率，确保 AudioQueue 和编码器两端一致（绝不变调）
        if (allow24kSampleRate && [name containsString:@"samplerate"]) {
            if (strcmp(typeEnc, "i") == 0 || strcmp(typeEnc, "I") == 0) {
                if (*(int *)(basePtr + offset) == 16000) {
                    *(int *)(basePtr + offset) = 24000;
                }
            } else if (strcmp(typeEnc, "d") == 0) {
                if (*(double *)(basePtr + offset) == 16000.0) {
                    *(double *)(basePtr + offset) = 24000.0;
                }
            }
        } else if ([name containsString:@"bitrate"]) {
            if (strcmp(typeEnc, "i") == 0 || strcmp(typeEnc, "I") == 0) {
                *(int *)(basePtr + offset) = targetBitRate;
                atomic_store(&gSilkPatched, YES);
            }
        }
    }
    free(ivars);
}

static BOOL TryPatchSilkControlAtAddress(uintptr_t baseAddr, int targetBitRate) {
    int32_t buf[64] = {0};
    vm_size_t outSize = 0;
    if (vm_read_overwrite(mach_task_self(), (vm_address_t)baseAddr, sizeof(buf), (vm_address_t)buf, &outSize) != KERN_SUCCESS) {
        return NO;
    }

    for (int i = 0; i + 7 < 64; i++) {
        int32_t apiSr = buf[i];
        int32_t maxSr = buf[i + 1];
        int32_t pktSz = buf[i + 2];
        int32_t br    = buf[i + 3];

        if ((apiSr == 16000 || apiSr == 24000) &&
            (maxSr == 16000 || maxSr == 24000) &&
            (pktSz == 320 || pktSz == 480) &&
            (br >= 8000 && br <= 32000)) {
            int32_t *liveWords = (int32_t *)(baseAddr + (uintptr_t)i * sizeof(int32_t));
            liveWords[1] = 24000;
            liveWords[3] = targetBitRate;
            liveWords[5] = 2; // complexity = 2
            liveWords[6] = 0; // useInBandFEC = 0
            liveWords[7] = 0; // useDTX = 0
            return YES;
        }
    }
    return NO;
}

static void PatchSilkRecorderMemory(id recorderObj) {
    HQVoiceLevel level = GetCurrentVoiceLevel();
    if (level == HQVoiceLevelOff || !recorderObj) return;

    int targetBitRate = (level == HQVoiceLevelHigh) ? 40000 : ((level == HQVoiceLevelMedium) ? 32000 : 24000);
    uintptr_t objAddr = (uintptr_t)(__bridge void *)recorderObj;

    if (TryPatchSilkControlAtAddress(objAddr, targetBitRate)) {
        atomic_store(&gSilkPatched, YES);
        return;
    }

    uintptr_t ptrSlots[48] = {0};
    vm_size_t outSize = 0;
    if (vm_read_overwrite(mach_task_self(), (vm_address_t)objAddr, sizeof(ptrSlots), (vm_address_t)ptrSlots, &outSize) == KERN_SUCCESS) {
        for (int i = 1; i < 48; i++) {
            uintptr_t candidate = ptrSlots[i];
            if (candidate > 0x100000000ULL && candidate < 0x400000000ULL && (candidate & 0x3) == 0) {
                if (TryPatchSilkControlAtAddress(candidate, targetBitRate)) {
                    atomic_store(&gSilkPatched, YES);
                    return;
                }
            }
        }
    }
}

@implementation NSObject (HQSilkRecorderCrystalHook)

- (BOOL)hq_prepareRecord {
    SyncUpgradeSilkRecorderObjC(self, YES);
    BOOL ret = [self hq_prepareRecord];
    PatchSilkRecorderMemory(self);
    return ret;
}

- (BOOL)hq_prepareRecordWithNotify:(BOOL)notify {
    SyncUpgradeSilkRecorderObjC(self, YES);
    BOOL ret = [self hq_prepareRecordWithNotify:notify];
    PatchSilkRecorderMemory(self);
    return ret;
}

@end

// ==========================================
// 9. 语音条快捷呼出菜单交互挂载
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
// 10. 动态库入口初始化
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
