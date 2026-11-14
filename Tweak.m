#import <UIKit/UIKit.h>
#import <AVFoundation/AVFoundation.h>
#import <AudioToolbox/AudioToolbox.h>
#import <AudioUnit/AudioUnit.h>
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
        case HQVoiceLevelLow:    return @"小等 (自然清晰 · 轻度去闷)";
        case HQVoiceLevelMedium: return @"中等 (播客磁性 · 饱满人声)";
        case HQVoiceLevelHigh:   return @"最高 (卸除电话滤镜 · 棚感直采)";
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
// 3. 音质选择弹窗 UI（带实时拦截命中计数）
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

    NSString *statusLine = (sr > 0)
        ? [NSString stringWithFormat:@"已接管音频包：%llu 次（硬件采样 %uHz）", hits, sr]
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
// 5. 核心 DSP 处理器（支持 Int16 与 Float32 麦克风流，零变调）
// ==========================================
typedef struct {
    float b0, b1, b2, a1, a2;
    float x1, x2, y1, y2;
} BiquadFilter;

static BiquadFilter gWarmthFilter;
static BiquadFilter gPresenceFilter;
static HQVoiceLevel gFilterConfiguredLevel = HQVoiceLevelOff;
static float gFilterConfiguredRate = 0.0f;
static float gHpPrevX = 0.0f;
static float gHpPrevY = 0.0f;
static float gEnvFollower = 0.0f;

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

static inline float SoftLimitFloat(float sample, float threshold, float maxVal, float knee) {
    float absVal = fabsf(sample);
    if (absVal > threshold) {
        float excess = absVal - threshold;
        float compressed = threshold + (maxVal - threshold) * (excess / (excess + knee));
        sample = (sample >= 0.0f) ? compressed : -compressed;
    }
    if (sample > maxVal) return maxVal;
    if (sample < -maxVal) return -maxVal;
    return sample;
}

static void EnsureFiltersConfigured(HQVoiceLevel level, float sampleRate) {
    if (sampleRate <= 0.0f) sampleRate = 16000.0f;
    if (gFilterConfiguredLevel == level && fabsf(gFilterConfiguredRate - sampleRate) < 1.0f) return;

    float warmthDb = 0.0f;
    float presenceDb = 0.0f;
    switch (level) {
        case HQVoiceLevelLow:
            warmthDb = 2.2f;
            presenceDb = 3.5f;
            break;
        case HQVoiceLevelMedium:
            warmthDb = 4.0f;
            presenceDb = 5.8f;
            break;
        case HQVoiceLevelHigh:
            warmthDb = 5.5f;
            presenceDb = 8.0f;
            break;
        default:
            break;
    }

    memset(&gWarmthFilter, 0, sizeof(BiquadFilter));
    memset(&gPresenceFilter, 0, sizeof(BiquadFilter));
    SetupLowShelfFilter(&gWarmthFilter, sampleRate, 180.0f, warmthDb);
    SetupPeakingFilter(&gPresenceFilter, sampleRate, 3600.0f, 1.1f, presenceDb);

    gFilterConfiguredLevel = level;
    gFilterConfiguredRate = sampleRate;
}

static void ProcessPCMBufferInPlace(void *data, UInt32 byteSize, UInt32 frameCount, BOOL isFloat32, float sampleRate, HQVoiceLevel level) {
    if (!data || frameCount == 0 || level == HQVoiceLevelOff) return;
    EnsureFiltersConfigured(level, sampleRate);

    float gain = 1.0f;
    float comp = 0.0f;
    switch (level) {
        case HQVoiceLevelLow:    gain = 1.55f; comp = 0.25f; break;
        case HQVoiceLevelMedium: gain = 2.25f; comp = 0.40f; break;
        case HQVoiceLevelHigh:   gain = 3.10f; comp = 0.55f; break;
        default: return;
    }

    if (isFloat32) {
        float *samples = (float *)data;
        UInt32 count = byteSize / sizeof(float);
        for (UInt32 i = 0; i < count; i++) {
            float x = samples[i];
            float hp = x - gHpPrevX + 0.972f * gHpPrevY;
            gHpPrevX = x;
            gHpPrevY = hp;

            float eq = ProcessBiquad(&gPresenceFilter, ProcessBiquad(&gWarmthFilter, hp));
            float absSig = fabsf(eq);
            gEnvFollower = 0.996f * gEnvFollower + 0.004f * absSig;
            float ratio = (gEnvFollower > 0.11f) ? (1.0f - comp * ((gEnvFollower - 0.11f) / (gEnvFollower + 0.20f))) : 1.0f;

            samples[i] = SoftLimitFloat(eq * gain * ratio, 0.78f, 0.98f, 0.22f);
        }
    } else {
        int16_t *samples = (int16_t *)data;
        UInt32 count = byteSize / sizeof(int16_t);
        for (UInt32 i = 0; i < count; i++) {
            float x = (float)samples[i];
            float hp = x - gHpPrevX + 0.972f * gHpPrevY;
            gHpPrevX = x;
            gHpPrevY = hp;

            float eq = ProcessBiquad(&gPresenceFilter, ProcessBiquad(&gWarmthFilter, hp));
            float absSig = fabsf(eq);
            gEnvFollower = 0.996f * gEnvFollower + 0.004f * absSig;
            float ratio = (gEnvFollower > 3600.0f) ? (1.0f - comp * ((gEnvFollower - 3600.0f) / (gEnvFollower + 6500.0f))) : 1.0f;

            samples[i] = (int16_t)SoftLimitFloat(eq * gain * ratio, 25500.0f, 32500.0f, 7200.0f);
        }
    }
}

// ==========================================
// 6. 微信 8.0.75 CoreAudio / AudioUnit 全链路拦截
// ==========================================

// 6.1 拦截 VoiceProcessingIO（电话语音单元）-> 替换为 RemoteIO（无滤波直采单元）
static AudioComponent (*orig_AudioComponentFindNext)(AudioComponent inComponent, const AudioComponentDescription *inDesc);

static AudioComponent my_AudioComponentFindNext(AudioComponent inComponent, const AudioComponentDescription *inDesc) {
    HQVoiceLevel level = GetCurrentVoiceLevel();
    if (level != HQVoiceLevelOff && inDesc != NULL &&
        inDesc->componentType == kAudioUnitType_Output &&
        inDesc->componentSubType == kAudioUnitSubType_VoiceProcessingIO) {
        AudioComponentDescription modDesc = *inDesc;
        modDesc.componentSubType = kAudioUnitSubType_RemoteIO;
        return orig_AudioComponentFindNext(inComponent, &modDesc);
    }
    return orig_AudioComponentFindNext(inComponent, inDesc);
}

// 6.2 兼容降级后的属性设置，防止微信设置电话单元专有属性时报错中断
static OSStatus (*orig_AudioUnitSetProperty)(AudioUnit inUnit, AudioUnitPropertyID inID, AudioUnitScope inScope, AudioUnitElement inElement, const void *inData, UInt32 inDataSize);

static OSStatus my_AudioUnitSetProperty(AudioUnit inUnit, AudioUnitPropertyID inID, AudioUnitScope inScope, AudioUnitElement inElement, const void *inData, UInt32 inDataSize) {
    OSStatus err = orig_AudioUnitSetProperty(inUnit, inID, inScope, inElement, inData, inDataSize);
    if (err != noErr && GetCurrentVoiceLevel() != HQVoiceLevelOff && inID >= 2100 && inID <= 2199) {
        return noErr;
    }
    return err;
}

// 6.3 拦截微信 8.0.75 麦克风渲染总线（Bus 1）实时 PCM 数据
static OSStatus (*orig_AudioUnitRender)(AudioUnit inUnit, AudioUnitRenderActionFlags *ioActionFlags, const AudioTimeStamp *inTimeStamp, UInt32 inBusNumber, UInt32 inNumberFrames, AudioBufferList *ioData);

static OSStatus my_AudioUnitRender(AudioUnit inUnit, AudioUnitRenderActionFlags *ioActionFlags, const AudioTimeStamp *inTimeStamp, UInt32 inBusNumber, UInt32 inNumberFrames, AudioBufferList *ioData) {
    OSStatus status = orig_AudioUnitRender(inUnit, ioActionFlags, inTimeStamp, inBusNumber, inNumberFrames, ioData);
    if (status == noErr && inBusNumber == 1 && ioData != NULL && ioData->mNumberBuffers > 0) {
        atomic_fetch_add(&gHitPacketsCount, 1);

        AudioStreamBasicDescription asbd;
        UInt32 propSize = sizeof(asbd);
        float sampleRate = 16000.0f;
        BOOL isFloat = NO;

        if (AudioUnitGetProperty(inUnit, kAudioUnitProperty_StreamFormat, kAudioUnitScope_Output, 1, &asbd, &propSize) == noErr) {
            sampleRate = (float)asbd.mSampleRate;
            isFloat = ((asbd.mFormatFlags & kAudioFormatFlagIsFloat) != 0);
            atomic_store(&gDetectedSampleRate, (uint32_t)asbd.mSampleRate);
        }

        HQVoiceLevel level = GetCurrentVoiceLevel();
        if (level != HQVoiceLevelOff) {
            AudioBuffer *buf = &ioData->mBuffers[0];
            ProcessPCMBufferInPlace(buf->mData, buf->mDataByteSize, inNumberFrames, isFloat, sampleRate, level);
        }
    }
    return status;
}

// 6.4 解除 AVAudioSession 通话模式过滤
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

        struct rebinding rebs[] = {
            { "AudioComponentFindNext", (void *)my_AudioComponentFindNext, (void **)&orig_AudioComponentFindNext },
            { "AudioUnitSetProperty",   (void *)my_AudioUnitSetProperty,   (void **)&orig_AudioUnitSetProperty },
            { "AudioUnitRender",        (void *)my_AudioUnitRender,        (void **)&orig_AudioUnitRender }
        };
        rebind_symbols(rebs, 3);

        Class sessionCls = [AVAudioSession class];
        SwizzleInstanceMethod(sessionCls, @selector(setMode:error:), @selector(hq_setMode:error:));
        SwizzleInstanceMethod(sessionCls, @selector(setCategory:mode:options:error:), @selector(hq_setCategory:mode:options:error:));

        Class btnCls = [UIButton class];
        SwizzleInstanceMethod(btnCls, @selector(setTitle:forState:), @selector(hq_setTitle:forState:));
        SwizzleInstanceMethod(btnCls, @selector(didMoveToWindow), @selector(hq_didMoveToWindow));
    }
}
