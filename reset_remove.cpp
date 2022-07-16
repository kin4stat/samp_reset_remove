#include "kthook/kthook.hpp"

enum class samp_version {
    kR1,
    kR2,
    kR3,
    kR4,
    kUnknown,
};

samp_version get_samp_version() {
    static samp_version ver = []() {
        auto base = reinterpret_cast<std::uintptr_t>(GetModuleHandleA("samp.dll"));
        auto ntheader = reinterpret_cast<IMAGE_NT_HEADERS*>(base + reinterpret_cast<IMAGE_DOS_HEADER*>(base)->e_lfanew);
        // NOLINT(performance-no-int-to-ptr)
        auto ep = ntheader->OptionalHeader.AddressOfEntryPoint;
        switch (ep) {
        case 0x31DF13:
            return samp_version::kR1;
        case 0x3195DD:
            return samp_version::kR2:
        case 0xCC4D0:
            return samp_version::kR3;
        case 0xCBCB0:
            return samp_version::kR4;
        default:
            return samp_version::kUnknown;
        //case 0xCBCB0:  return samp_version::SAMP_0_3_7_R4;
        }
    }();
    return ver;
}

struct Plugin {
    using window_init_t = HWND(__cdecl*)(HINSTANCE);

    Plugin() {
        window_init_hook.set_cb([this](const auto& hook, auto&& hinst) {
            auto sampdll = reinterpret_cast<std::uintptr_t>(GetModuleHandleA("samp.dll"));
            if (sampdll) {
                std::uintptr_t hook_address = 0;
                std::uintptr_t zero_address = 0;
                switch (get_samp_version()) {
                case samp_version::kR1:
                    hook_address = sampdll + 0xA131;
                    zero_address = sampdll + 0x13B958;
                    break;
                case samp_version::kR2:
                    hook_address = sampdll + 0xA122;
                    zero_address = sampdll + 0x13B958;
                    break;    
                case samp_version::kR3:
                    hook_address = sampdll + 0xA2BA;
                    zero_address = sampdll + 0x14FAD8;
                    break;
                case samp_version::kR4:
                    hook_address = sampdll + 0xA605;
                    zero_address = sampdll + 0x14FC00;
                    break;                
                default:
                    // if samp version unknown, then hook_address will be zero and
                    // kthook_naked.install() wont install hook
                    break;
                }
                reset_hook.set_dest(hook_address);
                reset_hook.set_cb([this, zero_address](const kthook::kthook_naked& hook) {
                    *reinterpret_cast<unsigned long*>(zero_address) = 0;
                });
                reset_hook.install();
            }

            return hook.get_trampoline()(hinst);
        });
    }

    kthook::kthook_naked reset_hook;

    kthook::kthook_simple<window_init_t> window_init_hook{0x745560};
} instance{};
