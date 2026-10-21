/*
 * winsdk_shim/wrl/client.h — Microsoft::WRL::ComPtr 的最小等价实现。
 * 仅用于在 Linux 下编译验证 Windows 专用源码，行为与 WRL 保持一致：
 * 析构 Release、operator& 先释放旧指针再返回地址。
 */
#ifndef WSDK_SHIM_WRL_CLIENT_H
#define WSDK_SHIM_WRL_CLIENT_H

#include <windows.h>
#include <cstddef>

namespace Microsoft {
namespace WRL {

template <typename T>
class ComPtr {
public:
    ComPtr() : ptr_(nullptr) {}
    ~ComPtr() { if (ptr_) ptr_->Release(); }

    ComPtr(const ComPtr &) = delete;
    ComPtr &operator=(const ComPtr &) = delete;

    T *Get() const { return ptr_; }

    T **GetAddressOf() {
        if (ptr_) { ptr_->Release(); ptr_ = nullptr; }
        return &ptr_;
    }
    T **operator&() { return GetAddressOf(); }

    T *operator->() const { return ptr_; }
    operator T *() const { return ptr_; }

    void Reset() { if (ptr_) { ptr_->Release(); ptr_ = nullptr; } }
    T *Detach() { T *t = ptr_; ptr_ = nullptr; return t; }

private:
    T *ptr_;
};

}
}

#endif
