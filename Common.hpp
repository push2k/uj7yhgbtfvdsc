#pragma once

#ifndef COMMON_HPP
#define COMMON_HPP
#define OPENSSL_STATIC

#include <string>
#include <vector>
#include <iostream>
#include <windows.h>
#include <phnt.h>
#include <filesystem>
#include <cassert>
#include <cstdint>

namespace caps_hook {
	using std::string;
	using std::wstring;
	using std::vector;
	using std::cout;
	using std::endl;
	using std::cerr;
	using byte_array = vector<uint8_t>;

	namespace fs = std::filesystem;
	using Path = fs::path;

#ifdef _MSC_VER
    template<auto fn> using deleter_from_fn =
        std::integral_constant<decltype(fn), fn>;
#else
    template<auto fn> struct deleter_from_fn {
        template<typename T> void operator()(T* ptr) const {
            if (ptr)
                fn(ptr);
        }
    };
#endif

    template<typename HandleT, auto HandleDeleterFunction> class WindowsPtr {
    public:
        using HandleDeleter = deleter_from_fn<HandleDeleterFunction>;

    private:
        HandleT mHandle = nullptr;

    public:
        WindowsPtr() : mHandle(nullptr) {}

        WindowsPtr(nullptr_t) : mHandle(nullptr) {}

        WindowsPtr(HandleT handle) : mHandle(handle) {}

        WindowsPtr& operator=(HandleT handle) noexcept {
            this->mHandle = handle;
            return *this;
        }

        WindowsPtr& operator=(nullptr_t) noexcept {
            this->mHandle = nullptr;
            return *this;
        }

        ~WindowsPtr() {
            if (this->isValid())
                HandleDeleter()(this->mHandle);
        }

        WindowsPtr(const WindowsPtr&) = delete;
        WindowsPtr& operator=(const WindowsPtr&) = delete;

        WindowsPtr(WindowsPtr&& other) :
            mHandle(std::exchange(other.mHandle, (HandleT) nullptr)) {
        }

        WindowsPtr& operator=(WindowsPtr&& other) {
            this->mHandle = std::exchange(other.mHandle, (HandleT) nullptr);
            return *this;
        }

        friend void swap(WindowsPtr& lhs, WindowsPtr& rhs) {
            std::swap(lhs.mHandle, rhs.mHandle);
        }

        bool isValid() const noexcept {
            return this->mHandle != (HandleT) nullptr &&
                this->mHandle != (HandleT)INVALID_HANDLE_VALUE;
        }

        HandleT get() const noexcept { return this->mHandle; }
        HandleT operator->() const noexcept { return this->get(); }

        HandleT release() noexcept {
            HandleT handle = this->mHandle;
            this->mHandle = nullptr;
            return handle;
        }

        void reset(HandleT handle) {
            if (this->isValid()) {
                HandleDeleter()(this->mHandle);
            }
            this->mHandle = handle;
        }

        void reset(nullptr_t = nullptr) {
            if (this->isValid()) {
                HandleDeleter()(this->mHandle);
            }
            this->mHandle = nullptr;
        }

        HandleT& operator*() { return this->mHandle; }

        HandleT* receive() {
            assert(!this->mHandle);
            return &this->mHandle;
        }

        HandleT* operator&() { return this->receive(); }

        operator bool() const { return this->isValid(); }
    };

    using AutoHandle = WindowsPtr<HANDLE, &CloseHandle>;
    using AutoNtHandle = WindowsPtr<HANDLE, &NtClose>;
}

#endif