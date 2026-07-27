// --- fifo_queue.h ---

#pragma once

#include <atomic>
#include <cstdint>
#include <new>

#include <common/platform.h>
#include <common/math.h>

namespace bcp::common::collections
{
    /** Lock-free MPMC FIFO queue. Multiple producers and consumers.
        Fixed capacity, must be initialized before use.
        Header-only because it's a template. */
    template<typename T>
    class FifoQueue {
    private:
        struct alignas(CACHE_LINE) Cell {
            std::atomic<uint32_t> sequence;
            T value;
        };

        Cell*    buffer_   = nullptr;
        uint32_t capacity_ = 0;
        uint32_t mask_     = 0;

        alignas(CACHE_LINE) std::atomic<uint32_t> head_{0};
        alignas(CACHE_LINE) std::atomic<uint32_t> tail_{0};

    public:
        FifoQueue() = default;
        ~FifoQueue() { Shutdown(); }

        FifoQueue(const FifoQueue&) = delete;
        FifoQueue& operator=(const FifoQueue&) = delete;

        [[nodiscard]] bool Init(uint32_t capacity) {
            capacity_ = NextPowerOfTwo(capacity);
            mask_ = capacity_ - 1;

            buffer_ = static_cast<Cell*>(
                ::operator new(sizeof(Cell) * capacity_, std::align_val_t(common::CACHE_LINE))
            );
            if (!buffer_) return false;

            for (uint32_t i = 0; i < capacity_; i++) {
                new(&buffer_[i]) Cell();
                buffer_[i].sequence.store(i, std::memory_order_relaxed);
            }

            head_.store(0, std::memory_order_relaxed);
            tail_.store(0, std::memory_order_relaxed);
            return true;
        }

        void Shutdown() {
            if (buffer_) {
                for (uint32_t i = 0; i < capacity_; i++)
                    buffer_[i].~Cell();
                ::operator delete(buffer_, std::align_val_t(common::CACHE_LINE));
                buffer_ = nullptr;
            }
            capacity_ = 0;
            mask_ = 0;
        }

        [[nodiscard]] bool Push(const T& item) {
            uint32_t tail = tail_.load(std::memory_order_acquire);
            for (;;) {
                Cell& cell = buffer_[tail & mask_];
                uint32_t seq = cell.sequence.load(std::memory_order_acquire);
                int32_t diff = static_cast<int32_t>(seq) - static_cast<int32_t>(tail);

                if (diff == 0) {
                    if (tail_.compare_exchange_weak(tail, tail + 1, std::memory_order_acquire)) {
                        cell.value = item;
                        cell.sequence.store(tail + 1, std::memory_order_release);
                        return true;
                    }
                } else if (diff < 0) {
                    return false;
                } else {
                    CpuPause();
                    tail = tail_.load(std::memory_order_acquire);
                }
            }
        }

        bool Pop(T& item) {
            uint32_t head = head_.load(std::memory_order_acquire);
            for (;;) {
                Cell& cell = buffer_[head & mask_];
                uint32_t seq = cell.sequence.load(std::memory_order_acquire);
                int32_t diff = static_cast<int32_t>(seq) - static_cast<int32_t>(head + 1);

                if (diff == 0) {
                    if (head_.compare_exchange_weak(head, head + 1, std::memory_order_acquire)) {
                        item = cell.value;
                        cell.sequence.store(head + capacity_, std::memory_order_release);
                        return true;
                    }
                } else if (diff < 0) {
                    return false;
                } else {
                    CpuPause();
                    head = head_.load(std::memory_order_acquire);
                }
            }
        }

        uint32_t PushBatch(const T* items, uint32_t count) {
            uint32_t tail = tail_.load(std::memory_order_acquire);
            for (;;) {
                uint32_t available = 0;
                for (available = 0; available < count; available++) {
                    Cell& cell = buffer_[(tail + available) & mask_];
                    uint32_t seq = cell.sequence.load(std::memory_order_acquire);
                    int32_t diff = static_cast<int32_t>(seq) - static_cast<int32_t>(tail + available);

                    if (diff > 0) break;
                    if (diff < 0) break;
                }

                if (available == 0) {
                    uint32_t newtail = tail_.load(std::memory_order_acquire);
                    if (newtail == tail) return 0;
                    CpuPause();
                    tail = newtail;
                    continue;
                }

                if (tail_.compare_exchange_weak(tail, tail + available, std::memory_order_acquire)) {
                    for (uint32_t i = 0; i < available; i++) {
                        Cell& cell = buffer_[(tail + i) & mask_];
                        cell.value = items[i];
                        cell.sequence.store(tail + i + 1, std::memory_order_release);
                    }
                    return available;
                }
            }
            return 0;
        }

        int PopBatch(T* items, uint32_t count) {
            uint32_t head = head_.load(std::memory_order_acquire);
            for (;;) {
                uint32_t available = 0;
                for (available = 0; available < count; available++) {
                    Cell& cell = buffer_[(head + available) & mask_];
                    uint32_t seq = cell.sequence.load(std::memory_order_acquire);
                    int32_t diff = static_cast<int32_t>(seq) - static_cast<int32_t>(head + available + 1);

                    if (diff > 0) break;
                    if (diff < 0) break;
                }

                if (available == 0) {
                    uint32_t newhead = head_.load(std::memory_order_acquire);
                    if (newhead == head) return 0;
                    CpuPause();
                    head = newhead;
                    continue;
                }

                if (head_.compare_exchange_weak(head, head + available, std::memory_order_acquire)) {
                    for (uint32_t i = 0; i < available; i++) {
                        Cell& cell = buffer_[(head + i) & mask_];
                        items[i] = cell.value;
                        cell.sequence.store(head + i + capacity_, std::memory_order_release);
                    }
                    return static_cast<int>(available);
                }
            }
            return 0;
        }

        bool Empty() const {
            return head_.load(std::memory_order_acquire) == tail_.load(std::memory_order_acquire);
        }

        uint32_t GetCapacity() const { return capacity_; }
    };
}