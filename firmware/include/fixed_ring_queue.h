#pragma once
#include <stddef.h>

template <typename T, size_t Capacity>
class FixedRingQueue {
 public:
  static_assert(Capacity > 0, "FixedRingQueue capacity must be greater than zero");

  bool push(const T& value) {
    if (count_ >= Capacity) return false;
    items_[head_] = value;
    head_ = (head_ + 1U) % Capacity;
    ++count_;
    return true;
  }

  bool pop(T& value) {
    if (count_ == 0) return false;
    value = items_[tail_];
    tail_ = (tail_ + 1U) % Capacity;
    --count_;
    return true;
  }

  void clear() {
    head_ = 0;
    tail_ = 0;
    count_ = 0;
  }

  size_t size() const { return count_; }
  constexpr size_t capacity() const { return Capacity; }
  bool empty() const { return count_ == 0; }
  bool full() const { return count_ == Capacity; }

 private:
  T items_[Capacity] = {};
  size_t head_ = 0;
  size_t tail_ = 0;
  size_t count_ = 0;
};
