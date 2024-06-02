#include <ntddk.h>
// Function to attempt to acquire a spin lock
inline bool spinlock_try_lock(volatile long* lock) {
    return (!(*lock) && !_interlockedbittestandset(lock, 0));
}

// Function to lock a spin lock
inline void spinlock_lock(volatile long* lock) {
    static unsigned max_wait = 65536;
    unsigned wait = 1;

    while (!spinlock_try_lock(lock)) {
        for (unsigned i = 0; i < wait; ++i) {
            _mm_pause();
        }

        if (wait * 2 > max_wait) {
            wait = max_wait;
        }
        else {
            wait = wait * 2;
        }
    }
}

// Function to unlock a spin lock
inline void spinlock_unlock(volatile long* lock) {
    *lock = 0;
}

inline volatile long handler_lock = 0;