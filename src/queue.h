// Copyright (c) 2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <deque>
#include <future>

#include <boost/variant.hpp>

#ifndef BITCOIN_QUEUE_H
#define BITCOIN_QUEUE_H

/**
 * Queue is a FIFO data structure that is safe for concurrent access by multiple threads.
 */
template <typename T>
class Queue {
private:
    std::deque<boost::variant<T, std::promise<void> > > m_queue;
    std::mutex m_mtx;
    std::condition_variable m_signal;
    std::atomic<bool> m_interrupted;

public:
    Queue() : m_interrupted(false) {}

    /// Interrupt all blocking pops and cause them to immediately return false.
    void Interrupt()
    {
        m_interrupted = true;
        m_signal.notify_all();
    }

    /// Pop the next item from the queue. Returns false if interrupted.
    bool Pop(T& item)
    {
        std::unique_lock<std::mutex> lock(m_mtx);
        while (!m_interrupted) {
            while (m_queue.empty()) {
                m_signal.wait(lock);
                if (m_interrupted) {
                    return false;
                }
            }

            auto entry = std::move(m_queue.front());
            m_queue.pop_front();

            // Queue entry may just be a marker inserted by WaitUntilProcessed.
            if (auto promise = boost::get<std::promise<void> >(&entry)) {
                promise->set_value();
                continue;
            }

            item = std::move(boost::get<T>(entry));
            return true;
        }
        return false;
    }

    void Push(const T& item)
    {
        {
            std::unique_lock<std::mutex> lock(m_mtx);
            m_queue.push_back(item);
        }
        m_signal.notify_all();
    }

    void Push(T&& item)
    {
        {
            std::unique_lock<std::mutex> lock(m_mtx);
            m_queue.push_back(item);
        }
        m_signal.notify_all();
    }

    /// Obtain a future that resolves when all items currently in the queue have been popped off.
    std::future<void> WaitUntilProcessed()
    {
        std::future<void> future;
        {
            std::unique_lock<std::mutex> lock(m_mtx);
            m_queue.push_back(std::promise<void>());

            auto& promise = boost::get<std::promise<void>>(m_queue.back());
            future = std::move(promise.get_future());
        }
        m_signal.notify_all();
        return future;
    }
};

#endif // BITCOIN_QUEUE_H
