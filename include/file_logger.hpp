#ifndef FILE_LOGGER_HPP
#define FILE_LOGGER_HPP

#include <string>
#include <fstream>
#include <memory>
#include <mutex>
#include <thread>
#include <queue>
#include <atomic>
#include <condition_variable>
#include <chrono>
#include <vector>
#include <unordered_map>

/**
 * @brief Thread-safe, deadlock-free file logging system for DDoS Inspector
 * 
 * This class handles all file I/O operations for logging, metrics, and IP lists
 * in a separate thread to prevent blocking the main packet processing pipeline.
 * Uses lock-free queues and timeout-based locking for deadlock prevention.
 */
class FileLogger {
public:
    enum class LogLevel : uint8_t {
        LOG_DEBUG = 0,
        LOG_INFO = 1,
        LOG_WARNING = 2,
        LOG_ERROR = 3,
        LOG_CRITICAL = 4
    };

    enum class FileType : uint8_t {
        METRICS = 0,
        BLOCKED_IPS = 1,
        RATE_LIMITED_IPS = 2,
        ATTACK_LOG = 3,
        PERFORMANCE_LOG = 4,
        DEBUG_LOG = 5
    };

    struct LogEntry {
        LogLevel level;
        FileType file_type;
        std::string message;
        std::chrono::steady_clock::time_point timestamp;
        std::string source_file;
        int line_number;
        
        LogEntry() = default;
        LogEntry(LogLevel lvl, FileType type, const std::string& msg, 
                const std::string& file = "", int line = 0)
            : level(lvl), file_type(type), message(msg), 
              timestamp(std::chrono::steady_clock::now()),
              source_file(file), line_number(line) {}
    };

    struct FileConfig {
        std::string file_path;
        size_t max_file_size = 100 * 1024 * 1024; // 100MB default
        int max_backup_files = 5;
        bool auto_flush = true;
        std::chrono::milliseconds flush_interval{5000}; // 5 seconds
        bool enable_compression = false; // For backup files
    };

private:
    // Thread-safe logging infrastructure
    std::atomic<bool> logger_running_{false};
    std::atomic<bool> shutdown_requested_{false};
    std::thread logger_thread_;
    
    // Lock-free queue for log entries
    mutable std::mutex queue_mutex_;
    std::queue<LogEntry> log_queue_;
    std::condition_variable queue_cv_;
    
    // File configurations
    mutable std::mutex config_mutex_; // Protects file_configs_
    std::unordered_map<FileType, FileConfig> file_configs_;
    std::unordered_map<FileType, std::unique_ptr<std::ofstream>> active_files_;
    std::unordered_map<FileType, std::chrono::steady_clock::time_point> last_flush_times_;
    
    // Deadlock prevention
    mutable std::timed_mutex file_operations_mutex_;
    static constexpr std::chrono::milliseconds LOCK_TIMEOUT{2000};
    
    // Performance metrics
    std::atomic<uint64_t> total_log_entries_{0};
    std::atomic<uint64_t> dropped_entries_{0};
    std::atomic<uint64_t> flush_operations_{0};
    std::atomic<uint64_t> file_rotations_{0};
    
    // Queue size limits
    static constexpr size_t MAX_QUEUE_SIZE = 10000;
    static constexpr size_t QUEUE_WARNING_SIZE = 8000;

public:
    FileLogger();
    ~FileLogger();
    
    // Prevent copying and moving due to thread and mutex management
    FileLogger(const FileLogger&) = delete;
    FileLogger& operator=(const FileLogger&) = delete;
    FileLogger(FileLogger&&) = delete;
    FileLogger& operator=(FileLogger&&) = delete;

    // Lifecycle management
    bool initialize(const std::unordered_map<FileType, FileConfig>& configs);
    void start();
    void stop();
    bool is_running() const { return logger_running_.load(std::memory_order_acquire); }

    // Logging interface
    void log(LogLevel level, FileType file_type, const std::string& message,
             const std::string& source_file = "", int line_number = 0);
    
    // Convenience methods for different log levels
    void debug(FileType file_type, const std::string& message, 
               const std::string& source_file = "", int line_number = 0);
    void info(FileType file_type, const std::string& message,
              const std::string& source_file = "", int line_number = 0);
    void warning(FileType file_type, const std::string& message,
                 const std::string& source_file = "", int line_number = 0);
    void error(FileType file_type, const std::string& message,
               const std::string& source_file = "", int line_number = 0);
    void critical(FileType file_type, const std::string& message,
                  const std::string& source_file = "", int line_number = 0);

    // Specialized file operations
    void write_metrics_file(const std::string& metrics_data);
    void write_blocked_ips_file(const std::vector<std::string>& blocked_ips);
    void write_rate_limited_ips_file(const std::vector<std::string>& rate_limited_ips);
    void write_attack_detection(const std::string& attack_info);
    void write_performance_metrics(const std::string& perf_data);

    // File management
    void flush_all_files();
    void rotate_file(FileType file_type);
    void set_file_config(FileType file_type, const FileConfig& config);
    FileConfig get_file_config(FileType file_type) const;

    // Status and metrics
    struct LoggerMetrics {
        uint64_t total_entries;
        uint64_t dropped_entries;
        uint64_t flush_operations;
        uint64_t file_rotations;
        size_t current_queue_size;
        bool is_running;
        std::unordered_map<FileType, size_t> file_sizes;
    };
    LoggerMetrics get_metrics() const;

    // Utility methods
    static std::string log_level_to_string(LogLevel level);
    static std::string file_type_to_string(FileType type);
    static std::string format_timestamp(const std::chrono::steady_clock::time_point& tp);

private:
    // Internal methods
    void logger_loop();
    void process_log_entry(const LogEntry& entry);
    bool open_file(FileType file_type);
    void close_file(FileType file_type);
    void ensure_directory_exists(const std::string& file_path);
    bool should_rotate_file(FileType file_type);
    void perform_file_rotation(FileType file_type);
    void compress_backup_file(const std::string& file_path);
    void cleanup_old_backups(FileType file_type);
    std::string get_backup_filename(FileType file_type, int backup_number);
    bool try_acquire_file_lock(std::chrono::milliseconds timeout = LOCK_TIMEOUT);
    void release_file_lock();
    void flush_file(FileType file_type);
    bool is_queue_full() const;
    void handle_queue_overflow();
    std::string format_log_message(const LogEntry& entry);
};

// Macros for convenient logging with file/line information
#define FILE_LOG_DEBUG(logger, file_type, message) \
    (logger).debug(file_type, message, __FILE__, __LINE__)

#define FILE_LOG_INFO(logger, file_type, message) \
    (logger).info(file_type, message, __FILE__, __LINE__)

#define FILE_LOG_WARNING(logger, file_type, message) \
    (logger).warning(file_type, message, __FILE__, __LINE__)

#define FILE_LOG_ERROR(logger, file_type, message) \
    (logger).error(file_type, message, __FILE__, __LINE__)

#define FILE_LOG_CRITICAL(logger, file_type, message) \
    (logger).critical(file_type, message, __FILE__, __LINE__)

// Global file logger instance
extern FileLogger g_file_logger;

#endif // FILE_LOGGER_HPP
