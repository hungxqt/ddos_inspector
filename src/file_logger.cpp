#include "file_logger.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <filesystem>
#include <cstring>

#ifdef __unix__
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#endif

// Global file logger instance
FileLogger g_file_logger;

FileLogger::FileLogger() {
    // Initialize default configurations for each file type
    file_configs_[FileType::METRICS] = {
        "/var/log/ddos_inspector/metrics.log", 50 * 1024 * 1024, 3, true, 
        std::chrono::milliseconds(5000), false
    };
    
    file_configs_[FileType::BLOCKED_IPS] = {
        "/var/log/ddos_inspector/blocked_ips.log", 10 * 1024 * 1024, 5, true,
        std::chrono::milliseconds(2000), false
    };
    
    file_configs_[FileType::RATE_LIMITED_IPS] = {
        "/var/log/ddos_inspector/rate_limited_ips.log", 10 * 1024 * 1024, 5, true,
        std::chrono::milliseconds(2000), false
    };
    
    file_configs_[FileType::ATTACK_LOG] = {
        "/var/log/ddos_inspector/attacks.log", 100 * 1024 * 1024, 10, true,
        std::chrono::milliseconds(1000), true
    };
    
    file_configs_[FileType::PERFORMANCE_LOG] = {
        "/var/log/ddos_inspector/performance.log", 20 * 1024 * 1024, 3, true,
        std::chrono::milliseconds(10000), false
    };
    
    file_configs_[FileType::DEBUG_LOG] = {
        "/var/log/ddos_inspector/debug.log", 50 * 1024 * 1024, 2, false,
        std::chrono::milliseconds(30000), false
    };
}

FileLogger::~FileLogger() {
    stop();
}

bool FileLogger::initialize(const std::unordered_map<FileType, FileConfig>& configs) {
    // Update configurations
    for (const auto& [type, config] : configs) {
        file_configs_[type] = config;
    }
    
    // Ensure all directories exist
    for (const auto& [type, config] : file_configs_) {
        try {
            ensure_directory_exists(config.file_path);
        } catch (const std::exception& e) {
            std::cerr << "FileLogger: Failed to create directory for " 
                      << file_type_to_string(type) << ": " << e.what() << '\n';
            return false;
        }
    }
    
    return true;
}

void FileLogger::start() {
    if (logger_running_.load(std::memory_order_acquire)) {
        return; // Already running
    }
    
    logger_running_.store(true, std::memory_order_release);
    shutdown_requested_.store(false, std::memory_order_release);
    
    logger_thread_ = std::thread(&FileLogger::logger_loop, this);
    
    // Initialize last flush times
    auto now = std::chrono::steady_clock::now();
    for (const auto& [type, config] : file_configs_) {
        last_flush_times_[type] = now;
    }
}

void FileLogger::stop() {
    if (!logger_running_.load(std::memory_order_acquire)) {
        return; // Not running
    }
    
    shutdown_requested_.store(true, std::memory_order_release);
    
    // Notify logger thread
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        queue_cv_.notify_all();
    }
    
    if (logger_thread_.joinable()) {
        logger_thread_.join();
    }
    
    logger_running_.store(false, std::memory_order_release);
    
    // Close all files
    for (auto& [type, file] : active_files_) {
        if (file && file->is_open()) {
            file->flush();
            file->close();
        }
    }
    active_files_.clear();
}

void FileLogger::log(LogLevel level, FileType file_type, const std::string& message,
                     const std::string& source_file, int line_number) {
    if (!logger_running_.load(std::memory_order_acquire)) {
        return; // Logger not running
    }
    
    // Check queue size to prevent memory issues
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        if (log_queue_.size() >= MAX_QUEUE_SIZE) {
            handle_queue_overflow();
            return;
        }
        
        if (log_queue_.size() >= QUEUE_WARNING_SIZE) {
            // Log queue getting full - this is logged without going through the queue
            // to avoid infinite recursion
            std::cerr << "FileLogger: Queue size warning (" 
                      << log_queue_.size() << "/" << MAX_QUEUE_SIZE << ")" << '\n';
        }
        
        log_queue_.emplace(level, file_type, message, source_file, line_number);
        total_log_entries_.fetch_add(1, std::memory_order_relaxed);
    }
    
    queue_cv_.notify_one();
}

void FileLogger::debug(FileType file_type, const std::string& message,
                       const std::string& source_file, int line_number) {
    log(LogLevel::LOG_DEBUG, file_type, message, source_file, line_number);
}

void FileLogger::info(FileType file_type, const std::string& message,
                      const std::string& source_file, int line_number) {
    log(LogLevel::LOG_INFO, file_type, message, source_file, line_number);
}

void FileLogger::warning(FileType file_type, const std::string& message,
                         const std::string& source_file, int line_number) {
    log(LogLevel::LOG_WARNING, file_type, message, source_file, line_number);
}

void FileLogger::error(FileType file_type, const std::string& message,
                       const std::string& source_file, int line_number) {
    log(LogLevel::LOG_ERROR, file_type, message, source_file, line_number);
}

void FileLogger::critical(FileType file_type, const std::string& message,
                          const std::string& source_file, int line_number) {
    log(LogLevel::LOG_CRITICAL, file_type, message, source_file, line_number);
}

void FileLogger::write_metrics_file(const std::string& metrics_data) {
    log(LogLevel::LOG_INFO, FileType::METRICS, metrics_data);
}

void FileLogger::write_blocked_ips_file(const std::vector<std::string>& blocked_ips) {
    std::ostringstream oss;
    oss << "# DDoS Inspector - Blocked IPs List\n";
    oss << "# Last updated: " << format_timestamp(std::chrono::steady_clock::now()) << '\n';
    oss << "# Format: IP_ADDRESS (remaining: XXXs, type: ATTACK_TYPE)\n";
    oss << "# Total blocked IPs: " << blocked_ips.size() << "\n\n";
    
    if (blocked_ips.empty()) {
        oss << "# No IPs currently blocked\n";
    } else {
        for (const auto& ip_info : blocked_ips) {
            oss << ip_info << "\n";
        }
    }
    
    log(LogLevel::LOG_INFO, FileType::BLOCKED_IPS, oss.str());
}

void FileLogger::write_rate_limited_ips_file(const std::vector<std::string>& rate_limited_ips) {
    std::ostringstream oss;
    oss << "# DDoS Inspector - Rate Limited IPs List\n";
    oss << "# Last updated: " << format_timestamp(std::chrono::steady_clock::now()) << '\n';
    oss << "# Format: IP_ADDRESS (level X) or IP_ADDRESS (added Xm ago)\n";
    oss << "# Rate limit levels: 1=10/sec, 2=5/sec, 3=2/sec, 4=1/sec\n";
    oss << "# Current active: " << rate_limited_ips.size() << "\n\n";
    
    if (rate_limited_ips.empty()) {
        oss << "# No IPs currently rate limited\n";
    } else {
        for (const auto& ip_info : rate_limited_ips) {
            oss << ip_info << "\n";
        }
    }
    
    log(LogLevel::LOG_INFO, FileType::RATE_LIMITED_IPS, oss.str());
}

void FileLogger::write_attack_detection(const std::string& attack_info) {
    log(LogLevel::LOG_WARNING, FileType::ATTACK_LOG, attack_info);
}

void FileLogger::write_performance_metrics(const std::string& perf_data) {
    log(LogLevel::LOG_INFO, FileType::PERFORMANCE_LOG, perf_data);
}

void FileLogger::flush_all_files() {
    if (!try_acquire_file_lock()) {
        return; // Skip flush if can't acquire lock quickly
    }
    
    try {
        for (auto& [type, file] : active_files_) {
            if (file && file->is_open()) {
                file->flush();
                flush_operations_.fetch_add(1, std::memory_order_relaxed);
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "FileLogger: Error during flush_all_files: " << e.what() << '\n';
    }
    
    release_file_lock();
}

void FileLogger::rotate_file(FileType file_type) {
    if (!try_acquire_file_lock()) {
        return; // Skip rotation if can't acquire lock
    }
    
    try {
        perform_file_rotation(file_type);
    } catch (const std::exception& e) {
        std::cerr << "FileLogger: Error during file rotation for " 
                  << file_type_to_string(file_type) << ": " << e.what() << '\n';
    }
    
    release_file_lock();
}

void FileLogger::set_file_config(FileType file_type, const FileConfig& config) {
    std::lock_guard<std::mutex> lock(config_mutex_);
    file_configs_[file_type] = config;
}

FileLogger::FileConfig FileLogger::get_file_config(FileType file_type) const {
    std::lock_guard<std::mutex> lock(config_mutex_);
    auto it = file_configs_.find(file_type);
    return (it != file_configs_.end()) ? it->second : FileConfig{};
}

FileLogger::LoggerMetrics FileLogger::get_metrics() const {
    LoggerMetrics metrics;
    metrics.total_entries = total_log_entries_.load(std::memory_order_acquire);
    metrics.dropped_entries = dropped_entries_.load(std::memory_order_acquire);
    metrics.flush_operations = flush_operations_.load(std::memory_order_acquire);
    metrics.file_rotations = file_rotations_.load(std::memory_order_acquire);
    metrics.is_running = logger_running_.load(std::memory_order_acquire);
    
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        metrics.current_queue_size = log_queue_.size();
    }
    
    // Get file sizes
    {
        std::lock_guard<std::mutex> lock(config_mutex_);
        for (const auto& [type, config] : file_configs_) {
            try {
                if (std::filesystem::exists(config.file_path)) {
                    metrics.file_sizes[type] = std::filesystem::file_size(config.file_path);
                } else {
                    metrics.file_sizes[type] = 0;
                }
            } catch (const std::filesystem::filesystem_error&) {
                metrics.file_sizes[type] = 0;
            }
        }
    }
    
    return metrics;
}

std::string FileLogger::log_level_to_string(LogLevel level) {
    switch (level) {
        case LogLevel::LOG_DEBUG: return "DEBUG";
        case LogLevel::LOG_INFO: return "INFO";
        case LogLevel::LOG_WARNING: return "WARNING";
        case LogLevel::LOG_ERROR: return "ERROR";
        case LogLevel::LOG_CRITICAL: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

std::string FileLogger::file_type_to_string(FileType type) {
    switch (type) {
        case FileType::METRICS: return "METRICS";
        case FileType::BLOCKED_IPS: return "BLOCKED_IPS";
        case FileType::RATE_LIMITED_IPS: return "RATE_LIMITED_IPS";
        case FileType::ATTACK_LOG: return "ATTACK_LOG";
        case FileType::PERFORMANCE_LOG: return "PERFORMANCE_LOG";
        case FileType::DEBUG_LOG: return "DEBUG_LOG";
        default: return "UNKNOWN";
    }
}

std::string FileLogger::format_timestamp(const std::chrono::steady_clock::time_point& tp) {
    // Convert steady_clock to system_clock for proper timestamp formatting
    auto now_steady = std::chrono::steady_clock::now();
    auto now_system = std::chrono::system_clock::now();
    auto elapsed = tp - now_steady;
    auto target_time = now_system + elapsed;
    
    auto time_t_target = std::chrono::system_clock::to_time_t(target_time);
    std::ostringstream oss;
    oss << std::put_time(std::localtime(&time_t_target), "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

// Private methods implementation

void FileLogger::logger_loop() {
    while (logger_running_.load(std::memory_order_acquire) || !log_queue_.empty()) {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        
        // Wait for log entries or shutdown
        queue_cv_.wait_for(lock, std::chrono::milliseconds(100), [this] {
            return !log_queue_.empty() || shutdown_requested_.load(std::memory_order_acquire);
        });
        
        // Process available log entries
        while (!log_queue_.empty()) {
            LogEntry entry = std::move(log_queue_.front());
            log_queue_.pop();
            lock.unlock();
            
            try {
                process_log_entry(entry);
            } catch (const std::exception& e) {
                std::cerr << "FileLogger: Error processing log entry: " << e.what() << '\n';
            }
            
            lock.lock();
        }
        
        lock.unlock();
        
        // Periodic maintenance
        auto now = std::chrono::steady_clock::now();
        
        // Create a snapshot of configs to avoid holding lock during file operations
        std::unordered_map<FileType, FileConfig> config_snapshot;
        {
            std::lock_guard<std::mutex> config_lock(config_mutex_);
            config_snapshot = file_configs_;
        }
        
        for (const auto& [type, config] : config_snapshot) {
            // Check if file needs flushing
            if (config.auto_flush) {
                auto last_flush = last_flush_times_[type];
                if (now - last_flush >= config.flush_interval) {
                    flush_file(type);
                    last_flush_times_[type] = now;
                }
            }
            
            // Check if file needs rotation
            if (should_rotate_file(type)) {
                perform_file_rotation(type);
            }
        }
        
        if (shutdown_requested_.load(std::memory_order_acquire) && log_queue_.empty()) {
            break;
        }
    }
    
    // Final flush before shutdown
    flush_all_files();
}

void FileLogger::process_log_entry(const LogEntry& entry) {
    if (!open_file(entry.file_type)) {
        dropped_entries_.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    
    auto& file = active_files_[entry.file_type];
    if (!file || !file->is_open()) {
        dropped_entries_.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    
    std::string formatted_message = format_log_message(entry);
    
    try {
        *file << formatted_message << '\n';
        
        // Immediate flush for critical messages
        if (entry.level == LogLevel::LOG_CRITICAL || entry.level == LogLevel::LOG_ERROR) {
            file->flush();
            flush_operations_.fetch_add(1, std::memory_order_relaxed);
        }
    } catch (const std::exception& e) {
        std::cerr << "FileLogger: Failed to write log entry: " << e.what() << '\n';
        dropped_entries_.fetch_add(1, std::memory_order_relaxed);
    }
}

bool FileLogger::open_file(FileType file_type) {
    auto it = active_files_.find(file_type);
    if (it != active_files_.end() && it->second && it->second->is_open()) {
        return true; // Already open
    }
    
    FileConfig config;
    {
        std::lock_guard<std::mutex> lock(config_mutex_);
        auto config_it = file_configs_.find(file_type);
        if (config_it == file_configs_.end()) {
            std::cerr << "FileLogger: No config found for file type: " 
                      << file_type_to_string(file_type) << '\n';
            return false;
        }
        config = config_it->second;
    }
    
    try {
        ensure_directory_exists(config.file_path);
        
        auto file = std::make_unique<std::ofstream>(config.file_path, std::ios::app);
        if (!file->is_open()) {
            std::cerr << "FileLogger: Failed to open file: " << config.file_path 
                      << " - " << std::strerror(errno) << '\n';
            return false;
        }
        
        active_files_[file_type] = std::move(file);
        return true;
    } catch (const std::exception& e) {
        std::cerr << "FileLogger: Exception opening file " << config.file_path 
                  << ": " << e.what() << '\n';
        return false;
    }
}

void FileLogger::close_file(FileType file_type) {
    auto it = active_files_.find(file_type);
    if (it != active_files_.end() && it->second) {
        if (it->second->is_open()) {
            it->second->flush();
            it->second->close();
        }
        active_files_.erase(it);
    }
}

void FileLogger::ensure_directory_exists(const std::string& file_path) {
    std::filesystem::path path(file_path);
    std::filesystem::path dir = path.parent_path();
    
    if (!dir.empty() && !std::filesystem::exists(dir)) {
        std::filesystem::create_directories(dir);
    }
}

bool FileLogger::should_rotate_file(FileType file_type) {
    FileConfig config;
    {
        std::lock_guard<std::mutex> lock(config_mutex_);
        auto config_it = file_configs_.find(file_type);
        if (config_it == file_configs_.end()) {
            return false;
        }
        config = config_it->second;
    }
    
    try {
        if (std::filesystem::exists(config.file_path)) {
            auto file_size = std::filesystem::file_size(config.file_path);
            return file_size >= config.max_file_size;
        }
    } catch (const std::filesystem::filesystem_error&) {
        // If we can't check file size, don't rotate
        return false;
    }
    
    return false;
}

void FileLogger::perform_file_rotation(FileType file_type) {
    FileConfig config;
    {
        std::lock_guard<std::mutex> lock(config_mutex_);
        auto config_it = file_configs_.find(file_type);
        if (config_it == file_configs_.end()) {
            std::cerr << "FileLogger: No config found for rotation of file type: " 
                      << file_type_to_string(file_type) << '\n';
            return;
        }
        config = config_it->second;
    }
    
    // Close current file
    close_file(file_type);
    
    try {
        // Move existing backups
        for (int i = config.max_backup_files - 1; i >= 1; i--) {
            std::string old_backup = get_backup_filename(file_type, i);
            std::string new_backup = get_backup_filename(file_type, i + 1);
            
            if (std::filesystem::exists(old_backup)) {
                if (i == config.max_backup_files - 1) {
                    // Remove oldest backup
                    std::filesystem::remove(old_backup);
                } else {
                    std::filesystem::rename(old_backup, new_backup);
                }
            }
        }
        
        // Move current file to .1 backup
        if (std::filesystem::exists(config.file_path)) {
            std::string first_backup = get_backup_filename(file_type, 1);
            std::filesystem::rename(config.file_path, first_backup);
            
            // Compress if enabled
            if (config.enable_compression) {
                compress_backup_file(first_backup);
            }
        }
        
        // Cleanup old backups beyond max_backup_files
        cleanup_old_backups(file_type);
        
        file_rotations_.fetch_add(1, std::memory_order_relaxed);
        
    } catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "FileLogger: File rotation failed for " 
                  << file_type_to_string(file_type) << ": " << e.what() << '\n';
    }
}

void FileLogger::compress_backup_file(const std::string& file_path) {
    // Simple compression using gzip if available
    // Safer implementation without shell injection risks
    try {
        // Validate file path to prevent injection
        if (file_path.find("..") != std::string::npos || 
            file_path.find(';') != std::string::npos ||
            file_path.find('&') != std::string::npos ||
            file_path.find('|') != std::string::npos) {
            std::cerr << "FileLogger: Invalid file path for compression: " << file_path << '\n';
            return;
        }
        
        // Use execvp to avoid shell injection
        pid_t pid = fork();
        if (pid == 0) {
            // Child process
            execlp("gzip", "gzip", file_path.c_str(), nullptr);
            _exit(1); // If exec fails
        } else if (pid > 0) {
            // Parent process
            int status;
            waitpid(pid, &status, 0);
            if (WEXITSTATUS(status) != 0) {
                std::cerr << "FileLogger: Failed to compress " << file_path << '\n';
            }
        } else {
            std::cerr << "FileLogger: Fork failed for compression of " << file_path << '\n';
        }
    } catch (const std::exception& e) {
        std::cerr << "FileLogger: Compression error for " << file_path 
                  << ": " << e.what() << '\n';
    }
}

void FileLogger::cleanup_old_backups(FileType file_type) {
    const auto& config = file_configs_[file_type];
    
    // Remove backups beyond max_backup_files
    for (int i = config.max_backup_files + 1; i <= config.max_backup_files + 10; i++) {
        std::string backup_file = get_backup_filename(file_type, i);
        std::string compressed_backup = backup_file + ".gz";
        
        try {
            if (std::filesystem::exists(backup_file)) {
                std::filesystem::remove(backup_file);
            }
            if (std::filesystem::exists(compressed_backup)) {
                std::filesystem::remove(compressed_backup);
            }
        } catch (const std::filesystem::filesystem_error&) {
            // Ignore cleanup errors
        }
    }
}

std::string FileLogger::get_backup_filename(FileType file_type, int backup_number) {
    const auto& config = file_configs_[file_type];
    return config.file_path + "." + std::to_string(backup_number);
}

bool FileLogger::try_acquire_file_lock(std::chrono::milliseconds timeout) {
    return file_operations_mutex_.try_lock_for(timeout);
}

void FileLogger::release_file_lock() {
    file_operations_mutex_.unlock();
}

void FileLogger::flush_file(FileType file_type) {
    auto it = active_files_.find(file_type);
    if (it != active_files_.end() && it->second && it->second->is_open()) {
        try {
            it->second->flush();
            flush_operations_.fetch_add(1, std::memory_order_relaxed);
        } catch (const std::exception& e) {
            std::cerr << "FileLogger: Flush error for " << file_type_to_string(file_type) 
                      << ": " << e.what() << '\n';
        }
    }
}

bool FileLogger::is_queue_full() const {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    return log_queue_.size() >= MAX_QUEUE_SIZE;
}

void FileLogger::handle_queue_overflow() {
    // Drop older entries to make room
    constexpr double overflow_factor = 0.8;
    size_t target_size = static_cast<size_t>(static_cast<double>(MAX_QUEUE_SIZE) * overflow_factor);
    size_t current_size = log_queue_.size();
    
    if (current_size <= target_size) {
        return;
    }
    
    size_t entries_to_drop = current_size - target_size;
    for (size_t i = 0; i < entries_to_drop && !log_queue_.empty(); i++) {
        log_queue_.pop();
        dropped_entries_.fetch_add(1, std::memory_order_relaxed);
    }
    
    std::cerr << "FileLogger: Queue overflow - dropped " << entries_to_drop 
              << " entries" << '\n';
}

std::string FileLogger::format_log_message(const LogEntry& entry) {
    std::ostringstream oss;
    
    // For structured files like BLOCKED_IPS and RATE_LIMITED_IPS, just return the message
    if (entry.file_type == FileType::BLOCKED_IPS || 
        entry.file_type == FileType::RATE_LIMITED_IPS ||
        entry.file_type == FileType::METRICS) {
        return entry.message;
    }
    
    // For other log files, add timestamp and level
    oss << "[" << format_timestamp(entry.timestamp) << "] ";
    oss << "[" << log_level_to_string(entry.level) << "] ";
    
    if (!entry.source_file.empty()) {
        // Extract just filename from full path
        std::string filename = entry.source_file;
        size_t last_slash = filename.find_last_of("/\\");
        if (last_slash != std::string::npos) {
            filename = filename.substr(last_slash + 1);
        }
        oss << "[" << filename << ":" << entry.line_number << "] ";
    }
    
    oss << entry.message;
    
    return oss.str();
}
