#include "ddos_inspector.hpp"
#include "behavior_tracker.hpp"
#include "firewall_action.hpp"
#include "packet_data.hpp"
#include "stats_engine.hpp"
#include "file_logger.hpp"

#ifdef TESTING
#include "testing_config.hpp"
#endif

#ifdef __unix__
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <unistd.h>
#endif

// Define thread_local variable for deadlock prevention
namespace DeadlockPrevention {
    thread_local std::vector<LockLevel> acquired_locks;
}

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <framework/snort_api.h>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <list>
#include <main/snort_config.h>
#include <protocols/ip.h>
#include <shared_mutex>
#include <sstream>
#include <string_view>
#include <system_error>
#include <thread>
#include <unordered_map>

using namespace snort;
using namespace std::chrono_literals;

// TTY detection for color codes
[[maybe_unused]] static bool is_tty()
{
    static bool cached = false;
    static bool is_terminal = false;
    if (!cached)
    {
#ifdef __unix__
        is_terminal = isatty(STDOUT_FILENO) == 1;
#else
        is_terminal = false; // Disable on non-POSIX systems
#endif
        cached = true;
    }
    return is_terminal;
}

// Logger abstraction to replace std::cout
class DDosLogger
{
public:
    enum Level : std::uint8_t
    {
        LOG_DEBUG = 0,
        LOG_INFO = 1,
        LOG_WARNING = 2,
        LOG_ERROR = 3
    };

    static void log(Level level, const std::string &message)
    {
        switch (level)
        {
        case LOG_DEBUG:
            // For debug, we'll just use LogMessage with a DEBUG prefix
            LogMessage("DDoS Inspector DEBUG: %s\n", message.c_str());
            break;
        case LOG_INFO:
            LogMessage("DDoS Inspector: %s\n", message.c_str());
            break;
        case LOG_WARNING:
            WarningMessage("DDoS Inspector: %s\n", message.c_str());
            break;
        case LOG_ERROR:
            ErrorMessage("DDoS Inspector: %s\n", message.c_str());
            break;
        default:
            LogMessage("DDoS Inspector: %s\n", message.c_str());
            break;
        }
    }

    static void info(const std::string &message) { log(LOG_INFO, message); }
    static void warning(const std::string &message) { log(LOG_WARNING, message); }
    static void error(const std::string &message) { log(LOG_ERROR, message); }
    static void debug(const std::string &message) { log(LOG_DEBUG, message); }
};

// Color constants for console output (only for TTY)
inline const char *get_color(const char *color)
{
#ifdef DDOS_INSPECTOR_COLOR
    return is_tty() ? color : "";
#else
    return "";
#endif
}

#define COLOR_GREEN get_color("\033[0;32m")
#define COLOR_BLUE get_color("\033[0;34m")
#define COLOR_YELLOW get_color("\033[0;33m")
#define COLOR_MAGENTA get_color("\033[0;35m")
#define COLOR_RED get_color("\033[0;31m")
#define COLOR_BOLD_RED get_color("\033[1;31m")
#define COLOR_RESET get_color("\033[0m")

// Thread-safe time formatting helper
static std::string formatCurrentTime()
{
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    
    // Thread-safe time formatting
    thread_local struct tm tm_storage;
    struct tm* tm = localtime_r(&time_t, &tm_storage);
    
    std::ostringstream oss;
    oss << std::put_time(tm, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

// Helper function to get path from environment variables or .env file
static std::string getPathFromEnv(const char* env_var_name, const std::string& default_path) {
    // First, try to get from environment variable directly
    const char* env_value = getenv(env_var_name);
    if (env_value && strlen(env_value) > 0) {
        return std::string(env_value);
    }
    
    // Then try to read from .env file in current directory
    std::ifstream env_file(".env");
    if (env_file.is_open()) {
        std::string line;
        std::string search_key = std::string(env_var_name) + "=";
        
        while (std::getline(env_file, line)) {
            // Skip comments and empty lines
            if (line.empty() || line[0] == '#') continue;
            
            // Remove leading/trailing whitespace
            line.erase(0, line.find_first_not_of(" \t\r\n"));
            line.erase(line.find_last_not_of(" \t\r\n") + 1);
            
            // Check if this line contains our variable
            if (line.find(search_key) == 0) {
                std::string value = line.substr(search_key.length());
                
                // Remove quotes if present
                if (value.length() >= 2 && 
                    ((value.front() == '"' && value.back() == '"') ||
                     (value.front() == '\'' && value.back() == '\''))) {
                    value = value.substr(1, value.length() - 2);
                }
                
                if (!value.empty()) {
                    env_file.close();
                    return value;
                }
            }
        }
        env_file.close();
    }
    
    // Fall back to SNORT_DATA_DIR + filename only (extract filename from default_path)
    const char* snort_data_dir = getenv("SNORT_DATA_DIR");
    if (snort_data_dir) {
        // Extract just the filename from the default path
        size_t last_slash = default_path.find_last_of('/');
        std::string filename = (last_slash != std::string::npos) ? default_path.substr(last_slash + 1) : default_path;
        return std::string(snort_data_dir) + "/" + filename;
    }
    
    // Final fallback: if default_path is absolute, use it; otherwise prepend /tmp/
    if (!default_path.empty() && default_path[0] == '/') {
        return default_path;
    } else {
        return "/tmp/" + default_path;
    }
}

// Thread-safe time wrapper similar to safe_localtime() from stats_engine.cpp
static struct tm safeLocaltime(std::time_t time)
{
    thread_local struct tm tm_storage;
    localtime_r(&time, &tm_storage);
    return tm_storage;
}

// Thread-safe formatted time for logs and metrics
[[maybe_unused]] static std::string formatTime(std::time_t time, const char* format = "%Y-%m-%d %H:%M:%S")
{
    struct tm tm = safeLocaltime(time);
    std::ostringstream oss;
    oss << std::put_time(&tm, format);
    return oss.str();
}

// Consolidated confidence calculation helper using configurable tuning
inline double calculateExtraConfidence(double current_rate, double current_entropy, 
                                      double baseline_rate, double baseline_entropy)
{
    double extra_confidence = 0.0;
    
    // Rate-based confidence boost with configurable thresholds
    double rate_ratio = current_rate / std::max(baseline_rate, g_threshold_tuning.min_rate_threshold);
    if (rate_ratio > g_threshold_tuning.rate_ratio_high_threshold) {
        extra_confidence += g_threshold_tuning.confidence_rate_high_bonus;
    } else if (rate_ratio > g_threshold_tuning.rate_ratio_med_threshold) {
        extra_confidence += g_threshold_tuning.confidence_rate_med_bonus;
    }
    
    // Entropy-based confidence boost with configurable thresholds  
    double entropy_ratio = baseline_entropy / std::max(current_entropy, 0.1);
    if (entropy_ratio > g_threshold_tuning.entropy_ratio_high_threshold) {
        extra_confidence += g_threshold_tuning.confidence_entropy_high_bonus;
    } else if (entropy_ratio > g_threshold_tuning.entropy_ratio_med_threshold) {
        extra_confidence += g_threshold_tuning.confidence_entropy_med_bonus;
    }
    
    return extra_confidence;
}

// Thread-safe amplification attempt tracking with bounded LRU
struct AmplificationTracker
{
    mutable std::shared_mutex mutex;
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> attempts;
    std::list<std::string> lru_list; // For LRU ordering
    std::unordered_map<std::string, std::list<std::string>::iterator> lru_map; // For O(1) access
    static constexpr size_t MAX_ENTRIES = 10000;
    std::atomic<int> cleanup_counter{0};

    bool checkAndUpdate(const std::string &src_ip)
    {
        auto now = std::chrono::steady_clock::now();

        // Read-only check first
        {
            std::shared_lock<std::shared_mutex> read_lock(mutex);
            auto it = attempts.find(src_ip);
            if (it != attempts.end())
            {
                auto time_diff = std::chrono::duration_cast<std::chrono::seconds>(now - it->second);
                if (time_diff.count() >= 5)
                {
                    // Need to update, fall through to write lock
                }
                else
                {
                    return true; // Rate exceeded
                }
            }
        }

        // Write lock for updates
        {
            std::unique_lock<std::shared_mutex> write_lock(mutex);
            
            // Update or insert entry
            auto it = attempts.find(src_ip);
            if (it != attempts.end())
            {
                // Update existing entry and move to front of LRU
                it->second = now;
                auto lru_it = lru_map[src_ip];
                lru_list.erase(lru_it);
                lru_list.push_front(src_ip);
                lru_map[src_ip] = lru_list.begin();
            }
            else
            {
                // Insert new entry
                if (attempts.size() >= MAX_ENTRIES)
                {
                    // Remove least recently used entry
                    const std::string &lru_ip = lru_list.back();
                    attempts.erase(lru_ip);
                    lru_map.erase(lru_ip);
                    lru_list.pop_back();
                }
                
                attempts[src_ip] = now;
                lru_list.push_front(src_ip);
                lru_map[src_ip] = lru_list.begin();
            }

            // Periodic cleanup of expired entries
            if (cleanup_counter.fetch_add(1) >= 1000)
            {
                cleanup_counter.store(0);
                auto threshold = now - std::chrono::minutes(10);
                
                for (auto lru_it = lru_list.begin(); lru_it != lru_list.end();)
                {
                    const std::string &ip = *lru_it;
                    auto attempt_it = attempts.find(ip);
                    if (attempt_it != attempts.end() && attempt_it->second < threshold)
                    {
                        attempts.erase(attempt_it);
                        lru_map.erase(ip);
                        lru_it = lru_list.erase(lru_it);
                    }
                    else
                    {
                        ++lru_it;
                    }
                }
            }
        }

        return false; // First attempt or old enough
    }
};

// Fragment tracking with per-IP counters
struct FragmentTracker
{
    mutable std::shared_mutex mutex;
    std::unordered_map<std::string, std::pair<uint32_t, std::chrono::steady_clock::time_point>>
        fragment_counts;

    bool checkFragmentFlood(const std::string &src_ip)
    {
        auto now = std::chrono::steady_clock::now();

        std::unique_lock<std::shared_mutex> lock(mutex);
        auto &[count, last_seen] = fragment_counts[src_ip];

        // Reset counter if more than 60 seconds have passed
        auto time_diff = std::chrono::duration_cast<std::chrono::seconds>(now - last_seen);
        if (time_diff.count() > 60)
        {
            count = 0;
        }

        count++;
        last_seen = now;

        // Cleanup old entries periodically
        static std::atomic<int> cleanup_counter{0};
        if (cleanup_counter.fetch_add(1) % 1000 == 0)
        {
            for (auto it = fragment_counts.begin(); it != fragment_counts.end();)
            {
                auto entry_time_diff =
                    std::chrono::duration_cast<std::chrono::minutes>(now - it->second.second);
                if (entry_time_diff.count() > 10)
                {
                    it = fragment_counts.erase(it);
                }
                else
                {
                    ++it;
                }
            }
        }

        return count > 100; // More than 100 fragments per minute from same IP
    }
};

// Singleton wrapper for global trackers with proper cleanup
class GlobalTrackers
{
private:
    static std::unique_ptr<GlobalTrackers> instance;
    static std::mutex instance_mutex;
    
public:
    AmplificationTracker amplification_tracker;
    FragmentTracker fragment_tracker;
    
    static GlobalTrackers& getInstance()
    {
        std::lock_guard<std::mutex> lock(instance_mutex);
        if (!instance)
        {
            instance = std::make_unique<GlobalTrackers>();
            // Register cleanup on exit
            std::atexit([]() {
                std::lock_guard<std::mutex> lock(instance_mutex);
                instance.reset();
            });
        }
        return *instance;
    }
    
    static void cleanup()
    {
        std::lock_guard<std::mutex> lock(instance_mutex);
        instance.reset();
    }
};

// Static member definitions
std::unique_ptr<GlobalTrackers> GlobalTrackers::instance = nullptr;
std::mutex GlobalTrackers::instance_mutex;

// Accessor functions for backward compatibility
static AmplificationTracker& getAmplificationTracker()
{
    return GlobalTrackers::getInstance().amplification_tracker;
}

static FragmentTracker& getFragmentTracker()
{
    return GlobalTrackers::getInstance().fragment_tracker;
}

// Global inspector instance for proper cleanup  
// Note: This is primarily for cleanup coordination, not for cross-thread access
static std::atomic<DdosInspector*> g_inspector_instance{nullptr};

//-------------------------------------------------------------------------
// module stuff
//-------------------------------------------------------------------------

static const Parameter ddos_params[] = {
    {"allow_icmp", Parameter::PT_BOOL, nullptr, "false", "allow ICMP packets to be processed"},

    {"entropy_threshold", Parameter::PT_REAL, "0.0:10.0", "2.0",
     "entropy threshold for anomaly detection"},

    {"ewma_alpha", Parameter::PT_REAL, "0.0:1.0", "0.1", "EWMA smoothing factor"},

    {"block_timeout", Parameter::PT_INT, "1:3600", "600", "IP block timeout in seconds"},

    {"blocked_ips_file", Parameter::PT_STRING, nullptr, "/var/log/ddos_inspector/blocked_ips.log",
     "path to blocked IPs output file (auto-reads from $DDOS_BLOCKED_IPS_FILE env var or .env file, fallback: $SNORT_DATA_DIR)"},

    {"rate_limited_ips_file", Parameter::PT_STRING, nullptr, "/var/log/ddos_inspector/rate_limited_ips.log", 
     "path to rate limited IPs output file (auto-reads from $DDOS_RATE_LIMITED_IPS_FILE env var or .env file, fallback: $SNORT_DATA_DIR)"},

    {"metrics_file", Parameter::PT_STRING, nullptr, "/var/log/ddos_inspector/metrics.log",
     "path to metrics output file (auto-reads from $DDOS_METRICS_FILE env var or .env file, fallback: $SNORT_DATA_DIR)"},

    {"use_env_files", Parameter::PT_BOOL, nullptr, "true",
     "enable automatic reading from environment variables and .env file"},

    {"config_profile", Parameter::PT_STRING, nullptr, "default",
     "configuration profile: default, strict, permissive, web_server, game_server"},

    {"protected_networks", Parameter::PT_STRING, nullptr, "192.168.0.0/16,10.0.0.0/8,172.16.0.0/12",
     "comma-separated list of protected network CIDRs"},

    {"log_level", Parameter::PT_STRING, nullptr, "info",
     "logging level: debug, info, warning, error"},

    {"enable_amplification_detection", Parameter::PT_BOOL, nullptr, "true",
     "enable amplification attack detection"},

    {"enable_adaptive_thresholds", Parameter::PT_BOOL, nullptr, "true",
     "enable adaptive threshold management"},

    {"enable_ipv6", Parameter::PT_BOOL, nullptr, "true", "enable IPv6 support"},

    {"enable_fragmentation_detection", Parameter::PT_BOOL, nullptr, "true",
     "enable fragment flood detection"},

    {"max_tracked_ips", Parameter::PT_INT, "100:100000", "10000",
     "maximum number of IPs to track simultaneously"},

    {"tarpit_enabled", Parameter::PT_BOOL, nullptr, "true", "enable tarpit for slow down attacks"},

    {"tcp_reset_enabled", Parameter::PT_BOOL, nullptr, "true",
     "enable TCP reset for malicious connections"},

    {"adaptation_factor", Parameter::PT_REAL, "0.01:1.0", "0.1",
     "EWMA adaptation factor for adaptive thresholds"},

    {"entropy_multiplier", Parameter::PT_REAL, "0.1:1.0", "0.3", 
     "entropy threshold multiplier for baseline adaptation"},

    {"rate_multiplier", Parameter::PT_REAL, "1.0:10.0", "3.0",
     "rate threshold multiplier for baseline adaptation"},

    // NEW: Adaptive behavioral threshold parameters
    {"syn_flood_baseline_multiplier", Parameter::PT_REAL, "1.0:20.0", "5.0",
     "SYN flood threshold multiplier for baseline adaptation"},

    {"ack_flood_baseline_multiplier", Parameter::PT_REAL, "1.0:15.0", "3.0",
     "ACK flood threshold multiplier for baseline adaptation"},

    {"http_flood_baseline_multiplier", Parameter::PT_REAL, "1.0:50.0", "10.0",
     "HTTP flood threshold multiplier for baseline adaptation"},

    {"enable_time_of_day_adaptation", Parameter::PT_BOOL, nullptr, "true",
     "enable time-of-day based threshold adaptation"},

    {"enable_network_load_adaptation", Parameter::PT_BOOL, nullptr, "true",
     "enable network load based threshold adaptation"},

    {nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr}};

#define DDOS_NAME "ddos_inspector"
#define DDOS_HELP "statistical and behavioral DDoS detection plugin"

DdosInspectorModule::DdosInspectorModule() : Module(DDOS_NAME, DDOS_HELP, ddos_params)
{
    // Initialize file paths from environment variables/env file with fallbacks
    metrics_file = getPathFromEnv("DDOS_METRICS_FILE", "/var/log/ddos_inspector/metrics.log");
    blocked_ips_file = getPathFromEnv("DDOS_BLOCKED_IPS_FILE", "/var/log/ddos_inspector/blocked_ips.log"); 
    rate_limited_ips_file = getPathFromEnv("DDOS_RATE_LIMITED_IPS_FILE", "/var/log/ddos_inspector/rate_limited_ips.log");
    
    DDosLogger::info("DDoS Inspector Plugin Module loaded successfully!");
    DDosLogger::info("File paths initialized: metrics=" + metrics_file + 
                     ", blocked_ips=" + blocked_ips_file + 
                     ", rate_limited_ips=" + rate_limited_ips_file);
}

const Parameter *DdosInspectorModule::get_parameters() const
{
    return ddos_params;
}

bool DdosInspectorModule::set(const char *fqn, Value &v, SnortConfig *)
{
    if (v.is("allow_icmp"))
        allow_icmp = v.get_bool();
    else if (v.is("entropy_threshold"))
        entropy_threshold = v.get_real();
    else if (v.is("ewma_alpha"))
        ewma_alpha = v.get_real();
    else if (v.is("block_timeout"))
        block_timeout = v.get_uint32();
    else if (v.is("metrics_file"))
    {
        std::string path = v.get_string();
        
        // Always try environment variables first if env files are enabled
        if (use_env_files) {
            std::string env_path = getPathFromEnv("DDOS_METRICS_FILE", path);
            if (env_path != path) {
                path = env_path; // Use environment variable value
            }
        }
        
        if (validateMetricsPath(path))
        {
            metrics_file = path;
        }
        else
        {
            DDosLogger::error("Invalid metrics file path, using default: " + metrics_file);
        }
    }
    else if (v.is("blocked_ips_file"))
    {
        std::string path = v.get_string();
        
        // Always try environment variables first if env files are enabled
        if (use_env_files) {
            std::string env_path = getPathFromEnv("DDOS_BLOCKED_IPS_FILE", path);
            if (env_path != path) {
                path = env_path; // Use environment variable value
            }
        }
        
        if (validateMetricsPath(path))
        {
            blocked_ips_file = path;
        }
        else
        {
            DDosLogger::error("Invalid blocked IPs file path, using default: " + blocked_ips_file);
        }
    }
    else if (v.is("rate_limited_ips_file"))
    {
        std::string path = v.get_string();
        
        // Always try environment variables first if env files are enabled
        if (use_env_files) {
            std::string env_path = getPathFromEnv("DDOS_RATE_LIMITED_IPS_FILE", path);
            if (env_path != path) {
                path = env_path; // Use environment variable value
            }
        }
        
        if (validateMetricsPath(path))
        {
            rate_limited_ips_file = path;
        }
        else
        {
            DDosLogger::error("Invalid rate limited IPs file path, using default: " + rate_limited_ips_file);
        }
    }
    else if (v.is("config_profile"))
        config_profile = v.get_string();
    else if (v.is("protected_networks"))
        protected_networks = v.get_string();
    else if (v.is("log_level"))
        log_level = v.get_string();
    else if (v.is("enable_amplification_detection"))
        enable_amplification_detection = v.get_bool();
    else if (v.is("enable_adaptive_thresholds"))
        enable_adaptive_thresholds = v.get_bool();
    else if (v.is("enable_ipv6"))
        enable_ipv6 = v.get_bool();
    else if (v.is("enable_fragmentation_detection"))
        enable_fragmentation_detection = v.get_bool();
    else if (v.is("max_tracked_ips"))
        max_tracked_ips = v.get_uint32();
    else if (v.is("tarpit_enabled"))
        tarpit_enabled = v.get_bool();
    else if (v.is("tcp_reset_enabled"))
        tcp_reset_enabled = v.get_bool();
    else if (v.is("adaptation_factor"))
    {
        adaptation_factor = v.get_real();
        g_threshold_tuning.adaptation_factor = adaptation_factor;
    }
    else if (v.is("entropy_multiplier"))
    {
        entropy_multiplier = v.get_real();
        g_threshold_tuning.entropy_multiplier = entropy_multiplier;
    }
    else if (v.is("rate_multiplier"))
    {
        rate_multiplier = v.get_real();
        g_threshold_tuning.rate_multiplier = rate_multiplier;
    }
    else if (v.is("syn_flood_baseline_multiplier"))
    {
        syn_flood_baseline_multiplier = v.get_real();
        g_threshold_tuning.syn_flood_baseline_multiplier = syn_flood_baseline_multiplier;
    }
    else if (v.is("ack_flood_baseline_multiplier"))
    {
        ack_flood_baseline_multiplier = v.get_real();
        g_threshold_tuning.ack_flood_baseline_multiplier = ack_flood_baseline_multiplier;
    }
    else if (v.is("http_flood_baseline_multiplier"))
    {
        http_flood_baseline_multiplier = v.get_real();
        g_threshold_tuning.http_flood_baseline_multiplier = http_flood_baseline_multiplier;
    }
    else if (v.is("enable_time_of_day_adaptation"))
    {
        enable_time_of_day_adaptation = v.get_bool();
        g_threshold_tuning.enable_time_of_day_adaptation = enable_time_of_day_adaptation;
    }
    else if (v.is("enable_network_load_adaptation"))
    {
        enable_network_load_adaptation = v.get_bool();
        g_threshold_tuning.enable_network_load_adaptation = enable_network_load_adaptation;
    }
    else if (v.is("use_env_files"))
        use_env_files = v.get_bool();
    else
        return false;

    return true;
}

bool DdosInspectorModule::begin(const char *, int, SnortConfig *)
{
    DDosLogger::info("DDoS Inspector Plugin configuration initialized");
    return true;
}

bool DdosInspectorModule::end(const char *, int, SnortConfig *)
{
    applyConfigurationProfile();
    
    // Log active threshold tuning configuration for operational visibility
    g_threshold_tuning.logConfiguration();
    
    // Check for runtime testing mode from environment
    const char* env_testing = std::getenv("TESTING");
    if (env_testing) {
        std::string testing_value = env_testing;
        std::transform(testing_value.begin(), testing_value.end(), testing_value.begin(), ::tolower);
        if (testing_value == "true" || testing_value == "1" || testing_value == "on") {
            setRuntimeTestingMode(true);
        }
    }
    
    // Validate all configured paths at configuration time
    if (!validateMetricsPath(metrics_file))
    {
        DDosLogger::error("Invalid metrics file path: " + metrics_file);
        return false;
    }
    
    if (!validateMetricsPath(blocked_ips_file))
    {
        DDosLogger::error("Invalid blocked IPs file path: " + blocked_ips_file);
        return false;
    }
    
    if (!validateMetricsPath(rate_limited_ips_file))
    {
        DDosLogger::error("Invalid rate limited IPs file path: " + rate_limited_ips_file);
        return false;
    }
    
    DDosLogger::info("DDoS Inspector Plugin configuration completed successfully");
    return true;
}

void DdosInspectorModule::applyConfigurationProfile()
{
    DDosLogger::info("Applying configuration profile: " + config_profile);

    if (config_profile == "strict")
    {
        // Strict mode: Lower thresholds, higher sensitivity
        entropy_threshold = 1.5;
        ewma_alpha = 0.15;
        block_timeout = 1800; // 30 minutes
        connection_threshold = 500;
        rate_threshold = 25000;
        DDosLogger::info("- Applied strict detection thresholds");
    }
    else if (config_profile == "permissive")
    {
        // Permissive mode: Higher thresholds, lower sensitivity
        entropy_threshold = 3.0;
        ewma_alpha = 0.05;
        block_timeout = 300; // 5 minutes
        connection_threshold = 2000;
        rate_threshold = 100000;
        DDosLogger::info("- Applied permissive detection thresholds");
    }
    else if (config_profile == "web_server")
    {
        // Web server optimized: Balanced for HTTP traffic
        entropy_threshold = 2.2;
        ewma_alpha = 0.08;
        block_timeout = 900; // 15 minutes
        connection_threshold = 1500;
        rate_threshold = 75000;
        DDosLogger::info("- Applied web server optimized thresholds");
    }
    else if (config_profile == "game_server")
    {
        // Game server optimized: Higher tolerance for UDP traffic
        entropy_threshold = 2.8;
        ewma_alpha = 0.06;
        block_timeout = 600; // 10 minutes
        connection_threshold = 3000;
        rate_threshold = 120000;
        DDosLogger::info("- Applied game server optimized thresholds");
    }
    else
    {
        // Default profile
        DDosLogger::info("- Using default detection thresholds");
    }
}

bool DdosInspectorModule::validateMetricsPath(const std::string &path) const
{
    if (path.empty())
        return true; // Empty path is valid (disables metrics)

    // Reject paths that could be security risks
    if (path.find("..") != std::string::npos ||
        path.find("//") != std::string::npos ||
        path[0] != '/')
    {
        return false;
    }

    return true;
}

// NEW: Runtime testing mode management methods
void DdosInspectorModule::setRuntimeTestingMode(bool enabled) {
    runtime_testing_mode = enabled;
    g_threshold_tuning.setRuntimeTestingMode(enabled);
    
    if (enabled) {
        DDosLogger::info("Runtime testing mode enabled - using low testing thresholds");
    } else {
        DDosLogger::info("Runtime testing mode disabled - using production thresholds");
    }
}

bool DdosInspectorModule::isRuntimeTestingMode() const {
    return runtime_testing_mode;
}

void DdosInspectorModule::reloadTestingConfiguration() {
    #ifdef TESTING
    if (g_testing_config.reload()) {
        DDosLogger::info("Testing configuration reloaded from testing_config.json");
        if (runtime_testing_mode) {
            // Reapply testing thresholds with new configuration
            g_threshold_tuning.applyRuntimeTestingThresholds();
        }
    } else {
        DDosLogger::warning("Failed to reload testing configuration - using existing settings");
    }
    #else
    DDosLogger::warning("Testing configuration reload not available - TESTING flag not defined");
    #endif
}

//-------------------------------------------------------------------------
// inspector stuff
//-------------------------------------------------------------------------

DdosInspector::DdosInspector(DdosInspectorModule *mod)
{
    std::stringstream init_msg;
    init_msg << "DDoS Inspector engine starting with configuration:\n"
             << "   - Allow ICMP: " << (mod->allow_icmp ? "enabled" : "disabled") << '\n'
             << "   - Entropy threshold: " << mod->entropy_threshold << '\n'
             << "   - EWMA alpha: " << mod->ewma_alpha << '\n'
             << "   - Block timeout: " << mod->block_timeout << "s\n"
             << "   - Metrics file: " << mod->metrics_file << '\n'
             << "   - Runtime testing mode: " << (mod->runtime_testing_mode ? "enabled" : "disabled");
    DDosLogger::info(init_msg.str());

    allow_icmp = mod->allow_icmp;
    metrics_file_path = mod->metrics_file;
    blocked_ips_file_path = mod->blocked_ips_file;
    rate_limited_ips_file_path = mod->rate_limited_ips_file;
    config_profile = mod->config_profile;
    
    // Initialize file logger with custom configurations
    std::unordered_map<FileLogger::FileType, FileLogger::FileConfig> file_configs;
    
    file_configs[FileLogger::FileType::METRICS] = {
        mod->metrics_file, 50 * 1024 * 1024, 3, true, 
        std::chrono::milliseconds(5000), false
    };
    
    file_configs[FileLogger::FileType::BLOCKED_IPS] = {
        mod->blocked_ips_file, 10 * 1024 * 1024, 5, true,
        std::chrono::milliseconds(2000), false
    };
    
    file_configs[FileLogger::FileType::RATE_LIMITED_IPS] = {
        mod->rate_limited_ips_file, 10 * 1024 * 1024, 5, true,
        std::chrono::milliseconds(2000), false
    };
    
    if (g_file_logger.initialize(file_configs)) {
        g_file_logger.start();
        DDosLogger::info("File logger initialized and started successfully");
    } else {
        DDosLogger::error("Failed to initialize file logger - file operations may not work");
    }
    
    // Initialize tuning parameters from module configuration
    g_threshold_tuning.adaptation_factor = mod->adaptation_factor;
    g_threshold_tuning.entropy_multiplier = mod->entropy_multiplier;
    g_threshold_tuning.rate_multiplier = mod->rate_multiplier;
    
    // Apply runtime testing mode if requested
    if (mod->runtime_testing_mode) {
        g_threshold_tuning.setRuntimeTestingMode(true);
    }

    // Initialize components with configuration
    stats_engine = std::make_unique<StatsEngine>(mod->entropy_threshold, mod->ewma_alpha);
    behavior_tracker = std::make_unique<BehaviorTracker>();
    firewall_action = std::make_unique<FirewallAction>(mod->block_timeout);

    // Initialize metrics tracking
    last_metrics_update = std::chrono::steady_clock::now();
    last_ip_list_update = std::chrono::steady_clock::now();
    block_rate_start_time = std::chrono::steady_clock::now();
    syn_flood_detections = 0;
    http_flood_detections = 0;
    slowloris_detections = 0;
    udp_flood_detections = 0;
    icmp_flood_detections = 0;
    amplification_detections = 0;
    total_blocks_issued = 0;
    current_blocked_count = 0;

    DDosLogger::info("DDoS Inspector engine initialized and ready for packet analysis!");

    // Start background metrics thread
    startMetricsThread();

    // Register global instance for cleanup coordination
    g_inspector_instance.store(this, std::memory_order_release);
}

DdosInspector::~DdosInspector()
{
    // Stop background metrics thread first to ensure no access to members
    stopMetricsThread();
    
    // Unregister global instance after thread is stopped
    g_inspector_instance.store(nullptr, std::memory_order_release);
}

void DdosInspector::writeMetrics()
{
    auto now = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - last_metrics_update);

    // Update metrics every 5 seconds (handled by background thread)
    if (duration.count() >= 5)
    {
        // DEADLOCK-FREE: Use file logger instead of direct file operations
        std::ostringstream metrics_data;
        
        // Build metrics content
        double current_rate = stats_engine ? stats_engine->get_current_rate() : 0.0;
        double current_entropy = stats_engine ? stats_engine->get_entropy() : 0.0;
        double block_rate = calculateBlockRate();
        
        // Enhanced metrics with comprehensive information
        metrics_data << "# DDoS Inspector Metrics - " << formatCurrentTime() << "\n";
        metrics_data << "# Real-time network security analytics\n";
        metrics_data << "# Configuration Profile: " << config_profile << "\n";
        metrics_data << "# Adaptive Thresholds: " << (g_threshold_tuning.enable_adaptive_behavioral_thresholds ? "enabled" : "disabled") << "\n";
        metrics_data << "# Testing Mode: " << (g_threshold_tuning.isRuntimeTestingMode() ? "enabled" : "disabled") << "\n\n";
        
        // Core packet processing metrics
        metrics_data << "[TRAFFIC_STATS]\n";
        metrics_data << "packets_processed=" << packets_processed.load() << "\n";
        metrics_data << "packets_blocked=" << packets_blocked.load() << "\n";
        metrics_data << "packets_rate_limited=" << packets_rate_limited.load() << "\n";
        metrics_data << "current_rate_pps=" << current_rate << "\n";
        metrics_data << "current_entropy=" << current_entropy << "\n";
        metrics_data << "block_rate_per_minute=" << block_rate << "\n";
        metrics_data << "false_positives=" << false_positives.load() << "\n\n";
        
        // Attack detection metrics
        metrics_data << "[ATTACK_DETECTION]\n";
        metrics_data << "syn_flood_detections=" << syn_flood_detections.load() << "\n";
        metrics_data << "http_flood_detections=" << http_flood_detections.load() << "\n";
        metrics_data << "slowloris_detections=" << slowloris_detections.load() << "\n";
        metrics_data << "udp_flood_detections=" << udp_flood_detections.load() << "\n";
        metrics_data << "icmp_flood_detections=" << icmp_flood_detections.load() << "\n";
        metrics_data << "amplification_detections=" << amplification_detections.load() << "\n\n";
        
        // Current firewall status
        metrics_data << "[FIREWALL_STATUS]\n";
        metrics_data << "total_blocked_ips=" << (firewall_action ? firewall_action->get_blocked_count() : 0) << "\n";
        metrics_data << "total_rate_limited_ips=" << (firewall_action ? firewall_action->get_rate_limited_count() : 0) << "\n";
        metrics_data << "current_threat_level=" << (firewall_action ? static_cast<int>(firewall_action->get_current_threat_level()) : 0) << "\n\n";
        
        // Adaptive threshold status
        metrics_data << "[ADAPTIVE_THRESHOLDS]\n";
        metrics_data << "entropy_threshold=" << adaptive_thresholds.entropy_threshold << "\n";
        metrics_data << "rate_threshold=" << adaptive_thresholds.rate_threshold << "\n";
        metrics_data << "syn_flood_threshold=" << adaptive_thresholds.syn_flood_threshold << "\n";
        metrics_data << "ack_flood_threshold=" << adaptive_thresholds.ack_flood_threshold << "\n";
        metrics_data << "http_flood_threshold=" << adaptive_thresholds.http_flood_threshold << "\n";
        metrics_data << "baseline_entropy=" << adaptive_thresholds.baseline_entropy << "\n";
        metrics_data << "baseline_rate=" << adaptive_thresholds.baseline_rate << "\n\n";
        
        // Performance metrics
        metrics_data << "[PERFORMANCE]\n";
        metrics_data << "total_processing_time_us=" << total_processing_time_us.load() << "\n";
        metrics_data << "max_processing_time_us=" << max_processing_time_us.load() << "\n";
        metrics_data << "avg_processing_time_us=" << (packets_processed.load() > 0 ? 
            total_processing_time_us.load() / packets_processed.load() : 0) << "\n\n";
        
        // Use file logger for thread-safe, deadlock-free writing
        g_file_logger.write_metrics_file(metrics_data.str());
        
        last_metrics_update = now;

        // Write IP lists less frequently (every 30 seconds)
        auto ip_list_duration =
            std::chrono::duration_cast<std::chrono::seconds>(now - last_ip_list_update);
        if (ip_list_duration.count() >= 30 && firewall_action)
        {
            // DEADLOCK-FREE: Use file logger for IP lists
            g_file_logger.write_blocked_ips_file(firewall_action->get_blocked_ips());
            g_file_logger.write_rate_limited_ips_file(firewall_action->get_rate_limited_ips());
            last_ip_list_update = now;
        }
    }
}

void DdosInspector::eval(Packet *p)
{
    auto eval_start = std::chrono::steady_clock::now();

    if (!p || !p->ptrs.ip_api.is_ip())
        return;

    // Cache packet size once
    const uint32_t packet_size = static_cast<uint32_t>(p->dsize);

    // Enhanced IP version support
    bool is_ipv4 = p->ptrs.ip_api.is_ip4();
    bool is_ipv6 = p->ptrs.ip_api.is_ip6();

    if (!is_ipv4 && !is_ipv6)
        return;

    // Get protocol type efficiently (cache header pointers)
    uint8_t proto = 0;
    const snort::ip::IP4Hdr *ip4h = nullptr;
    const snort::ip::IP6Hdr *ip6h = nullptr;
    
    if (is_ipv4)
    {
        ip4h = p->ptrs.ip_api.get_ip4h();
        proto = static_cast<uint8_t>(ip4h->proto());
    }
    else if (is_ipv6)
    {
        ip6h = p->ptrs.ip_api.get_ip6h();
        proto = static_cast<uint8_t>(ip6h->next());
    }

    // Only handle TCP/UDP (and optionally ICMP) - quick reject
    if (proto != IPPROTO_TCP && proto != IPPROTO_UDP &&
        (!allow_icmp || (proto != IPPROTO_ICMP && proto != IPPROTO_ICMPV6)))
        return;

    packets_processed.fetch_add(1, std::memory_order_relaxed);
    detection_start_time = std::chrono::steady_clock::now();

    // Extract addresses using optimized caching
    auto [src_ip, dst_ip] = extractAddresses(p);

    // Extract packet data using helper
    PacketData pkt_data = extractPacketData(p, src_ip, dst_ip, packet_size, proto);

    // Analyze packet with improved correlation
    bool stats_anomaly = stats_engine->analyze(pkt_data);
    bool behavior_anomaly = behavior_tracker->inspect(pkt_data);
    bool amplification_detected = detectAmplificationAttack(pkt_data, proto);
    bool fragment_flood = checkForFragmentation(p, src_ip);

    // Update adaptive thresholds periodically (less frequent)
    static std::atomic<uint64_t> threshold_update_counter{0};
    if (threshold_update_counter.fetch_add(1, std::memory_order_relaxed) % 1000 == 0)
    {
        updateAdaptiveThresholds();
    }

    // Enhanced attack classification with confidence scoring
    if (stats_anomaly || behavior_anomaly || amplification_detected || fragment_flood)
    {
        AttackInfo attack_info = classifyAttack(pkt_data, stats_anomaly, behavior_anomaly, proto);

        // Add amplification and fragment detection to confidence
        if (amplification_detected)
        {
            attack_info.confidence += 0.3;
            amplification_detections.fetch_add(1, std::memory_order_relaxed);
        }

        if (fragment_flood)
        {
            attack_info.confidence += 0.4;
            attack_info.type =
                AttackInfo::Type::VOLUME_ATTACK; // Fragment floods are volume attacks
        }

        // Use adaptive confidence calculation (returns value in hundredths: 0-100)
        uint8_t calculated_confidence_hundredths =
            calculateConfidenceScore(pkt_data, stats_anomaly, behavior_anomaly);
        double calculated_confidence = calculated_confidence_hundredths / 100.0;
        attack_info.confidence = std::max(attack_info.confidence, calculated_confidence);

        // Lower confidence threshold for SYN floods since they naturally have zero entropy
        double confidence_threshold = 0.5; // Reduced from 0.7 to 0.5
        if (attack_info.type == AttackInfo::Type::SYN_FLOOD)
        {
            confidence_threshold = 0.4; // Even lower for SYN floods
        }

        if (attack_info.confidence >= confidence_threshold)
        {
            incrementAttackCounter(attack_info.type);

            // Enhanced mitigation with granular options
            if (attack_info.severity >= AttackInfo::Severity::SEVERITY_HIGH)
            {
                int block_duration = calculateBlockDuration(attack_info.severity, attack_info.type);
                firewall_action->block(pkt_data.src_ip, block_duration);
                packets_blocked.fetch_add(1, std::memory_order_relaxed);
                incrementBlockCounter(); // Track block rate

                // Apply additional mitigation for sophisticated attacks
                if (attack_info.type == AttackInfo::Type::SLOWLORIS)
                {
                    firewall_action->apply_tarpit(pkt_data.src_ip);
                }
                else if (attack_info.type == AttackInfo::Type::SYN_FLOOD)
                {
                    firewall_action->send_tcp_reset(pkt_data.src_ip);
                }
            }
            else if (attack_info.severity >= AttackInfo::Severity::SEVERITY_MEDIUM)
            {
                // Rate limit instead of full block for medium severity
                firewall_action->rate_limit(pkt_data.src_ip,
                                            static_cast<int>(attack_info.severity));
                packets_rate_limited.fetch_add(1, std::memory_order_relaxed);
            }
            // Log low severity attacks but don't block
            logAttackDetection(attack_info, pkt_data, stats_anomaly, behavior_anomaly);
        }
    }

    // Track performance metrics
    auto eval_end = std::chrono::steady_clock::now();
    auto processing_time =
        std::chrono::duration_cast<std::chrono::microseconds>(eval_end - eval_start);
    updatePerformanceMetrics(processing_time);
}

AttackInfo DdosInspector::classifyAttack(const PacketData &pkt_data, bool stats_anomaly,
                                         bool behavior_anomaly, uint8_t proto)
{
    AttackInfo attack;
    attack.confidence = 0.0;
    attack.severity = AttackInfo::Severity::SEVERITY_LOW;
    attack.type = AttackInfo::Type::UNKNOWN;

    // Multi-factor analysis for better accuracy
    double behavioral_score = behavior_anomaly ? 0.6 : 0.0;
    double statistical_score = stats_anomaly ? 0.4 : 0.0;

    // Get current stats for classification
    double current_rate = stats_engine ? stats_engine->get_current_rate() : 0.0;
    double current_entropy = stats_engine ? stats_engine->get_entropy() : 1.0;

    if (proto == IPPROTO_TCP)
    {
        if (pkt_data.is_syn && !pkt_data.is_ack)
        {
            attack.type = AttackInfo::Type::SYN_FLOOD;
            attack.confidence = behavioral_score + statistical_score;
            // Higher confidence if both engines detect anomaly
            if (stats_anomaly && behavior_anomaly)
                attack.confidence += 0.2;

            // Determine severity based on rate and volume
            if (current_rate > 100000)
            {
                attack.severity = AttackInfo::Severity::SEVERITY_CRITICAL;
            }
            else if (current_rate > 50000)
            {
                attack.severity = AttackInfo::Severity::SEVERITY_HIGH;
            }
            else
            {
                attack.severity = AttackInfo::Severity::SEVERITY_MEDIUM;
            }
        }
        else if (pkt_data.is_http)
        {
            // Distinguish between HTTP flood and Slowloris
            size_t connection_count = behavior_tracker->get_connection_count();

            if (connection_count > 1000 && current_rate < 10000)
            {
                attack.type = AttackInfo::Type::SLOWLORIS;
                attack.confidence =
                    behavioral_score + 0.3; // Behavioral detection more important for Slowloris
            }
            else
            {
                attack.type = AttackInfo::Type::HTTP_FLOOD;
                attack.confidence = behavioral_score + statistical_score + 0.1;
            }
            attack.severity = (connection_count > 5000) ? AttackInfo::Severity::SEVERITY_HIGH
                                                        : AttackInfo::Severity::SEVERITY_MEDIUM;
        }
        else if (pkt_data.is_ack && !pkt_data.is_syn)
        {
            attack.type = AttackInfo::Type::ACK_FLOOD;
            attack.confidence = behavioral_score + statistical_score;
            attack.severity = AttackInfo::Severity::SEVERITY_MEDIUM;
        }
        else
        {
            // Fallback: High-rate, low-entropy TCP traffic likely SYN flood
            if (behavior_anomaly && current_rate > 20000 && current_entropy < 0.5 &&
                pkt_data.size >= 40 && pkt_data.size <= 60)
            {
                attack.type = AttackInfo::Type::SYN_FLOOD;
                attack.confidence = behavioral_score + 0.2; // High confidence for this pattern
                if (current_rate > 50000)
                {
                    attack.severity = AttackInfo::Severity::SEVERITY_HIGH;
                }
                else
                {
                    attack.severity = AttackInfo::Severity::SEVERITY_MEDIUM;
                }
            }
        }
    }
    else if (proto == IPPROTO_UDP)
    {
        attack.type = AttackInfo::Type::UDP_FLOOD;
        attack.confidence = behavioral_score + statistical_score;
        attack.severity = (current_rate > 75000) ? AttackInfo::Severity::SEVERITY_HIGH
                                                 : AttackInfo::Severity::SEVERITY_MEDIUM;
    }
    else if (proto == IPPROTO_ICMP)
    {
        attack.type = AttackInfo::Type::ICMP_FLOOD;
        attack.confidence = statistical_score + 0.3; // ICMP floods are primarily volume-based
        attack.severity = AttackInfo::Severity::SEVERITY_MEDIUM;
    }
    else
    {
        // Protocol-agnostic fallback for unknown protocols
        if (behavior_anomaly && current_rate > 30000 && current_entropy < 1.0)
        {
            if (pkt_data.size >= 40 && pkt_data.size <= 60)
            {
                // Small packets, likely SYN flood
                attack.type = AttackInfo::Type::SYN_FLOOD;
                attack.confidence = behavioral_score;
                attack.severity = (current_rate > 50000) ? AttackInfo::Severity::SEVERITY_HIGH
                                                         : AttackInfo::Severity::SEVERITY_MEDIUM;
            }
            else if (pkt_data.size > 200)
            {
                // Larger packets, likely volume attack
                attack.type = AttackInfo::Type::VOLUME_ATTACK;
                attack.confidence = behavioral_score;
                attack.severity = AttackInfo::Severity::SEVERITY_MEDIUM;
            }
        }
    }

    // Check for advanced attack patterns detected by behavior tracker
    if (behavior_anomaly && behavior_tracker)
    {
        auto detected_patterns = behavior_tracker->getLastDetectedPatterns();

        // Prioritize advanced patterns (they override basic classifications)
        for (const std::string &pattern : detected_patterns)
        {
            if (pattern == "PULSE_ATTACK")
            {
                attack.type = AttackInfo::Type::PULSE_ATTACK;
                attack.confidence = 0.9; // High confidence for sophisticated attacks
                attack.severity = AttackInfo::Severity::SEVERITY_HIGH;
                break;
            }
            else if (pattern == "PROTOCOL_MIXING")
            {
                attack.type = AttackInfo::Type::PROTOCOL_MIXING;
                attack.confidence = 0.8;
                attack.severity = AttackInfo::Severity::SEVERITY_HIGH;
                break;
            }
            else if (pattern == "GEO_DISTRIBUTED")
            {
                attack.type = AttackInfo::Type::GEO_DISTRIBUTED;
                attack.confidence = 0.95; // Very high confidence
                attack.severity = AttackInfo::Severity::SEVERITY_CRITICAL;
                break;
            }
            else if (pattern == "LOW_AND_SLOW")
            {
                attack.type = AttackInfo::Type::LOW_AND_SLOW;
                attack.confidence = 0.85;
                attack.severity = AttackInfo::Severity::SEVERITY_HIGH;
                break;
            }
            else if (pattern == "RANDOMIZED_PAYLOADS")
            {
                attack.type = AttackInfo::Type::RANDOMIZED_PAYLOADS;
                attack.confidence = 0.7;
                attack.severity = AttackInfo::Severity::SEVERITY_MEDIUM;
                break;
            }
            else if (pattern == "LEGITIMATE_MIXING")
            {
                attack.type = AttackInfo::Type::LEGITIMATE_MIXING;
                attack.confidence = 0.9;
                attack.severity = AttackInfo::Severity::SEVERITY_CRITICAL;
                break;
            }
            else if (pattern == "DYNAMIC_ROTATION")
            {
                attack.type = AttackInfo::Type::DYNAMIC_ROTATION;
                attack.confidence = 0.8;
                attack.severity = AttackInfo::Severity::SEVERITY_HIGH;
                break;
            }
        }

        // Don't clear patterns immediately - let them persist for consistent classification
        // Patterns will be naturally updated on the next behavior analysis cycle
    }

    return attack;
}

void DdosInspector::incrementAttackCounter(AttackInfo::Type type)
{
    switch (type)
    {
    case AttackInfo::Type::SYN_FLOOD:
        syn_flood_detections.fetch_add(1, std::memory_order_relaxed);
        break;
    case AttackInfo::Type::HTTP_FLOOD:
        http_flood_detections.fetch_add(1, std::memory_order_relaxed);
        break;
    case AttackInfo::Type::SLOWLORIS:
        slowloris_detections.fetch_add(1, std::memory_order_relaxed);
        break;
    case AttackInfo::Type::UDP_FLOOD:
        udp_flood_detections.fetch_add(1, std::memory_order_relaxed);
        break;
    case AttackInfo::Type::ICMP_FLOOD:
        icmp_flood_detections.fetch_add(1, std::memory_order_relaxed);
        break;
    case AttackInfo::Type::DNS_AMPLIFICATION:
    case AttackInfo::Type::NTP_AMPLIFICATION:
    case AttackInfo::Type::REFLECTION_ATTACK:
        amplification_detections.fetch_add(1, std::memory_order_relaxed);
        break;
    case AttackInfo::Type::PULSE_ATTACK:
    case AttackInfo::Type::PROTOCOL_MIXING:
    case AttackInfo::Type::GEO_DISTRIBUTED:
    case AttackInfo::Type::LOW_AND_SLOW:
    case AttackInfo::Type::RANDOMIZED_PAYLOADS:
    case AttackInfo::Type::LEGITIMATE_MIXING:
    case AttackInfo::Type::DYNAMIC_ROTATION:
    case AttackInfo::Type::VOLUME_ATTACK:
    case AttackInfo::Type::ACK_FLOOD:
        // Advanced attacks - could add separate counters if needed
        break;
    case AttackInfo::Type::UNKNOWN:
    default:
        // Unknown attack types - no specific counter
        break;
    }
}

int DdosInspector::calculateBlockDuration(AttackInfo::Severity severity, AttackInfo::Type type)
{
    // Base durations in seconds
    int base_duration = 600; // 10 minutes default

    // Severity multipliers
    switch (severity)
    {
    case AttackInfo::Severity::SEVERITY_LOW:
        base_duration = 300; // 5 minutes
        break;
    case AttackInfo::Severity::SEVERITY_MEDIUM:
        base_duration = 600; // 10 minutes
        break;
    case AttackInfo::Severity::SEVERITY_HIGH:
        base_duration = 1800; // 30 minutes
        break;
    case AttackInfo::Severity::SEVERITY_CRITICAL:
        base_duration = 3600; // 1 hour
        break;
    default:
        // Unknown severity level - use default duration
        break;
    }

    // Attack type adjustments
    switch (type)
    {
    case AttackInfo::Type::SYN_FLOOD:
    case AttackInfo::Type::UDP_FLOOD:
        // Volume attacks get longer blocks
        base_duration = static_cast<int>(base_duration * 1.5);
        break;
    case AttackInfo::Type::SLOWLORIS:
        // Sophisticated attacks get much longer blocks
        base_duration = static_cast<int>(base_duration * 2.0);
        break;
    case AttackInfo::Type::HTTP_FLOOD:
        // Standard duration
        break;
    default:
        break;
    }

    return base_duration;
}

double DdosInspector::calculateBlockRate() const
{
    auto now = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - block_rate_start_time);
    
    if (duration.count() > 0) {
        return static_cast<double>(total_blocks_issued.load()) / duration.count();
    }
    
    return 0.0;
}

void DdosInspector::logAttackDetection(const AttackInfo &attack_info, const PacketData &pkt_data,
                                       bool stats_anomaly, bool behavior_anomaly)
{
    // Enhanced logging with detailed attack information
    std::string attack_type_str;
    switch (attack_info.type)
    {
    case AttackInfo::Type::SYN_FLOOD:
        attack_type_str = "SYN_FLOOD";
        break;
    case AttackInfo::Type::HTTP_FLOOD:
        attack_type_str = "HTTP_FLOOD";
        break;
    case AttackInfo::Type::SLOWLORIS:
        attack_type_str = "SLOWLORIS";
        break;
    case AttackInfo::Type::ACK_FLOOD:
        attack_type_str = "ACK_FLOOD";
        break;
    case AttackInfo::Type::UDP_FLOOD:
        attack_type_str = "UDP_FLOOD";
        break;
    case AttackInfo::Type::ICMP_FLOOD:
        attack_type_str = "ICMP_FLOOD";
        break;
    case AttackInfo::Type::VOLUME_ATTACK:
        attack_type_str = "VOLUME_ATTACK";
        break;
    case AttackInfo::Type::DNS_AMPLIFICATION:
        attack_type_str = "DNS_AMPLIFICATION";
        break;
    case AttackInfo::Type::NTP_AMPLIFICATION:
        attack_type_str = "NTP_AMPLIFICATION";
        break;
    case AttackInfo::Type::REFLECTION_ATTACK:
        attack_type_str = "REFLECTION_ATTACK";
        break;
    case AttackInfo::Type::PULSE_ATTACK:
        attack_type_str = "PULSE_ATTACK";
        break;
    case AttackInfo::Type::PROTOCOL_MIXING:
        attack_type_str = "PROTOCOL_MIXING";
        break;
    case AttackInfo::Type::GEO_DISTRIBUTED:
        attack_type_str = "GEO_DISTRIBUTED";
        break;
    case AttackInfo::Type::LOW_AND_SLOW:
        attack_type_str = "LOW_AND_SLOW";
        break;
    case AttackInfo::Type::RANDOMIZED_PAYLOADS:
        attack_type_str = "RANDOMIZED_PAYLOADS";
        break;
    case AttackInfo::Type::LEGITIMATE_MIXING:
        attack_type_str = "LEGITIMATE_MIXING";
        break;
    case AttackInfo::Type::DYNAMIC_ROTATION:
        attack_type_str = "DYNAMIC_ROTATION";
        break;
    default:
        attack_type_str = "UNKNOWN";
        break;
    }

    std::string severity_str;
    switch (attack_info.severity)
    {
    case AttackInfo::Severity::SEVERITY_LOW:
        severity_str = "LOW";
        break;
    case AttackInfo::Severity::SEVERITY_MEDIUM:
        severity_str = "MEDIUM";
        break;
    case AttackInfo::Severity::SEVERITY_HIGH:
        severity_str = "HIGH";
        break;
    case AttackInfo::Severity::SEVERITY_CRITICAL:
        severity_str = "CRITICAL";
        break;
    default:
        severity_str = "UNKNOWN";
        break;
    }

    std::stringstream attack_msg;
    attack_msg << "[ATTACK DETECTED] Type: " << attack_type_str 
               << " | Severity: " << severity_str
               << " | Confidence: " << std::fixed << std::setprecision(2) << attack_info.confidence
               << " | Source: " << pkt_data.src_ip << " | Target: " << pkt_data.dst_ip
               << " | Size: " << pkt_data.size << " bytes";

    if (stats_engine)
    {
        attack_msg << " | Rate: " << std::fixed << std::setprecision(0)
                   << stats_engine->get_current_rate() << " pps"
                   << " | Entropy: " << std::fixed << std::setprecision(2)
                   << stats_engine->get_entropy();
    }

    if (behavior_tracker)
    {
        attack_msg << " | Connections: " << behavior_tracker->get_connection_count();
    }

    attack_msg << " | Triggers: ";
    if (stats_anomaly)
        attack_msg << "STATS ";
    if (behavior_anomaly)
        attack_msg << "BEHAVIOR ";

    // Use appropriate logging level based on severity
    switch (attack_info.severity)
    {
    case AttackInfo::Severity::SEVERITY_LOW:
        DDosLogger::info(attack_msg.str());
        break;
    case AttackInfo::Severity::SEVERITY_MEDIUM:
        DDosLogger::warning(attack_msg.str());
        break;
    case AttackInfo::Severity::SEVERITY_HIGH:
    case AttackInfo::Severity::SEVERITY_CRITICAL:
        DDosLogger::error(attack_msg.str());
        break;
    default:
        DDosLogger::info(attack_msg.str());
        break;
    }

    // Also log to syslog if available (basic implementation)
    // In a production environment, you'd want more sophisticated logging
    // using proper syslog facilities or centralized logging systems
}

void DdosInspector::updatePerformanceMetrics(std::chrono::microseconds processing_time)
{
    // Update total processing time
    total_processing_time_us.fetch_add(processing_time.count());

    // Update maximum processing time with improved backoff strategy
    uint64_t current_max = max_processing_time_us.load();
    uint64_t new_time = processing_time.count();

    if (new_time > current_max) {
        // Try a limited number of CAS attempts with exponential backoff
        int attempts = 0;
        const int max_attempts = 3;
        
        while (new_time > current_max &&
               !max_processing_time_us.compare_exchange_weak(current_max, new_time) &&
               attempts < max_attempts)
        {
            // Exponential backoff with sleep to reduce cache-line contention
            std::this_thread::sleep_for(std::chrono::nanoseconds(1 << attempts));
            attempts++;
        }
    }
}

void DdosInspector::updateAdaptiveThresholds()
{
    auto now = std::chrono::steady_clock::now();
    auto duration =
        std::chrono::duration_cast<std::chrono::minutes>(now - adaptive_thresholds.last_update);

    // Update thresholds every 10 minutes
    if (duration.count() >= 10)
    {
        // DEADLOCK FIX: Use timeout-based locking and avoid nested locks
        try {
            TimeoutLockGuard<std::mutex> lock(metrics_mutex, std::chrono::milliseconds(500));

            // Update baseline entropy and rate based on recent observations
            if (stats_engine)
            {
                double current_entropy = stats_engine->get_entropy();
                double current_rate = stats_engine->get_current_rate();

                // Gradually adapt baselines using EWMA with configurable factor
                adaptive_thresholds.baseline_entropy =
                    g_threshold_tuning.adaptation_factor * current_entropy +
                    (1.0 - g_threshold_tuning.adaptation_factor) * adaptive_thresholds.baseline_entropy;

                adaptive_thresholds.baseline_rate =
                    g_threshold_tuning.adaptation_factor * current_rate +
                    (1.0 - g_threshold_tuning.adaptation_factor) * adaptive_thresholds.baseline_rate;

                // Adjust detection thresholds based on baselines with configurable multipliers
                adaptive_thresholds.entropy_threshold =
                    std::max(g_threshold_tuning.min_entropy_threshold, 
                            adaptive_thresholds.baseline_entropy * g_threshold_tuning.entropy_multiplier);

                adaptive_thresholds.rate_threshold =
                    std::max(g_threshold_tuning.min_rate_threshold, 
                            adaptive_thresholds.baseline_rate * g_threshold_tuning.rate_multiplier);
            }

            // Update behavioral thresholds based on behavior tracker metrics
            if (behavior_tracker && g_threshold_tuning.enable_adaptive_behavioral_thresholds)
            {
                // Get current behavioral rates
                double current_syn_rate = behavior_tracker->getGlobalSynRate();
                double current_ack_rate = behavior_tracker->getGlobalAckRate();
                double current_http_rate = behavior_tracker->getGlobalHttpRate();

                // Update baseline behavioral rates using EWMA
                adaptive_thresholds.baseline_syn_rate =
                    g_threshold_tuning.adaptation_factor * current_syn_rate +
                    (1.0 - g_threshold_tuning.adaptation_factor) * adaptive_thresholds.baseline_syn_rate;

                adaptive_thresholds.baseline_ack_rate =
                    g_threshold_tuning.adaptation_factor * current_ack_rate +
                    (1.0 - g_threshold_tuning.adaptation_factor) * adaptive_thresholds.baseline_ack_rate;

                adaptive_thresholds.baseline_http_rate =
                    g_threshold_tuning.adaptation_factor * current_http_rate +
                    (1.0 - g_threshold_tuning.adaptation_factor) * adaptive_thresholds.baseline_http_rate;

                // Update adaptive behavioral thresholds with multipliers and minimums
                adaptive_thresholds.syn_flood_threshold =
                    std::max(g_threshold_tuning.min_syn_flood_threshold,
                            adaptive_thresholds.baseline_syn_rate * g_threshold_tuning.syn_flood_multiplier);

                adaptive_thresholds.ack_flood_threshold =
                    std::max(g_threshold_tuning.min_ack_flood_threshold,
                            adaptive_thresholds.baseline_ack_rate * g_threshold_tuning.ack_flood_multiplier);

                adaptive_thresholds.http_flood_threshold =
                    std::max(g_threshold_tuning.min_http_flood_threshold,
                            adaptive_thresholds.baseline_http_rate * g_threshold_tuning.http_flood_multiplier);
            }

            adaptive_thresholds.last_update = now;
        } catch (const std::runtime_error& e) {
            // Timeout occurred - skip this update to prevent deadlock
            DDosLogger::warning("Adaptive threshold update skipped due to lock timeout");
            return;
        }
    }
}

uint8_t DdosInspector::calculateConfidenceScore(const PacketData &pkt_data, bool stats_anomaly,
                                               bool behavior_anomaly)
{
    double confidence = 0.0;

    // Base confidence from detection engines using configurable values
    if (stats_anomaly)
        confidence += g_threshold_tuning.confidence_base_stats;
    if (behavior_anomaly)
        confidence += g_threshold_tuning.confidence_base_behavior;

    // Additional confidence modifiers
    double extra_confidence = 0.0;
    
    // Calculate rate ratio if we have stats engine data
    if (stats_engine) {
        double current_rate = stats_engine->get_current_rate();
        double baseline_rate = adaptive_thresholds.baseline_rate;
        double rate_ratio = current_rate / std::max(baseline_rate, g_threshold_tuning.min_rate_threshold);
        if (rate_ratio > g_threshold_tuning.rate_ratio_high_threshold) {
            extra_confidence += g_threshold_tuning.confidence_rate_high_bonus;
        } else if (rate_ratio > g_threshold_tuning.rate_ratio_med_threshold) {
            extra_confidence += g_threshold_tuning.confidence_rate_med_bonus;
        }
        
        // Calculate entropy ratio
        double current_entropy = stats_engine->get_entropy();
        double entropy_ratio = current_entropy / std::max(adaptive_thresholds.baseline_entropy, g_threshold_tuning.min_entropy_threshold);
        if (entropy_ratio > g_threshold_tuning.entropy_ratio_high_threshold) {
            extra_confidence += g_threshold_tuning.confidence_entropy_high_bonus;
        } else if (entropy_ratio > g_threshold_tuning.entropy_ratio_med_threshold) {
            extra_confidence += g_threshold_tuning.confidence_entropy_med_bonus;
        }
    }

    // SYN flood bonus
    if (pkt_data.is_syn && !pkt_data.is_ack) {
        extra_confidence += g_threshold_tuning.confidence_syn_bonus;
    }

    // Short HTTP request bonus (potential attack)
    if (pkt_data.is_http && pkt_data.payload.length() < 100) {
        extra_confidence += g_threshold_tuning.confidence_http_short_bonus;
    }

    confidence += extra_confidence;
    
    // Clamp to valid range and convert to percentage (0-100)
    return static_cast<uint8_t>(std::min(100.0, std::max(0.0, confidence * 100.0)));
}

// NEW: Runtime testing mode management methods
void DdosInspector::setRuntimeTestingMode(bool enabled) {
    g_threshold_tuning.setRuntimeTestingMode(enabled);
    
    // Force threshold recalculation
    reloadAdaptiveThresholds();
    
    DDosLogger::info(enabled ? "Runtime testing mode enabled" : "Runtime testing mode disabled");
}

bool DdosInspector::isRuntimeTestingMode() const {
    return g_threshold_tuning.isRuntimeTestingMode();
}

void DdosInspector::reloadAdaptiveThresholds() {
    std::lock_guard<std::mutex> lock(metrics_mutex);
    
    // Force immediate threshold update
    auto now = std::chrono::steady_clock::now();
    adaptive_thresholds.last_update = now - std::chrono::minutes(11); // Force update on next call
    
    // Update thresholds immediately
    updateAdaptiveThresholds();
    
    DDosLogger::info("Adaptive thresholds reloaded with current configuration");
}

bool DdosInspector::detectAmplificationAttack(const PacketData &pkt_data, uint8_t proto)
{
    if (proto != IPPROTO_UDP)
    {
        return false; // Amplification attacks are primarily UDP-based
    }

    // Use global thread-safe tracker
    bool rate_exceeded = getAmplificationTracker().checkAndUpdate(pkt_data.src_ip);

    // More strict criteria to reduce false positives
    bool potential_amplification = false;

    // DNS amplification detection (port 53)
    if (pkt_data.dst_port == 53 && pkt_data.size > 512)
    {
        // Check for DNS query patterns that indicate amplification potential
        if (!pkt_data.payload_view.empty() && pkt_data.payload_view.size() >= 12)
        {
            // Safe binary search in payload view
            const char dns_any_pattern[] = "\x00\xFF\x00\x01";
            auto payload_data = reinterpret_cast<const uint8_t*>(pkt_data.payload_view.data());
            
            // Search for DNS ANY record type pattern
            bool found_any_pattern = false;
            for (size_t i = 0; i <= pkt_data.payload_view.size() - 4; ++i)
            {
                if (std::memcmp(payload_data + i, dns_any_pattern, 4) == 0)
                {
                    found_any_pattern = true;
                    break;
                }
            }
            
            if (found_any_pattern)
            {
                potential_amplification = true;
            }
            // Check for long domain names that suggest reflection abuse
            else if (pkt_data.payload_view.size() > 100)
            {
                potential_amplification = true;
            }
        }
    }

    // NTP amplification detection (port 123)
    else if (pkt_data.dst_port == 123 && pkt_data.size > 200)
    {
        // NTP monlist requests are smaller but generate large responses
        if (!pkt_data.payload_view.empty() && pkt_data.payload_view.size() >= 8)
        {
            // Look for NTP mode 6 (control) or mode 7 (private) requests
            auto payload_data = reinterpret_cast<const uint8_t*>(pkt_data.payload_view.data());
            uint8_t mode = payload_data[0] & 0x07;
            if (mode == 6 || mode == 7)
            {
                potential_amplification = true;
            }
        }
    }

    // SSDP amplification (port 1900)
    else if (pkt_data.dst_port == 1900 && pkt_data.size > 150)
    {
        if (pkt_data.payload_view.find("M-SEARCH") != std::string_view::npos)
        {
            potential_amplification = true;
        }
    }

    // Only return true if we have both: potential amplification pattern AND rate exceeded
    return potential_amplification && rate_exceeded;
}

bool DdosInspector::detectFragmentFlood(const std::string &src_ip)
{
    // Use global thread-safe fragment tracker
    return getFragmentTracker().checkFragmentFlood(src_ip);
}

void DdosInspector::startMetricsThread()
{
    metrics_running.store(true, std::memory_order_release);
    metrics_thread = std::thread(
        [this]()
        {
            int consecutive_errors = 0;
            const int max_consecutive_errors = 5;
            
            while (metrics_running.load(std::memory_order_acquire))
            {
                // Check if inspector is still valid
                if (g_inspector_instance.load(std::memory_order_acquire) != this)
                {
                    break; // Inspector was destroyed, exit thread
                }
                
                try
                {
                    writeMetrics();
                    consecutive_errors = 0; // Reset on success
                }
                catch (const std::filesystem::filesystem_error& e)
                {
                    DDosLogger::error("Metrics thread filesystem error: " + std::string(e.what()));
                    consecutive_errors++;
                }
                catch (const std::system_error& e)
                {
                    DDosLogger::error("Metrics thread system error: " + std::string(e.what()));
                    consecutive_errors++;
                }
                catch (const std::bad_alloc& e)
                {
                    DDosLogger::error("Metrics thread memory allocation error: " + std::string(e.what()));
                    // Memory issues are critical - terminate after logging
                    std::terminate();
                }
                catch (const std::exception& e)
                {
                    DDosLogger::error("Metrics thread unexpected error: " + std::string(e.what()));
                    consecutive_errors++;
                }
                catch (...)
                {
                    DDosLogger::error("Metrics thread unknown error occurred");
                    consecutive_errors++;
                }
                
                // Back off on consecutive errors
                if (consecutive_errors > 0)
                {
                    if (consecutive_errors >= max_consecutive_errors)
                    {
                        DDosLogger::error("Too many consecutive metrics errors, stopping metrics thread");
                        metrics_running.store(false, std::memory_order_release);
                        break;
                    }
                    
                    // Exponential backoff with jitter
                    auto backoff_ms = std::min(1000 * (1 << consecutive_errors), 30000);
                    try
                    {
                        std::this_thread::sleep_for(std::chrono::milliseconds(backoff_ms));
                    }
                    catch (...)
                    {
                        std::terminate();
                    }
                }
                else
                {
                    // Normal sleep interval
                    try
                    {
                        std::this_thread::sleep_for(5s);
                    }
                    catch (...)
                    {
                        std::terminate();
                    }
                }
            }
        });
}

void DdosInspector::stopMetricsThread()
{
    metrics_running.store(false, std::memory_order_release);
    if (metrics_thread.joinable())
    {
        metrics_thread.join();
    }
}

// NOTE: File writing methods removed - now handled by FileLogger

// LRU cache implementation for rate-limited IPs with TTL-based cleanup
void DdosInspector::cleanupExpiredRateLimitedIPs()
{
    std::lock_guard<std::mutex> lock(rate_limited_cache_mutex);
    auto now = std::chrono::steady_clock::now();
    
    // Remove entries older than 24 hours
    auto it = rate_limited_cache.begin();
    while (it != rate_limited_cache.end()) {
        auto age = std::chrono::duration_cast<std::chrono::hours>(now - it->second);
        if (age.count() >= 24) {
            // Remove from LRU tracking
            auto lru_it = rate_limited_lru_map.find(it->first);
            if (lru_it != rate_limited_lru_map.end()) {
                rate_limited_lru_list.erase(lru_it->second);
                rate_limited_lru_map.erase(lru_it);
            }
            it = rate_limited_cache.erase(it);
        } else {
            ++it;
        }
    }
}

void DdosInspector::addToRateLimitedCache(const std::string& ip)
{
    std::lock_guard<std::mutex> lock(rate_limited_cache_mutex);
    auto now = std::chrono::steady_clock::now();
    
    // Check if IP already exists
    auto cache_it = rate_limited_cache.find(ip);
    if (cache_it != rate_limited_cache.end()) {
        // Update timestamp and move to front of LRU
        cache_it->second = now;
               auto lru_it = rate_limited_lru_map.find(ip);
        if (lru_it != rate_limited_lru_map.end()) {
            rate_limited_lru_list.erase(lru_it->second);
            rate_limited_lru_list.push_front(ip);
            lru_it->second = rate_limited_lru_list.begin();
        }
        return;
    }
 
    
    // Enforce cache size limit
    if (rate_limited_cache.size() >= MAX_RATE_LIMITED_ENTRIES) {
        // Remove oldest entry
        if (!rate_limited_lru_list.empty()) {
            const std::string& oldest_ip = rate_limited_lru_list.back();
            rate_limited_cache.erase(oldest_ip);
            rate_limited_lru_map.erase(oldest_ip);
            rate_limited_lru_list.pop_back();
        }
    }
    
    // Add new entry
    rate_limited_cache[ip] = now;
    rate_limited_lru_list.push_front(ip);
    rate_limited_lru_map[ip] = rate_limited_lru_list.begin();
}

std::vector<std::string> DdosInspector::getRateLimitedIpsFromCache()
{
    std::lock_guard<std::mutex> lock(rate_limited_cache_mutex);
    std::vector<std::string> result;
    auto now = std::chrono::steady_clock::now();
    
    for (const auto& [ip, timestamp] : rate_limited_cache) {
        auto age = std::chrono::duration_cast<std::chrono::minutes>(now - timestamp);
        result.push_back(ip + " (added " + std::to_string(age.count()) + "m ago)");
    }
    
    return result;
}

// Address caching implementation for performance optimization
std::string DdosInspector::getIPv4String(uint32_t addr)
{
    std::lock_guard<std::mutex> lock(address_cache_mutex);
    auto it = ipv4_cache.find(addr);
    if (it != ipv4_cache.end())
    {
        return it->second;
    }

    char buffer[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &addr, buffer, sizeof(buffer)))
    {
        std::string addr_str(buffer);
        // Keep cache size bounded
        if (ipv4_cache.size() >= 1000)
        {
            ipv4_cache.clear();
        }
        ipv4_cache[addr] = addr_str;
        return addr_str;
    }

    return "0.0.0.0"; // Fallback for errors
}

std::string DdosInspector::getIPv6String(const snort::ip::snort_in6_addr *addr)
{
    std::lock_guard<std::mutex> lock(address_cache_mutex);

    // Create a stable binary key by copying the address bytes
    std::array<uint8_t, 16> addr_bytes;
    std::memcpy(addr_bytes.data(), addr, 16);
    
    // Use the array as a map key (requires custom hash)
    auto it = ipv6_cache.find(addr_bytes);
    if (it != ipv6_cache.end())
    {
        return it->second;
    }

    char buffer[INET6_ADDRSTRLEN];
    if (inet_ntop(AF_INET6, addr, buffer, sizeof(buffer)))
    {
        std::string addr_str(buffer);
        // Keep cache size bounded
        if (ipv6_cache.size() >= 1000)
        {
            ipv6_cache.clear();
        }
        ipv6_cache[addr_bytes] = addr_str;
        return addr_str;
    }

    return "::"; // Fallback for errors
}

// NOTE: writeMetricsToFile method removed - now handled by FileLogger

// Protocol parsing helpers to reduce eval() function size
std::pair<std::string, std::string> DdosInspector::extractAddresses(snort::Packet *p)
{
    std::string src_ip, dst_ip;

    if (p->ptrs.ip_api.is_ip4())
    {
        const snort::ip::IP4Hdr *ip4h = p->ptrs.ip_api.get_ip4h();
        uint32_t src_addr = ip4h->get_src();
        uint32_t dst_addr = ip4h->get_dst();
        src_ip = getIPv4String(src_addr);
        dst_ip = getIPv4String(dst_addr);
    }
    else if (p->ptrs.ip_api.is_ip6())
    {
        const snort::ip::IP6Hdr *ip6h = p->ptrs.ip_api.get_ip6h();
        const snort::ip::snort_in6_addr *src_addr = ip6h->get_src();
        const snort::ip::snort_in6_addr *dst_addr = ip6h->get_dst();
        src_ip = getIPv6String(src_addr);
        dst_ip = getIPv6String(dst_addr);
    }

    return {src_ip, dst_ip};
}

PacketData DdosInspector::extractPacketData(snort::Packet *p, const std::string &src_ip,
                                            const std::string &dst_ip, uint32_t packet_size, uint8_t protocol)
{
    PacketData pkt_data;
    pkt_data.src_ip = src_ip;
    pkt_data.dst_ip = dst_ip;
    pkt_data.protocol = protocol;
    
    // Use cached packet size for performance if provided, otherwise calculate
    pkt_data.size = packet_size > 0 ? packet_size : static_cast<uint32_t>(p->dsize);
    
    pkt_data.src_port = 0;
    pkt_data.dst_port = 0;
    pkt_data.is_syn = false;
    pkt_data.is_ack = false;
    pkt_data.is_http = false;
    
    // NEW: Detect multicast/broadcast traffic
    pkt_data.is_multicast = false;
    pkt_data.is_broadcast = false;
    
    // Check for multicast/broadcast destination
    if (!dst_ip.empty()) {
        // IPv4 checks
        if (dst_ip.find('.') != std::string::npos) {
            struct sockaddr_in sa4;
            if (inet_pton(AF_INET, dst_ip.c_str(), &sa4.sin_addr) == 1) {
                uint32_t addr = ntohl(sa4.sin_addr.s_addr);
                
                // Broadcast address
                if (addr == 0xFFFFFFFF) {
                    pkt_data.is_broadcast = true;
                }
                // Multicast range (224.0.0.0 to 239.255.255.255)
                else if ((addr >= 0xE0000000) && (addr <= 0xEFFFFFFF)) {
                    pkt_data.is_multicast = true;
                }
                // Limited broadcast (ends with .255)
                else if ((addr & 0xFF) == 0xFF) {
                    pkt_data.is_broadcast = true;
                }
            }
        }
        // IPv6 checks
        else if (dst_ip.find(':') != std::string::npos) {
            struct sockaddr_in6 sa6;
            if (inet_pton(AF_INET6, dst_ip.c_str(), &sa6.sin6_addr) == 1) {
                // Multicast (starts with ff)
                if (sa6.sin6_addr.s6_addr[0] == 0xff) {
                    pkt_data.is_multicast = true;
                }
            }
        }
    }

    // Extract TCP/UDP port information
    if (p->ptrs.tcph)
    {
        pkt_data.src_port = ntohs(p->ptrs.tcph->th_sport);
        pkt_data.dst_port = ntohs(p->ptrs.tcph->th_dport);
        pkt_data.is_syn = (p->ptrs.tcph->th_flags & TH_SYN) != 0;
        pkt_data.is_ack = (p->ptrs.tcph->th_flags & TH_ACK) != 0;
    }
    else if (p->ptrs.udph)
    {
        pkt_data.src_port = ntohs(p->ptrs.udph->uh_sport);
        pkt_data.dst_port = ntohs(p->ptrs.udph->uh_dport);
    }

    // Defer payload copying for hot-path optimization
    if (p->data && p->dsize > 0)
    {
        // Store string_view pointing to packet data - no copying yet
        pkt_data.payload_view = std::string_view(
            static_cast<const char *>(static_cast<const void *>(p->data)), p->dsize);
        
        // Simple HTTP detection using string_view (no allocation)
        if (pkt_data.payload_view.find("HTTP/") != std::string_view::npos ||
            pkt_data.payload_view.starts_with("GET ") || 
            pkt_data.payload_view.starts_with("POST "))
        {
            pkt_data.is_http = true;
        }
    }

    return pkt_data;
}

bool DdosInspector::checkForFragmentation(snort::Packet *p, const std::string &src_ip)
{
    if (!p || !p->ptrs.ip_api.is_ip())
    {
        return false;
    }

    // Check for IP fragmentation in IPv4
    if (p->ptrs.ip_api.is_ip4())
    {
        const snort::ip::IP4Hdr *ip4h = p->ptrs.ip_api.get_ip4h();
        uint16_t flags_and_offset = ntohs(ip4h->off_w_flags());
        bool more_fragments = (flags_and_offset & 0x2000) != 0;
        uint16_t fragment_offset = flags_and_offset & 0x1FFF;

        // Detect suspicious fragmentation patterns
        if (more_fragments || fragment_offset > 0)
        {
            return getFragmentTracker().checkFragmentFlood(src_ip);
        }
    }

    return false;
}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module *mod_ctor()
{
    return new DdosInspectorModule;
}

static void mod_dtor(Module *m)
{
    delete m;
}

static Inspector *ddos_ctor(Module *m)
{
    DdosInspectorModule *mod = dynamic_cast<DdosInspectorModule *>(m);
    return new DdosInspector(mod);
}

static void ddos_dtor(Inspector *p)
{
    delete p;
}

static const InspectApi ddos_api = {
    {PT_INSPECTOR, sizeof(InspectApi), INSAPI_VERSION, 0, API_RESERVED, API_OPTIONS, DDOS_NAME,
     DDOS_HELP, mod_ctor, mod_dtor},
    IT_PACKET, // Changed from IT_PROBE to IT_PACKET
    PROTO_BIT__ANY_IP,
    nullptr, // buffers
    nullptr, // service
    nullptr, // pinit
    nullptr, // pterm
    nullptr, // tinit
    nullptr, // tterm
    ddos_ctor,
    ddos_dtor,
    nullptr, // ssn
    nullptr  // reset
};

//-------------------------------------------------------------------------
// plugin
//-------------------------------------------------------------------------

SO_PUBLIC const BaseApi *snort_plugins[] = {&ddos_api.base, nullptr};