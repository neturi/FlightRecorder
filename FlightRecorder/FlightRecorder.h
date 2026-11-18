// FlightRecorder.h : Include file for standard system include files,
// or project specific include files.

#pragma once
#include <chrono>
#include <cstddef>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace flightrecorder {

enum class EvidenceKind { Log, Progress, Metric, Failure, KernelSample };

enum class MonitoringKind { Network, DiskIo, Cpu, SystemHang, Other };

struct MonitoringEvent {
	std::chrono::system_clock::time_point time;
	MonitoringKind kind = MonitoringKind::Other;
	std::string severity;
	std::string source;
	std::string message;
};

struct Evidence {
	std::chrono::system_clock::time_point time;
	EvidenceKind kind;
	std::string component;
	std::string message;
	std::size_t bytes() const noexcept;
};

struct Limits {
	std::size_t max_events = 256;
	std::size_t max_bytes = 64 * 1024; // 64k bytes
	std::chrono::seconds heartbeat_timeout{30};
	std::chrono::seconds post_failure_window{5};
};

struct Incident {
	std::string id;
	std::chrono::system_clock::time_point detected_at;
	std::string reason;
	std::vector<Evidence> before;
	std::vector<Evidence> during;
	std::vector<Evidence> after;
};

struct FollowUpRequest {
	std::string incident_id;
	std::vector<std::string> components;
	std::vector<EvidenceKind> kinds;
	std::size_t max_events = 32;
	std::chrono::seconds duration{30};
};

class Recorder {
public:
	explicit Recorder(Limits limits = {});
	void start(std::string component = "application");
	void stop();
	bool running() const noexcept;
	void log(std::string component, std::string message);
	void progress(std::string component, std::string operation, int percent);
	void metric(std::string component, std::string name, double value);
	void report_failure(std::string component, std::string reason);
	void heartbeat(std::string component);
	void sample_kernel();
	void ingest(MonitoringEvent event);
	bool ingest_syslog(const std::string& line);
	void poll_linux();
	std::optional<Incident> incident() const;
	std::vector<Evidence> recent() const;
	std::size_t retained_bytes() const noexcept;
	bool apply_follow_up(const FollowUpRequest& request) const;
	bool save(const std::filesystem::path& path) const;
	static std::optional<Incident> load(const std::filesystem::path& path);
private:
	class Impl;
	std::shared_ptr<Impl> impl_;
};

std::string redact(std::string message);
std::string to_string(EvidenceKind kind);
std::optional<EvidenceKind> evidence_kind_from_string(const std::string& value);
std::string to_string(MonitoringKind kind);
std::optional<MonitoringKind> monitoring_kind_from_string(const std::string& value);
std::optional<MonitoringEvent> parse_syslog(const std::string& line);

} // namespace flightrecorder

#include <iostream>

// TODO: Reference additional headers your program requires here.
