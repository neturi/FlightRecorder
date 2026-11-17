// FlightRecorder.cpp : Defines the entry point for the application.
//

#include "FlightRecorder.h"
#include <algorithm>
#include <atomic>
#include <fstream>
#include <iomanip>
#include <map>
#include <mutex>
#include <sstream>
#include <thread>

namespace flightrecorder {
	namespace {
		using Clock = std::chrono::system_clock;
		using Millis = std::chrono::milliseconds;

		long long stamp(Clock::time_point value) { return std::chrono::duration_cast<Millis>(value.time_since_epoch()).count(); }
		Clock::time_point from_stamp(long long value) { return Clock::time_point{ Millis{value} }; }

		std::string encode(const std::string& value) {
			std::ostringstream out;
			for (unsigned char c : value) out << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
			return out.str();
		}
		std::string decode(const std::string& value) {
			std::string result;
			for (std::size_t i = 0; i + 1 < value.size(); i += 2) {
				unsigned int byte = 0;
				std::istringstream(value.substr(i, 2)) >> std::hex >> byte;
				result.push_back(static_cast<char>(byte));
			}
			return result;
		}
		std::vector<std::string> split(const std::string& value) {
			std::vector<std::string> fields; std::stringstream stream(value); std::string field;
			while (std::getline(stream, field, '\t')) fields.push_back(field);
			return fields;
		}
	}

	std::size_t Evidence::bytes() const noexcept { return component.size() + message.size() + 32; }

	std::string to_string(EvidenceKind kind) {
		switch (kind) {
		case EvidenceKind::Log: return "log"; case EvidenceKind::Progress: return "progress";
		case EvidenceKind::Metric: return "metric"; case EvidenceKind::Failure: return "failure"; case EvidenceKind::KernelSample: return "kernel";
		}
		return "log";
	}
	std::optional<EvidenceKind> evidence_kind_from_string(const std::string& value) {
		for (auto kind : { EvidenceKind::Log, EvidenceKind::Progress, EvidenceKind::Metric, EvidenceKind::Failure, EvidenceKind::KernelSample })
			if (to_string(kind) == value) return kind;
		return std::nullopt;
	}

	std::string redact(std::string message) {
		const std::vector<std::string> keys{ "password=", "token=", "authorization=", "secret=" };
		for (const auto& key : keys) {
			std::size_t at = 0;
			while ((at = message.find(key, at)) != std::string::npos) {
				auto end = message.find_first_of(" &\t\n", at + key.size());
				message.replace(at + key.size(), (end == std::string::npos ? message.size() : end) - at - key.size(), "[REDACTED]");
				at += key.size() + 10;
			}
		}
		return message;
	}

	class Recorder::Impl {
	public:
		explicit Impl(Limits value) : limits(std::move(value)) {}
		Limits limits;
		mutable std::mutex mutex;
		bool active = false;
		std::string default_component;
		std::vector<Evidence> buffer; // Should use std::deque as fixed-size circular buffer for easier management.
		std::size_t bytes = 0;
		std::map<std::string, Clock::time_point> heartbeats;
		std::optional<Incident> current;
		unsigned long sequence = 0;

		void append(EvidenceKind kind, std::string component, std::string message) {
			Evidence item{ Clock::now(), kind, std::move(component), redact(std::move(message)) };
			buffer.push_back(item); bytes += item.bytes();
			while (buffer.size() > limits.max_events || bytes > limits.max_bytes) { bytes -= buffer.front().bytes(); buffer.erase(buffer.begin()); }
			if (current && current->after.empty() && item.kind != EvidenceKind::Failure) current->during.push_back(item);
		}
		void fail(std::string component, std::string reason) {
			if (current) return;
			Incident value;
			value.id = "incident-" + std::to_string(++sequence);
			value.detected_at = Clock::now(); value.reason = redact(std::move(reason)); value.before = buffer;
			current = std::move(value);
			append(EvidenceKind::Failure, std::move(component), current->reason);
		}
	};

	Recorder::Recorder(Limits limits) : impl_(std::make_shared<Impl>(std::move(limits))) {}
	void Recorder::start(std::string component) { std::lock_guard lock(impl_->mutex); impl_->active = true; impl_->default_component = std::move(component); impl_->append(EvidenceKind::Log, impl_->default_component, "recorder_started"); }
	void Recorder::stop() { std::lock_guard lock(impl_->mutex); impl_->active = false; impl_->append(EvidenceKind::Log, impl_->default_component, "recorder_stopped"); if (impl_->current) { impl_->current->after = impl_->current->during; impl_->current->during.clear(); } }
	bool Recorder::running() const noexcept { std::lock_guard lock(impl_->mutex); return impl_->active; }
	void Recorder::log(std::string component, std::string message) { std::lock_guard lock(impl_->mutex); impl_->append(EvidenceKind::Log, std::move(component), std::move(message)); }
	void Recorder::progress(std::string component, std::string operation, int percent) { std::lock_guard lock(impl_->mutex); const auto now = Clock::now();
		for (const auto& heartbeat : impl_->heartbeats) if (now - heartbeat.second > impl_->limits.heartbeat_timeout) { impl_->fail(heartbeat.first, "heartbeat_timeout"); break; } 
		impl_->heartbeats[component] = now; impl_->append(EvidenceKind::Progress, std::move(component), std::move(operation) + " percent=" + std::to_string(std::clamp(percent, 0, 100))); }
	// add a dedicated watchdog thread or supervisor timer if truly silent components must be detected without any later recorder activity.
	void Recorder::metric(std::string component, std::string name, double value) { std::lock_guard lock(impl_->mutex); impl_->append(EvidenceKind::Metric, std::move(component), std::move(name) + " value=" + std::to_string(value)); }
	void Recorder::heartbeat(std::string component) { std::lock_guard lock(impl_->mutex); impl_->heartbeats[component] = Clock::now(); impl_->append(EvidenceKind::Progress, component, "heartbeat"); }
	void Recorder::report_failure(std::string component, std::string reason) { std::lock_guard lock(impl_->mutex); impl_->fail(std::move(component), std::move(reason)); }

		void Recorder::sample_kernel() {
#ifdef __linux__
		std::ifstream stat("/proc/self/status"); std::string line, result;
		while (std::getline(stat, line)) if (line.rfind("VmRSS:", 0) == 0 || line.rfind("Threads:", 0) == 0) result += line + " ";
		std::lock_guard lock(impl_->mutex);
		impl_->append(EvidenceKind::KernelSample, "kernel", result.empty() ? "proc_unavailable" : result);
#else
		std::lock_guard lock(impl_->mutex); impl_->append(EvidenceKind::KernelSample, "kernel", "not_supported_on_this_platform");
#endif
	} // This interface can later be extended with optional eBPF or perf-based collectors without changing the recorder API.
	std::optional<Incident> Recorder::incident() const { std::lock_guard lock(impl_->mutex); return impl_->current; }
	std::vector<Evidence> Recorder::recent() const { std::lock_guard lock(impl_->mutex); return impl_->buffer; }
	std::size_t Recorder::retained_bytes() const noexcept { std::lock_guard lock(impl_->mutex); return impl_->bytes; }
	bool Recorder::apply_follow_up(const FollowUpRequest& request) const {
		std::lock_guard lock(impl_->mutex);
		if (!impl_->current || request.incident_id != impl_->current->id || request.max_events == 0 || request.max_events > impl_->limits.max_events || request.duration <= std::chrono::seconds::zero()) return false;
		if (request.components.empty() || request.kinds.empty()) return false;
		return std::all_of(request.components.begin(), request.components.end(), [](const auto& c) { return c.size() <= 128 && c.find("..") == std::string::npos; });
	}

	bool Recorder::save(const std::filesystem::path& path) const {
		std::lock_guard lock(impl_->mutex); if (!impl_->current) return false;
		std::ofstream out(path); if (!out) return false;
		const auto write = [&out](char phase, const Evidence& item) { out << phase << '\t' << stamp(item.time) << '\t' << to_string(item.kind) << '\t' << encode(item.component) << '\t' << encode(item.message) << '\n'; };
		out << "FLIGHTRECORDER1\t" << encode(impl_->current->id) << '\t' << stamp(impl_->current->detected_at) << '\t' << encode(impl_->current->reason) << '\n';
		for (const auto& item : impl_->current->before) write('B', item); for (const auto& item : impl_->current->during) write('D', item); for (const auto& item : impl_->current->after) write('A', item);
		return static_cast<bool>(out);
	}

	std::optional<Incident> Recorder::load(const std::filesystem::path& path) {
		std::ifstream in(path); std::string line; if (!std::getline(in, line)) return std::nullopt;
		auto header = split(line); if (header.size() != 4 || header[0] != "FLIGHTRECORDER1") return std::nullopt;
		Incident result; try { result.id = decode(header[1]); result.detected_at = from_stamp(std::stoll(header[2])); result.reason = decode(header[3]); }
		catch (...) { return std::nullopt; }
		while (std::getline(in, line)) { auto fields = split(line); if (fields.size() != 5) continue; auto kind = evidence_kind_from_string(fields[2]); if (!kind) continue; Evidence item; try { item.time = from_stamp(std::stoll(fields[1])); } catch (...) { continue; } item.kind = *kind; item.component = decode(fields[3]); item.message = decode(fields[4]); if (fields[0] == "B") result.before.push_back(item); else if (fields[0] == "D") result.during.push_back(item); else if (fields[0] == "A") result.after.push_back(item); }
		return result;
	}
} // namespace FlightRecorder
