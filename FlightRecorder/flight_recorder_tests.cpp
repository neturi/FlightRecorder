#include "FlightRecorder.h"

#include <cassert>
#include <chrono>
#include <filesystem>
#include <iostream>

using namespace flightrecorder;

void bounded_retention() {
	Recorder recorder(Limits{3, 100000, std::chrono::seconds(30), std::chrono::seconds(1)});
	recorder.start(); recorder.log("app", "one"); recorder.log("app", "two"); recorder.log("app", "three"); recorder.log("app", "four");
	assert(recorder.recent().size() <= 3); assert(recorder.retained_bytes() <= 100000);
}
void privacy_and_context() {
	Recorder recorder; recorder.start(); recorder.log("auth", "password=super-secret token=abc"); recorder.report_failure("worker", "crash"); recorder.log("worker", "after evidence"); recorder.stop();
	auto item = recorder.incident(); assert(item); assert(item->before.size() >= 2); assert(!item->after.empty());
	for (const auto& event : item->before) assert(event.message.find("super-secret") == std::string::npos);
}
void watchdog_and_scope() {
	Recorder recorder(Limits{20, 10000, std::chrono::seconds(0), std::chrono::seconds(1)});
	recorder.heartbeat("worker"); recorder.progress("other", "tick", 50); auto item = recorder.incident(); assert(item); 
	FollowUpRequest valid{item->id, {"worker"}, {EvidenceKind::Progress}, 2, std::chrono::seconds(5)}; assert(recorder.apply_follow_up(valid));
	valid.components = {"../etc"}; assert(!recorder.apply_follow_up(valid)); valid.components = {"worker"}; valid.max_events = 1000; assert(!recorder.apply_follow_up(valid));
}
void persistence() {
	Recorder recorder; recorder.start(); recorder.report_failure("worker", "disk\tfailure"); recorder.stop();
	const auto path = std::filesystem::temp_directory_path() / "flight-recorder-test.frb";
	assert(recorder.save(path)); auto loaded = Recorder::load(path); assert(loaded); assert(loaded->reason == "disk\tfailure"); assert(loaded->id == recorder.incident()->id); std::filesystem::remove(path);
}
void monitoring_ingestion() {
	auto event = parse_syslog("<11> network interface eth0 down token=private");
	assert(event); assert(event->kind == MonitoringKind::Network); assert(event->severity == "error");
	Recorder recorder; recorder.start();
	assert(recorder.ingest_syslog("<4> disk I/O latency increased password=hidden"));
	assert(!recorder.ingest_syslog(""));
	const auto records = recorder.recent();
	assert(!records.empty());
	for (const auto& record : records) assert(record.message.find("hidden") == std::string::npos);
}
void local_monitoring() {
	Recorder recorder; recorder.start(); recorder.heartbeat("endpoint");
	recorder.poll_linux();
	assert(!recorder.recent().empty());
}
int main() {
	bounded_retention(); privacy_and_context(); watchdog_and_scope(); persistence(); monitoring_ingestion(); local_monitoring();
	std::cout << "all flight recorder tests passed\n";
}
