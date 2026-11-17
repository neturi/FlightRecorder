#include "FlightRecorder.h"

#include <iostream>

int main(int argc, char** argv) {
	using namespace flightrecorder;
	const std::string output = argc > 1 ? argv[1] : "flight-incident.frb";
	Recorder recorder;
	recorder.start("flight-agent");
	recorder.heartbeat("scheduler");
	recorder.progress("scheduler", "initializing", 10);
	recorder.metric("scheduler", "queue_depth", 3);
	recorder.sample_kernel();
	recorder.log("scheduler", "cloud upload deferred: endpoint unavailable");
	recorder.report_failure("scheduler", "worker stopped making progress");
	recorder.log("scheduler", "post-failure supervisor context retained");
	recorder.stop();
	if (!recorder.save(output)) {
		std::cerr << "Unable to save incident bundle: " << output << '\n';
		return 1;
	}
	const auto incident = recorder.incident();
	std::cout << "Saved " << incident->id << " with "
			  << incident->before.size() + incident->during.size() + incident->after.size()
			  << " evidence records to " << output << '\n';
	return 0;
}
