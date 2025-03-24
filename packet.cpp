#include "packet.h"
#include <sstream>

Packet::Packet(const timeval& timestamp)
	:timestamp_(timestamp){}

void Packet::add_layer(std::unique_ptr<ProtocolLayer> layer) {
	layers_.push_back(std::move(layer));
}

const timeval& Packet::timestamp() const noexcept {
	return timestamp_;
}

std::string Packet::to_string() const {
	std::ostringstream oss;
	oss << "Packet (Timestamp: " << timestamp_.tv_sec << "."
		<< timestamp_.tv_usec << ")\n";
	oss << "Protocol Layers:\n";

	for (const auto& layer : layers_) {
		oss << "- " << layer->summary() << "\n";
	}
	return oss.str();
}
