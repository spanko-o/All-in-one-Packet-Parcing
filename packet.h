#pragma once

#include "protocol_layer.h"
#include <sys/time.h>

class Packet {
public:
	explicit Packet(const timeval& timestamp);

	void add_layer(std::unique_ptr<ProtocolLayer> layer);

	const timeval& timestamp() const noexcept;

	template <typename T>
	const T* find_layer() const noexcept {
		for (const auto& layer : layers_) {
			if (dynamic_cast<const T*>(layer.get())) {
				return static_cast<const T*>(layer.get());
			}
		}
		return nullptr;
	}

	std::string to_string() const;

private:

	timeval timestamp_;

	std::vector<std::unique_ptr<ProtocolLayer>> layers_;
};