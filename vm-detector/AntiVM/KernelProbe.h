#pragma once

#include "Adversary.h"
#include "../Kernel/Protocol.h"

namespace adversary {
std::vector<Result> evaluate_kernel(const Sample<Bytes>& response);
}
