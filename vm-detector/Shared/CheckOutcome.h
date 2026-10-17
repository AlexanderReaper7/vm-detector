#pragma once

// GOOD means this predicate was evaluated and did not match, not that the PC is physical.
enum CheckOutcome {
	CHECK_GOOD = 0,
	CHECK_BAD = 1,
	CHECK_OBSERVATION = 2,
	CHECK_ERROR = 3
};
