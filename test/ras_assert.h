#pragma once
#include "write_dump.h"

#define RAS_ASSERT(eval) \
	if (!eval){ \
		__try \
		{ \
			RaiseException(EXCEPTION_ASSERT_MINI, 0, 0, NULL); \
		} \
		__except (EXCEPTION_CONTINUE_EXECUTION) {} \
	}