x18-leak
===================================================================================================

iOS 11.2 introduced a kernel information leak that could be used to determine the kASLR slide. The
issue was the result of a newly added feature, `__ARM_KERNEL_PROTECT__`, that inadvertently caused
the address of the kernel function `Lel0_synchronous_vector_64_long` to appear in register `x18`
when obtaining the values of a thread's registers using `thread_get_state`. The issue was
discovered when kernel pointers started appearing in iOS application crash logs.


The vulnerability
---------------------------------------------------------------------------------------------------

In iOS 11.2, Apple introduced a feature on arm64 called `__ARM_KERNEL_PROTECT__`. According to a
comment in [`osfmk/arm64/proc_reg.h`][proc_reg.h]:

[proc_reg.h]: https://opensource.apple.com/source/xnu/xnu-4570.31.3/osfmk/arm64/proc_reg.h.auto.html

	__ARM_KERNEL_PROTECT__ is a feature intended to guard against potential
	architectural or microarchitectural vulnerabilities that could allow cores to
	read/access EL1-only mappings while in EL0 mode.  This is achieved by
	removing as many mappings as possible when the core transitions to EL0 mode
	from EL1 mode, and restoring those mappings when the core transitions to EL1
	mode from EL0 mode.

That is, when transitioning from EL1 (kernel mode) to EL0 (user mode), as many kernel mappings as
possible will be removed. This should limit the possible attack surface against kernel memory
mappings when exploiting microarchitectural vulnerabilities like Spectre or Meltdown.

If you look through the diff between XNU versions 4570.20.62 and 4570.31.3, you'll find a number of
new references to register `x18` pop up in the file [`osfmk/arm64/locore.s`][XNU 4570.31.3
locore.s] in relation to `__ARM_KERNEL_PROTECT__`. In particular, you'll see that the exception
vector `Lel0_synchronous_vector_64`, which is the exception vector invoked on a system call
(instruction `svc #0`), now looks like this:

[XNU 4570.31.3 locore.s]: https://opensource.apple.com/source/xnu/xnu-4570.31.3/osfmk/arm64/locore.s.auto.html

```assembly
	.text
	.align 7
Lel0_synchronous_vector_64:
	MAP_KERNEL
	BRANCH_TO_KVA_VECTOR Lel0_synchronous_vector_64_long, 8
```

The macro `BRANCH_TO_KVA_VECTOR` is defined as:

```assembly
.macro BRANCH_TO_KVA_VECTOR
#if __ARM_KERNEL_PROTECT__
	/*
	 * Find the kernelcache table for the exception vectors by accessing
	 * the per-CPU data.
	 */
	mrs		x18, TPIDR_EL1
	ldr		x18, [x18, ACT_CPUDATAP]
	ldr		x18, [x18, CPU_EXC_VECTORS]

	/*
	 * Get the handler for this exception and jump to it.
	 */
	ldr		x18, [x18, #($1 << 3)]
	br		x18
#else
	b		$0
#endif /* __ARM_KERNEL_PROTECT__ */
.endmacro
```

This macro performs an indirect branch to the true exception vector implementation,
`Lel0_synchronous_vector_64_long`, by loading a pointer to that function into the register `x18`.
Notice, however, that this clobber of `x18` happens before the userspace registers are saved by the
function `fleh_dispatch64`, which is called by `Lel0_synchronous_vector_64_long`. This means that
when the user registers are saved, `x18` will actually be a pointer to
`Lel0_synchronous_vector_64_long` rather than the original value from userspace.

Even though `x18` is cleared on exception return, storing a kernel pointer in the user register
state is problematic because `thread_get_state` can be used to copy the saved user register state
back to userspace, including the value of register `x18`. All a thread needs to do in order to
obtain the address of the `Lel0_synchronous_vector_64_long` function is call `thread_get_state` on
itself and look at the reported value of `x18`. This makes it trivial to determine the kASLR slide
by subtracting the value of `x18` thus obtained by the static address of
`Lel0_synchronous_vector_64_long`.


Exploitation
---------------------------------------------------------------------------------------------------

As mentioned above, exploitation is trivial: simply call the function `thread_get_state`, look at
the value for register `x18`, and subtract from it the static address of the kernel function
`Lel0_synchronous_vector_64_long`.


Discovery
---------------------------------------------------------------------------------------------------

I discovered this issue on February 26, 2018, after noticing a kernel pointer in register `x18` of
an iOS application crash log. A quick check showed that the same value appeared in register `x18`
of every crash log on the device, which suggested a serious information leak.

I next tried to determine what exactly was going on with register `x18` through experimentation. I
set a breakpoint in an empty iOS app and used lldb to read the value of register `x18`, confirming
that the leak was not restricted to crashing applications. Next I tried to read the value of `x18`
using inline assembly and found that the value obtained did not match the value shown by the
debugger when using a command like `reg read x18`. This suggested that perhaps the leak was really
in `thread_get_state`, and that register `x18` didn't truly contain a kernel pointer while the CPU
was executing in userspace. A quick proof-of-concept that read the value of `x18` using
`thread_get_state` confirmed that this function was indeed the source of the leak.


Timeline
---------------------------------------------------------------------------------------------------

I reported the issue to Apple on February 26, 2018, the same day I discovered it.


---------------------------------------------------------------------------------------------------
By Brandon Azad
