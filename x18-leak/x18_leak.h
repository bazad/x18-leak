#ifndef X18_LEAK__X18_LEAK_H_
#define X18_LEAK__X18_LEAK_H_

#include <stdint.h>

/*
 * x18_leak
 *
 * Description:
 * 	Leak the address of the Lel0_synchronous_vector_64_long kernel function.
 *
 * Returns:
 * 	The kernel address of Lel0_synchronous_vector_64_long or 0.
 */
uint64_t x18_leak(void);

#endif
