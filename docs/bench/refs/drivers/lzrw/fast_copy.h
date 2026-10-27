/* Minimal fast_copy.h stub. */
#ifndef DONE_FAST_COPY_H
#define DONE_FAST_COPY_H
#include "port.h"
#include <string.h>
static void fast_copy(UBYTE *p_src, UBYTE *p_dst, ULONG len) {
    memcpy(p_dst, p_src, (size_t)len);
}
#endif
