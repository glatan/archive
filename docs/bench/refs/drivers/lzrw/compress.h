/* Minimal compress.h stub matching lzrw_headers.h's interface. */
#ifndef DONE_COMPRESS_H
#define DONE_COMPRESS_H

#include "port.h"

#define COMPRESS_ACTION_IDENTITY 0
#define COMPRESS_ACTION_COMPRESS 1
#define COMPRESS_ACTION_DECOMPRESS 2

#define COMPRESS_OVERRUN 1024
#define COMPRESS_MAX_COM 0x70000000
#define COMPRESS_MAX_ORG (COMPRESS_MAX_COM - COMPRESS_OVERRUN)
#define COMPRESS_MAX_STRLEN 255

struct compress_identity {
    ULONG id;
    ULONG memory;
    char *name;
    char *version;
    char *date;
    char *copyright;
    char *author;
    char *affiliation;
    char *vendor;
};

void compress(UWORD action, UBYTE *wrk_mem, UBYTE *src_adr, ULONG src_len,
              UBYTE *dst_adr, ULONG *p_dst_len);

#endif
