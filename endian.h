/* Copyright */
#ifndef _ENDIAN_H_
#define _ENDIAN_H_

#include <inttypes.h>
#include <sys/types.h>
#include <arpa/inet.h>

static __inline uint64_t
ntohll(uint64_t v)
{
    if(ntohl(1) == 1) return v;
    uint32_t lo = v & 0xffffffff, hi = v >> 32;
    return ((uint64_t)ntohl(lo)) << 32 | ntohl(hi);
}

static __inline int
le16dec(u_char *buf)
{
	int result = *buf++;
	result |= *buf << 8;
	return result;
}

static __inline uint32_t
le32dec(u_char *buf)
{
	uint32_t result = *buf++;
	result |= (uint32_t)*buf++ << 8;
	result |= (uint32_t)*buf++ << 16;
	result |= (uint32_t)*buf   << 24;
	return result;
}

static __inline uint64_t
le64dec(u_char *buf)
{
	uint64_t result = *buf++;
	result |= (uint64_t)*buf++ << 8;
	result |= (uint64_t)*buf++ << 16;
	result |= (uint64_t)*buf++ << 24;
	result |= (uint64_t)*buf++ << 32;
	result |= (uint64_t)*buf++ << 40;
	result |= (uint64_t)*buf++ << 48;
	result |= (uint64_t)*buf   << 56;
	return result;
}

static __inline void
be32enc(u_char *buf, uint32_t arg)
{
	*buf++ = (arg >> 24) & 0xff;
	*buf++ = (arg >> 16) & 0xff;
	*buf++ = (arg >>  8) & 0xff;
	*buf   = (arg      ) & 0xff;
}

static __inline void
le16enc(u_char *buf, uint16_t arg)
{
        *buf++ = (arg      ) & 0xff;
	*buf++ = (arg >>  8) & 0xff;
}

static __inline void
le32enc(u_char *buf, uint32_t arg)
{
        *buf++ = (arg      ) & 0xff;
	*buf++ = (arg >>  8) & 0xff;
	*buf++ = (arg >> 16) & 0xff;
	*buf++ = (arg >> 24) & 0xff;
}

static __inline void
le64enc(u_char *buf, uint64_t arg)
{
	*buf++ = (arg      ) & 0xff;
	*buf++ = (arg >>  8) & 0xff;
	*buf++ = (arg >> 16) & 0xff;
	*buf++ = (arg >> 24) & 0xff;
	*buf++ = (arg >> 32) & 0xff;
	*buf++ = (arg >> 40) & 0xff;
	*buf++ = (arg >> 48) & 0xff;
	*buf   = (arg >> 56) & 0xff;
}
#endif /* !_ENDIAN_H_ */
