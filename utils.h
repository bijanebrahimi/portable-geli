/* Copyright */
#ifndef _UTILS_H_
#define _UTILS_H_

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>

static __inline int
read_data(int fd, u_char *buf, size_t buf_sz)
{
	int nbytes;
	u_char *ptr;

	ptr = buf;
	while (buf_sz) {
		/* Read */
		nbytes = read(fd, ptr, buf_sz);
		if (nbytes == 0)
			break;
		if (nbytes < 0 && errno == EAGAIN)
			continue;
		if (nbytes < 0)
			return errno;
		ptr += nbytes;
		buf_sz -= nbytes;
	}

	/* NULL terminate if possible */
	if (buf_sz)
		*ptr = '\0';
	return 0;
}

static __inline int
write_data(int fd, u_char *buf, int buf_sz)
{
	int nbytes;
	u_char *ptr;

	ptr = buf;
	while (buf_sz) {
		nbytes = write(fd, buf, buf_sz);
		if (nbytes < 0 && errno == EAGAIN)
			continue;
		if (nbytes <= 0)
			return errno;
		ptr += nbytes;
		buf_sz -= nbytes;
	}

	return 0;
}

static __inline void
dump_data(u_char *data, unsigned long length)
{
	u_char *ptr;
	int i;

	for (ptr = data, i = 1; ptr < (data+length); ptr++, i++)
		printf("0x%02x%s", *ptr, (i % 16) == 0 ? "\n" : " ");
	if (i % 16)
		printf("\n");
}
#endif /* !_UTILS_H_ */
