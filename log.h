/* Copyright */
#ifndef _LOG_H_
#define _LOG_H_

#include <syslog.h>
#include <stdarg.h>

int daemonized;
const char *ident = "geli";


void
syslog_init()
{
	if (daemonized)
		openlog(ident, LOG_PID, LOG_DAEMON);
}

void
log_prio(int prio, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (daemonized)
		vsyslog(prio, fmt, ap);
	else
		vfprintf(stderr, fmt, ap);

	va_end(ap);
}

#define log_err(fmt, ...)	log_prio(LOG_ERR, fmt, __VA_ARGS__)
#define log_info(fmt, ...)	log_prio(LOG_INFO, fmt, __VA_ARGS__)
#define log_debug(fmt, ...)	log_prio(LOG_DEBUG, fmt, __VA_ARGS__)
#define log_warning(fmt, ...)	log_prio(LOG_WARNING, fmt, __VA_ARGS__)
#endif /* ! _LOG_H_ */
