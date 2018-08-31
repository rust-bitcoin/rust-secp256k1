#ifndef RUST_SGX_SDK_OCALL_H
#define RUST_SGX_SDK_OCALL_H

#include <string.h>
#include <stdio.h>
#include <stdarg.h>

#ifdef    __cplusplus
extern "C" {
#endif

extern int u_stdout_ocall(size_t* retval, const void* buf, size_t nbytes);

static inline int printf_sgx(const char *fmt, ...) {
  va_list ap;
  char buf[BUFSIZ] = {'\0'};
  va_start(ap, fmt);
  vsnprintf(buf, BUFSIZ, fmt, ap);
  va_end(ap);
  
  size_t ret;
  u_stdout_ocall(&ret, buf, strnlen(buf, BUFSIZ));
  return 0;
}

enum {
  LOG_LVL_NONE,
  LOG_LVL_CRITICAL,
  LOG_LVL_WARNING,
  LOG_LVL_NOTICE,
  LOG_LVL_LOG,
  LOG_LVL_DEBUG,
  LOG_LVL_NEVER
};

#ifndef LOG_BUILD_LEVEL
#ifdef NDEBUG
#define LOG_BUILD_LEVEL LOG_LVL_CRITICAL
#else
#define LOG_BUILD_LEVEL LOG_LVL_DEBUG
#endif
#endif

static unsigned char log_run_level = LOG_LVL_DEBUG;
static const char *log_level_strings[] = {
    "NONE",
    "CRIT",
    "WARN",
    "NOTI",
    " LOG",
    "DEBG"
};

#ifdef __cplusplus
#define _FALSE false
#else
#define _FALSE 0
#endif

#define LOG_SHOULD_I(level) ( level <= LOG_BUILD_LEVEL && level <= log_run_level )

#define LOG(level, fmt, arg...) do {    \
    if ( LOG_SHOULD_I(level) ) { \
        printf_sgx("[%s] (%s:%d) " fmt "\n", log_level_strings[level], strrchr(__FILE__, '/')+1,__LINE__, ##arg); \
    } \
} while(_FALSE)

#define LL_DEBUG(fmt, arg...) LOG( LOG_LVL_DEBUG, fmt, ##arg )
#define LL_LOG(fmt, arg...) LOG( LOG_LVL_LOG, fmt,##arg )
#define LL_TRACE(fmt, arg...) LOG( LOG_LVL_LOG, fmt,##arg )
#define LL_NOTICE(fmt, arg...) LOG( LOG_LVL_NOTICE, fmt, ##arg )
#define LL_INFO(fmt, arg...) LOG( LOG_LVL_NOTICE, fmt, ##arg )
#define LL_WARNING(fmt, arg...) LOG( LOG_LVL_WARNING, fmt, ##arg )
#define LL_CRITICAL(fmt, arg...) LOG( LOG_LVL_CRITICAL, fmt, ##arg )

#ifdef    __cplusplus
}
#endif

#endif