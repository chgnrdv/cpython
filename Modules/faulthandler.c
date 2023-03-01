#include "Python.h"
#include "pycore_initconfig.h"    // _PyStatus_ERR
#include "pycore_pyerrors.h"      // _Py_DumpExtensionModules
#include "pycore_pystate.h"       // _PyThreadState_GET()
#include "pycore_signal.h"        // Py_NSIG
#include "pycore_traceback.h"     // _Py_DumpTracebackThreads

#include <object.h>
#include <signal.h>
#include <stdlib.h>               // abort()
#if defined(HAVE_PTHREAD_SIGMASK) && !defined(HAVE_BROKEN_PTHREAD_SIGMASK) && defined(HAVE_PTHREAD_H)
#  include <pthread.h>
#endif
#ifdef MS_WINDOWS
#  include <windows.h>
#endif
#ifdef HAVE_SYS_RESOURCE_H
#  include <sys/resource.h>
#endif

#if defined(FAULTHANDLER_USE_ALT_STACK) && defined(HAVE_LINUX_AUXVEC_H) && defined(HAVE_SYS_AUXV_H)
#  include <linux/auxvec.h>       // AT_MINSIGSTKSZ
#  include <sys/auxv.h>           // getauxval()
#endif

/* Allocate at maximum 100 MiB of the stack to raise the stack overflow */
#define STACK_OVERFLOW_MAX_SIZE (100 * 1024 * 1024)

#define PUTS(fd, str) _Py_write_noraise(fd, str, strlen(str))


// clang uses __attribute__((no_sanitize("undefined")))
// GCC 4.9+ uses __attribute__((no_sanitize_undefined))
#if defined(__has_feature)  // Clang
#  if __has_feature(undefined_behavior_sanitizer)
#    define _Py_NO_SANITIZE_UNDEFINED __attribute__((no_sanitize("undefined")))
#  endif
#endif
#if defined(__GNUC__) \
    && ((__GNUC__ >= 5) || (__GNUC__ == 4) && (__GNUC_MINOR__ >= 9))
#  define _Py_NO_SANITIZE_UNDEFINED __attribute__((no_sanitize_undefined))
#endif
#ifndef _Py_NO_SANITIZE_UNDEFINED
#  define _Py_NO_SANITIZE_UNDEFINED
#endif


/*[clinic input]
module faulthandler
[clinic start generated code]*/
/*[clinic end generated code: output=da39a3ee5e6b4b0d input=c3d4f47c4f3d440f]*/

#include "clinic/faulthandler.c.h"


typedef struct {
    int signum;
    int enabled;
    const char* name;
    _Py_sighandler_t previous;
    int all_threads;
} fault_handler_t;

#define fatal_error _PyRuntime.faulthandler.fatal_error
#define thread _PyRuntime.faulthandler.thread

#ifdef FAULTHANDLER_USER
#define user_signals _PyRuntime.faulthandler.user_signals
typedef struct faulthandler_user_signal user_signal_t;
static void user_handler(int signum);
#endif /* FAULTHANDLER_USER */


static fault_handler_t faulthandler_handlers[] = {
#ifdef SIGBUS
    {SIGBUS, 0, "Bus error", },
#endif
#ifdef SIGILL
    {SIGILL, 0, "Illegal instruction", },
#endif
    {SIGFPE, 0, "Floating point exception", },
    {SIGABRT, 0, "Aborted", },
    /* define SIGSEGV at the end to make it the default choice if searching the
       handler fails in fatal_error_handler() */
    {SIGSEGV, 0, "Segmentation fault", }
};
static const size_t faulthandler_nsignals = \
    Py_ARRAY_LENGTH(faulthandler_handlers);

#ifdef FAULTHANDLER_USE_ALT_STACK
#  define stack _PyRuntime.faulthandler.stack
#  define old_stack _PyRuntime.faulthandler.old_stack
#endif


/* Get the file descriptor of a file by calling its fileno() method and then
   call its flush() method.

   If file is NULL or Py_None, use sys.stderr as the new file.
   If file is an integer, it will be treated as file descriptor.

   On success, return the file descriptor and write the new file into *file_ptr.
   On error, return -1. */

static int
get_fileno(PyObject **file_ptr)
{
    PyObject *result;
    long fd_long;
    int fd;
    PyObject *file = *file_ptr;

    if (file == NULL || file == Py_None) {
        PyThreadState *tstate = _PyThreadState_GET();
        file = _PySys_GetAttr(tstate, &_Py_ID(stderr));
        if (file == NULL) {
            PyErr_SetString(PyExc_RuntimeError, "unable to get sys.stderr");
            return -1;
        }
        if (file == Py_None) {
            PyErr_SetString(PyExc_RuntimeError, "sys.stderr is None");
            return -1;
        }
    }
    else if (PyLong_Check(file)) {
        fd = _PyLong_AsInt(file);
        if (fd == -1 && PyErr_Occurred())
            return -1;
        if (fd < 0) {
            PyErr_SetString(PyExc_ValueError,
                            "file is not a valid file descripter");
            return -1;
        }
        *file_ptr = NULL;
        return fd;
    }

    result = PyObject_CallMethodNoArgs(file, &_Py_ID(fileno));
    if (result == NULL)
        return -1;

    fd = -1;
    if (PyLong_Check(result)) {
        fd_long = PyLong_AsLong(result);
        if (0 <= fd_long && fd_long < INT_MAX)
            fd = (int)fd_long;
    }
    Py_DECREF(result);

    if (fd == -1) {
        PyErr_SetString(PyExc_RuntimeError,
                        "file.fileno() is not a valid file descriptor");
        return -1;
    }

    result = PyObject_CallMethodNoArgs(file, &_Py_ID(flush));
    if (result != NULL)
        Py_DECREF(result);
    else {
        /* ignore flush() error */
        PyErr_Clear();
    }
    *file_ptr = file;
    return fd;
}


/* Get the state of the current thread: only call this function if the current
   thread holds the GIL. Raise an exception on error. */
static PyThreadState*
get_thread_state(void)
{
    PyThreadState *tstate = _PyThreadState_GET();
    if (tstate == NULL) {
        /* just in case but very unlikely... */
        PyErr_SetString(PyExc_RuntimeError,
                        "unable to get the current thread state");
        return NULL;
    }
    return tstate;
}

static void
dump_traceback(int fd, int all_threads, PyInterpreterState *interp)
{
    static volatile int reentrant = 0;
    PyThreadState *tstate;

    if (reentrant)
        return;

    reentrant = 1;

    /* SIGSEGV, SIGFPE, SIGABRT, SIGBUS and SIGILL are synchronous signals and
       are thus delivered to the thread that caused the fault. Get the Python
       thread state of the current thread.

       PyThreadState_Get() doesn't give the state of the thread that caused the
       fault if the thread released the GIL, and so this function cannot be
       used. Read the thread specific storage (TSS) instead: call
       PyGILState_GetThisThreadState(). */
    tstate = PyGILState_GetThisThreadState();

    if (all_threads) {
        (void)_Py_DumpTracebackThreads(fd, NULL, tstate);
    }
    else {
        if (tstate != NULL)
            _Py_DumpTraceback(fd, tstate);
    }

    reentrant = 0;
}


/*[clinic input]
faulthandler.dump_traceback

    file: object(c_default='NULL') = sys.stderr
    all_threads: bool = True
    /

Dump traceback.

dump the traceback of the current thread, or of all threads if all_threads is True, into file
[clinic start generated code]*/

static PyObject *
faulthandler_dump_traceback_impl(PyObject *module, PyObject *file,
                                 int all_threads)
/*[clinic end generated code: output=1cd07adb72af5986 input=1694f0d2c10f1d0f]*/
{
    PyThreadState *tstate;
    const char *errmsg;
    int fd;

    fd = get_fileno(&file);
    if (fd < 0)
        return NULL;

    tstate = get_thread_state();
    if (tstate == NULL)
        return NULL;

    if (all_threads) {
        errmsg = _Py_DumpTracebackThreads(fd, NULL, tstate);
        if (errmsg != NULL) {
            PyErr_SetString(PyExc_RuntimeError, errmsg);
            return NULL;
        }
    }
    else {
        _Py_DumpTraceback(fd, tstate);
    }

    if (PyErr_CheckSignals())
        return NULL;

    Py_RETURN_NONE;
}


static void
fatal_handler_disable(fault_handler_t *handler)
{
    if (!handler->enabled)
        return;
    handler->enabled = 0;
#ifdef HAVE_SIGACTION
    (void)sigaction(handler->signum, &handler->previous, NULL);
#else
    (void)signal(handler->signum, handler->previous);
#endif
}


/* Handler for SIGSEGV, SIGFPE, SIGABRT, SIGBUS and SIGILL signals.

   Display the current Python traceback, restore the previous handler and call
   the previous handler.

   On Windows, don't explicitly call the previous handler, because the Windows
   signal handler would not be called (for an unknown reason). The execution of
   the program continues at fatal_error_handler() exit, but the same
   instruction will raise the same fault (signal), and so the previous handler
   will be called.

   This function is signal-safe and should only call signal-safe functions. */

static void
fatal_error_handler(int signum)
{
    const int fd = fatal_error.fd;
    size_t i;
    fault_handler_t *handler = NULL;
    int save_errno = errno;
    int found = 0;

    if (!fatal_error.enabled)
        return;

    for (i=0; i < faulthandler_nsignals; i++) {
        handler = &faulthandler_handlers[i];
        if (handler->signum == signum) {
            found = 1;
            break;
        }
    }
    if (handler == NULL) {
        /* faulthandler_nsignals == 0 (unlikely) */
        return;
    }

    /* restore the previous handler */
    fatal_handler_disable(handler);

    if (found) {
        PUTS(fd, "Fatal Python error: ");
        PUTS(fd, handler->name);
        PUTS(fd, "\n\n");
    }
    else {
        char unknown_signum[23] = {0,};
        snprintf(unknown_signum, 23, "%d", signum);
        PUTS(fd, "Fatal Python error from unexpected signum: ");
        PUTS(fd, unknown_signum);
        PUTS(fd, "\n\n");
    }

    dump_traceback(fd, fatal_error.all_threads,
                                fatal_error.interp);

    _Py_DumpExtensionModules(fd, fatal_error.interp);

    errno = save_errno;
#ifdef MS_WINDOWS
    if (signum == SIGSEGV) {
        /* don't explicitly call the previous handler for SIGSEGV in this signal
           handler, because the Windows signal handler would not be called */
        return;
    }
#endif
    /* call the previous signal handler: it is called immediately if we use
       sigaction() thanks to SA_NODEFER flag, otherwise it is deferred */
    raise(signum);
}

#ifdef MS_WINDOWS
static int
ignore_exception(DWORD code)
{
    /* bpo-30557: ignore exceptions which are not errors */
    if (!(code & 0x80000000)) {
        return 1;
    }
    /* bpo-31701: ignore MSC and COM exceptions
       E0000000 + code */
    if (code == 0xE06D7363 /* MSC exception ("Emsc") */
        || code == 0xE0434352 /* COM Callable Runtime exception ("ECCR") */) {
        return 1;
    }
    /* Interesting exception: log it with the Python traceback */
    return 0;
}

static LONG WINAPI
exception_handler(struct _EXCEPTION_POINTERS *exc_info)
{
    const int fd = fatal_error.fd;
    DWORD code = exc_info->ExceptionRecord->ExceptionCode;
    DWORD flags = exc_info->ExceptionRecord->ExceptionFlags;

    if (ignore_exception(code)) {
        /* ignore the exception: call the next exception handler */
        return EXCEPTION_CONTINUE_SEARCH;
    }

    PUTS(fd, "Windows fatal exception: ");
    switch (code)
    {
    /* only format most common errors */
    case EXCEPTION_ACCESS_VIOLATION: PUTS(fd, "access violation"); break;
    case EXCEPTION_FLT_DIVIDE_BY_ZERO: PUTS(fd, "float divide by zero"); break;
    case EXCEPTION_FLT_OVERFLOW: PUTS(fd, "float overflow"); break;
    case EXCEPTION_INT_DIVIDE_BY_ZERO: PUTS(fd, "int divide by zero"); break;
    case EXCEPTION_INT_OVERFLOW: PUTS(fd, "integer overflow"); break;
    case EXCEPTION_IN_PAGE_ERROR: PUTS(fd, "page error"); break;
    case EXCEPTION_STACK_OVERFLOW: PUTS(fd, "stack overflow"); break;
    default:
        PUTS(fd, "code 0x");
        _Py_DumpHexadecimal(fd, code, 8);
    }
    PUTS(fd, "\n\n");

    if (code == EXCEPTION_ACCESS_VIOLATION) {
        /* disable signal handler for SIGSEGV */
        for (size_t i=0; i < faulthandler_nsignals; i++) {
            fault_handler_t *handler = &faulthandler_handlers[i];
            if (handler->signum == SIGSEGV) {
                fatal_handler_disable(handler);
                break;
            }
        }
    }

    dump_traceback(fd, fatal_error.all_threads,
                                fatal_error.interp);

    /* call the next exception handler */
    return EXCEPTION_CONTINUE_SEARCH;
}
#endif


#ifdef FAULTHANDLER_USE_ALT_STACK
static int
use_alt_stack(void)
{
    if (stack.ss_sp != NULL) {
        return 0;
    }
    /* Allocate an alternate stack for faulthandler() signal handler
       to be able to execute a signal handler on a stack overflow error */
    stack.ss_sp = PyMem_Malloc(stack.ss_size);
    if (stack.ss_sp == NULL) {
        PyErr_NoMemory();
        return -1;
    }

    int err = sigaltstack(&stack, &old_stack);
    if (err) {
        /* Release the stack to retry sigaltstack() next time */
        PyMem_Free(stack.ss_sp);
        stack.ss_sp = NULL;

        PyErr_SetFromErrno(PyExc_OSError);
        return -1;
    }
    return 0;
}
#endif


/* Install the handler for fatal signals, fatal_error_handler(). */

static int
enable_fatal_handler(void)
{
    if (fatal_error.enabled) {
        return 0;
    }
    fatal_error.enabled = 1;

#ifdef FAULTHANDLER_USE_ALT_STACK
    if (use_alt_stack() < 0) {
        return -1;
    }
#endif

    for (size_t i=0; i < faulthandler_nsignals; i++) {
        fault_handler_t *handler;
        int err;

        handler = &faulthandler_handlers[i];
        assert(!handler->enabled);
#ifdef HAVE_SIGACTION
        struct sigaction action;
        action.sa_handler = fatal_error_handler;
        sigemptyset(&action.sa_mask);
        /* Do not prevent the signal from being received from within
           its own signal handler */
        action.sa_flags = SA_NODEFER;
#ifdef FAULTHANDLER_USE_ALT_STACK
        assert(stack.ss_sp != NULL);
        /* Call the signal handler on an alternate signal stack
           provided by sigaltstack() */
        action.sa_flags |= SA_ONSTACK;
#endif
        err = sigaction(handler->signum, &action, &handler->previous);
#else
        handler->previous = signal(handler->signum,
                                   fatal_error_handler);
        err = (handler->previous == SIG_ERR);
#endif
        if (err) {
            PyErr_SetFromErrno(PyExc_RuntimeError);
            return -1;
        }

        handler->enabled = 1;
    }

#ifdef MS_WINDOWS
    assert(fatal_error.exc_handler == NULL);
    fatal_error.exc_handler = AddVectoredExceptionHandler(1, exception_handler);
#endif
    return 0;
}


/*[clinic input]
faulthandler.enable

    file: object(c_default='NULL') = sys.stderr
    all_threads: bool = True
    /

Enable faulthandler.

enable the fault handler
[clinic start generated code]*/

static PyObject *
faulthandler_enable_impl(PyObject *module, PyObject *file, int all_threads)
/*[clinic end generated code: output=41a54f5df5148123 input=afc5e34d478f866e]*/
{
    int fd;
    PyThreadState *tstate;

    fd = get_fileno(&file);
    if (fd < 0)
        return NULL;

    tstate = get_thread_state();
    if (tstate == NULL)
        return NULL;

    Py_XINCREF(file);
    Py_XSETREF(fatal_error.file, file);
    fatal_error.fd = fd;
    fatal_error.all_threads = all_threads;
    fatal_error.interp = PyThreadState_GetInterpreter(tstate);

    if (enable_fatal_handler() < 0) {
        return NULL;
    }

    Py_RETURN_NONE;
}


static void
disable_fatal_handler(void)
{
    if (fatal_error.enabled) {
        fatal_error.enabled = 0;
        for (size_t i=0; i < faulthandler_nsignals; i++) {
            fault_handler_t *handler;
            handler = &faulthandler_handlers[i];
            fatal_handler_disable(handler);
        }
    }
#ifdef MS_WINDOWS
    if (fatal_error.exc_handler != NULL) {
        RemoveVectoredExceptionHandler(fatal_error.exc_handler);
        fatal_error.exc_handler = NULL;
    }
#endif
    Py_CLEAR(fatal_error.file);
}

/*[clinic input]
faulthandler.disable

Disable faulthandler.

disable the fault handler
[clinic start generated code]*/

static PyObject *
faulthandler_disable_impl(PyObject *module)
/*[clinic end generated code: output=fd27e9b2709d5adc input=717e68f023c319f6]*/
{
    if (!fatal_error.enabled) {
        Py_RETURN_FALSE;
    }
    disable_fatal_handler();
    Py_RETURN_TRUE;
}

/*[clinic input]
faulthandler.is_enabled

Check if the handler is enabled.

check if the handler is enabled
[clinic start generated code]*/

static PyObject *
faulthandler_is_enabled_impl(PyObject *module)
/*[clinic end generated code: output=28123edc0c1da320 input=8c7403294b7df009]*/
{
    return PyBool_FromLong(fatal_error.enabled);
}

static void
watchdog_thread(void *unused)
{
    PyLockStatus st;
    const char* errmsg;
    int ok;
#if defined(HAVE_PTHREAD_SIGMASK) && !defined(HAVE_BROKEN_PTHREAD_SIGMASK)
    sigset_t set;

    /* we don't want to receive any signal */
    sigfillset(&set);
    pthread_sigmask(SIG_SETMASK, &set, NULL);
#endif

    do {
        st = PyThread_acquire_lock_timed(thread.cancel_event,
                                         thread.timeout_us, 0);
        if (st == PY_LOCK_ACQUIRED) {
            PyThread_release_lock(thread.cancel_event);
            break;
        }
        /* Timeout => dump traceback */
        assert(st == PY_LOCK_FAILURE);

        _Py_write_noraise(thread.fd, thread.header, (int)thread.header_len);

        errmsg = _Py_DumpTracebackThreads(thread.fd, thread.interp, NULL);
        ok = (errmsg == NULL);

        if (thread.exit)
            _exit(1);
    } while (ok && thread.repeat);

    /* The only way out */
    PyThread_release_lock(thread.running);
}

static void
cancel_dump_traceback_later(void)
{
    /* If not scheduled, nothing to cancel */
    if (!thread.cancel_event) {
        return;
    }

    /* Notify cancellation */
    PyThread_release_lock(thread.cancel_event);

    /* Wait for thread to join */
    PyThread_acquire_lock(thread.running, 1);
    PyThread_release_lock(thread.running);

    /* The main thread should always hold the cancel_event lock */
    PyThread_acquire_lock(thread.cancel_event, 1);

    Py_CLEAR(thread.file);
    if (thread.header) {
        PyMem_Free(thread.header);
        thread.header = NULL;
    }
}

#define SEC_TO_US (1000 * 1000)

static char*
format_timeout(_PyTime_t us)
{
    unsigned long sec, min, hour;
    char buffer[100];

    /* the downcast is safe: the caller check that 0 < us <= LONG_MAX */
    sec = (unsigned long)(us / SEC_TO_US);
    us %= SEC_TO_US;

    min = sec / 60;
    sec %= 60;
    hour = min / 60;
    min %= 60;

    if (us != 0) {
        PyOS_snprintf(buffer, sizeof(buffer),
                      "Timeout (%lu:%02lu:%02lu.%06u)!\n",
                      hour, min, sec, (unsigned int)us);
    }
    else {
        PyOS_snprintf(buffer, sizeof(buffer),
                      "Timeout (%lu:%02lu:%02lu)!\n",
                      hour, min, sec);
    }
    return _PyMem_Strdup(buffer);
}

/*[clinic input]
faulthandler.dump_traceback_later

    timeout as timeout_obj: object
    repeat: bool = False
    file: object(c_default='NULL') = sys.stderr
    exit: bool = False
    /

Dump traceback later.

dump the traceback of all threads in timeout seconds, or each timeout seconds if repeat is True. If exit is True, "call _exit(1) which is not safe.
[clinic start generated code]*/

static PyObject *
faulthandler_dump_traceback_later_impl(PyObject *module,
                                       PyObject *timeout_obj, int repeat,
                                       PyObject *file, int exit)
/*[clinic end generated code: output=a24d80d694d25ba2 input=fed9f01dbb57467c]*/
{
    _PyTime_t timeout, timeout_us;
    int fd;
    PyThreadState *tstate;
    char *header;
    size_t header_len;

    if (_PyTime_FromSecondsObject(&timeout, timeout_obj,
                                  _PyTime_ROUND_TIMEOUT) < 0) {
        return NULL;
    }
    timeout_us = _PyTime_AsMicroseconds(timeout, _PyTime_ROUND_TIMEOUT);
    if (timeout_us <= 0) {
        PyErr_SetString(PyExc_ValueError, "timeout must be greater than 0");
        return NULL;
    }
    /* Limit to LONG_MAX seconds for format_timeout() */
    if (timeout_us > PY_TIMEOUT_MAX || timeout_us / SEC_TO_US > LONG_MAX) {
        PyErr_SetString(PyExc_OverflowError,
                        "timeout value is too large");
        return NULL;
    }

    tstate = get_thread_state();
    if (tstate == NULL) {
        return NULL;
    }

    fd = get_fileno(&file);
    if (fd < 0) {
        return NULL;
    }

    if (!thread.running) {
        thread.running = PyThread_allocate_lock();
        if (!thread.running) {
            return PyErr_NoMemory();
        }
    }
    if (!thread.cancel_event) {
        thread.cancel_event = PyThread_allocate_lock();
        if (!thread.cancel_event || !thread.running) {
            return PyErr_NoMemory();
        }

        /* cancel_event starts to be acquired: it's only released to cancel
           the thread. */
        PyThread_acquire_lock(thread.cancel_event, 1);
    }

    /* format the timeout */
    header = format_timeout(timeout_us);
    if (header == NULL) {
        return PyErr_NoMemory();
    }
    header_len = strlen(header);

    /* Cancel previous thread, if running */
    cancel_dump_traceback_later();

    Py_XINCREF(file);
    Py_XSETREF(thread.file, file);
    thread.fd = fd;
    /* the downcast is safe: we check that 0 < timeout_us < PY_TIMEOUT_MAX */
    thread.timeout_us = (PY_TIMEOUT_T)timeout_us;
    thread.repeat = repeat;
    thread.interp = PyThreadState_GetInterpreter(tstate);
    thread.exit = exit;
    thread.header = header;
    thread.header_len = header_len;

    /* Arm these locks to serve as events when released */
    PyThread_acquire_lock(thread.running, 1);

    if (PyThread_start_new_thread(watchdog_thread, NULL) == PYTHREAD_INVALID_THREAD_ID) {
        PyThread_release_lock(thread.running);
        Py_CLEAR(thread.file);
        PyMem_Free(header);
        thread.header = NULL;
        PyErr_SetString(PyExc_RuntimeError,
                        "unable to start watchdog thread");
        return NULL;
    }

    Py_RETURN_NONE;
}

/*[clinic input]
faulthandler.cancel_dump_traceback_later

Cancel previous call to ...

cancel the previous call to dump_traceback_later().
[clinic start generated code]*/

static PyObject *
faulthandler_cancel_dump_traceback_later_impl(PyObject *module)
/*[clinic end generated code: output=bcc1b37a8e7c1b57 input=9ac152231399c3c3]*/
{
    cancel_dump_traceback_later();
    Py_RETURN_NONE;
}


#ifdef FAULTHANDLER_USER
static int
register_user_handler(int signum, int chain, _Py_sighandler_t *previous_p)
{
#ifdef HAVE_SIGACTION
    struct sigaction action;
    action.sa_handler = user_handler;
    sigemptyset(&action.sa_mask);
    /* if the signal is received while the kernel is executing a system
       call, try to restart the system call instead of interrupting it and
       return EINTR. */
    action.sa_flags = SA_RESTART;
    if (chain) {
        /* do not prevent the signal from being received from within its
           own signal handler */
        action.sa_flags = SA_NODEFER;
    }
#ifdef FAULTHANDLER_USE_ALT_STACK
    assert(stack.ss_sp != NULL);
    /* Call the signal handler on an alternate signal stack
       provided by sigaltstack() */
    action.sa_flags |= SA_ONSTACK;
#endif
    return sigaction(signum, &action, previous_p);
#else
    _Py_sighandler_t previous;
    previous = signal(signum, user_handler);
    if (previous_p != NULL) {
        *previous_p = previous;
    }
    return (previous == SIG_ERR);
#endif
}

/* Handler of user signals (e.g. SIGUSR1).

   Dump the traceback of the current thread, or of all threads if
   thread.all_threads is true.

   This function is signal safe and should only call signal safe functions. */

static void
user_handler(int signum)
{
    user_signal_t *user;
    int save_errno = errno;

    user = &user_signals[signum];
    if (!user->enabled)
        return;

    dump_traceback(user->fd, user->all_threads, user->interp);

#ifdef HAVE_SIGACTION
    if (user->chain) {
        (void)sigaction(signum, &user->previous, NULL);
        errno = save_errno;

        /* call the previous signal handler */
        raise(signum);

        save_errno = errno;
        (void)register_user_handler(signum, user->chain, NULL);
        errno = save_errno;
    }
#else
    if (user->chain && user->previous != NULL) {
        errno = save_errno;
        /* call the previous signal handler */
        user->previous(signum);
    }
#endif
}

static int
check_signum(int signum)
{
    for (size_t i=0; i < faulthandler_nsignals; i++) {
        if (faulthandler_handlers[i].signum == signum) {
            PyErr_Format(PyExc_RuntimeError,
                         "signal %i cannot be registered, "
                         "use enable() instead",
                         signum);
            return 0;
        }
    }
    if (signum < 1 || Py_NSIG <= signum) {
        PyErr_SetString(PyExc_ValueError, "signal number out of range");
        return 0;
    }
    return 1;
}


/*[clinic input]
faulthandler.register

    signum: int
    file: object(c_default='NULL') = sys.stderr
    all_threads: bool = True
    chain: bool = False
    /

Register bla bla bla

register a handler for the signal 'signum': dump the traceback of the current thread, or of all threads if all_threads is True, into file"
[clinic start generated code]*/

static PyObject *
faulthandler_register_impl(PyObject *module, int signum, PyObject *file,
                           int all_threads, int chain)
/*[clinic end generated code: output=e9ed0d71d3007c28 input=8e8c2eee566a18f5]*/
{
    int fd;
    user_signal_t *user;
    _Py_sighandler_t previous;
    PyThreadState *tstate;
    int err;

    if (!check_signum(signum))
        return NULL;

    tstate = get_thread_state();
    if (tstate == NULL)
        return NULL;

    fd = get_fileno(&file);
    if (fd < 0)
        return NULL;

    if (user_signals == NULL) {
        user_signals = PyMem_Calloc(Py_NSIG, sizeof(user_signal_t));
        if (user_signals == NULL)
            return PyErr_NoMemory();
    }
    user = &user_signals[signum];

    if (!user->enabled) {
#ifdef FAULTHANDLER_USE_ALT_STACK
        if (use_alt_stack() < 0) {
            return NULL;
        }
#endif

        err = register_user_handler(signum, chain, &previous);
        if (err) {
            PyErr_SetFromErrno(PyExc_OSError);
            return NULL;
        }

        user->previous = previous;
    }

    Py_XINCREF(file);
    Py_XSETREF(user->file, file);
    user->fd = fd;
    user->all_threads = all_threads;
    user->chain = chain;
    user->interp = PyThreadState_GetInterpreter(tstate);
    user->enabled = 1;

    Py_RETURN_NONE;
}

static int
unregister_user_handler(user_signal_t *user, int signum)
{
    if (!user->enabled)
        return 0;
    user->enabled = 0;
#ifdef HAVE_SIGACTION
    (void)sigaction(signum, &user->previous, NULL);
#else
    (void)signal(signum, user->previous);
#endif
    Py_CLEAR(user->file);
    user->fd = -1;
    return 1;
}


/*[clinic input]
faulthandler.unregister

    signum: int
    /

Unregister bla bla bla

unregister the handler of the signal 'signum' registered by register()"
[clinic start generated code]*/

static PyObject *
faulthandler_unregister_impl(PyObject *module, int signum)
/*[clinic end generated code: output=6f9c1149687cf687 input=4ed49efc6c1700fb]*/
{
    user_signal_t *user;
    int change;

    if (!check_signum(signum))
        return NULL;

    if (user_signals == NULL)
        Py_RETURN_FALSE;

    user = &user_signals[signum];
    change = unregister_user_handler(user, signum);
    return PyBool_FromLong(change);
}
#endif   /* FAULTHANDLER_USER */


static void
suppress_crash_report(void)
{
#ifdef MS_WINDOWS
    UINT mode;

    /* Configure Windows to not display the Windows Error Reporting dialog */
    mode = SetErrorMode(SEM_NOGPFAULTERRORBOX);
    SetErrorMode(mode | SEM_NOGPFAULTERRORBOX);
#endif

#ifdef HAVE_SYS_RESOURCE_H
    struct rlimit rl;

    /* Disable creation of core dump */
    if (getrlimit(RLIMIT_CORE, &rl) == 0) {
        rl.rlim_cur = 0;
        setrlimit(RLIMIT_CORE, &rl);
    }
#endif

#ifdef _MSC_VER
    /* Visual Studio: configure abort() to not display an error message nor
       open a popup asking to report the fault. */
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
#endif
}


/*[clinic input]
faulthandler._read_null

Read BLA BLA BLA !!!!

read from NULL, raise a SIGSEGV or SIGBUS signal depending on the platform
[clinic start generated code]*/

static PyObject *
faulthandler__read_null_impl(PyObject *module)
/*[clinic end generated code: output=c7ad9056c81209c0 input=b489511f3dfd2b8c]*/
{
    volatile int *x;
    volatile int y;

    suppress_crash_report();
    x = NULL;
    y = *x;
    return PyLong_FromLong(y);
}

static void
raise_sigsegv(void)
{
    suppress_crash_report();
#if defined(MS_WINDOWS)
    /* For SIGSEGV, fatal_error_handler() restores the previous signal
       handler and then gives back the execution flow to the program (without
       explicitly calling the previous error handler). In a normal case, the
       SIGSEGV was raised by the kernel because of a fault, and so if the
       program retries to execute the same instruction, the fault will be
       raised again.

       Here the fault is simulated by a fake SIGSEGV signal raised by the
       application. We have to raise SIGSEGV at lease twice: once for
       fatal_error_handler(), and one more time for the previous signal
       handler. */
    while(1)
        raise(SIGSEGV);
#else
    raise(SIGSEGV);
#endif
}


/*[clinic input]
faulthandler._sigsegv

    release_gil: bool = False
    /

Raise BLA BL ABL A!!!

raise a SIGSEGV signal
[clinic start generated code]*/

static PyObject *
faulthandler__sigsegv_impl(PyObject *module, int release_gil)
/*[clinic end generated code: output=96e5a2f215b01b76 input=e85f891c203dadc1]*/
{
    if (release_gil) {
        Py_BEGIN_ALLOW_THREADS
        raise_sigsegv();
        Py_END_ALLOW_THREADS
    } else {
        raise_sigsegv();
    }
    Py_RETURN_NONE;
}

static void _Py_NO_RETURN
fatal_error_thread(void *plock)
{
    Py_FatalError("in new thread");
}

/*[clinic input]
faulthandler._fatal_error_c_thread

Call this thing.

call Py_FatalError() in a new C thread.
[clinic start generated code]*/

static PyObject *
faulthandler__fatal_error_c_thread_impl(PyObject *module)
/*[clinic end generated code: output=101bc8aaf4a5eec1 input=3148172a01eb998a]*/
{
    long tid;
    PyThread_type_lock lock;

    suppress_crash_report();

    lock = PyThread_allocate_lock();
    if (lock == NULL)
        return PyErr_NoMemory();

    PyThread_acquire_lock(lock, WAIT_LOCK);

    tid = PyThread_start_new_thread(fatal_error_thread, lock);
    if (tid == -1) {
        PyThread_free_lock(lock);
        PyErr_SetString(PyExc_RuntimeError, "unable to start the thread");
        return NULL;
    }

    /* wait until the thread completes: it will never occur, since Py_FatalError()
       exits the process immediately. */
    PyThread_acquire_lock(lock, WAIT_LOCK);
    PyThread_release_lock(lock);
    PyThread_free_lock(lock);

    Py_RETURN_NONE;
}

/*[clinic input]
faulthandler._sigfpe

SIGFPE GLA BLA BLAH

raise a SIGFPE signal
[clinic start generated code]*/

static PyObject *
faulthandler__sigfpe_impl(PyObject *module)
/*[clinic end generated code: output=dec9c98100e986db input=0aadab1eca865dee]*/
{
    suppress_crash_report();

    /* Do an integer division by zero: raise a SIGFPE on Intel CPU, but not on
       PowerPC. Use volatile to disable compile-time optimizations. */
    volatile int x = 1, y = 0, z;
    z = x / y;

    /* If the division by zero didn't raise a SIGFPE (e.g. on PowerPC),
       raise it manually. */
    raise(SIGFPE);

    /* This line is never reached, but we pretend to make something with z
       to silence a compiler warning. */
    return PyLong_FromLong(z);
}

/*[clinic input]
faulthandler._sigabrt

SIGABRT OK?

raise a SIGABRT signal
[clinic start generated code]*/

static PyObject *
faulthandler__sigabrt_impl(PyObject *module)
/*[clinic end generated code: output=58c1378a0c166682 input=6a1870b9370fa2b3]*/
{
    suppress_crash_report();
    abort();
    Py_RETURN_NONE;
}

#if defined(FAULTHANDLER_USE_ALT_STACK)
#define FAULTHANDLER_STACK_OVERFLOW

static uintptr_t
stack_overflow(uintptr_t min_sp, uintptr_t max_sp, size_t *depth)
{
    /* Allocate (at least) 4096 bytes on the stack at each call.

       bpo-23654, bpo-38965: use volatile keyword to prevent tail call
       optimization. */
    volatile unsigned char buffer[4096];
    uintptr_t sp = (uintptr_t)&buffer;
    *depth += 1;
    if (sp < min_sp || max_sp < sp)
        return sp;
    buffer[0] = 1;
    buffer[4095] = 0;
    return stack_overflow(min_sp, max_sp, depth);
}

/*[clinic input]
faulthandler._stack_overflow

BLA BLA BLA TIRED I AM

perform recursive call to raise a stack overflow
[clinic start generated code]*/

static PyObject *
faulthandler__stack_overflow_impl(PyObject *module)
/*[clinic end generated code: output=efffba4be522d8fb input=bafc6367176ddb26]*/
{
    size_t depth, size;
    uintptr_t sp = (uintptr_t)&depth;
    uintptr_t stop, lower_limit, upper_limit;

    suppress_crash_report();
    depth = 0;

    if (STACK_OVERFLOW_MAX_SIZE <= sp) {
        lower_limit = sp - STACK_OVERFLOW_MAX_SIZE;
    }
    else {
        lower_limit = 0;
    }

    if (UINTPTR_MAX - STACK_OVERFLOW_MAX_SIZE >= sp) {
        upper_limit = sp + STACK_OVERFLOW_MAX_SIZE;
    }
    else {
        upper_limit = UINTPTR_MAX;
    }

    stop = stack_overflow(lower_limit, upper_limit, &depth);
    if (sp < stop)
        size = stop - sp;
    else
        size = sp - stop;
    PyErr_Format(PyExc_RuntimeError,
        "unable to raise a stack overflow (allocated %zu bytes "
        "on the stack, %zu recursive calls)",
        size, depth);
    return NULL;
}
#endif   /* defined(FAULTHANDLER_USE_ALT_STACK) && defined(HAVE_SIGACTION) */


static int
faulthandler_traverse(PyObject *module, visitproc visit, void *arg)
{
    Py_VISIT(thread.file);
#ifdef FAULTHANDLER_USER
    if (user_signals != NULL) {
        for (size_t signum=0; signum < Py_NSIG; signum++)
            Py_VISIT(user_signals[signum].file);
    }
#endif
    Py_VISIT(fatal_error.file);
    return 0;
}

#ifdef MS_WINDOWS
/*[clinic input]
faulthandler._raise_exception

    code: unsigned_int
    flags: unsigned_int
    /

RAISE FOOOO

Call RaiseException(code, flags).
[clinic start generated code]*/

static PyObject *
faulthandler__raise_exception_impl(PyObject *module, unsigned int code,
                                   unsigned int flags)
/*[clinic end generated code: output=2346cf318eab10dc input=ef66ae73b6187626]*/
{
    suppress_crash_report();
    RaiseException(code, flags, 0, NULL);
    Py_RETURN_NONE;
}
#endif

PyDoc_STRVAR(module_doc,
"faulthandler module.");

static PyMethodDef module_methods[] = {
    FAULTHANDLER_ENABLE_METHODDEF
    FAULTHANDLER_DISABLE_METHODDEF
    FAULTHANDLER_IS_ENABLED_METHODDEF
    FAULTHANDLER_DUMP_TRACEBACK_METHODDEF
    FAULTHANDLER_DUMP_TRACEBACK_LATER_METHODDEF
    FAULTHANDLER_CANCEL_DUMP_TRACEBACK_LATER_METHODDEF
#ifdef FAULTHANDLER_USER
    FAULTHANDLER_REGISTER_METHODDEF
    FAULTHANDLER_UNREGISTER_METHODDEF
#endif
    FAULTHANDLER__READ_NULL_METHODDEF
    FAULTHANDLER__SIGSEGV_METHODDEF
    FAULTHANDLER__FATAL_ERROR_C_THREAD_METHODDEF
    FAULTHANDLER__SIGABRT_METHODDEF
    FAULTHANDLER__SIGFPE_METHODDEF
#ifdef FAULTHANDLER_STACK_OVERFLOW
    FAULTHANDLER__STACK_OVERFLOW_METHODDEF
#endif
#ifdef MS_WINDOWS
    FAULTHANDLER__RAISE_EXCEPTION_METHODDEF
#endif
    {NULL, NULL}  /* sentinel */
};

static int
PyExec_faulthandler(PyObject *module) {
    /* Add constants for unit tests */
#ifdef MS_WINDOWS
    /* RaiseException() codes (prefixed by an underscore) */
    if (PyModule_AddIntConstant(module, "_EXCEPTION_ACCESS_VIOLATION",
                                EXCEPTION_ACCESS_VIOLATION)) {
        return -1;
    }
    if (PyModule_AddIntConstant(module, "_EXCEPTION_INT_DIVIDE_BY_ZERO",
                                EXCEPTION_INT_DIVIDE_BY_ZERO)) {
        return -1;
    }
    if (PyModule_AddIntConstant(module, "_EXCEPTION_STACK_OVERFLOW",
                                EXCEPTION_STACK_OVERFLOW)) {
        return -1;
    }

    /* RaiseException() flags (prefixed by an underscore) */
    if (PyModule_AddIntConstant(module, "_EXCEPTION_NONCONTINUABLE",
                                EXCEPTION_NONCONTINUABLE)) {
        return -1;
    }
    if (PyModule_AddIntConstant(module, "_EXCEPTION_NONCONTINUABLE_EXCEPTION",
                                EXCEPTION_NONCONTINUABLE_EXCEPTION)) {
        return -1;
    }
#endif
    return 0;
}

static PyModuleDef_Slot faulthandler_slots[] = {
    {Py_mod_exec, PyExec_faulthandler},
    {0, NULL}
};

static struct PyModuleDef module_def = {
    PyModuleDef_HEAD_INIT,
    .m_name = "faulthandler",
    .m_doc = module_doc,
    .m_methods = module_methods,
    .m_traverse = faulthandler_traverse,
    .m_slots = faulthandler_slots
};

PyMODINIT_FUNC
PyInit_faulthandler(void)
{
    return PyModuleDef_Init(&module_def);
}

static int
faulthandler_init_enable(void)
{
    PyObject *enable = _PyImport_GetModuleAttrString("faulthandler", "enable");
    if (enable == NULL) {
        return -1;
    }

    PyObject *res = PyObject_CallNoArgs(enable);
    Py_DECREF(enable);
    if (res == NULL) {
        return -1;
    }
    Py_DECREF(res);

    return 0;
}

PyStatus
_PyFaulthandler_Init(int enable)
{
#ifdef FAULTHANDLER_USE_ALT_STACK
    memset(&stack, 0, sizeof(stack));
    stack.ss_flags = 0;
    /* bpo-21131: allocate dedicated stack of SIGSTKSZ*2 bytes, instead of just
       SIGSTKSZ bytes. Calling the previous signal handler in faulthandler
       signal handler uses more than SIGSTKSZ bytes of stack memory on some
       platforms. */
    stack.ss_size = SIGSTKSZ * 2;
#ifdef AT_MINSIGSTKSZ
    /* bpo-46968: Query Linux for minimal stack size to ensure signal delivery
       for the hardware running CPython. This OS feature is available in
       Linux kernel version >= 5.14 */
    unsigned long at_minstack_size = getauxval(AT_MINSIGSTKSZ);
    if (at_minstack_size != 0) {
        stack.ss_size = SIGSTKSZ + at_minstack_size;
    }
#endif
#endif

    memset(&thread, 0, sizeof(thread));

    if (enable) {
        if (faulthandler_init_enable() < 0) {
            return _PyStatus_ERR("failed to enable faulthandler");
        }
    }
    return _PyStatus_OK();
}

void _PyFaulthandler_Fini(void)
{
    /* later */
    if (thread.cancel_event) {
        cancel_dump_traceback_later();
        PyThread_release_lock(thread.cancel_event);
        PyThread_free_lock(thread.cancel_event);
        thread.cancel_event = NULL;
    }
    if (thread.running) {
        PyThread_free_lock(thread.running);
        thread.running = NULL;
    }

#ifdef FAULTHANDLER_USER
    /* user */
    if (user_signals != NULL) {
        for (size_t signum=0; signum < Py_NSIG; signum++) {
            unregister_user_handler(&user_signals[signum], signum);
        }
        PyMem_Free(user_signals);
        user_signals = NULL;
    }
#endif

    /* fatal */
    disable_fatal_handler();

#ifdef FAULTHANDLER_USE_ALT_STACK
    if (stack.ss_sp != NULL) {
        /* Fetch the current alt stack */
        stack_t current_stack;
        memset(&current_stack, 0, sizeof(current_stack));
        if (sigaltstack(NULL, &current_stack) == 0) {
            if (current_stack.ss_sp == stack.ss_sp) {
                /* The current alt stack is the one that we installed.
                 It is safe to restore the old stack that we found when
                 we installed ours */
                sigaltstack(&old_stack, NULL);
            } else {
                /* Someone switched to a different alt stack and didn't
                   restore ours when they were done (if they're done).
                   There's not much we can do in this unlikely case */
            }
        }
        PyMem_Free(stack.ss_sp);
        stack.ss_sp = NULL;
    }
#endif
}
