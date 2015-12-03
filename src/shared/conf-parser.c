/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <netinet/ether.h>
#include <ctype.h>

#include "conf-parser.h"
#include "conf-files.h"
#include "util.h"
#include "macro.h"
#include "strv.h"
#include "log.h"
#include "utf8.h"
#include "path-util.h"
#include "set.h"
#include "exit-status.h"
#include "sd-messages.h"

int log_syntax_internal(
                const char *unit,
                int level,
                const char *file,
                int line,
                const char *func,
                const char *config_file,
                unsigned config_line,
                int error,
                const char *format, ...) {

        _cleanup_free_ char *msg = NULL;
        int r;
        va_list ap;

        va_start(ap, format);
        r = vasprintf(&msg, format, ap);
        va_end(ap);
        if (r < 0)
                return log_oom();

        if (unit)
                r = log_struct_internal(level,
                                        error,
                                        file, line, func,
                                        getpid() == 1 ? "UNIT=%s" : "USER_UNIT=%s", unit,
                                        LOG_MESSAGE_ID(SD_MESSAGE_CONFIG_ERROR),
                                        "CONFIG_FILE=%s", config_file,
                                        "CONFIG_LINE=%u", config_line,
                                        LOG_MESSAGE("[%s:%u] %s", config_file, config_line, msg),
                                        NULL);
        else
                r = log_struct_internal(level,
                                        error,
                                        file, line, func,
                                        LOG_MESSAGE_ID(SD_MESSAGE_CONFIG_ERROR),
                                        "CONFIG_FILE=%s", config_file,
                                        "CONFIG_LINE=%u", config_line,
                                        LOG_MESSAGE("[%s:%u] %s", config_file, config_line, msg),
                                        NULL);

        return r;
}

/* Run the user supplied parser for an assignment */
static int next_assignment(const char * __restrict__ unit,
                           const char * __restrict__ filename,
                           unsigned line,
                           bool perf_lookup,
                           const void * __restrict__ table,
                           char *section,
                           unsigned section_line,
                           char *lvalue,
                           const char * __restrict__ rvalue,
                           uint_fast32_t len_section,
                           uint_fast32_t len_lvalue,
                           bool relaxed,
                           void * __restrict__ userdata) {

        ConfigParserCallback func = NULL;
        int ltype;
        void *data;

        assert(filename);
        assert(line > 0);
        assert(lvalue);
        assert(rvalue);
        assert(table);

        if (perf_lookup) {
                ConfigPerfItemLookup lookup = (ConfigPerfItemLookup) table;
                ConfigPerfItem const *p;
                char const *key = lvalue;
                uint_fast32_t len_key = len_lvalue;

                if (section) {
                        key = section;
                        section[len_section] = '.';
                        memmove(section + len_section + 1, lvalue, len_lvalue);
                        section[len_section + 1 + len_lvalue] = '\0';
                        lvalue = section + len_section + 1;
                        len_key += len_section + 1;
                }

                p = lookup(key, len_key);

                if (section)
                        section[len_section] = '\0';

                if (p) {
                        func = p->parse;
                        ltype = p->ltype;
                        data = (uint8_t*) userdata + p->offset;
                }
        } else {
                const ConfigTableItem *t;
                uint_fast32_t const size_lvalue = len_lvalue + 1;
                uint_fast32_t size_section = len_section + 1;

                for (t = (ConfigTableItem const *)table; t->lvalue; ++t) {

                        if (memcmp(lvalue, t->lvalue, size_lvalue))
                                continue;

                        if (section) {
                                if (!t->section || memcmp(section, t->section, size_section))
                                        continue;
                        } else if (t->section)
                                continue;

                        func = t->parse;
                        ltype = t->ltype;
                        data = t->data;
                        break;
                }
        }

        if (func)
                return func(unit, filename, line, section, section_line,
                            lvalue, ltype, rvalue, data, userdata);

        /* Warn about unknown non-extension fields. */
        if (!relaxed && !startswith(lvalue, "X-"))
                log_syntax(unit, LOG_WARNING, filename, line, EINVAL,
                           "Unknown lvalue '%s' in section '%s'", lvalue, section);

        return 0;
}

/* Parse a variable assignment line */
static int parse_line(const char * __restrict__ unit,
                      const char * __restrict__ filename,
                      uint_fast32_t line,
                      const char * __restrict__ sections,
                      bool perf_lookup,
                      const void * __restrict__ table,
                      bool relaxed,
                      bool allow_include,
                      char * __restrict__ * __restrict__ section,
                      uint_fast32_t * __restrict__ section_line,
                      uint_fast32_t * __restrict__ len_section,
                      bool * __restrict__ section_seen,
                      char * __restrict__ l,
                      uint_fast32_t l_size,
                      bool buffers_beg /* first line, no heading whitespace */,
                      bool buffers_end /* last line, no trailing whitespace */,
                      void * __restrict__ userdata) {

        char *e;
        char *f;
        uint_fast32_t e_size;
        char fallback[256];
        int r;

        assert(filename);
        assert(line > 0);
        assert(l);
        assert(l_size > 0);

        {
                char first = *l;

                if ('[' == first) {
                        char *n;

                        if (l[l_size-1] != ']') {
                                log_syntax(unit, LOG_ERR, filename, line, EBADMSG,
                                           "Invalid section header '%s'", l);
                                return -EBADMSG;
                        }

                        *section_seen = true;

                        l[l_size-1] = '\0';

                        n = l+1;

                        if (sections && !nulstr_contains(sections, n)) {

                                if (!relaxed && !startswith(n, "X-"))
                                        log_syntax(unit, LOG_WARNING, filename, line, EINVAL,
                                                   "Unknown section '%s'. Ignoring.", n);

                                *section = NULL;
                                *section_line = 0;
                        } else {
                                *section = n;
                                *section_line = line;
                                *len_section = l_size - 2;
                        }

                        return 0;
                }
                else if (_unlikely_('.' == first) && !memcmp(l+1, "include ", 8)) {
                        _cleanup_free_ char *fn = NULL;
                        char *p;

                        /* .includes are a bad idea, we only support them here
                         * for historical reasons. They create cyclic include
                         * problems and make it difficult to detect
                         * configuration file changes with an easy
                         * stat(). Better approaches, such as .d/ drop-in
                         * snippets exist.
                         *
                         * Support for them should be eventually removed. */

                        if (!allow_include) {
                                log_syntax(unit, LOG_ERR, filename, line, EBADMSG,
                                           ".include not allowed here. Ignoring.");
                                return 0;
                        }

                        p = l+9;
                        if (_unlikely_(buffers_end)) {
                            memmove(p-1, p, l_size-9);
                            --p;
                        }
                        p[l_size-9] = '\0';

                        fn = file_in_same_dir(filename, p);
                        if (_unlikely_(!fn))
                                return -ENOMEM;

                        return config_parse(unit, fn, NULL, sections, perf_lookup, table, relaxed, false, false, userdata);
                }
        }

        if (sections && !*section) {

                if (!relaxed && !*section_seen)
                        log_syntax(unit, LOG_WARNING, filename, line, EINVAL,
                                   "Assignment outside of section. Ignoring.");

                return 0;
        }

        e = (char*)memchr(l, '=', l_size);
        if (_unlikely_(!e)) {
                log_syntax(unit, LOG_WARNING, filename, line, EINVAL, "Missing '='.");
                return -EBADMSG;
        }

        f = e;
        while (--e >= l && isspace(*e));
        e_size = e-l+1;
        while (++f < l+l_size && isspace(*f));
        e[1] = '\0';

        if (_unlikely_(buffers_end)) {
                if (e+1 == f-1) {
                        if (_unlikely_(buffers_beg)) {

                                if (_likely_(e_size < sizeof(fallback)))
                                        e = fallback;
                                else if (!(e = new(char, e_size+1)))
                                        return -ENOMEM;

                                memcpy(e, l, e_size);
                        } else {
                                memmove(l-1, l, e_size);
                                e = l-1;
                        }
                } else
                        e = l;

                memmove(f-1, f, l_size - (f-l));
                --f;
                --l_size;
        } else
                e = l;

        e[e_size] = '\0';
        l[l_size] = '\0';

        r = next_assignment(unit,
                            filename,
                            line,
                            perf_lookup,
                            table,
                            *section,
                            *section_line,
                            e,
                            f,
                            *len_section,
                            e_size,
                            relaxed,
                            userdata);

        if (_unlikely_(e != l) && _unlikely_(e != l-1) && _unlikely_(e != fallback))
                free(e);

        return r;
}

/* Go through the file and parse each line */
int config_parse(const char * __restrict__ unit,
                 const char * __restrict__ filename,
                 FILE * __restrict__ f,
                 const char * __restrict__ sections,
                 bool perf_lookup,
                 const void * __restrict__ table,
                 bool relaxed,
                 bool allow_include,
                 bool warn,
                 void * __restrict__ userdata) {

        char *section = NULL;
        char *line = NULL;
        uint_fast32_t lineno = 0, section_line = 0;
        int fd, r = 0;
        uint_fast32_t size, s, line_size, len_section;
        bool in_comment;
        char * __restrict__ ptr, *p;
        bool section_seen = false;

        assert(filename);

        fd = f ? fileno(f) : open(filename, O_RDONLY);
        if (_unlikely_(fd < 0)) {
                /* Only log on request, except for ENOENT,
                 * since we return 0 to the caller. */
                if (warn || errno == ENOENT)
                        log_full(errno == ENOENT ? LOG_DEBUG : LOG_ERR,
                                 "Failed to open configuration file '%s': %m", filename);
                return errno == ENOENT ? 0 : -errno;
        }

        {
                struct stat st;

                if (_unlikely_(fstat(fd, &st))) {
                        r = -errno;
                        goto close;
                }

                if (_unlikely_(st.st_size <= 0))
                        goto close;

                if (_unlikely_(st.st_size > UINT32_MAX)) {
                        r = ENOMEM;
                        goto close;
                }

                size = st.st_size;
        }

        fd_warn_permissions(filename, fd);

        ptr = (char*)mmap(0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

        if (_unlikely_(MAP_FAILED == ptr)) {
                r = -errno;
                goto close;
        }

        p = ptr;
        s = size;
        for (;;) {
                char *nl = (char*)memchr(p, '\n', s);
                uint_fast32_t nl_size = _likely_(nl) ? (uint_fast32_t)(nl-p) : s;

                s -= nl_size + 1;

                if (line) {
                        if (_likely_(!in_comment))
                                memmove(line + line_size, p, nl_size);
                        else
                                ++line_size;

                        line_size += nl_size;
                } else {
                        char c = '\0';
                        while (nl_size) {
                                c = *p;
                                if (!isspace(c))
                                        break;
                                ++p;
                                --nl_size;
                        }

                        line = p;
                        line_size = nl_size;
                        in_comment = (';' == c || '#' == c);
                }

                p += nl_size + 1;

                {
                        uint_fast32_t i = line_size;
                        int_fast8_t escaped = 0;

                        while (i && _unlikely_('\\' == line[--i]))
                                escaped = ~escaped;

                        if (_unlikely_(escaped)) {
                                if (_likely_(line_size > 1))
                                        line[line_size-1] = ' ';
                                else /* just whitespace with \\ at the end -> skip */
                                        line = NULL;

                                if (_likely_(nl))
                                        continue;
                                if (_unlikely_(line_size == 1))
                                        break;
                        }
                }

                ++lineno;

                if (_likely_(!in_comment)) {
                        while (line_size && isspace(line[line_size-1]))
                                --line_size;

                        if (_likely_(line_size))
                                r = parse_line(unit,
                                               filename,
                                               lineno,
                                               sections,
                                               perf_lookup,
                                               table,
                                               relaxed,
                                               allow_include,
                                               &section,
                                               &section_line,
                                               &len_section,
                                               &section_seen,
                                               line,
                                               line_size,
                                               _unlikely_(line == ptr),
                                               _unlikely_(line+line_size == ptr+size),
                                               userdata);
                }

                if (_unlikely_(!nl || r)) {
                        if (_unlikely_(warn && r))
                                log_warning_errno(r, "Failed to parse file '%s': %m",
                                                  filename);
                        break;
                }

                line = NULL;
        }

        assert_se(munmap(ptr, size) == 0);

close:
        if (!f)
                safe_close(fd);

        return r;
}

/* Parse each config file in the specified directories. */
int config_parse_many(const char *conf_file,
                      const char *conf_file_dirs,
                      const char *sections,
                      bool perf_lookup,
                      const void *table,
                      bool relaxed,
                      void *userdata) {
        _cleanup_strv_free_ char **files = NULL;
        char **fn;
        int r;

        r = conf_files_list_nulstr(&files, ".conf", NULL, conf_file_dirs);
        if (r < 0)
                return r;

        if (conf_file) {
                r = config_parse(NULL, conf_file, NULL, sections, perf_lookup, table, relaxed, false, true, userdata);
                if (r < 0)
                        return r;
        }

        STRV_FOREACH(fn, files) {
                r = config_parse(NULL, *fn, NULL, sections, perf_lookup, table, relaxed, false, true, userdata);
                if (r < 0)
                        return r;
        }

        return 0;
}

#define DEFINE_PARSER(type, vartype, conv_func)                         \
        int config_parse_##type(const char *unit,                       \
                                const char *filename,                   \
                                unsigned line,                          \
                                const char *section,                    \
                                unsigned section_line,                  \
                                const char *lvalue,                     \
                                int ltype,                              \
                                const char *rvalue,                     \
                                void *data,                             \
                                void *userdata) {                       \
                                                                        \
                vartype *i = data;                                      \
                int r;                                                  \
                                                                        \
                assert(filename);                                       \
                assert(lvalue);                                         \
                assert(rvalue);                                         \
                assert(data);                                           \
                                                                        \
                r = conv_func(rvalue, i);                               \
                if (r < 0)                                              \
                        log_syntax(unit, LOG_ERR, filename, line, -r,   \
                                   "Failed to parse %s value, ignoring: %s", \
                                   #vartype, rvalue);                   \
                                                                        \
                return 0;                                               \
        }

DEFINE_PARSER(int, int, safe_atoi)
DEFINE_PARSER(long, long, safe_atoli)
DEFINE_PARSER(uint64, uint64_t, safe_atou64)
DEFINE_PARSER(unsigned, unsigned, safe_atou)
DEFINE_PARSER(double, double, safe_atod)
DEFINE_PARSER(nsec, nsec_t, parse_nsec)
DEFINE_PARSER(sec, usec_t, parse_sec)

int config_parse_iec_size(const char* unit,
                            const char *filename,
                            unsigned line,
                            const char *section,
                            unsigned section_line,
                            const char *lvalue,
                            int ltype,
                            const char *rvalue,
                            void *data,
                            void *userdata) {

        size_t *sz = data;
        off_t o;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = parse_size(rvalue, 1024, &o);
        if (r < 0 || (off_t) (size_t) o != o) {
                log_syntax(unit, LOG_ERR, filename, line, r < 0 ? -r : ERANGE, "Failed to parse size value, ignoring: %s", rvalue);
                return 0;
        }

        *sz = (size_t) o;
        return 0;
}

int config_parse_si_size(const char* unit,
                            const char *filename,
                            unsigned line,
                            const char *section,
                            unsigned section_line,
                            const char *lvalue,
                            int ltype,
                            const char *rvalue,
                            void *data,
                            void *userdata) {

        size_t *sz = data;
        off_t o;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        r = parse_size(rvalue, 1000, &o);
        if (r < 0 || (off_t) (size_t) o != o) {
                log_syntax(unit, LOG_ERR, filename, line, r < 0 ? -r : ERANGE, "Failed to parse size value, ignoring: %s", rvalue);
                return 0;
        }

        *sz = (size_t) o;
        return 0;
}

int config_parse_iec_off(const char* unit,
                           const char *filename,
                           unsigned line,
                           const char *section,
                           unsigned section_line,
                           const char *lvalue,
                           int ltype,
                           const char *rvalue,
                           void *data,
                           void *userdata) {

        off_t *bytes = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        assert_cc(sizeof(off_t) == sizeof(uint64_t));

        r = parse_size(rvalue, 1024, bytes);
        if (r < 0)
                log_syntax(unit, LOG_ERR, filename, line, -r, "Failed to parse size value, ignoring: %s", rvalue);

        return 0;
}

int config_parse_bool(const char* unit,
                      const char *filename,
                      unsigned line,
                      const char *section,
                      unsigned section_line,
                      const char *lvalue,
                      int ltype,
                      const char *rvalue,
                      void *data,
                      void *userdata) {

        int k;
        bool *b = data;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        k = parse_boolean(rvalue);
        if (k < 0) {
                log_syntax(unit, LOG_ERR, filename, line, -k,
                           "Failed to parse boolean value, ignoring: %s", rvalue);
                return 0;
        }

        *b = !!k;
        return 0;
}

int config_parse_string(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        char **s = data, *n;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (!utf8_is_valid(rvalue)) {
                log_invalid_utf8(unit, LOG_ERR, filename, line, EINVAL, rvalue);
                return 0;
        }

        if (isempty(rvalue))
                n = NULL;
        else {
                n = strdup(rvalue);
                if (!n)
                        return log_oom();
        }

        free(*s);
        *s = n;

        return 0;
}

int config_parse_path(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        char **s = data, *n;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (!utf8_is_valid(rvalue)) {
                log_invalid_utf8(unit, LOG_ERR, filename, line, EINVAL, rvalue);
                return 0;
        }

        if (!path_is_absolute(rvalue)) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL, "Not an absolute path, ignoring: %s", rvalue);
                return 0;
        }

        n = strdup(rvalue);
        if (!n)
                return log_oom();

        path_kill_slashes(n);

        free(*s);
        *s = n;

        return 0;
}

int config_parse_strv(const char *unit,
                      const char *filename,
                      unsigned line,
                      const char *section,
                      unsigned section_line,
                      const char *lvalue,
                      int ltype,
                      const char *rvalue,
                      void *data,
                      void *userdata) {

        char ***sv = data;
        const char *word, *state;
        size_t l;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (isempty(rvalue)) {
                char **empty;

                /* Empty assignment resets the list. As a special rule
                 * we actually fill in a real empty array here rather
                 * than NULL, since some code wants to know if
                 * something was set at all... */
                empty = strv_new(NULL, NULL);
                if (!empty)
                        return log_oom();

                strv_free(*sv);
                *sv = empty;
                return 0;
        }

        FOREACH_WORD_QUOTED(word, l, rvalue, state) {
                char *n;

                n = strndup(word, l);
                if (!n)
                        return log_oom();

                if (!utf8_is_valid(n)) {
                        log_invalid_utf8(unit, LOG_ERR, filename, line, EINVAL, rvalue);
                        free(n);
                        continue;
                }

                r = strv_consume(sv, n);
                if (r < 0)
                        return log_oom();
        }
        if (!isempty(state))
                log_syntax(unit, LOG_ERR, filename, line, EINVAL,
                           "Trailing garbage, ignoring.");

        return 0;
}

int config_parse_mode(const char *unit,
                      const char *filename,
                      unsigned line,
                      const char *section,
                      unsigned section_line,
                      const char *lvalue,
                      int ltype,
                      const char *rvalue,
                      void *data,
                      void *userdata) {

        mode_t *m = data;
        long l;
        char *x = NULL;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        errno = 0;
        l = strtol(rvalue, &x, 8);
        if (!x || x == rvalue || *x || errno) {
                log_syntax(unit, LOG_ERR, filename, line, errno,
                           "Failed to parse mode value, ignoring: %s", rvalue);
                return 0;
        }

        if (l < 0000 || l > 07777) {
                log_syntax(unit, LOG_ERR, filename, line, ERANGE,
                           "Mode value out of range, ignoring: %s", rvalue);
                return 0;
        }

        *m = (mode_t) l;
        return 0;
}

int config_parse_log_facility(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {


        int *o = data, x;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        x = log_facility_unshifted_from_string(rvalue);
        if (x < 0) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL, "Failed to parse log facility, ignoring: %s", rvalue);
                return 0;
        }

        *o = (x << 3) | LOG_PRI(*o);

        return 0;
}

int config_parse_log_level(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {


        int *o = data, x;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        x = log_level_from_string(rvalue);
        if (x < 0) {
                log_syntax(unit, LOG_ERR, filename, line, EINVAL, "Failed to parse log level, ignoring: %s", rvalue);
                return 0;
        }

        *o = (*o & LOG_FACMASK) | x;
        return 0;
}
