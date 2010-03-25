#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.62])
AC_INIT(minidlna, 0.1, dominik.epple@googlemail.com)
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([albumart.c])
AM_CONFIG_HEADER([config.h])

AC_CANONICAL_HOST

# Checks for programs.
AC_PROG_AWK
AC_PROG_CC
AC_PROG_INSTALL

# Checks for libraries.
AC_CHECK_LIB([FLAC], [main],, AC_MSG_ERROR(Cannot find required library FLAC.))
AC_CHECK_LIB([avformat], [main],, AC_MSG_ERROR(Cannot find required library avformat.))
AC_CHECK_LIB([exif], [main],, AC_MSG_ERROR(Cannot find required library exif.))
AC_CHECK_LIB([id3tag], [main],, AC_MSG_ERROR(Cannot find required library id3tag.))
AC_CHECK_LIB([jpeg], [main],, AC_MSG_ERROR(Cannot find required library jpeg.))
AC_CHECK_LIB([ogg], [main],, AC_MSG_ERROR(Cannot find required library ogg.))
AC_CHECK_LIB([sqlite3], [main],, AC_MSG_ERROR(Cannot find required library sqlite3.))
AC_CHECK_LIB([vorbis], [main],, AC_MSG_ERROR(Cannot find required library vorbis.))

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h locale.h netdb.h netinet/in.h stddef.h stdlib.h string.h sys/file.h sys/ioctl.h sys/param.h sys/socket.h sys/time.h unistd.h])

AC_CHECK_HEADER(avutil.h,, AC_MSG_ERROR(Cannot find required header file avutil.h.))
AC_CHECK_HEADER(avcodec.h,, AC_MSG_ERROR(Cannot find required header file avcodec.h.))
AC_CHECK_HEADER(avformat.h,, AC_MSG_ERROR(Cannot find required header file avformat.h.))

AC_CHECK_HEADERS([linux/types.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_INT32_T
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_STRUCT_ST_BLOCKS
AC_HEADER_STDBOOL
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([dup2 gethostname gettimeofday inet_ntoa memmove memset mkdir realpath select setlocale socket strcasecmp strchr strdup strerror strncasecmp strpbrk strrchr strstr strtol strtoul])

#AC_ARG_ENABLE (feature, help-string, [action-if-given], [action-if-not-given])

OS_NAME=`uname -s`
OS_VERSION=`uname -r`
# OS Specific stuff
case $OS_NAME in
        Darwin)
                OS_URL=http://www.opensource.apple.com/
                ;;
        OpenBSD)
                MAJORVER=`echo $OS_VERSION | cut -d. -f1`
                MINORVER=`echo $OS_VERSION | cut -d. -f2`
                #echo "OpenBSD majorversion=$MAJORVER minorversion=$MINORVER"
                # rtableid was introduced in OpenBSD 4.0
                if [[ $MAJORVER -ge 4 ]]; then
			AC_DEFINE(PFRULE_HAS_RTABLEID,, [rtableid was introduced in OpenBSD 4.0])
                fi
                # from the 3.8 version, packets and bytes counters are double : in/out
                if [[ \( $MAJORVER -ge 4 \) -o \( $MAJORVER -eq 3 -a $MINORVER -ge 8 \) ]]; then
			AC_DEFINE(PFRULE_INOUT_COUNTS,, [from the 3.8 version, packets and bytes counters are double : in/out])
                fi
                OS_URL=http://www.openbsd.org/
                ;;
        FreeBSD)
                VER=`grep '#define __FreeBSD_version' /usr/include/sys/param.h | awk '{print $3}'`
                if [[ $VER -ge 700049 ]]; then
			AC_DEFINE(PFRULE_INOUT_COUNTS,  [FIXME: update comment])
                fi
                OS_URL=http://www.freebsd.org/
                ;;
        pfSense)
                # we need to detect if PFRULE_INOUT_COUNTS macro is needed
                OS_URL=http://www.pfsense.com/
                ;;
        NetBSD)
                OS_URL=http://www.netbsd.org/
                ;;
        SunOS)
                AC_DEFINE(USE_IPF, 1, [FIXME: update comment])
                AC_DEFINE(LOG_PERROR, 0, [FIXME: update comment])
                AC_DEFINE(SOLARIS_KSTATS, 1, [FIXME: update comment])
                # moved those typedefs into minidlnatypes.h
                OS_URL=http://www.sun.com/solaris/
                ;;
        Linux)
                OS_URL=http://www.kernel.org/
                KERNVERA=`echo $OS_VERSION | awk -F. '{print $1}'`
                KERNVERB=`echo $OS_VERSION | awk -F. '{print $2}'`
                KERNVERC=`echo $OS_VERSION | awk -F. '{print $3}'`
                KERNVERD=`echo $OS_VERSION | awk -F. '{print $4}'`
                #echo "$KERNVERA.$KERNVERB.$KERNVERC.$KERNVERD"
                # NETGEAR ReadyNAS special case
                if [[ -f /etc/raidiator_version ]]; then
                        OS_NAME=$(awk -F'!!|=' '{ print $1 }' /etc/raidiator_version)
                        OS_VERSION=[$(awk -F'!!|[=,.]' '{ print $3"."$4 }' /etc/raidiator_version)]
                        OS_URL="http://www.readynas.com/"
                        DB_PATH="/var/cache/minidlna"
			AC_DEFINE(TIVO,, [Compile in TiVo support])
			AC_DEFINE(NETGEAR,, [Enable NETGEAR-specific tweaks])
			AC_DEFINE(READYNAS,, [Enable ReadyNAS-specific tweaks])
                # Debian GNU/Linux special case
                elif [[ -f /etc/debian_version ]]; then
                        OS_NAME=Debian
                        OS_VERSION=`cat /etc/debian_version`
                        OS_URL=http://www.debian.org/
                        # use lsb_release (Linux Standard Base) when available
                        LSB_RELEASE=`which lsb_release 2>/dev/null`
                        if [[ 0 -eq $? ]]; then
                                OS_NAME=`${LSB_RELEASE} -i -s`
                                OS_VERSION=`${LSB_RELEASE} -r -s`
                        fi
                else
                        # use lsb_release (Linux Standard Base) when available
                        LSB_RELEASE=`which lsb_release 2>/dev/null`
                        if [[ 0 -eq $? ]]; then
                                OS_NAME=`${LSB_RELEASE} -i -s`
                                OS_VERSION=`${LSB_RELEASE} -r -s`
                        fi
                fi
                ;;
        *)
                echo "Unknown OS : $OS_NAME"
                exit 1
                ;;
esac

AC_DEFINE_UNQUOTED(OS_NAME, "$OS_NAME", [Name of the operating system])
AC_DEFINE_UNQUOTED(OS_VERSION, "$OS_NAME/$OS_VERSION", [Version of the operating system])
AC_DEFINE_UNQUOTED(OS_URL, "$OS_URL", [URL for the operating system])

AC_DEFINE_UNQUOTED(DEFAULT_DB_PATH, "$DB_PATH", [full path of the file database])

AC_DEFINE(USE_DAEMON,, [Comment the following line to use home made daemonize() func instead of BSD daemon()])

AC_CHECK_HEADER([iconv.h], 
    [AC_DEFINE(HAVE_ICONV_H,, [Enable if the system iconv.h exists.  ID3 tag reading in various character sets will not work properly otherwise])],
    [], [])

AC_CHECK_HEADER([sys/inotify.h], 
    [AC_DEFINE(HAVE_INOTIFY_H,, [Enable if the system inotify.h exists.  Otherwise our own inotify.h will be used])],
    [], [])
    # trailing unused arguments are: action if not found, includes, see http://www.gnu.org/software/hello/manual/autoconf/Generic-Headers.html

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
