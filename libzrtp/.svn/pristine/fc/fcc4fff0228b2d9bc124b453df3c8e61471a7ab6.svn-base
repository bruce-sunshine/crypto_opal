s/^#undef  *\([ABCDEFGHIJKLMNOPQRSTUVWXYZ_]\)/#undef ZRTP_\1/
s/^#undef  *\([abcdefghijklmnopqrstuvwxyz]\)/#undef _zrtp_\1/
s/^#define  *\([ABCDEFGHIJKLMNOPQRSTUVWXYZ_][abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_]*\)\(.*\)/#ifndef ZRTP_\1 \
#define ZRTP_\1 \2 \
#endif/
s/^#define  *\([abcdefghijklmnopqrstuvwxyz][abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_]*\)\(.*\)/#ifndef _zrtp_\1 \
#define _zrtp_\1 \2 \
#endif/
