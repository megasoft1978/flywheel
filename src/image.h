/* image.c — image attachments. Paths and URLs given here must come from the
   user's own input, never from the model, a tool result or a project file:
   file loading is not confined to the project directory. */
#ifndef FW_IMAGE_H
#define FW_IMAGE_H

#include "flywheel.h"
#include <sys/socket.h>

#define IMG_FILE_MAX (10 * 1024 * 1024)
#define IMG_MAX_DIM  1568

/* MIME type from the magic bytes (PNG, JPEG, GIF, WebP), else NULL */
const char *image_mime(const unsigned char *d, size_t n);
/* pixel size from the header; false if it cannot be read */
bool image_dims(const unsigned char *d, size_t n, long *w, long *h);
/* one dragged/pasted path: shell escapes and quotes, file://, ~/ undone.
   malloc'd; NULL if it is not a single well-formed word */
char *image_path_parse(const char *s);

/* Image files and image URLs named in a message the user typed or pasted:
   absolute, ~/, ./, ../ or file:// paths of existing .png/.jpg/.jpeg/.gif/.webp
   files, and http(s) URLs ending so. Stores up to max malloc'd references and
   returns their number; *only is true if the message holds nothing else. */
int image_find_refs(const char *cwd, const char *msg, char **refs, int max, bool *only);

/* Fill *out (free with image_part_free); false with a reason in err.
   Relative paths resolve against cwd (NULL = process cwd). */
bool image_from_file(const char *cwd, const char *spec, ImagePart *out, char *err, size_t errcap);
/* http(s) only, public addresses only, no redirects, no proxy. Always refuses
   in FW_MINI_HTTP builds. */
bool image_from_url(const char *url, ImagePart *out, char *err, size_t errcap);
/* true unless sa is a public unicast IPv4/IPv6 address */
bool image_addr_blocked(const struct sockaddr *sa);

#ifdef FW_IMAGE_TEST
extern int image_test_port;   /* 127.0.0.1:<port> is allowed when nonzero */
#endif
#endif
