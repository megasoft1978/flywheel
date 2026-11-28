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
/* all-or-none load of refs into set (see image.c); why gets the reason */
bool image_attach_refs(const char *cwd, char **refs, int n, Images *set, const Msgs *conv,
                       char *why, size_t cap);
/* after a refused request: drop the images of the newest message that has not
   been accepted yet, note what went; nothing on a context overflow */
bool image_drop_rejected(Msgs *msgs, const char *err, char *note, size_t cap);
/* tui.c: true only when /models says the current model cannot take images;
   no_vision fills why for that refusal */
bool vision_off(void);
void no_vision(char *why, size_t cap);
/* true unless sa is a public unicast IPv4/IPv6 address */
bool image_addr_blocked(const struct sockaddr *sa);

/* The picture on the clipboard, read with the system's own program: osascript on
   a Mac, else wl-paste or xclip. find locates a trusted program of that name
   (out holds PATH_MAX bytes). Anything but CLIP_OK leaves the reason in err. */
typedef bool (*ImageFind)(const char *name, char *out);
typedef enum { CLIP_OK, CLIP_NONE, CLIP_NO_TOOL, CLIP_ERR } ClipResult;
ClipResult image_from_clipboard(bool mac, ImageFind find, ImagePart *out, char *err, size_t errcap);

/* Runs prog [opt] FILE, FILE being a private copy of the bytes of p, without
   waiting for it; its output is discarded. path (may be NULL) replaces its PATH. */
bool image_preview(const ImagePart *p, const char *prog, const char *opt, const char *path,
                   char *err, size_t errcap);
/* removes the preview copies (also done at exit); async-signal-safe */
void image_preview_cleanup(void);

#ifdef FW_IMAGE_TEST
extern int image_test_port;   /* 127.0.0.1:<port> is allowed when nonzero */
extern int image_test_clip_s; /* clipboard timeout in seconds when nonzero */
#endif
#endif
