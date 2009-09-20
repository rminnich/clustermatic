#ifndef _MODULE_H
#define _MODULE_H

struct module_t {
    struct module_t *next;

    const char  *krev;		/* kernel revision */
    const char  *name;		/* module name (filename) */
    const char  *loaded_name;	/* module name (internal, loaded name) */
    int    installed;
    char  *args;		/* Canned args from config file */
    char **aliases;		/* aliases for modprobing later on */

    /* Mapping information */
    void *map;
    int   size;
};

extern int              install_seq;
extern struct module_t *modlist;
extern const char *     module_path; /* where to find modules  */

/* Management of module binaries */
int         module_map        (const char *name, void **module_, int *modlen_);

/* Information extraction */
char **     module_get_deps   (void *module, int len);
const char *module_get_modname(const void *module, int len);
const char *module_modinfo_first(const void *module, int modlen);
const char *module_modinfo_next(const void *module, int modlen, const char *p);

/* Management of multiple modules in memory. */
struct module_t *module_get(const char *krev, const char *name);

int modprobe(struct module_t *mod, char *args);
const char *mod_strerror(int err);

/* These come from the C library... */
long init_module(void *, unsigned long, const char *);
long delete_module(const char *, unsigned int);
#endif

/*
 * Local variables:
 * c-basic-offset: 4
 * End:
 */
