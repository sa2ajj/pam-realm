//
// Copyright (C) 2002, Mikhail Sobolev
//
// You may use, modify and redistribute this program according to the terms
// and conditions of GPL v2
//
// Module: pam_realm
//
// Parameters:
//      debug       -- you know what
//      realm       -- realm to check against
//      allowbare   -- allow user without @realm part
//      nostrip     -- just check the realm, but do not strip it
//

#include <string.h>
#include <stdarg.h>

#define PAM_SM_AUTH

#include <security/pam_modules.h>
#include <security/_pam_macros.h>

enum {
    PR_DEBUG = 1,
    PR_ALLOWBARE = 2,
    PR_NOSTRIP = 4,
};

static void
_pam_log(int err, const char *format, ...) {
	va_list args;

	va_start(args, format);
	vsyslog(LOG_AUTH | err, format, args);
	va_end(args);
}

static int
_pam_parse(int argc, const char **argv, char **realm) {
    int ctrl = 0;

    for (ctrl = 0; argc-- > 0; ++argv) {
        if (strcmp(*argv, "debug") == 0)
            ctrl |= PR_DEBUG;
        else if (strncmp(*argv, "realm=", 6) == 0) {
            *realm = x_strdup(*argv + 6);
            if (*realm == NULL)
                _pam_log(LOG_CRIT, "failed to obtain realm");
        } else if (!strcmp(*argv, "allowbare"))
            ctrl |= PR_ALLOWBARE;
        else if (!strcmp(*argv, "nostrip"))
            ctrl |= PR_NOSTRIP;
        else
            _pam_log(LOG_ERR, "pam_parse: unknown option; %s", *argv);
    }

    return ctrl;
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    int retval, options;
    const char *user, *ptr;
    char *realm = NULL;

    for (;;) {
        options = _pam_parse(argc, argv, &realm);

        if (realm == NULL) {
            _pam_log(LOG_ERR, "no realm is specified. aborted");

            retval = PAM_SERVICE_ERR;

            break;
        }

        if ((retval = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS || user == NULL) {
            _pam_log(LOG_ERR, "no user specified");

            retval = PAM_USER_UNKNOWN;
            break;
        }

        ptr = strchr(user, '@');

        if (ptr == NULL) {
            if ((options & PR_ALLOWBARE) == 0) {
                _pam_log(LOG_ERR, "username does not contain @");

                retval = PAM_USER_UNKNOWN;
            } else {
                retval = PAM_SUCCESS;
            }

            break;
        }

        // from this point on, ptr is not NULL

        if (strcasecmp(realm, ptr + 1) != 0) {
            _pam_log(LOG_ERR, "the realms do not match: %s != %s", realm, ptr + 1);

            retval = PAM_AUTH_ERR;

            break;
        }

        if ((options & PR_NOSTRIP) == 0) {
            char *tempo = (char *)malloc(ptr - user + 1);

            if (tempo == NULL) {
                retval = PAM_BUF_ERR;

                _pam_log(LOG_ERR, "unable to create a temporary buffer");

                break;
            }

            memcpy(tempo, user, ptr - user);
            tempo[ptr - user] = '\0';

            retval = pam_set_item(pamh, PAM_USER, tempo);

            free(tempo);
        } else {
            retval = PAM_SUCCESS;
        }

        break;
    }

    return retval;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t * pamh, int flags, int argc, const char **argv) {
    return PAM_IGNORE;
}

#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_realm_modstruct = {
    "pam_realm",
    pam_sm_authenticate,
    pam_sm_setcred,
    NULL,
    NULL,
    NULL,
    NULL,
};

#endif
