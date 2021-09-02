#include "rfc5322.h"

int rfc5322_is_atext(char c) {
    if ('A' <= c && c <= 'Z')
        return 1;
    if ('a' <= c && c <= 'z')
        return 1;
    if ('0' <= c && c <= '9')
        return 1;
    switch (c) {
        case '!':
        case '#':
        case '$':
        case '%':
        case '&':
        case '\'':
        case '*':
        case '+':
        case '-':
        case '/':
        case '=':
        case '?':
        case '^':
        case '_':
        case '`':
        case '{':
        case '}':
        case '|':
        case '~':
            return 1;
        default:
            return 0;
    }
}

#define rfc5322_is_WSP(c) ((c)==' '||(c)=='\t')

int rfc5322_skip_FWS(char **ptr_s) {
    /*  https://datatracker.ietf.org/doc/html/rfc5322#section-3.2.2
     *
     *  FWS             =   ([*WSP CRLF] 1*WSP) /  obs-FWS
     *
     *  [...] the space (SP, ASCII value 32) and horizontal tab (HTAB,
   ASCII value 9) characters (together known as the white space
   characters, WSP)
     *  */
    char *s = *ptr_s;
    int did_something = 0;
    while (rfc5322_is_WSP(*s)) {
        s++;
        did_something = 1;
    }
    while (*s != '\0' &&
           ((*s == '\r' && *(s+1) == '\n') ||
            rfc5322_is_WSP(*s))) {
        did_something = 1;
        if (*s == '\r' && *(s+1) == '\n') {
            s += 2;
        }
        if (rfc5322_is_WSP(*s)) {
            s++;
        }
    }
    *ptr_s = s;
    return did_something;
}

int rfc5322_is_obs_NO_WS_CTL(char c) {
    // https://datatracker.ietf.org/doc/html/rfc5322#section-4.1
    if (1 <= c && c <= 8) {
        return 1;
    }
    if (14 <= c && c <= 31) {
        return 1;
    }
    if (c == 11 || c == 12 || c == 127) {
        return 1;
    }
    return 0;
}

int rfc5322_is_ctext(char c) {
    // https://datatracker.ietf.org/doc/html/rfc5322#section-3.2.2
    if (c == '(' || c == ')' || c == '\\') {
        return 0;
    }
    if (33 <= c && c <= 126) {
        return 1;
    }
    return rfc5322_is_obs_NO_WS_CTL(c);
}

// RFC5234: https://datatracker.ietf.org/doc/html/rfc5234#appendix-B.1
#define rfc5234_is_VCHAR(c) (0x21 <= (c) && (c) <= 0x7e)

int rfc5322_skip_quoted_pair(char **ptr_s) {
    char *s = *ptr_s;
    int did_something = 0;
    if (*s == '\\') {
        // quoted-pair
        if ((rfc5234_is_VCHAR(*(s+1)) || rfc5322_is_WSP(*(s+1)))) {
            s+=2;
            did_something = 1;
        }
        // obsolete quoted-pair
        if (/* *(s+1) == '\0' || */ // <---- DON'T DO THAT
                                    //       STANDARDS MAY BE DANGEROUS: "malicious \"
            rfc5322_is_obs_NO_WS_CTL(*(s+1)) || *(s+1) == '\r' || *(s+1) == '\n') {
            s+=2;
            did_something = 1;
        }
    }
    *ptr_s = s;
    return did_something;
}

int rfc5322_skip_comment(char **ptr_s) {
    /*  ccontent        =   ctext / quoted-pair / comment
     *  comment         =   "(" *([FWS] ccontent) [FWS] ")"
        *  */
    char *s = *ptr_s;
    int did_something = 0;
    if (*s != '(') {
        return did_something;
    }
    s++;
    did_something = 1;
    while (*s != '\0') {
        rfc5322_skip_FWS(&s);
        if (*s == ')') {
            s++;
            break;
        }
        rfc5322_skip_ccontent(&s);
    }
    *ptr_s = s;
    return did_something;
}

int rfc5322_skip_ccontent(char **ptr_s) {
    char *s = *ptr_s;
    if (rfc5322_is_ctext(*s)) {
        s++;
        *ptr_s = s;
        return 1;
    }
    if (rfc5322_skip_quoted_pair(&s)) {
        *ptr_s = s;
        return 1; // did something
    }
    if (*s == '(') {
        *ptr_s = s;
        return rfc5322_skip_comment(&s);
    }
    return 0; // did nothing
}

int rfc5322_skip_CFWS(char **ptr_s) {
    /* CFWS            =   (1*([FWS] comment) [FWS]) / FWS
     * */
    char *s = *ptr_s;
    int did_something = rfc5322_skip_FWS(&s);
    if (rfc5322_skip_comment(&s)) {
        did_something = 1;
        rfc5322_skip_FWS(&s);
    }
    *ptr_s = s;
    return did_something;
}

int rfc5322_is_qtext(char c) {
    if (c == '"' || c == '\\') {
        return 0;
    }
    if (33 <= c && c <= 126) {
        return 1;
    }
    return rfc5322_is_obs_NO_WS_CTL(c);
}

int rfc5322_get_quoted_string(char **ptr_s, char **out_ptr) {
    // Returns (through out_ptr) the quoted-string content, minus
    // the delimiting CFWS. Inserts a '\0' after the closing DQUOTE.
    // Leaves ptr_s pointing to the newly inserted '\0'
    //
    // If parsing, might want to run rfc5322_skip_CFWS(<input ptr_s>+1) after,
    // to clean the potential following CFWS.
    //
    // Returns 1 if found the quoted-string, or 0 if not.
    //
    /* qcontent        =   qtext / quoted-pair
     * quoted-string   =   [CFWS]
     *                     DQUOTE *([FWS] qcontent) [FWS] DQUOTE
     *                     [CFWS]
     * */
    char *s = *ptr_s;
    rfc5322_skip_CFWS(&s);
    if (*s != '"') {
        return 0;
    }
    *out_ptr = s;
    s++;
    while (*s != '\0' && *s != '"') {
        rfc5322_skip_FWS(&s);
        while (rfc5322_is_qtext(*s)) {
            s++;
        }
        rfc5322_skip_quoted_pair(&s);
    }
    if (*s == '"') {
        *(s+1) = '\0';
        *ptr_s = s+1;
        return 1;
    }
    return 0;
}

int rfc5322_get_dot_atom(char **ptr_s, char **out_ptr) {
    // Returns (through out_ptr) the dot-atom, minus the opening CFWS
    // (if it has any. Effectively, returns the dot-atom-text).
    // Leaves ptr_s at the end of dot-atom-text (beggining of CFWS, if any)
    // Returns 1 if found the dot-atom, or 0 if not.
    /*    dot-atom-text   =   1*atext *("." 1*atext)
     *    dot-atom        =   [CFWS] dot-atom-text [CFWS]
     *    */
    char *s = *ptr_s;
    rfc5322_skip_CFWS(&s);
    *out_ptr = s;
    if (!rfc5322_is_atext(*s)) {
        return 0;
    }
    s++;
    while (*s != '\0') {
        // This accepts even malformed, ".." strings
        if (rfc5322_is_atext(*s) || *s == '.') {
            s++;
        } else {
            break;
        }
    }

    *ptr_s = s;
    return 1;
}

int rfc5322_is_dtext(char c) {
    // Warning: doesn't allow quoted-pairs
    if (c == '[' || c == ']'|| c == '\\') {
        return 0;
    }
    if (33 <= c && c <= 126) {
        return 1;
    }
    return rfc5322_is_obs_NO_WS_CTL(c);
}

int rfc5322_get_domain_literal(char **ptr_s, char **out_ptr) {
    /* domain-literal  =   [CFWS] "[" *([FWS] dtext) [FWS] "]" [CFWS]
     * */
    char *s = *ptr_s;
    rfc5322_skip_CFWS(&s);
    if (*s != '[') {
        return 0;
    }
    s++;
    int did_something = 0;
    do {
        did_something = rfc5322_skip_FWS(&s);
    } while (!did_something && *s != '\0');
    // stripped all whitespace
    *out_ptr = s;
    while (*s != '\0') {
        rfc5322_skip_FWS(&s);
        if (rfc5322_is_dtext(*s)) {
            s++;
        }
        if (*s == ']') {
            break;
        }
    }
    if (*s != ']') {
        return 0;
    }

    *s = '\0';
    *ptr_s = s;
    return 1;
}

int rfc5322_get_domain(char **ptr_s, char **out_ptr) {
    // This function DOESN'T take care of obs-domain (a bit too much, innit?)
    // If dot-atom, leaves ptr_s at the end of dot-atom-text (beggining of CFWS, if any)
    // If domain-literal, leaves ptr_s just after the inserted NULL
    // This behaviour is tricky.
    // Might want to call rfc5322_skip_CFWS after passing an input, just in case.
    //
    /* domain          =   dot-atom / domain-literal / obs-domain
     * */
    char *s = *ptr_s;
    if (rfc5322_get_domain_literal(&s, out_ptr)) {
        *ptr_s = s+1;
        return 1;
    }
    s = *ptr_s;
    if (rfc5322_get_dot_atom(&s, out_ptr)) {
        *ptr_s = s;
        return 1;
    }
    return 0;
}

int rfc5322_get_local_part(char **ptr_s, char **out_ptr) {
    // This function DOESN'T take care of obs-local-part (a bit too much, innit?)
    //
    /* local-part      =   dot-atom / quoted-string / obs-local-part
     * */
    char *s = *ptr_s;
    if (rfc5322_get_quoted_string(&s, out_ptr)) {
        *ptr_s = s;
        return 1;
    }
    s = *ptr_s;
    if (rfc5322_get_dot_atom(&s, out_ptr)) {
        *ptr_s = s;
        return 1;
    }
    return 0;
}

int rfc5322_get_addr_spec(char **ptr_s, char **out_ptr) {
    /* addr-spec       =   local-part "@" domain
     * */
    char *s = *ptr_s;
    if (!rfc5322_get_local_part(&s, out_ptr)) {
        return 0;
    }
    char *non_local_part = s;
    int local_part_has_cfws = rfc5322_skip_CFWS(&non_local_part);
    if (*non_local_part != '@') {
        return 0;
    }
    char *domain_part_input = non_local_part+1;
    char *domain_part;
    if (!rfc5322_get_domain(&domain_part_input, &domain_part)) {
        return 0;
    }

    // Copy '@'+domain to the end of the local-part
    *s = '@';
    s++;
    char *this_domain_part = s;
    while (s < domain_part_input) {
        *s++ = *domain_part++;
    }
    // Need to point ptr_s again to the end of *this* (the copied destination) domain
    rfc5322_get_domain(&this_domain_part, &non_local_part /* dummy pointer */);
    *ptr_s = this_domain_part;

    return 1;
}

int remove_trailing_CFWS(char **ptr_s) {
    // Utility function
    // See test #9
    char *canary = *ptr_s;
    if (!rfc5322_skip_CFWS(&canary)) {
        return 0;
    }
    **ptr_s = '\0';
    return 1;
}
