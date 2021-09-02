#ifndef RFC5322_H
#define RFC5322_H

/*
 * This is a PARTIAL implementation of email address parsing (addr-spec)
 * according to RFC5322 (https://datatracker.ietf.org/doc/html/rfc5322).
 * */

// rfc5322_is_X functions/macros:
// Returns 1 if matches the specification, 0 otherwise
int rfc5322_is_atext(char c);
#define rfc5322_is_WSP(c) ((c)==' '||(c)=='\t')
int rfc5322_is_obs_NO_WS_CTL(char c);
int rfc5322_is_ctext(char c);
int rfc5322_is_qtext(char c);
int rfc5322_is_dtext(char c);
#define rfc5234_is_VCHAR(c) (0x21 <= (c) && (c) <= 0x7e)

// rfc5322_skip_X functions:
// Returns 1 if the pointed string matches the specification,
// 0 otherwise.
// Advances the input pointer to somewhere useful to keep
// parsing (see code and tests)
int rfc5322_skip_FWS(char **ptr_s);
int rfc5322_skip_quoted_pair(char **ptr_s);
int rfc5322_skip_comment(char **ptr_s);
int rfc5322_skip_ccontent(char **ptr_s);
int rfc5322_skip_CFWS(char **ptr_s);

// rfc5322_get_X functions:
// Returns 1 if the pointed string matches the specification,
// 0 otherwise.
// Advances the input pointer to somewhere useful to keep
// parsing (see code and tests)
// If 1 is returned, leaves the output string pointed by out_ptr.
// If 0 is returned, the out_ptr may or may not be overwritten.
int rfc5322_get_quoted_string(char **ptr_s, char **out_ptr);
int rfc5322_get_dot_atom(char **ptr_s, char **out_ptr);
int rfc5322_get_domain_literal(char **ptr_s, char **out_ptr);
int rfc5322_get_domain(char **ptr_s, char **out_ptr);
int rfc5322_get_local_part(char **ptr_s, char **out_ptr);
int rfc5322_get_addr_spec(char **ptr_s, char **out_ptr);
int remove_trailing_CFWS(char **ptr_s);

#endif // RFC5322_H
