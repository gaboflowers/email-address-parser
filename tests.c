#include "rfc5322.h"
#include <stdio.h>
#include <stdlib.h> // exit
#include <string.h> // strcmp

// Testing stuff

typedef int (*rfc5322_get_func_t)(char**, char**);

void assert_str(char *tested, char *supposed) {
    if (strcmp(tested, supposed)) {
        fprintf(stderr, "Assertion Failed: '%s' should be '%s'\n", tested, supposed);
        exit(EXIT_FAILURE);
    }
}

void test_get(rfc5322_get_func_t tested_func, char *test_input, char *supposed, char **remainder, char **ptr_test_output, char *test_label) {
    char *test_output;
    char *label = test_label != NULL ? test_label : "";
    if (!tested_func(&test_input, &test_output)) {
        fprintf(stderr, "Test %s is idle: f(%s) == %s\n", label, test_input, test_output);
        exit(EXIT_FAILURE);
    }
    if (strcmp(test_output, supposed)) {
        fprintf(stderr, "Test %s failed: '%s' should be '%s'\n", label, test_output, supposed);
        exit(EXIT_FAILURE);
    }
    if (remainder != NULL) {
        *remainder = test_input;
    }
    if (ptr_test_output != NULL) {
        *ptr_test_output = test_output;
    }
}

int main(int argc, char *argv[]) {
    char *remainder;
    const char CONST_domain_literal_with_cfws[] = "( left outer comment ) [ my. example domain.tld ] (  right outer comment) NOT-A-CFWS";
    const char CONST_addr_spec_with_cfws[] = "pete ( his account)@silly.test(his host)";

    // #1
    char quoted_str_with_cfws[] = "( left outer comment ) \"local part \" (right outer comment)";
    test_get(rfc5322_get_quoted_string, quoted_str_with_cfws, "\"local part \"", &remainder, NULL, "1");
    assert_str(remainder+1, "(right outer comment)");

    // #2
    char domain_literal_with_cfws[sizeof(CONST_domain_literal_with_cfws)];
    strcpy(domain_literal_with_cfws,  CONST_domain_literal_with_cfws);
    test_get(rfc5322_get_domain_literal, domain_literal_with_cfws, "my. example domain.tld ", &remainder, NULL, "2");
    remainder++;
    assert_str(remainder, " (  right outer comment) NOT-A-CFWS");
    // #2b
    rfc5322_skip_CFWS(&remainder);
    assert_str(remainder, "NOT-A-CFWS");

    // #3
    char dot_atom_with_cfws[] = " ( left comment ) a.123.$%%#.example.tld ( right comment)";
    test_get(rfc5322_get_dot_atom, dot_atom_with_cfws, "a.123.$%%#.example.tld ( right comment)", &remainder, NULL, "3");
    assert_str(remainder, " ( right comment)");

    // #4
    strcpy(domain_literal_with_cfws,  CONST_domain_literal_with_cfws);
    test_get(rfc5322_get_domain, domain_literal_with_cfws, "my. example domain.tld ", &remainder, NULL, "4");
    assert_str(remainder, " (  right outer comment) NOT-A-CFWS");

    // #5
    test_get(rfc5322_get_domain, dot_atom_with_cfws, "a.123.$%%#.example.tld ( right comment)", &remainder, NULL, "5");
    assert_str(remainder, " ( right comment)");

    // #6
    char local_part_with_cfws[] = "pete ( his account) BEYOND-LOCAL-PART";
    char *output;
    /* This test doesn't change anything in the input string, but leaves the remainder pointing just to where
     * you should skip a CFWS and insert a '\0' if you want a clean local-part */
    test_get(rfc5322_get_local_part, local_part_with_cfws, "pete ( his account) BEYOND-LOCAL-PART", &remainder, &output, "6");
    assert_str(remainder, " ( his account) BEYOND-LOCAL-PART");
    assert_str(output, "pete ( his account) BEYOND-LOCAL-PART");
    char *dummy = remainder;
    if (!rfc5322_skip_CFWS(&dummy)) { // `dummy` gets moved to the beggining of BEYOND-LOCAL-PART
        fprintf(stderr, "There should be a CFWS to consume in '%s'\n", local_part_with_cfws);
        exit(EXIT_FAILURE);
    }
    *remainder = '\0';
    assert_str(output, "pete");

    // #7
    char addr_spec_with_cfws[sizeof(CONST_addr_spec_with_cfws)];
    strcpy(addr_spec_with_cfws, CONST_addr_spec_with_cfws);
    test_get(rfc5322_get_local_part, addr_spec_with_cfws, addr_spec_with_cfws, &remainder, &output, "7");
    char *non_local_part = remainder;
    if (!rfc5322_skip_CFWS(&non_local_part)) {
        fprintf(stderr, "There should be a CFWS to consume in '%s'\n", addr_spec_with_cfws);
        exit(EXIT_FAILURE);
    }
    *remainder = '\0';
    assert_str(non_local_part, "@silly.test(his host)");
    assert_str(output, "pete");

    // #8
    char addr_spec_with_cfws_domain[] = "pete@silly.test(his host)";
    test_get(rfc5322_get_local_part, addr_spec_with_cfws_domain, addr_spec_with_cfws_domain, &remainder, &output, "8");
    non_local_part = remainder;
    if (rfc5322_skip_CFWS(&non_local_part)) {
        fprintf(stderr, "There should NOT be a CFWS to consume in '%s'\n", addr_spec_with_cfws_domain);
        exit(EXIT_FAILURE);
    }
    if (*non_local_part != '@') {
        fprintf(stderr, "non_local_part should point to @\n");
        exit(EXIT_FAILURE);
    }
    *non_local_part = '\0';
    non_local_part++;
    assert_str(non_local_part, "silly.test(his host)");
    assert_str(output, "pete");

    // #9
    strcpy(addr_spec_with_cfws, CONST_addr_spec_with_cfws);
    test_get(rfc5322_get_addr_spec, addr_spec_with_cfws, addr_spec_with_cfws, &remainder, &output, "9");
    assert_str(output, "pete@silly.test(his host)");
    assert_str(remainder, "(his host)");
    /*
    // This block is now replaced by remove_trailing_CFWS
    dummy = remainder;
    if (!rfc5322_skip_CFWS(&dummy)) {
        fprintf(stderr, "There should be a CFWS to consume in '%s'\n", addr_spec_with_cfws);
        exit(EXIT_FAILURE);
    }
    *remainder = '\0';
    */
    if (!remove_trailing_CFWS(&remainder)) {
        fprintf(stderr, "There should be a CFWS to consume in '%s'\n", addr_spec_with_cfws);
        exit(EXIT_FAILURE);
    }
    assert_str(output, "pete@silly.test");

    printf("Tests passed\n");
    return 0;
}

