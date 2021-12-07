#include "common.p4"

control invalid_constraints(inout headers_t headers,
                            inout local_metadata_t local_metadata,
                            inout standard_metadata_t standard_metadata) {

  @entry_restriction(forgot)
  table forgot_quotes { actions = {} key = {} }

  @file(__FILE__)
  @line(__LINE__)
  @entry_restriction(forgot)
  table forgot_quotes_with_srcloc { actions = {} key = {} }

  @entry_restriction("")
  table empty_restriction { actions = {} key = {} }

  @file(__FILE__)
  @line(__LINE__)
  @entry_restriction("
  ")
  table empty_restriction_with_src_loc { actions = {} key = {} }

  @file(__FILE__)
  @line(__LINE__)
  @entry_restriction("
    foo.bar.baz == 2
  ")
  table unknown_key { actions = {} key = {} }

  // Same constraint without @file/@line annotations.
  @entry_restriction("foo.bar.baz == 2")
  table unknown_key_no_srcloc { actions = {} key = {} }

  @file(__FILE__)
  @line(__LINE__)
  @entry_restriction("
    foo.bar.baz == 0b2
  ")
  table bad_binary_numeral { actions = {} key = {} }

  // Same constraint without @file/@line annotations.
  @entry_restriction("foo.bar.baz == 0b2")
  table bad_binary_numeral_no_srcloc { actions = {} key = {} }

  @file(__FILE__)
  @line(__LINE__)
  @entry_restriction("
    /* This is to demonstrate that the lexer correctly updates the source
       location when scanning through multi-line comments such as this one */
    /**************************************************************************/
    error here
  ")
  table multiline_comment { actions = {} key = {} }


  @file(__FILE__)
  @line(__LINE__)
  @entry_restriction("
    ternary_key::prefix_length
  ")
  table unknown_field {
    actions = {}
    key = { headers.ipv4.src_addr : ternary @name("ternary_key"); }
  }

  @file(__FILE__)
  @line(__LINE__)
  @entry_restriction("
    0x0F0F :: value
  ")
  table scalar_has_no_field { actions = {} key = {} }

  @file(__FILE__)
  @line(__LINE__)
  @entry_restriction("
    -0x0F0F == -0o01234567 -> !false && -false
  ")
  table arithmetic_negation_of_boolean { actions = {} key = {} }

  @file(__FILE__)
  @line(__LINE__)
  @entry_restriction("
    !false -> -8 == -0b1000 || !1
  ")
  table boolean_negation_of_integer { actions = {} key = {} }


  @file(__FILE__)
  @line(__LINE__)
  @entry_restriction("
    optional_key > 10;
  ")
  table optional_does_not_support_ordered_comparison {
    key = { headers.ipv4.dst_addr : optional  @name("optional_key"); }
    actions = {}
  }

  @file(__FILE__)
  @line(__LINE__)
  @entry_restriction("
    ::unknown > 10;
  ")
  table unknown_metadata { actions = {} key = {} }

  apply {
    forgot_quotes.apply();
    forgot_quotes_with_srcloc.apply();
    empty_restriction.apply();
    empty_restriction_with_src_loc.apply();
    unknown_key.apply();
    unknown_key_no_srcloc.apply();
    bad_binary_numeral.apply();
    bad_binary_numeral_no_srcloc.apply();
    multiline_comment.apply();
    unknown_field.apply();
    scalar_has_no_field.apply();
    arithmetic_negation_of_boolean.apply();
    boolean_negation_of_integer.apply();
    optional_does_not_support_ordered_comparison.apply();
    unknown_metadata.apply();
   }
 }

V1Switch(packet_paser(), verify_ipv4_checksum(), invalid_constraints(),
         egress(),
         compute_ipv4_checksum(), deparser()) main;
