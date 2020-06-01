# p4-constraints language specification

The general design philosophy behind the p4-constraints language is to recycle
[P4 language] constructs as much as possible, both syntactically and
semantically. Where the languages overlap, p4-constraints aims to be consistent
with the [P4 language specification]. This is to minimize the cost of adaption
for programmers already familiar with [P4].

Where [P4] lacks constructs required in p4-constraints, we add new constructs
guided by the principle of least surprise.

[P4]: https://p4.org/specs/
[P4 language]: https://p4.org/specs/
[P4 language specification]: https://p4.org/specs/

## Tour of the language

The p4-constraints language is a simple, expression-based language for
specifying properties of P4 table entries.

### Keys and comparisons

At the heart of the language lies the ability to talk about table keys,
and to constrain their values using comparison operators.
```p4
@entry_restriction("ipv4.valid == 1")
table ipv4_table { 
  key {
    ipv4.valid : exact;
    ipv4.dst : lpm;
  }
}
```
For example, the above constraint `ipv4.valid == 1` states that the key
`ipv4.valid` must be equal to `1` for all table entries. Just like P4, the
constraint language provides the comparison operators `==`, `!=`, `>`, `>=`,
`<`, and `<=` with the usual semantics.

### Boolean operations

The language provides the Boolean constants `true` and `false` for allowing
or disallowing all table entries:

```p4
@entry_restriction("true")
table all_entries_allowed { ... }

@entry_restriction("false")
table all_entries_disallowed { ... }
```

As in P4, Boolean expressions can be negated using `!`,
or combined conjunctively using `&&` or disjunctively using `||`, allowing


## Grammar
```
// Constraints are expressions of type bool.
expression ::=
  | 'true' | 'false'                                               // Boolean constants.
  | numeral                                                        // Numeric constants.
  | key                                                            // Table keys.
  | '!' expression                                                 // Boolean negation.
  | '-' expression                                                 // Arithmetic negation.
  | '(' expression ')'                                             // Parentheses.
  | expression '::' id                                             // Field access (projection).
  | expression ('&&' | '||' | '->' | ';') expression               // Binary boolean operators.
  | expression ('==' | '!=' | '>' | '>=' | '<' | '<=') expression  // Comparisons.

key ::= id ('.' id)*                                               // Table keys, e.g. "hdr.ethernet.eth_type".
id ::= [_a-zA-Z][_a-zA-Z0-9]*                                      // Identifiers.

numeral ::=
  | (0[dD])? [0-9]+                                                // Decimal numerals.
  | 0[bB] [0-1]+                                                   // Binary numerals.
  | 0[oO] [0-7]+                                                   // Octary numerals.
  | 0[xX] [0-9a-fA-F]+                                             // Hexadecimal numerals.
```
Top-level expression may optionally be terminated by a trailing ';'.

### Precedence and Associativity

Operators ordered by precedence: higher in the table means "binds stronger".

| Syntax               | Semantics           | Associativity | Examples                                            |
|----------------------|---------------------|---------------|-----------------------------------------------------|
| ::                   | Field access        | N/A           | ipv4.dst::prefix_length                             |
| !                    | Boolean negation    | N/A           | !true, !(key == 2), !!false                         |
| -                    | Arithmetic negation | N/A           | -1, -(10 + 3), --2                                  |
| ==, !=, >, >=, <, <= | Comparison          | none          | 2 == 4, 1 > -12, true != false                      |
| &&                   | Boolean conjunction | left          | ipv4.valid == 1 && ipv4.dst == 0xf0f0f0f0           |
| \|\|                 | Boolean disjunction | left          | ipv4.valid == 1 \|\| ipv6.valid == 1                |
| ->                   | Boolean implication | none          | ipv4.dst::mask != 0 -> ethernet.ether_type == 0x800 |
| ;                    | Boolean conjunction | left          | ipv4.valid == 1 -> ipv6.valid == 0;<br>ipv6.valid == 1 -> ipv4.valid == 0|
