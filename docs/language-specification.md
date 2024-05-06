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
  key = {
    ipv4.isValid() : exact @name("ipv4.valid");
    ipv4.dst : ternary;
  }
}
```
For example, the above constraint states that the key `ipv4.valid` must be equal
to `1` for all table entries. Just like P4, the constraint language provides the
comparison operators `==`, `!=`, `>`, `>=`, `<`, and `<=` with the usual
semantics.

### Accessing the fields of a key

While an `exact` match consists of a single value, a `ternary` match is given
by a value together with a mask. Similarly, an `lpm` match consists of a value
together with a prefix length, and a range match consists of lower and upper
bounds.

To access the different values associated with a key, the language provides a
field access (or "projection") operator `::`.
```p4
@entry_restriction("ipv6.dst::prefix_length <= 64")
table ipv6_table {
  key = {
    ipv6.dst : lpm;
  }
}
```
For example, the above constraint states that entries should only ever match on
the most-significant 64 bits of an IPv6 address.

More generally, assume we have a P4 table of the form
```p4
table t {
  key = {
    k : <match_type>;
  }
}
```
with `k` being of type `bit<W>`. Then the fields that can be accessed using
the `::` operator together with their types are summarized in the following
table:

| <match_type> | field            | field type | assumed P4Runtime well-formedness constraints | 
|--------------|------------------|------------|-----------------------------------------------|
| exact        | k::value         | bit\<W\>   | 
| ternary      | k::value         | bit\<W\>   | masked-off bits are zero: `value & !mask == 0`
|              | k::mask          | bit\<W\>   |
| optional     | k::value         | bit\<W\>   | masked-off bits are zero: `value & !mask == 0` 
|              | k::mask          | bit\<W\>   | wildcard or exact match: `mask == -1 \|\| mask == 0`
| lpm          | k::value         | bit\<W\>   | masked-off bits are zero:`value & !prefix_mask == 0`<br> where `prefix_mask` is a `W`-bit vector whose upper `prefix_length` bits are 1 and the lower bits are 0
|              | k::prefix_length | int        | `0 <= prefix_length && prefix_length <= W` 
| range        | k::low           | bit\<W\>   | `low < high \|\| (low == 0 & high == 0)`
|              | k::high          | bit\<W\>   |

Note that an `optional` match is just a restricted kind of `ternary` match whose mask always satisfies the following constraint:
```
// Wildcard match or exact match.
optional_match_key::mask == 0 || optional_match_key::mask == -1
```

When `k` is of type `bool`, everything behaves precisely as if `k` was of type
`bit<1>`, with the boolean constant `true` and `false` being mapped to `1` and
`0`, respectively.


### Assumed P4runtime Well-Formedness Constraints

In p4-constraints, we assume that all table entries we consider satisify certain 
*well-formedness constraints* that do not require an explicit 
`@entry_restriction`.
These well-formedness constraints are shown in the table above and essentially
say that the entries are valid [according to the P4Runtime standard].
This includes *canonicity constraints* that rule out distinct but semantically
equivalent representations of table entries. For example, using
[P4's mask notation], the ternaries `10 &&& 10` and `11 &&& 10` are equivalent,
as both match the set of bitvectors `{10, 11}`. But only `10 &&& 10` is legal
[according to the P4Runtime standard], which says that  masked-off bits must be
0. In general, this is captured by the constraint `value & !mask == 0`.

*CAUTION:* As of May 2024, p4-constraint's implementation *assumes*, but
*does not enforce* these P4Runtime well-formedness constraints.

[according to the P4Runtime standard]: https://p4.org/p4-spec/p4runtime/v1.3.0/P4Runtime-Spec.html#sec-match-format
[P4's mask notation]: https://p4.org/p4-spec/docs/P4-16-v1.2.4.html#sec-cubes

### Attribute access

A table entry might include data other than the values for the keys.
We refer to this information as "attribute", and it can be accessed in the
constraint by `::<attribute>` syntax:
```
// Accessing priority attribute of the table entry.
::priority < 0x7ffffff
```

The operator `::` here should not be confused with the projection operator for
accessing fields of a key. If positioned at the beginining of a constraint, the
operator indicates attribute access. If positioned after a filed access, it
indicates projection.

Here are the list of attribute that are currently supported:

| attribute    | type  | description                      |
|--------------|-------|----------------------------------|
| ::priority   | int   | The priority of the table entry. |


### Implicit conversions
TODO

### Boolean operations

As in P4, Boolean expressions can be negated using `!`,
or combined conjunctively using `&&` or disjunctively using `||`.

Additionally, p4-constraints provides the binary operator `->` to express
[logical implication](https://en.wikipedia.org/wiki/Material_conditional):
```p4
@entry_restriction("ipv4.valid == 0 -> ipv4.dst::mask == 0")
table ipv4_table {
  key {
    ipv4.isValid() : exact @name("ipv4.valid");
    ipv4.dst : ternary;
  }
}
```
For example, the entry restriction above demands that table entries must ignore
invalid IPv4 destination addresses by masking them off.

As a convenience, expressions can also be combined using `;` in place of `&&`:
```p4
@entry_restriction("
  constraint1;
  constraint2;
  constraint3;  // The trailing ';' is optional.
")
```
While `;` and `&&` are semantically equivalent, ';' is defined to have the
[lowest level of precedence](#precedence-and-associativity), making it
convenient for combining several top-level constraints without having to
insert parentheses. For example,
```p4
@entry_restriction("
  (ipv4.valid == 1 -> ipv6.valid == 0) &&
  (ipv6.valid == 1 -> ipv4.valid == 0)
")
```
can be expressed more succinctly without parentheses as
```p4
@entry_restriction("
  ipv4.valid == 1 -> ipv6.valid == 0;
  ipv6.valid == 1 -> ipv4.valid == 0;
")
```

Like P4, the language also provides the Boolean constants `true` and `false`.

### Network address syntax

A table entry may want to restrict certain values to valid network addresses. For example, the following constraint sets restrictions on IPv4, IPv6 and MAC addresses.

```
@entry_restriction("
  hdr.ethernet.dst_addr::value < mac('00:00:00:00:00:05');
  hdr.ipv4.dst_addr == ipv4('0.0.0.255');
  hdr.ipv6.dst_addr::value > ipv6('::');
")
```

Network address notation follows the syntax of `<address_type>(<string>)`
where the `<address_type>` must be `ipv4`, `ipv6` or `mac` and `<string>` represents the respective network address in single quotes.
Network addresses using this notation get converted into integer values.

## Grammar

Formally, the set of expressions is given by the following grammar:
```
// Constraints are expressions of type bool.
expression ::=
  | 'true' | 'false'                                               // Boolean constants.
  | numeral                                                        // Numeric constants.
  | address_type '(' string ')'                                    // Network address constant.
  | key                                                            // Table keys.
  | attribute_access                                               // Accessing table entry attribute.
  | '!' expression                                                 // Boolean negation.
  | '-' expression                                                 // Arithmetic negation.
  | '(' expression ')'                                             // Parentheses.
  | expression '::' id                                             // Field access (projection).
  | expression ('&&' | '||' | '->' | ';') expression               // Binary boolean operators.
  | expression ('==' | '!=' | '>' | '>=' | '<' | '<=') expression  // Comparisons.

attribute_access ::= '::' id                                       // Entry attribute access (e.g. "::priority").

numeral ::=
  | (0[dD])? [0-9]+                                                // Decimal numerals.
  | 0[bB] [0-1]+                                                   // Binary numerals.
  | 0[oO] [0-7]+                                                   // Octary numerals.
  | 0[xX] [0-9a-fA-F]+                                             // Hexadecimal numerals.

key ::= id ('.' id)*                                               // Table keys, e.g. "hdr.ethernet.eth_type".
id ::= [_a-zA-Z][_a-zA-Z0-9]*                                      // Identifiers.
address_type ::= `ipv4` | 'ipv6' | `mac`                           // Network address types.
```
As a syntactic convenience, top-level expression may be terminated
by a trailing ';' without affecting the semantics of the expression.

### Precedence and Associativity

The following table lists all operator ordered by precedence:
higher in the table means "binds stronger".

| Syntax               | Semantics           | Associativity | Examples                                            |
|----------------------|---------------------|---------------|-----------------------------------------------------|
| :: (after key)       | Field access        | N/A           | ipv4.dst::prefix_length                             |
| :: (otherwise)       | Attribute access    | N/A           | ::priority                                          |
| !                    | Boolean negation    | N/A           | !true, !(key == 2), !!false                         |
| -                    | Arithmetic negation | N/A           | -1, -ipv4.dst::prefix_length, --2                   |
| ==, !=, >, >=, <, <= | Comparison          | none          | 2 == 4, 1 > -12, true != false                      |
| &&                   | Boolean conjunction | left          | ipv4.valid == 1 && ipv4.dst == 0xf0f0f0f0           |
| \|\|                 | Boolean disjunction | left          | ipv4.valid == 1 \|\| ipv6.valid == 1                |
| ->                   | Boolean implication | none          | ipv4.dst::mask != 0 -> ethernet.ether_type == 0x800 |
| ;                    | Boolean conjunction | left          | ipv4.valid == 1 -> ipv6.valid == 0;<br>ipv6.valid == 1 -> ipv4.valid == 0|

The first four operators are unary operators in the sense that they act on a
single expression; as such they can always be parsed unambiguously without
imposing an [associativity](https://en.wikipedia.org/wiki/Operator_associativity).

The comparison operators as well as `->` are none-associative; this means that
expressions involving these operators that could be parsed in both a left-
and right-associative manner are syntactically illegal. For example,
p4-constraints will reject the expression
```p4
ipv4.valid == ipv6.valid == 0
```
with a syntax error and demand that it be disambiguated using parentheses,
e.g. by writing
```p4
(ipv4.valid == ipv6.valid) == 0
```
Note that the above expression is syntactically valid but will not type check
since the left-hand side of the equality is of type `bool` whereas the
right-hand side is of type `int`; instead we would have to write
```p4
ipv4.valid == 0 && ipv6.valid == 0
```
if we intended to express that both valid bits must be unset.


[associativity]: https://en.wikipedia.org/wiki/Operator_associativity
