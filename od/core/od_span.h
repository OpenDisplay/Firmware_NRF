/* od_span.h -- the non-owning view that every shared/ buffer argument travels as.
 *
 * WHY THIS EXISTS. `(const uint8_t *p, size_t n)` is two arguments the compiler will never
 * check against each other. Nothing stops a caller passing one function's pointer with another's
 * length, and nothing stops a callee reading past `n` because the bound lived in a separate
 * variable it forgot to consult. In the config walk -- the PRE-AUTH attack surface, parsed at
 * boot from storage a client can write -- that is the whole bug class.
 *
 * A span makes the pair one value, so it can only be split by the two functions below, and both
 * of them do the bounds arithmetic once, overflow-safely, in a place that is unit-tested. This
 * is CLAUDE.md decision 1's second C-side rule: it buys back most of what a C++ `span` type
 * would have given, in C99, with no language change.
 *
 * IT IS NOT A SAFE-BUFFER TYPE AND DOES NOT PRETEND TO BE. `s.p[i]` still compiles. What the
 * type removes is the mismatched pair and the recomputed bound, not indexing; the discipline is
 * to reach a span of exactly the bytes you may touch (via od_span_split) and index inside that.
 *
 * NO COST ON THE SMALL TARGETS. Two words, returned and passed by value: the AAPCS on the BG22
 * and nRF52 hands it in r0/r1 exactly as the pointer and length were handed separately. There is
 * no allocation here and nothing with a lifetime -- a span borrows, always, and never outlives
 * the buffer it was made from.
 *
 * C99, header-only, and included from C++ translation units on the ESP32: no compound literals,
 * no designated initialisers, nothing that is C-only.
 */
#ifndef OD_SPAN_H
#define OD_SPAN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Lengths are size_t, not the uint16_t the wire uses. Callers widen at the boundary; each module
 * still enforces its OWN wire limits (od_config_asm's 202-byte frame shapes, the walk's declared
 * body sizes). A span is a memory bound, never a protocol bound -- do not let one stand in for
 * the other. */
typedef struct od_span {
    const uint8_t *p;
    size_t         n;
} od_span_t;

/* Writable counterpart used when a caller lends bounded scratch/output storage. It has the same
 * borrowing and bounds semantics as od_span_t; the distinct type keeps writable memory explicit
 * and avoids casting const away at a sink boundary. */
typedef struct od_mut_span {
    uint8_t *p;
    size_t   n;
} od_mut_span_t;

/* A span over n bytes at p. Passing (NULL, n>0) builds a span that od_span_valid() rejects
 * rather than one that traps here: the callee's argument check is where a bad buffer belongs,
 * and every entry point in shared/ has one. */
static inline od_span_t od_span_make(const uint8_t *p, size_t n)
{
    od_span_t s;
    s.p = p;
    s.n = n;
    return s;
}

static inline od_span_t od_span_none(void)
{
    return od_span_make(NULL, 0u);
}

static inline od_mut_span_t od_mut_span_make(uint8_t *p, size_t n)
{
    od_mut_span_t s;
    s.p = p;
    s.n = n;
    return s;
}

static inline od_mut_span_t od_mut_span_none(void)
{
    return od_mut_span_make(NULL, 0u);
}

static inline bool od_mut_span_valid(od_mut_span_t s)
{
    return s.p != NULL || s.n == 0u;
}

static inline od_span_t od_mut_span_const(od_mut_span_t s)
{
    return od_span_make(s.p, s.n);
}

/* Well-formed: a null pointer is only allowed with a zero length. This is the check that
 * replaces the `if (!buf)` at the top of every shared/ entry point. */
static inline bool od_span_valid(od_span_t s)
{
    return s.p != NULL || s.n == 0u;
}

static inline bool od_span_is_empty(od_span_t s)
{
    return s.n == 0u;
}

/* Does this span certainly hold n readable bytes? Comparison only -- no addition -- so a huge n
 * cannot wrap a sum and answer yes. */
static inline bool od_span_has(od_span_t s, size_t n)
{
    return od_span_valid(s) && n <= s.n;
}

/* THE WORKHORSE, and the reason the type earns its place. Cut n bytes off the front:
 * *head becomes exactly those n bytes, *tail the remainder. Either output may be NULL.
 *
 * Returns false and writes nothing when the span is short or malformed, so a truncation is a
 * branch the caller must take rather than a length it must remember to re-check. This is the
 * one place the "does it fit" arithmetic is written, and it is written as a comparison for the
 * same reason as od_span_has(). */
static inline bool od_span_split(od_span_t s, size_t n, od_span_t *head, od_span_t *tail)
{
    if (!od_span_has(s, n)) {
        return false;
    }
    if (head != NULL) {
        *head = od_span_make(s.p, n);
    }
    if (tail != NULL) {
        /* s.p is non-null whenever n > 0 or s.n > 0; the empty case returns an empty span
         * instead of forming NULL + 0, which is undefined however harmless it looks. */
        *tail = (s.p != NULL) ? od_span_make(s.p + n, s.n - n) : od_span_none();
    }
    return true;
}

/* SATURATING, deliberately: take/drop clamp to what is there instead of failing. They are for
 * places where the length is already known to fit (trimming a trailing CRC whose presence the
 * caller has checked), NOT for parsing untrusted lengths -- use od_span_split for that, so a
 * short buffer is a false you cannot ignore rather than a quietly shorter span. */
static inline od_span_t od_span_take(od_span_t s, size_t n)
{
    if (!od_span_valid(s)) {
        return od_span_none();
    }
    return od_span_make(s.p, (n < s.n) ? n : s.n);
}

static inline od_span_t od_span_drop(od_span_t s, size_t n)
{
    if (!od_span_valid(s) || s.p == NULL) {
        return od_span_none();
    }
    return (n < s.n) ? od_span_make(s.p + n, s.n - n) : od_span_make(s.p + s.n, 0u);
}

#ifdef __cplusplus
}
#endif

#endif /* OD_SPAN_H */
