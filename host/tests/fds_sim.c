/* fds_sim.c -- a flash simulator behind the fds.h subset glue/od_nrf_nvs.c uses.
 *
 * Model: one 4 KB virtual data page (FDS_VIRTUAL_PAGES = 2, one of them the GC swap page), so
 * 1022 words hold record headers (3 words) plus data. Deleted records keep their space until
 * fds_gc(). Operations are queued and run, with their completion event, when the application
 * pumps events, as FDS does. Each flash step (a record becoming valid, a record being marked
 * deleted, a GC) can be cut: fds_sim_cut_after(n) longjmps to the test's jmp_buf when the
 * (n+1)th step would run, and that step does not happen -- a torn write leaves no valid record,
 * which is what FDS's header-last write order guarantees. */
#include <setjmp.h>
#include <string.h>

#include "fds.h"
#include "fds_sim.h"

#define PAGE_WORDS 1022u
#define HDR_WORDS  3u
#define MAXREC     16

struct rec {
    bool used;
    bool dirty;
    fds_header_t hdr;
    uint32_t data[PAGE_WORDS];
};

static struct rec s_rec[MAXREC];
static uint32_t s_next_id = 1;
static fds_cb_t s_cb;

enum job_kind { J_NONE, J_INIT, J_WRITE, J_UPDATE, J_DELETE, J_GC };
static struct job {
    enum job_kind kind;
    uint32_t old_id;
    fds_record_t r;
} s_q[8];
static int s_qn;

static int s_cut = -1;
jmp_buf *fds_sim_jmp;
unsigned fds_sim_steps;

void fds_sim_cut_after(int steps) { s_cut = steps; }

static void step(void)
{
    if (s_cut == 0) {
        s_cut = -1;
        longjmp(*fds_sim_jmp, 1);
    }
    if (s_cut > 0) {
        s_cut--;
    }
    fds_sim_steps++;
}

static uint32_t used_words(void)
{
    uint32_t w = 0;
    for (int i = 0; i < MAXREC; i++) {
        if (s_rec[i].used) {
            w += HDR_WORDS + s_rec[i].hdr.length_words;
        }
    }
    return w;
}

static uint32_t queued_words(void)
{
    uint32_t w = 0;
    for (int i = 0; i < s_qn; i++) {
        if (s_q[i].kind == J_WRITE || s_q[i].kind == J_UPDATE) {
            w += HDR_WORDS + s_q[i].r.data.length_words;
        }
    }
    return w;
}

static struct rec *by_id(uint32_t id)
{
    for (int i = 0; i < MAXREC; i++) {
        if (s_rec[i].used && !s_rec[i].dirty && s_rec[i].hdr.record_id == id) {
            return &s_rec[i];
        }
    }
    return NULL;
}

static void put(const fds_record_t *r)
{
    for (int i = 0; i < MAXREC; i++) {
        if (!s_rec[i].used) {
            step();   /* the record becomes valid, or (cut) never existed */
            s_rec[i].used = true;
            s_rec[i].dirty = false;
            s_rec[i].hdr.file_id = r->file_id;
            s_rec[i].hdr.record_key = r->key;
            s_rec[i].hdr.length_words = (uint16_t)r->data.length_words;
            s_rec[i].hdr.record_id = s_next_id++;
            memcpy(s_rec[i].data, r->data.p_data, r->data.length_words * 4u);
            return;
        }
    }
}

static void mark(uint32_t id)
{
    struct rec *x = by_id(id);
    if (x) {
        step();
        x->dirty = true;
    }
}

static void emit(fds_evt_id_t id, ret_code_t rc)
{
    const fds_evt_t e = { id, rc };
    if (s_cb) {
        s_cb(&e);
    }
}

void fds_sim_pump(void)
{
    while (s_qn > 0) {
        struct job j = s_q[0];
        memmove(s_q, s_q + 1, (size_t)(s_qn - 1) * sizeof s_q[0]);
        s_qn--;
        switch (j.kind) {
        case J_INIT:   emit(FDS_EVT_INIT, NRF_SUCCESS); break;
        case J_WRITE:  put(&j.r); emit(FDS_EVT_WRITE, NRF_SUCCESS); break;
        case J_UPDATE: put(&j.r); mark(j.old_id); emit(FDS_EVT_UPDATE, NRF_SUCCESS); break;
        case J_DELETE: mark(j.old_id); emit(FDS_EVT_DEL_RECORD, NRF_SUCCESS); break;
        case J_GC:
            step();
            for (int i = 0; i < MAXREC; i++) {
                if (s_rec[i].dirty) {
                    s_rec[i].used = false;
                    s_rec[i].dirty = false;
                }
            }
            emit(FDS_EVT_GC, NRF_SUCCESS);
            break;
        default: break;
        }
    }
}

void fds_sim_reboot(void)
{
    s_qn = 0;
    s_cb = NULL;
    s_cut = -1;
    uint32_t max = 0;
    for (int i = 0; i < MAXREC; i++) {
        if (s_rec[i].used && s_rec[i].hdr.record_id > max) {
            max = s_rec[i].hdr.record_id;
        }
    }
    s_next_id = max + 1u;
}

void fds_sim_wipe(void)
{
    memset(s_rec, 0, sizeof s_rec);
    s_next_id = 1;
    fds_sim_reboot();
}

int fds_sim_valid_records(void)
{
    int n = 0;
    for (int i = 0; i < MAXREC; i++) {
        n += s_rec[i].used && !s_rec[i].dirty;
    }
    return n;
}

static ret_code_t enqueue(enum job_kind k, uint32_t old_id, const fds_record_t *r)
{
    if (s_qn >= (int)(sizeof s_q / sizeof s_q[0])) {
        return NRF_ERROR_BUSY;
    }
    if (r && used_words() + queued_words() + HDR_WORDS + r->data.length_words > PAGE_WORDS) {
        return FDS_ERR_NO_SPACE_IN_FLASH;
    }
    s_q[s_qn].kind = k;
    s_q[s_qn].old_id = old_id;
    if (r) {
        s_q[s_qn].r = *r;
    }
    s_qn++;
    return NRF_SUCCESS;
}

ret_code_t fds_register(fds_cb_t cb) { s_cb = cb; return NRF_SUCCESS; }
ret_code_t fds_init(void) { return enqueue(J_INIT, 0, NULL); }
ret_code_t fds_gc(void) { return enqueue(J_GC, 0, NULL); }

ret_code_t fds_record_write(fds_record_desc_t *d, fds_record_t const *r)
{
    (void)d;
    return enqueue(J_WRITE, 0, r);
}

ret_code_t fds_record_update(fds_record_desc_t *d, fds_record_t const *r)
{
    return enqueue(J_UPDATE, d->record_id, r);
}

ret_code_t fds_record_delete(fds_record_desc_t *d)
{
    return enqueue(J_DELETE, d->record_id, NULL);
}

ret_code_t fds_record_find(uint16_t file_id, uint16_t key, fds_record_desc_t *d,
                           fds_find_token_t *tok)
{
    for (int i = tok->p_addr ? tok->page : 0; i < MAXREC; i++) {
        const struct rec *x = &s_rec[i];
        if (x->used && !x->dirty && x->hdr.file_id == file_id && x->hdr.record_key == key) {
            memset(d, 0, sizeof *d);
            d->record_id = x->hdr.record_id;
            d->p_record = (const uint32_t *)&x->hdr;
            tok->p_addr = d->p_record;
            tok->page = (uint16_t)(i + 1);
            return NRF_SUCCESS;
        }
    }
    return NRF_ERROR_NOT_FOUND;
}

ret_code_t fds_record_open(fds_record_desc_t *d, fds_flash_record_t *fr)
{
    struct rec *x = by_id(d->record_id);
    if (!x) {
        return NRF_ERROR_NOT_FOUND;
    }
    fr->p_header = &x->hdr;
    fr->p_data = x->data;
    return NRF_SUCCESS;
}

ret_code_t fds_record_close(fds_record_desc_t *d)
{
    (void)d;
    return NRF_SUCCESS;
}
