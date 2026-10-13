/* ioring.c — minimal io_uring import stub, shared object.
 * no calls, no strings beyond a marker. exercises rule H-203 alone.
 */
extern void io_uring_setup(void);
extern void io_uring_enter(void);
extern void io_uring_register(void);

volatile void *husk_ring_anchors[3];

__attribute__((constructor))
static void husk_ring_anchor(void)
{
    husk_ring_anchors[0] = (void *)io_uring_setup;
    husk_ring_anchors[1] = (void *)io_uring_enter;
    husk_ring_anchors[2] = (void *)io_uring_register;
}
