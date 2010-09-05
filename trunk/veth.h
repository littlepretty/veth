/*
 * Macros to help debugging
 */

#define VETH_RX_INTR 0x0001
#define VETH_TX_INTR 0x0002

#undef PDEBUG
#ifdef VETH_DEBUG
      /* This one if debugging is on, and kernel space */
#     define PDEBUG(fmt, args...) printk( KERN_ALERT "veth: " fmt, ## args)

#endif

