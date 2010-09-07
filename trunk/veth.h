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

#ifndef VETH_DEBUG
#define PDEBUG(fmt, args...)
#endif

__inline u_int32_t veth_ntohl(u_int32_t n)
{
  return ((n & 0xFF) << 24) | ((n & 0xFF00) << 8) | ((n & 0xFF0000) >> 8) | ((n & 0xFF000000) >> 24);
}
__inline u_int32_t veth_htonl(u_int32_t n)
{
  return((n & 0xFF) << 24) | ((n &0xFF00) << 8) | ((n & 0xFF0000) >> 8) | ((n & 0xFF000000) >> 24);
}

