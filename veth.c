#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kthread.h>
#include <linux/time.h>
#include <linux/errno.h>

#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <linux/skbuff.h>

#include <linux/socket.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <net/arp.h>

#include "veth.h"

#define DRV_NAME      "veth"
#define DRV_VERSION   "1.0"

#define MAX_PAYLOAD 1564
#define MODULE_NAME "veth"
#define INADDR_SEND INADDR_LOOPBACK

MODULE_AUTHOR("Choonho Son");
MODULE_LICENSE("Dual BSD/GPL");

/* module parameter variable */
static int srcport = 10000;
static char *dstip = "127.0.0.1";
static int dstport = 10001;
module_param(dstip, charp, S_IWUSR);
module_param(srcport, int, S_IWUSR);
module_param(dstport, int, S_IWUSR);

struct net_device *veth_dev;
static void (*veth_interrupt)(int, void *, struct pt_regs *);
void veth_rx(struct net_device*, char*, int);

//static struct socket *client;
//static struct sockaddr_in cliaddr;

/* UDP client socket */
struct udp_client {
  struct socket *sock;
  struct sockaddr_in addr;
  int connect;
};

struct udp_client *myclient;

/* UDP Server kernel socket */
struct kthread_t {
  struct task_struct *thread;
  struct socket *sock;
  //struct socket *client;
  struct sockaddr_in addr;
  //struct sockaddr_in cliaddr;
  int running;
};

/* function prototype */
int ksocket_recv(struct socket *sock, struct sockaddr_in *addr, unsigned char *buf, int len);
int ksocket_send(struct socket *sock, struct sockaddr_in *addr, unsigned char *buf, int len);

struct veth_packet {
  struct veth_packet *next;
  struct net_device *dev;
  int datalen;
  u8 data[ETH_DATA_LEN];
};

int pool_size = 8;
module_param(pool_size, int, 0);


struct veth_priv {
  struct net_device_stats stats;
  int status;
  struct veth_packet *ppool;
  struct veth_packet *rx_queue;    /* list of incoming packets */
  int rx_int_enabled;
  int tx_packetlen;
  u8 *tx_packetdata;

  struct sk_buff *skb;
  spinlock_t lock;
};

struct kthread_t *kthread = NULL;

static char buf[4*sizeof "123"];
char* inet_ntoa(struct in_addr ina)
{
  unsigned char *ucp = (unsigned char*)&ina;
  sprintf(buf, "%d.%d.%d.%d",
	  ucp[0]&0xff,
	  ucp[1]&0xff,
	  ucp[2]&0xff,
	  ucp[3]&0xff);
  return buf;
}

/* Kernel thread */
static void xmit_server(void) 
{
  int bufsize = 1024;
  unsigned char msgbuf[bufsize];
  int err;
  int backlog = 1024;
  int len;
  struct veth_priv *priv;
  u_int32_t pkt_len;
  u_int32_t pkt_len_temp;

  PDEBUG("\n#### Kernel thread initialize #####\n");
  lock_kernel();
  kthread->running = 1;
  current->flags |= PF_NOFREEZE;
  daemonize(MODULE_NAME);
  allow_signal(SIGKILL);
  unlock_kernel();

  //kthread->running = -1;
  //kthread->client_socket = -1;
  priv = netdev_priv(veth_dev);

  /* create socket */
  /* initial udp kernel socket server */
  err = sock_create_kern(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &kthread->sock);
  if (err < 0) {
    printk("sock_create() err %d\n", err);
    return;
  }

  memset(&kthread->addr, 0, sizeof(kthread->addr));
  kthread->addr.sin_family      = AF_INET;
  kthread->addr.sin_addr.s_addr = htonl(INADDR_ANY);
  kthread->addr.sin_port        = htons(srcport);

  // bind
  err = kthread->sock->ops->bind(kthread->sock, (struct sockaddr *)&kthread->addr, sizeof(struct sockaddr_in));
  if (err < 0) {
    printk("sock_bind() err %d\n", err);
    goto release;
  }
  
  // listen
  /*
  err = kthread->sock->ops->listen(kthread->sock, backlog);
  if (err < 0) {
    printk("sock_listen() err %d\n", err);
    goto release;
  }
  */


  /* main loop for client connect */
  while(!kthread_should_stop()) {
    // receive data from remote device, and interrupt RECV
    memset(&msgbuf, 0, bufsize);
    // read data size (4 bytes)
    len = ksocket_recv(kthread->sock, &kthread->addr, msgbuf, MAX_PAYLOAD);
    if (len < 0 || len > MAX_PAYLOAD) {
      PDEBUG("RECV MSG size(%d)\n", len);
      continue;
    }

    if(signal_pending(current)) break;
    
    veth_rx(veth_dev, msgbuf, pkt_len);
  }


 release:
  sock_release(kthread->sock);
  kthread->sock = NULL;
}

static struct udp_client* client_init(struct udp_client* client)
{
  struct udp_client *myclient = client;
  int err;

  //myclient = kmalloc(sizeof(struct udp_client),GFP_KERNEL);

  /* create client socket */
  if ( (err=sock_create(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &myclient->sock)) < 0) {
    PDEBUG("Can not create client socket\n");
    goto out;
  }

  memset(&myclient->addr, 0, sizeof(struct sockaddr));
  myclient->addr.sin_family = AF_INET;
  myclient->addr.sin_addr.s_addr = htonl(INADDR_SEND);
  myclient->addr.sin_port = htons(dstport);

  if(  (err = myclient->sock->ops->connect(myclient->sock, (struct sockaddr *)&myclient->addr, sizeof(struct sockaddr),0)) < 0) {
    PDEBUG("Failed to connect\n");
    goto close_out;
  }
 out:
  myclient->connect = -1;
 close_out:
  sock_release(myclient->sock);
  myclient->connect = -1;

  return myclient;
}

int ksocket_send(struct socket *sock, struct sockaddr_in *addr, unsigned char *buf, int len)
{
  struct msghdr msg;
  struct iovec iov;
  mm_segment_t oldfs;
  int size = 0;
  
  if (sock->sk == NULL)
    return 0;

  iov.iov_base = buf;
  iov.iov_len = len;
  
  msg.msg_flags = 0;
  msg.msg_name = addr;
  msg.msg_namelen = sizeof(struct sockaddr_in);
  msg.msg_control = NULL;
  msg.msg_controllen = 0;
  msg.msg_iov = &iov;

  oldfs = get_fs();
  set_fs(KERNEL_DS);
  size = sock_sendmsg(sock, &msg, len);
  set_fs(oldfs);

  return size;
}

int ksocket_recv(struct socket* sock, struct sockaddr_in* addr, unsigned char* buf, int len)
{
  struct msghdr msg;
  struct iovec iov;
  mm_segment_t oldfs;
  int size = 0;

  if (sock->sk == NULL) return 0;

  iov.iov_base = buf;
  iov.iov_len = len;
  
  msg.msg_flags = 0;
  msg.msg_name = addr;
  msg.msg_namelen = sizeof(struct sockaddr_in);
  msg.msg_control = NULL;
  msg.msg_controllen = 0;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  
  oldfs = get_fs();
  set_fs(KERNEL_DS);
  size = sock_recvmsg(sock, &msg, len, msg.msg_flags);
  set_fs(oldfs);

  return size;
}

int veth_open(struct net_device *dev)
{
  PDEBUG("veth_open\n");
  PDEBUG("Server IP:localhost(%d)\n",srcport);
  PDEBUG("Client IP:(%d)(%d)\n",dstip, dstport);
  
  myclient = kmalloc(sizeof(struct udp_client),GFP_KERNEL);
  memset(myclient,0,sizeof(struct udp_client));

  netif_start_queue(dev);

  return 0;

}

int veth_release(struct net_device *dev)
{
  PDEBUG("veth stop\n");

  netif_stop_queue(dev);
  
   return 0;
}

static void veth_hw_tx(char *buf, int len, struct net_device *dev)
{
  struct veth_priv *priv; 
  u_int32_t pkt_len, pkt_len_temp;

  priv = netdev_priv(dev);
  if (len < sizeof(struct ethhdr) + sizeof(struct iphdr)) {
    printk("veth: packet too short .. (%i octets\n",len);
    return;
  }

  if (myclient->connect == 0) {
    // reconnect
    myclient = client_init(myclient);
    if(myclient->connect == 0) {
      PDEBUG("Client init fail\n");
      return;
    }
  }
  ksocket_send(myclient->sock, &myclient->addr, buf, len);

  /*
  if(ksocket_send(client, &cliaddr, &pkt_len, 4) != -1) {
    ksocket_send(client, &cliaddr, buf, len);
    dev_kfree_skb(priv->skb);
  }
  */

}

static int veth_tx(struct sk_buff *skb, struct net_device *dev)
{

  int len;
  char *data,shortpkt[ETH_ZLEN];
  struct veth_priv *priv = netdev_priv(dev);
  unsigned char *p;
  struct iphdr ipheader;
  struct in_addr in;
    
  DECLARE_MAC_BUF(mac);

  printk(KERN_ALERT "called veth_tx(data len:%d > %d)\n",skb->len,ETH_ZLEN);
  data = skb->data;
  len = skb->len;
  if (len < ETH_ZLEN) {
    memset(shortpkt, 0, ETH_ZLEN);
    memcpy(shortpkt, skb->data, skb->len);
    len = ETH_ZLEN;
    data = shortpkt;
  }
  dev->trans_start = jiffies;   /* save the timestamp */

  /* Remember the skb, so we can free it at interrupt time */
  priv->skb = skb;

#ifdef DEBUG_HDR
  PDEBUG("PKT type:%d\n",skb->pkt_type);
  // MAC Header
  skb_reset_mac_header(skb);
  p = skb_mac_header(skb);
  
  if(p) {
    printk(KERN_ALERT"Dst:%s\n",print_mac(mac, p));
    printk(KERN_ALERT"Src:%s\n",print_mac(mac,&p[6])); 
    printk(KERN_ALERT"Type:%02x%02x\n",p[12],p[13]);
  } else
    PDEBUG("null skb_mac_header\n");
  if(p[12] == 8 && p[13] == 0) {
    PDEBUG("IP Payload\n");
    // IP Header


    p = skb_network_header(skb);
    memcpy(&ipheader, p, sizeof(ipheader));
    in.s_addr = ipheader.saddr;
    printk(KERN_ALERT"src ip : %s\n", inet_ntoa(in));
    in.s_addr = ipheader.daddr;
    printk(KERN_ALERT"dst ip : %s\n", inet_ntoa(in));
  }
  else if(p[12] == 8 && p[13] == 6)
    PDEBUG("ARP Payload\n");
  /* actual deliver of data */
  veth_hw_tx(data, len, dev);
#endif

  return 0;
}

/*
 * Receive a packet: retrieve, encapsulate and pass to upper levels
 */
//void veth_rx(struct net_device *dev, struct veth_packet *pkt)
void veth_rx(struct net_device *dev, char* data, int datalen)
{
  struct sk_buff *skb;
  struct veth_priv *priv = netdev_priv(dev);
  
  PDEBUG("VETH_RX:len(%d)\n",datalen);
  skb = dev_alloc_skb(datalen + 2);
  if (!skb) {
    if (printk_ratelimit())
      printk(KERN_NOTICE "veth rx: low on mem - packet dropped\n");
    priv->stats.rx_dropped++;
    goto out;
  }

  skb_reserve(skb, 2); /* align IP on 16B boundary */
  memcpy(skb_put(skb, datalen), data, datalen);

  /* Write metadata, and the pass to the receive level */
  skb->dev = dev;
  skb->protocol = eth_type_trans(skb, dev);
  skb->ip_summed = CHECKSUM_UNNECESSARY;  // don't check it
  priv->stats.rx_packets++;
  priv->stats.rx_bytes += datalen;
  netif_rx(skb);

 out:
  return;
}


static void veth_regular_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{
  struct net_device *dev = (struct net_device *)dev_id;

  PDEBUG("Interrupt called(irq:%d)",irq);
  if(!dev)
    return;
}

struct net_device_stats *veth_stats(struct net_device *dev)
{
  struct veth_priv *priv = netdev_priv(dev);
  return &priv->stats;
}

/*
 * It is invoked by register_netdev()
 */
void veth_init(struct net_device *dev)
{
  struct veth_priv *priv;
  PDEBUG("veth init...\n");
  
  // ethernet setup
  ether_setup(dev);
  memcpy(dev->dev_addr, "\0VETH0", ETH_ALEN);
  dev->open            = veth_open;
  dev->stop            = veth_release;
  dev->hard_start_xmit = veth_tx;
  dev->get_stats       = veth_stats; 
  priv = netdev_priv(dev);
  memset(priv, 0, sizeof(struct veth_priv));
  spin_lock_init(&priv->lock);   /* enable receive interrupt */
}



static void veth_cleanup(void)
{
  printk(KERN_ALERT "veth cleanup\n");

  sock_release(kthread->sock);
  //sock_release(client);
  //kthread_stop((struct task_struct*)kthread);
  kfree(kthread);

  unregister_netdev(veth_dev);
  free_netdev(veth_dev);
  return;
}

static int __init veth_init_module(void)
{
  int result, ret = -ENOMEM;
  veth_interrupt = veth_regular_interrupt;

  PDEBUG("veth init module...\n");

  veth_dev = alloc_netdev(sizeof(struct veth_priv), "veth%d", veth_init);
  if (veth_dev == NULL)
    goto out;

  ret = -ENODEV;
  if( (result = register_netdev(veth_dev)) )
    printk("veth: error registering device\n"); 
  else
    ret = 0;

  /* kthread */
  kthread = kmalloc(sizeof(struct kthread_t), GFP_KERNEL);
  memset(kthread, 0, sizeof(struct kthread_t));
  kthread->thread = NULL;

  /* start kernel thread */
  kthread->thread = kthread_run((void*)xmit_server, NULL, "xmit_server");
  if(IS_ERR(kthread->thread))
    goto out;
  return 0;
  
 out:
  if (ret)
    veth_cleanup();
  return ret;
}

  
module_init(veth_init_module);
module_exit(veth_cleanup);
