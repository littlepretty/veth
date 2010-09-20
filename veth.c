#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kthread.h>
#include <linux/sched.h>
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
#define MODULE_NAME1 "veth_client"
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
  struct sockaddr_in addr;
  int running;
};

signed long delay = 100;

/* function prototype */
int ksocket_recv(struct socket *sock, struct sockaddr_in *addr, unsigned char *buf, int len);
int ksocket_send(struct socket *sock, struct sockaddr_in *addr, unsigned char *buf, int len);

struct veth_packet {
  struct veth_packet *next;
  //struct net_device *dev;
  int datalen;
  u8 data[ETH_DATA_LEN];
};

int pool_size = 100;
module_param(pool_size, int, 0);

struct veth_priv {
  struct net_device_stats stats;
  int status;
  struct veth_packet *pool;
  struct veth_packet *tx_queue;    /* list of incoming packets */
  struct veth_packet *last;
  //int rx_int_enabled;
  int tx_packetlen;
  //u8 *tx_packetdata;

  struct sk_buff *skb;
  spinlock_t lock;
};

void veth_setup_tx_pool()
{
  struct veth_priv *priv;
  struct veth_packet *pkt;
  int i;

  PDEBUG("veth_setup_tx_pool\n");

  priv = netdev_priv(veth_dev);
  for(i = 0; i < pool_size; i++) {
    pkt = kmalloc(sizeof(struct veth_packet), GFP_KERNEL);
    if (pkt == NULL) {
      PDEBUG("Ran out of memory\n");
      return;
    }
    pkt->next = priv->pool;
    priv->pool = pkt;
  }
}

struct veth_packet* veth_get_tx_buffer()
{
  unsigned long flags;
  struct veth_packet *pkt;
  struct veth_priv *priv = netdev_priv(veth_dev);

  PDEBUG("veth_get_tx_buffer\n");
  spin_lock_irqsave(&priv->lock, flags);
  pkt = priv->pool;
  priv->pool = pkt->next;
  if (priv->pool == NULL) {
    printk(KERN_INFO "pool empty\n");
    netif_stop_queue(veth_dev);
    return NULL;
  }

  spin_unlock_irqrestore(&priv->lock, flags);
  return pkt;
}

void veth_release_buf(struct veth_packet *pkt)
{
  //unsigned long flags;
  struct veth_priv *priv = netdev_priv(veth_dev);
  PDEBUG("veth_release_buf\n");

  //spin_lock_irqsave(&priv->lock, flags);
  pkt->next = priv->pool;
  priv->pool = pkt;
  //spin_unlock_irqrestore(&priv->lock, flags);
}

void veth_enqueue_buf(struct veth_packet *pkt)
{
  unsigned long flags;
  struct veth_packet *last;

  struct veth_priv *priv = netdev_priv(veth_dev);
  
  PDEBUG("veth_enqueue_buf\n");
  spin_lock_irqsave(&priv->lock, flags);
  last = priv->last;
  if (last == NULL) {
    priv->tx_queue = pkt;
  }
  else
    last->next = pkt;

  priv->last = pkt;
  priv->tx_packetlen++;
  pkt->next = NULL;
  PDEBUG("Have to send tx buffer len:(%d)\n",priv->tx_packetlen);
  spin_unlock_irqrestore(&priv->lock, flags);
}

struct veth_packet* veth_dequeue_buf()
{
  unsigned long flags;
  struct veth_packet *head;
  struct veth_packet *next;
  struct veth_priv *priv = netdev_priv(veth_dev);

  //spin_lock_irqsave(&priv->lock, flags);
  PDEBUG("veth_dequeue_buf\n");

  head = priv->tx_queue;
  if (head == NULL)
    PDEBUG("Head is NULL\n");
  priv->tx_queue = head->next;
  priv->tx_packetlen--;

  //spin_unlock_irqrestore(&priv->lock, flags);
  return head;
}
  
struct kthread_t *recv_kthread = NULL;
struct kthread_t *send_kthread = NULL;

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

unsigned long in_aton(const char *str)
/* [<][>][^][v][top][bottom][index][help] */
{
  u_int32_t l;
  unsigned int val;
  int i;
  
  l = 0;
  for (i = 0; i < 4; i++)
	{
	  l <<= 8;
	  if (*str != '\0')
		{
		  val = 0;
		  while (*str != '\0' && *str != '.')
			{
			  val *= 10;
			  val += *str - '0';
			  str++;
			}
		  l |= val;
		  if (*str != '\0')
			str++;
		}
	}
  return(veth_htonl(l));
}

/* Kernel Send Thread */
static void send_client(void)
{
  int bufsize = 1024;
  unsigned char msgbuf[bufsize];
  unsigned long flags;
  int err;
  int len;
  struct veth_priv *priv;
  struct veth_packet *pkt;

  PDEBUG("#### Kernel thread SEND client ####\n");
  lock_kernel();
  send_kthread->running = 1;
  current->flags |= PF_NOFREEZE;
  daemonize(MODULE_NAME1);
  allow_signal(SIGKILL);
  unlock_kernel();

  priv = netdev_priv(veth_dev);
  if ( (err=sock_create(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &send_kthread->sock)) < 0) {
	PDEBUG("Cannot create client socket\n");
	goto out;
  }

  memset(&send_kthread->addr, 0, sizeof(struct sockaddr));
  send_kthread->addr.sin_family = AF_INET;
  send_kthread->addr.sin_addr.s_addr = in_aton(dstip);
  send_kthread->addr.sin_port = htons(dstport);

  if( (err = send_kthread->sock->ops->connect(send_kthread->sock,
											  (struct sockaddr *)&send_kthread->addr,
											  sizeof(struct sockaddr),0)) < 0) {
	PDEBUG("Fail to connect\n");
	goto close_out;
  }
  
  /* main loop for client send */
  while(!kthread_should_stop()) {
    PDEBUG("send client work\n");
    spin_lock_irqsave(&priv->lock, flags);
    while(priv->tx_packetlen > 0) {
      PDEBUG("In send_client:tx_packetlen(%d)\n",priv->tx_packetlen);
      pkt = veth_dequeue_buf();
      ksocket_send(send_kthread->sock, &send_kthread->addr, pkt->data, pkt->datalen);
      PDEBUG("push to used pkt\n");
      pkt->next = priv->pool;
      priv->pool = pkt;
    }
  spin_unlock_irqrestore(&priv->lock, flags);
  
  set_current_state(TASK_INTERRUPTIBLE);
  schedule_timeout(30*HZ);
  //set_current_state(TASK_RUNNING);
  if(signal_pending(current)) break;
  
  }  
 out:
  PDEBUG("Error:Called out\n");
  return;
 close_out:
  PDEBUG("Error:Called close_out\n");
  sock_release(send_kthread->sock);

  return;
  
}

/* Kernel thread */
static void recv_server(void) 
{
  int bufsize = 1024;
  unsigned char msgbuf[bufsize];
  int err;
  int len;
  struct veth_priv *priv;


  PDEBUG("#### Recv Kernel thread initialize #####\n");
  lock_kernel();
  recv_kthread->running = 1;
  current->flags |= PF_NOFREEZE;
  daemonize(MODULE_NAME);
  allow_signal(SIGKILL);
  unlock_kernel();

  priv = netdev_priv(veth_dev);

  /* create socket */
  /* initial udp kernel socket server */
  err = sock_create_kern(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &recv_kthread->sock);
  if (err < 0) {
    PDEBUG("sock_create() err %d\n", err);
    return;
  }

  memset(&recv_kthread->addr, 0, sizeof(recv_kthread->addr));
  recv_kthread->addr.sin_family      = AF_INET;
  recv_kthread->addr.sin_addr.s_addr = htonl(INADDR_ANY);
  recv_kthread->addr.sin_port        = htons(srcport);

  // bind
  err = recv_kthread->sock->ops->bind(recv_kthread->sock, 
				      (struct sockaddr *)&recv_kthread->addr, 
				      sizeof(struct sockaddr_in));
  if (err < 0) {
    PDEBUG("sock_bind() err %d\n", err);
    goto release;
  }
  
  /* main loop for client connect */
  while(!kthread_should_stop()) {
    // receive data from remote device, and interrupt RECV
    memset(&msgbuf, 0, bufsize);
    // read data size (4 bytes)
    len = ksocket_recv(recv_kthread->sock, &recv_kthread->addr, 
		       msgbuf, MAX_PAYLOAD);
    if (len < 0 || len > MAX_PAYLOAD) {
      PDEBUG("RECV MSG size(%d)\n", len);
      continue;
    }

    if(signal_pending(current)) break;
    
    veth_rx(veth_dev, msgbuf, len);
  }


 release:
  sock_release(recv_kthread->sock);
  recv_kthread->sock = NULL;
}

static void client_init(struct udp_client *myclient)
{
  int err;
  
  PDEBUG("Called client_init\n");
  /* create client socket */

  if ( (err=sock_create(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &myclient->sock)) < 0) {
	PDEBUG("Can not create client socket\n");
	goto out;
  }

  memset(&myclient->addr, 0, sizeof(struct sockaddr));
  myclient->addr.sin_family = AF_INET;
  //myclient->addr.sin_addr.s_addr = htonl(in_aton("127.0.0.1"));
  myclient->addr.sin_addr.s_addr = in_aton(dstip);
  myclient->addr.sin_port = htons(dstport);
  

  if(  (err = myclient->sock->ops->connect(myclient->sock, (struct sockaddr *)&myclient->addr, sizeof(struct sockaddr),0)) < 0) {
    PDEBUG("Failed to connect\n");
    goto close_out;
	}
  myclient->connect = 1;
  PDEBUG("Success connect\n");
  return;
  
 out:
  myclient->connect = 0;
 close_out:
  sock_release(myclient->sock);
  myclient->connect = 0;
  
  PDEBUG("MY client connect:(%d)\n",myclient->connect);
  return;
}

int ksocket_send(struct socket *sock, struct sockaddr_in *addr, unsigned char *buf, int len)
{
  struct msghdr msg;
  struct iovec iov;
  mm_segment_t oldfs;
  int size = 0;
  
  if (sock->sk == NULL) {
	PDEBUG("Client Sock fail\n");
    return 0;
  }

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
  PDEBUG("KSOCKET SEND(%d)\n",size);
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
  PDEBUG("Client IP:(%s)(%d)\n",dstip, dstport);
  
  //myclient = kmalloc(sizeof(struct udp_client),GFP_KERNEL);
  //memset(myclient,0,sizeof(struct udp_client));

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
  struct veth_packet *pkt;

  priv = netdev_priv(dev);
  if (len < sizeof(struct ethhdr) + sizeof(struct iphdr)) {
    PDEBUG("veth: packet too short .. (%i octets\n",len);
    return;
  }

  // get veth_packet
  pkt = veth_get_tx_buffer();
  if (pkt == NULL) {
    PDEBUG("No tx buffer\n");
    return;
  }

  memcpy(pkt->data, buf, len);
  pkt->datalen = len;

  // push into buffer
  veth_enqueue_buf(pkt);

  /*
  if (myclient->connect != 1) {
    // reconnect
    client_init(myclient);
    if(myclient->connect != 1) {
      PDEBUG("Client init fail\n");
      return;
    }
  }
  */
  
  PDEBUG("Send pkt size(%d)\n", len); 
  //ksocket_send(myclient->sock, &myclient->addr, buf, len);

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

  PDEBUG("called veth_tx(data len:%d > %d)\n",skb->len,ETH_ZLEN);
  data = skb->data;
  len = skb->len;
  /*
  if (len < ETH_ZLEN) {
    memset(shortpkt, 0, ETH_ZLEN);
    memcpy(shortpkt, skb->data, skb->len);
    len = ETH_ZLEN;
    data = shortpkt;
	}
  */
  dev->trans_start = jiffies;   /* save the timestamp */

  /* Remember the skb, so we can free it at interrupt time */
  priv->skb = skb;


  PDEBUG("PKT type:%d\n",skb->pkt_type);
  // MAC Header
  skb_reset_mac_header(skb);
  p = skb_mac_header(skb);
  
#ifdef DEBUG_HDR  
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
#endif
  
  /* actual deliver of data */
  veth_hw_tx(data, len, dev);


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
      PDEBUG("veth rx: low on mem - packet dropped\n");
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
  priv->tx_queue = NULL;
  priv->last = NULL;
  priv->tx_packetlen = 0;
  spin_lock_init(&priv->lock);   /* enable receive interrupt */
  

  //myclient = kmalloc(sizeof(struct udp_client),GFP_KERNEL);
  //client_init(myclient);
  //myclient->sock = NULL;
}



static void veth_cleanup(void)
{
  PDEBUG("veth cleanup\n");

  sock_release(recv_kthread->sock);
  sock_release(send_kthread->sock);
  
  //sock_release(myclient->sock);
  
  //sock_release(client);
  //kthread_stop((struct task_struct*)kthread);
  kfree(recv_kthread);
  kfree(send_kthread);
  //kfree(myclient);
  
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
  if( (result = register_netdev(veth_dev)) ) {
    PDEBUG("veth: error registering device\n");
  }
  else
    ret = 0;

  veth_setup_tx_pool();

  /* kthread */
  // Server
  PDEBUG("recv_kthread create\n");
  recv_kthread = kmalloc(sizeof(struct kthread_t), GFP_KERNEL);
  memset(recv_kthread, 0, sizeof(struct kthread_t));
  recv_kthread->thread = NULL;
  // Client

  PDEBUG("send_kthread create\n");
  send_kthread = kmalloc(sizeof(struct kthread_t), GFP_KERNEL);
  memset(send_kthread, 0, sizeof(struct kthread_t));
  send_kthread->thread = NULL;

  /* start kernel thread */
  PDEBUG("thread 1\n");
  recv_kthread->thread = kthread_run((void*)recv_server, NULL, "recv_server");
  if(IS_ERR(recv_kthread->thread))
    goto out;

  PDEBUG("thread 2\n");
  send_kthread->thread = kthread_run((void*)send_client, NULL, "send_client");
  if(IS_ERR(send_kthread->thread))
    goto out;
  return 0;

 out:
  PDEBUG("THREAD ERR\n");
  if (ret)
    veth_cleanup();
  return ret;
}

  
module_init(veth_init_module);
module_exit(veth_cleanup);