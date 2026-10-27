// SPDX-License-Identifier: GPL-2.0-only
// Queue-only local NAT repair. mirred/IFB resets nfct; restore the ORIGINAL
// or REPLY pre-NAT tuple so the same connection is reattached on loopback RX.
// No conntrack allocation, mutation, map, socket, payload forwarding or NAT
// decision is performed here. An absent/mismatched entry drops the packet.
// Use the 12-byte default-zone lookup ABI supported by Linux 6.1 and 6.12.
typedef unsigned char u8;typedef unsigned short u16;typedef unsigned int u32;typedef unsigned long long u64;typedef int s32;
#define CORE __attribute__((preserve_access_index))
struct __sk_buff {u32 len,pkt_type,mark;};
union nf_inet_addr {u32 all[4];u32 ip;u32 ip6[4];};
union nf_conntrack_man_proto {u16 all;};
struct nf_conntrack_man {union nf_inet_addr u3;union nf_conntrack_man_proto u;u16 l3num;} CORE;
struct nf_conntrack_tuple {struct nf_conntrack_man src;struct {union nf_inet_addr u3;union nf_conntrack_man_proto u;u8 protonum,dir;}dst;} CORE;
struct hlist_nulls_node {void*next;void**pprev;};
struct nf_conntrack_tuple_hash {struct hlist_nulls_node hnnode;struct nf_conntrack_tuple tuple;} CORE;
struct nf_conn {struct nf_conntrack_tuple_hash tuplehash[2];u32 mark;} CORE;
struct bpf_sock_tuple {union {struct{u32 saddr,daddr;u16 sport,dport;}ipv4;struct{u32 saddr[4],daddr[4];u16 sport,dport;}ipv6;};};
struct bpf_ct_opts {s32 netns_id,error;u8 l4proto,dir,reserved[2];};
extern struct nf_conn*bpf_skb_ct_lookup(struct __sk_buff*,struct bpf_sock_tuple*,u32,struct bpf_ct_opts*,u32) __attribute__((section(".ksyms")));
extern void bpf_ct_release(struct nf_conn*) __attribute__((section(".ksyms")));
static long(*load)(void*,u32,void*,u32)=(void*)26;
static long(*store)(void*,u32,const void*,u32,u64)=(void*)9;
static long(*l3csum)(void*,u32,u64,u64,u64)=(void*)10;
static long(*l4csum)(void*,u32,u64,u64,u64)=(void*)11;

__attribute__((section("tc"),used)) int restore(struct __sk_buff*skb){
 u8 h[40]={0};struct bpf_sock_tuple lookup={0},wanted={0};u32 off=14,l4,proto,family,size;struct bpf_ct_opts opts={.netns_id=-1};
 if(load(skb,off,h,20))return 2;family=h[0]>>4;
 if(family==4){proto=h[9];if(proto!=6&&proto!=17)return 0;if((h[6]&31)||h[7])return 2;if((h[0]&15)<5)return 2;l4=off+(h[0]&15)*4;size=12;__builtin_memcpy(&lookup.ipv4.saddr,h+16,4);__builtin_memcpy(&lookup.ipv4.daddr,h+12,4);}
 else if(family==6){if(load(skb,off,h,40))return 2;proto=h[6];l4=off+40;size=36;__builtin_memcpy(lookup.ipv6.saddr,h+24,16);__builtin_memcpy(lookup.ipv6.daddr,h+8,16);
  for(int n=0;n<8;n++){if(proto==6||proto==17)break;u8 ext[8];if(load(skb,l4,ext,8))return 2;if(proto==0||proto==60){proto=ext[0];l4+=((u32)ext[1]+1)*8;}else if(proto==44){if(ext[2]||(ext[3]&248))return 2;proto=ext[0];l4+=8;}else return 2;}
  if(proto!=6&&proto!=17)return 2;
 }else return 0;
 u16 ports[2];if(load(skb,l4,ports,4))return 2;if(family==4){lookup.ipv4.sport=ports[1];lookup.ipv4.dport=ports[0];}else{lookup.ipv6.sport=ports[1];lookup.ipv6.dport=ports[0];}opts.l4proto=proto;
 struct nf_conn*ct=bpf_skb_ct_lookup(skb,&lookup,size,&opts,12);if(!ct)return 2;
 if((ct->mark&0xffffff00)!=(skb->mark&0xffffff00)){bpf_ct_release(ct);return 2;}
 u32 direction=(skb->mark&0x80)?0:1;
 if(direction==0){
  if(family==4){wanted.ipv4.saddr=ct->tuplehash[0].tuple.src.u3.ip;wanted.ipv4.daddr=ct->tuplehash[0].tuple.dst.u3.ip;wanted.ipv4.sport=ct->tuplehash[0].tuple.src.u.all;wanted.ipv4.dport=ct->tuplehash[0].tuple.dst.u.all;}
  else{for(int i=0;i<4;i++){wanted.ipv6.saddr[i]=ct->tuplehash[0].tuple.src.u3.ip6[i];wanted.ipv6.daddr[i]=ct->tuplehash[0].tuple.dst.u3.ip6[i];}wanted.ipv6.sport=ct->tuplehash[0].tuple.src.u.all;wanted.ipv6.dport=ct->tuplehash[0].tuple.dst.u.all;}
 }else{
  if(family==4){wanted.ipv4.saddr=ct->tuplehash[1].tuple.src.u3.ip;wanted.ipv4.daddr=ct->tuplehash[1].tuple.dst.u3.ip;wanted.ipv4.sport=ct->tuplehash[1].tuple.src.u.all;wanted.ipv4.dport=ct->tuplehash[1].tuple.dst.u.all;}
  else{for(int i=0;i<4;i++){wanted.ipv6.saddr[i]=ct->tuplehash[1].tuple.src.u3.ip6[i];wanted.ipv6.daddr[i]=ct->tuplehash[1].tuple.dst.u3.ip6[i];}wanted.ipv6.sport=ct->tuplehash[1].tuple.src.u.all;wanted.ipv6.dport=ct->tuplehash[1].tuple.dst.u.all;}
 }
 bpf_ct_release(ct);
 u32 cs=l4+(proto==6?16:6);u64 zero=proto==17?32:0;u16 nextports[2];
 if(family==4){u32 old[2];__builtin_memcpy(old,h+12,8);
  if(l3csum(skb,off+10,old[0],wanted.ipv4.saddr,4)||l3csum(skb,off+10,old[1],wanted.ipv4.daddr,4))return 2;
  if(l4csum(skb,cs,old[0],wanted.ipv4.saddr,4|16|zero)||l4csum(skb,cs,old[1],wanted.ipv4.daddr,4|16|zero))return 2;
  if(store(skb,off+12,&wanted.ipv4.saddr,8,1))return 2;nextports[0]=wanted.ipv4.sport;nextports[1]=wanted.ipv4.dport;
 }else{u32 old[8];__builtin_memcpy(old,h+8,32);for(int i=0;i<4;i++){if(l4csum(skb,cs,old[i],wanted.ipv6.saddr[i],4|16|zero)||l4csum(skb,cs,old[i+4],wanted.ipv6.daddr[i],4|16|zero))return 2;}
  if(store(skb,off+8,wanted.ipv6.saddr,32,1))return 2;nextports[0]=wanted.ipv6.sport;nextports[1]=wanted.ipv6.dport;
 }
 if(l4csum(skb,cs,ports[0],nextports[0],2|zero)||l4csum(skb,cs,ports[1],nextports[1],2|zero))return 2;
 if(store(skb,l4,nextports,4,1))return 2;return -1;
}
char bpf_license[] __attribute__((section("license"),used))="GPL";
