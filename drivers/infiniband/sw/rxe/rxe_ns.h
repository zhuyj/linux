#ifndef RXE_NS_H
#define RXE_NS_H

struct sock *rxe_ns_pernet_sk4(struct net *net);
struct sock *rxe_ns_pernet_sk6(struct net *net);
void rxe_ns_pernet_set_sk4(struct net *net, struct sock *sk);
void rxe_ns_pernet_set_sk6(struct net *net, struct sock *sk);
int __init rxe_namespace_init(void);
void __exit rxe_namespace_exit(void);

#endif /* RXE_NS_H */
