---
title: "IC - Construindo um Sniffer com a Libpcap"
layout: default
---

# Estudo do Código do scanlogd

## O que é o scanlog?

## Estrutura do Código
* scanlog.c
  * params.h (Definição das constantes utilizadas em tempo de compilação)
  * in.h (Definições de estruturas e funções para a captura dos pacotes)
    * struct header
  * in_linux.c (implementa as funções in_init e in_run definidas em in.h)
    * int in_init() -> faz a abertura de um socket raw
    * void in_run(void (\*process_packet), int size) realiza a captura de pacotes e executa o processamento do pacote

## scanlog.c
O scanlogd mantém as seguintes informações para cada endereço fonte:
```c
struct host {
	struct host *next;		/* Next entry with the same hash */
	clock_t timestamp;		/* Last update time */
	time_t start;			/* Entry creation time */
	struct in_addr saddr, daddr;	/* Source and destination addresses */
	unsigned short sport;		/* Source port */
	int count;			/* Number of ports in the list */
	int weight;			/* Total weight of ports in the list */
	unsigned short ports[SCAN_MAX_COUNT - 1];	/* List of ports */
	unsigned char tos;		/* TOS */
	unsigned char ttl;		/* TTL */
	unsigned char flags_or;		/* TCP flags OR mask */
	unsigned char flags_and;	/* TCP flags AND mask */
	unsigned char flags;		/* HF_ flags bitmask */
};
```
Possui uma estrutra que armazena o estado dos pacotes lidos

```c
static struct {
	struct host list[LIST_SIZE];	/* List of source addresses */
	struct host *hash[HASH_SIZE];	/* Hash: pointers into the list */
	int index;			/* Oldest entry to be replaced */
} state;
```
Para cada pacote que chega, é aplicada a seguinte função hash no enfereço ip para introduzir o host na hash table:

```c
static int hashfunc(struct in_addr addr)
{
	unsigned int value;
	int hash;

	value = addr.s_addr;
	hash = 0;
	do {
		hash ^= value;
	} while ((value >>= HASH_LOG));

	return hash & (HASH_SIZE - 1);
}
```
