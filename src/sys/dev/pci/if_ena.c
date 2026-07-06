/*	$OpenBSD$ */

/*
 * Copyright (c) 2026 Ilya Voronin <ivoronin@octalwave.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "bpfilter.h"

/*
 * Driver for the AWS Elastic Network Adapter (ENA), the NIC of EC2
 * Nitro instances.  Written from the ENA specification; see
 * if_enareg.h for the hardware interface.
 *
 * The device is driven through three rings programmed via BAR0: an
 * admin queue (AQ) for commands, an admin completion queue (ACQ) for
 * their results and an async event queue (AENQ) for link state,
 * keepalive and error events.  IO queues are created on top of those
 * with admin commands.  Admin commands are executed synchronously by
 * polling: they only run from attach, configuration and reset paths
 * where sleeping is fine, which keeps the whole completion machinery
 * out (see docs/adr/0002 in the driver's development history).
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/device.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/mutex.h>
#include <sys/rwlock.h>
#include <sys/sched.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/syslog.h>
#include <sys/task.h>
#include <sys/time.h>
#include <sys/timeout.h>
#include <sys/atomic.h>
#include <sys/kstat.h>

#include <machine/bus.h>
#include <machine/intr.h>

#include <net/if.h>
#include <net/if_media.h>

#if NBPFILTER > 0
#include <net/bpf.h>
#endif

#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <dev/pci/pcireg.h>
#include <dev/pci/pcivar.h>
#include <dev/pci/pcidevs.h>

#include <dev/pci/if_enareg.h>

CTASSERT(sizeof(struct ena_mem_addr) == 8);
CTASSERT(sizeof(struct ena_aq_desc) == 64);
CTASSERT(sizeof(struct ena_aq_feat_cmd) == 64);
CTASSERT(sizeof(union ena_aq_cmd) == 64);
CTASSERT(sizeof(struct ena_acq_desc) == 64);
CTASSERT(sizeof(struct ena_feat_device_attr) == 36);
CTASSERT(sizeof(struct ena_feat_max_queues_ext) == 44);
CTASSERT(sizeof(struct ena_feat_max_queues) == 32);
CTASSERT(sizeof(struct ena_feat_mtu) == 4);
CTASSERT(sizeof(struct ena_feat_aenq) == 8);
CTASSERT(sizeof(struct ena_feat_llq) == 36);
CTASSERT(sizeof(struct ena_feat_host_attr) == 20);
CTASSERT(sizeof(struct ena_create_cq_resp) == 16);
CTASSERT(sizeof(struct ena_create_sq_resp) == 16);
CTASSERT(sizeof(struct ena_host_info) == 196);
CTASSERT(sizeof(struct ena_aenq_desc) == 64);
CTASSERT(sizeof(struct ena_aq_create_cq_cmd) == 64);
CTASSERT(sizeof(struct ena_aq_create_sq_cmd) == 64);
CTASSERT(sizeof(struct ena_aq_destroy_cq_cmd) == 64);
CTASSERT(sizeof(struct ena_aq_destroy_sq_cmd) == 64);
CTASSERT(sizeof(struct ena_aq_get_stats_cmd) == 64);
CTASSERT(sizeof(struct ena_basic_stats) == 56);
CTASSERT(sizeof(struct ena_eni_stats) == 40);
CTASSERT(sizeof(struct ena_rx_desc) == 16);
CTASSERT(sizeof(struct ena_rx_cdesc) == 16);
CTASSERT(sizeof(struct ena_tx_desc) == 16);
CTASSERT(sizeof(struct ena_tx_cdesc) == 8);

#define ENA_PCI_BAR0		PCI_MAPREG_START
#define ENA_PCI_BAR2		(PCI_MAPREG_START + 8)	/* LLQ window */

#define ENA_AQ_NUM		32	/* power of two */
#define ENA_AENQ_NUM		16	/* power of two */

/* AENQ groups the driver handles. */
#define ENA_AENQ_GROUPS_MVP \
    (ENA_AENQ_GROUP_BIT(ENA_AENQ_GROUP_LINK_CHANGE) | \
     ENA_AENQ_GROUP_BIT(ENA_AENQ_GROUP_FATAL_ERROR) | \
     ENA_AENQ_GROUP_BIT(ENA_AENQ_GROUP_WARNING) | \
     ENA_AENQ_GROUP_BIT(ENA_AENQ_GROUP_NOTIFICATION) | \
     ENA_AENQ_GROUP_BIT(ENA_AENQ_GROUP_KEEP_ALIVE))

/* Reset if the device stays silent longer than this, in seconds. */
#define ENA_KEEPALIVE_TIMEOUT	6

/* Ring size target, clamped to the device limits at attach. */
#define ENA_NDESCS_MAX		1024
/* Smaller rings than this can't even hold one max-sized packet. */
#define ENA_NDESCS_MIN		16

#define ENA_IO_VECTOR		1	/* MSI-X vector of the IO pair */

/* DMA segments per TX packet; more than this gets defragmented. */
#define ENA_TX_NSEGS		8

/* Ticks without TX completion progress before we give up. */
#define ENA_TX_STUCK_TIMEOUT	3

/*
 * LLQ geometry.  The entry size is negotiated in ena_llq_negotiate():
 * 128 bytes, or wide 256-byte entries when the device recommends them
 * (Nitro v5 and later require that in practice).  Two descriptor
 * slots (meta + first data) sit in front of the pushed header;
 * continuation entries carry entry_size / 16 descriptors.
 */
#define ENA_LLQ_ENTRY_MIN	128
#define ENA_LLQ_ENTRY_MAX	256
#define ENA_LLQ_DESCS_BEFORE_HDR 2
#define ENA_LLQ_HDR_OFF		(ENA_LLQ_DESCS_BEFORE_HDR * \
				 sizeof(struct ena_tx_desc))

/* Admin/reset polling: exponential backoff between register reads. */
#define ENA_POLL_MIN_US		100
#define ENA_POLL_MAX_US		5000
#define ENA_AQ_TIMEOUT_US	3000000	/* if CAPS doesn't say better */

#define ENA_DRIVER_VERSION	0x00000002	/* 2.0.0 */

struct ena_dmamem {
	bus_dmamap_t		 edm_map;
	bus_dma_segment_t	 edm_seg;	/* always a single segment */
	size_t			 edm_size;
	caddr_t			 edm_kva;
};
#define ENA_DMA_MAP(_e)		((_e)->edm_map)
#define ENA_DMA_DVA(_e)		((_e)->edm_map->dm_segs[0].ds_addr)
#define ENA_DMA_KVA(_e)		((void *)(_e)->edm_kva)
/* A zero length doubles as "not allocated": free() resets it. */
#define ENA_DMA_LEN(_e)		((_e)->edm_size)
#define ENA_DMA_SYNC(_sc, _e, _ops)					\
	bus_dmamap_sync((_sc)->sc_dmat, ENA_DMA_MAP(_e), 0,		\
	    ENA_DMA_LEN(_e), (_ops))

struct ena_rx_slot {
	struct mbuf		*ers_m;
	bus_dmamap_t		 ers_map;
};

/*
 * Software counters.  Each field has a single writer on the datapath
 * (TX serialized by the ifq, the RX consumer only from the IO
 * interrupt), so plain increments are safe; the kstat read snapshots
 * them and a torn read costs at most one stale sample.  A kstat template
 * binds each key to its field by offsetof (see ENA_KV), so field order
 * and layout here are free - a template row only needs a field that
 * exists, which the compiler checks.
 */
struct ena_txq_stats {
	uint64_t		 packets;
	uint64_t		 bytes;
	uint64_t		 doorbells;
	uint64_t		 dma_map_err;
	uint64_t		 defrags;
	uint64_t		 stalls;
	uint64_t		 bad_reqid;
	uint64_t		 desc_err;
};

struct ena_rxq_stats {
	uint64_t		 packets;
	uint64_t		 bytes;
	uint64_t		 mbuf_alloc_err;
	uint64_t		 dma_map_err;
	uint64_t		 ring_empty;
	uint64_t		 bad_reqid;
	uint64_t		 desc_err;
};

/*
 * Device-level driver counters, exported by the "device" kstat.  A field
 * is mirrored in two more places: it needs a row in ena_kstat_device_tpl
 * to be exported at all, and each reset_* field also has a row in
 * ena_reset_reasons[] that bumps it by offset.  Adding a counter means
 * touching all three (the compiler only catches a bad field name).
 */
struct ena_device_stats {
	uint64_t		 resets;
	uint64_t		 reset_keepalive;
	uint64_t		 reset_admin_to;
	uint64_t		 reset_miss_tx;
	uint64_t		 reset_rx_reqid;
	uint64_t		 reset_tx_reqid;
	uint64_t		 reset_dev_err;
	uint64_t		 reset_user;
	uint64_t		 admin_cmds;
	uint64_t		 admin_errors;
	uint64_t		 admin_timeouts;
	uint64_t		 aenq_link;
	uint64_t		 aenq_keepalive;
	uint64_t		 aenq_warning;
	uint64_t		 aenq_notify;
	uint64_t		 aenq_fatal;
	uint64_t		 aenq_unknown;
	uint64_t		 link_changes;
};

/*
 * Decoded device counters from GET_STATS, refreshed on the stats task
 * and read straight out by the basic/eni kstats (same offset-copy path
 * as the software counters).  The device reports BASIC as lo/hi 32-bit
 * halves and ENI as native little-endian; the task does that decode
 * once so the kstat read stays a plain memory copy.
 */
struct ena_basic_cache {
	uint64_t		 tx_bytes;
	uint64_t		 tx_packets;
	uint64_t		 rx_bytes;
	uint64_t		 rx_packets;
	uint64_t		 rx_drops;
	uint64_t		 tx_drops;
	uint64_t		 rx_overruns;
};

struct ena_eni_cache {
	uint64_t		 bw_in_exceeded;
	uint64_t		 bw_out_exceeded;
	uint64_t		 pps_exceeded;
	uint64_t		 conntrack_excd;
	uint64_t		 linklocal_excd;
};

/*
 * kstat key/value template: one COUNTER64 per entry.  Every kstat reads
 * the same way - the value lives at `offset` into the struct the kstat
 * points at, so one generic read copies them all and each key stays
 * bound to its field (see ENA_KV).
 */
struct ena_kv_tpl {
	const char		*name;
	unsigned int		 unit;
	size_t			 offset;
};

/*
 * RX ring pair: the SQ hands buffers to the device, the CQ describes
 * received packets.  req_ids are drawn from rxr_ids, a ring of free
 * ids: the device returns buffers in an order of its own choosing, so
 * a buffer's id cannot be tied to the SQ position it was posted at.
 * Ids leave the ring at rxr_prod and return at rxr_cons; completions
 * always trail fills, so the two never touch the same entry.  The
 * producer side (rxr_prod, refill) is serialized by rxr_mtx; the
 * consumer side runs only from the IO interrupt.
 */
struct ena_rxr {
	struct ena_softc	*rxr_sc;
	struct mutex		 rxr_mtx;
	struct if_rxring	 rxr_acct;
	struct timeout		 rxr_refill;
	struct ena_dmamem	 rxr_sq_ring;
	struct ena_dmamem	 rxr_cq_ring;
	struct ena_rx_slot	*rxr_slots;
	uint16_t		*rxr_ids;
	unsigned int		 rxr_ndescs;
	uint16_t		 rxr_prod;
	uint16_t		 rxr_cons;
	uint8_t			 rxr_sq_phase;
	uint8_t			 rxr_cq_phase;
	uint16_t		 rxr_sq_idx;
	uint16_t		 rxr_cq_idx;
	bus_size_t		 rxr_db_off;
	bus_size_t		 rxr_unmask_off;
	struct mbuf		*rxr_m_head;
	struct mbuf		**rxr_m_tail;
	unsigned int		 rxr_m_len;

	struct ena_rxq_stats	 rxr_st;
	struct kstat		*rxr_kstat;
};

struct ena_tx_slot {
	struct mbuf		*ets_m;
	bus_dmamap_t		 ets_map;
	unsigned int		 ets_ndescs;
};

/*
 * TX ring pair.  The producer side (ena_start) runs serialized by the
 * ifq, the consumer side (ena_txeof) from the IO interrupt; the number
 * of outstanding SQ descriptors is the atomically maintained txr_used.
 * req_id of a packet is the slot index of its first descriptor.
 * Unlike RX there is no free-id ring: ena_start() refuses to reuse a
 * slot whose packet is still outstanding, so an out-of-order
 * completion costs waiting, never a corrupted slot.
 */
struct ena_txr {
	struct ena_softc	*txr_sc;
	struct ena_dmamem	 txr_sq_ring;
	struct ena_dmamem	 txr_cq_ring;
	struct ena_tx_slot	*txr_slots;
	unsigned int		 txr_ndescs;
	unsigned int		 txr_used;
	uint16_t		 txr_prod;
	uint16_t		 txr_cq_cons;
	uint8_t			 txr_sq_phase;
	uint8_t			 txr_cq_phase;
	uint16_t		 txr_sq_idx;
	uint16_t		 txr_cq_idx;
	bus_size_t		 txr_db_off;

	/* LLQ mode: KVA of this SQ's entry ring in the LLQ window. */
	caddr_t			 txr_llq_win;
	unsigned int		 txr_burst_left;

	/* watchdog state, touched only by the watchdog tick */
	uint16_t		 txr_last_cq_cons;
	unsigned int		 txr_stuck;

	struct ena_txq_stats	 txr_st;
	struct kstat		*txr_kstat;
};

struct ena_softc {
	struct device		 sc_dev;
	struct arpcom		 sc_ac;
	struct ifmedia		 sc_media;

	pci_chipset_tag_t	 sc_pc;
	pcitag_t		 sc_tag;
	bus_dma_tag_t		 sc_dmat;
	bus_space_tag_t		 sc_memt;
	bus_space_handle_t	 sc_memh;
	bus_size_t		 sc_mems;

	/* LLQ window: prefetchable BAR, mapped write-combining. */
	bus_space_tag_t		 sc_llq_memt;
	bus_space_handle_t	 sc_llq_memh;
	bus_size_t		 sc_llq_mems;

	/*
	 * Admin queue.  One synchronous command in flight at a time,
	 * under sc_aq_mtx; see ena_aq_exec().  A command timeout marks
	 * the queue dead and every later call fails until reset.
	 */
	struct mutex		 sc_aq_mtx;
	struct ena_dmamem	 sc_aq_ring;
	struct ena_dmamem	 sc_acq_ring;
	uint16_t		 sc_aq_prod;
	uint16_t		 sc_acq_cons;
	uint8_t			 sc_aq_phase;
	uint8_t			 sc_acq_phase;
	int			 sc_aq_dead;
	unsigned int		 sc_aq_timeout_us;

	struct ena_dmamem	 sc_hostinfo;
	struct ena_dmamem	 sc_mmio_resp;

	/* AENQ; the ring is consumed by sc_aenq_task on systq. */
	struct ena_dmamem	 sc_aenq_ring;
	uint16_t		 sc_aenq_head;
	uint8_t			 sc_aenq_phase;
	struct task		 sc_aenq_task;

	void			*sc_ih_admin;	/* MSI-X vector 0 */
	void			*sc_ih_queue;	/* MSI-X vector 1 */
	char			 sc_qintr_name[16];

	struct mutex		 sc_link_mtx;
	int			 sc_link_state;

	/* Written by the AENQ task, read by the watchdog tick. */
	time_t			 sc_keepalive_ts;
	struct timeout		 sc_watchdog_tmo;

	/* Recovery runs as a task on systq, like the AENQ handler. */
	struct task		 sc_reset_task;
	int			 sc_reset_pending;
	int			 sc_reset_reason;
	int			 sc_debug_reset;

	/*
	 * Three lifecycle flags, three writers, deliberately not one enum:
	 *   sc_attached    - set once at end of attach, cleared first in
	 *                    detach; gates the reset task against a
	 *                    torn-down softc.
	 *   sc_reset_pending - set lock-free from interrupt/watchdog/admin
	 *                    contexts to collapse reset requests; cleared
	 *                    by the reset task.
	 *   sc_dead        - set under cfg_lock when recovery gives up;
	 *                    permanent, fails every later up with ENXIO.
	 */
	struct rwlock		 sc_cfg_lock;	/* serializes up/down/reset */
	int			 sc_dead;
	int			 sc_attached;

	/* Device facts cached from DEVICE_ATTRIBUTES and queue limits. */
	uint32_t		 sc_supported_features;
	uint32_t		 sc_capabilities;
	uint32_t		 sc_max_mtu;
	uint32_t		 sc_max_tx_sq_depth;
	uint32_t		 sc_max_rx_sq_depth;
	uint16_t		 sc_max_tx_segs;
	uint16_t		 sc_tx_max_hdr;	/* LLQ push limit, bytes */

	/* IO rings, allocated on up, freed on down. */
	struct ena_rxr		*sc_rxr;
	struct ena_txr		*sc_txr;
	unsigned int		 sc_rx_ndescs;
	unsigned int		 sc_tx_ndescs;
	unsigned int		 sc_rx_buf_len;	/* payload bytes per RX buffer */

	/*
	 * The seam between the TX submission modes: host mode writes
	 * descriptors into the SQ ring in RAM, LLQ pushes them into
	 * device memory.  Everything else in the TX path is shared.
	 * Returns the number of SQ units (descriptors or entries) the
	 * packet consumed.
	 */
	unsigned int		(*sc_tx_submit)(struct ena_txr *,
				    struct ena_tx_slot *);

	/* LLQ negotiation results. */
	int			 sc_llq_on;
	unsigned int		 sc_llq_entry_size; /* 128 or wide 256 */
	int			 sc_llq_meta;	/* meta desc per packet */
	unsigned int		 sc_llq_burst;	/* entries/doorbell, 0=inf */
	uint32_t		 sc_llq_max_depth; /* TX entries in LLQ mode */

	/*
	 * Statistics.  The device-lifetime kstats and their read lock
	 * live here; per-ring kstats hang off the rings.  sc_dev_st holds
	 * the driver's own device-level counters; sc_basic/sc_eni cache the
	 * device's own counters, refreshed by the stats task (systq, so it
	 * never races the reset task) and copied out by the basic/eni
	 * kstats.  Every kstat read is a plain offset copy.
	 *
	 * sc_kstat_lock serializes kstat reads against each other and against
	 * kstat destroy; it does NOT cover the stats task, which writes
	 * sc_basic/sc_eni lock-free.  So a read may see a half-updated cache -
	 * a torn snapshot, harmless like the other counters here.
	 */
	struct rwlock		 sc_kstat_lock;
	struct kstat		*sc_kstat_device;
	struct kstat		*sc_kstat_basic;
	struct kstat		*sc_kstat_eni;
	struct task		 sc_stats_task;
	struct ena_device_stats	 sc_dev_st;
	struct ena_basic_cache	 sc_basic;
	struct ena_eni_cache	 sc_eni;

	/*
	 * The stats task also feeds the device drop deltas into the ifnet
	 * counters (netstat), using sc_basic as the baseline.  sc_stats_seen
	 * gates the first sample (and every one after an up) so a fresh
	 * baseline never turns the device's running total into one huge
	 * delta.
	 */
	int			 sc_stats_seen;
};
#define DEVNAME(_sc)	((_sc)->sc_dev.dv_xname)

static inline uint32_t
ena_rd(struct ena_softc *sc, bus_size_t r)
{
	return (bus_space_read_4(sc->sc_memt, sc->sc_memh, r));
}

/*
 * Register writes are bare.  Ordering against DMA memory comes from
 * bus_dmamap_sync(), and the two doorbells that need more (LLQ, AENQ)
 * carry explicit membars at the call sites.
 */
static inline void
ena_wr(struct ena_softc *sc, bus_size_t r, uint32_t v)
{
	bus_space_write_4(sc->sc_memt, sc->sc_memh, r, v);
}

/* The device uses 48-bit addresses; the high word is zero on ILP32. */
static inline uint32_t
ena_addr_hi(bus_addr_t addr)
{
#ifdef __LP64__
	return (addr >> 32);
#else
	return (0);
#endif
}

/* Program a ring base into its LO/HI register pair (HI = LO + 4). */
static inline void
ena_wr_base(struct ena_softc *sc, bus_size_t lo, bus_addr_t dva)
{
	ena_wr(sc, lo, dva);
	ena_wr(sc, lo + 4, ena_addr_hi(dva));
}

static int	ena_match(struct device *, void *, void *);
static void	ena_attach(struct device *, struct device *, void *);
static int	ena_detach(struct device *, int);
static int	ena_msix_bar_assign(struct pci_attach_args *);

static int	ena_dev_reset(struct ena_softc *, int);
static int	ena_reset_wait(struct ena_softc *, uint32_t, uint32_t,
		    unsigned int);

static int	ena_dmamem_alloc(struct ena_softc *, struct ena_dmamem *,
		    bus_size_t, u_int);
static void	ena_dmamem_free(struct ena_softc *, struct ena_dmamem *);

static int	ena_aq_alloc(struct ena_softc *);
static void	ena_admin_init(struct ena_softc *);
static void	ena_aq_fini(struct ena_softc *);
static int	ena_aq_exec(struct ena_softc *, union ena_aq_cmd *,
		    struct ena_acq_desc *);
static int	ena_aq_get_feature(struct ena_softc *, uint8_t, uint8_t,
		    void *, size_t);
static int	ena_aq_set_feature(struct ena_softc *, uint8_t, uint8_t,
		    const void *, size_t);
static int	ena_aq_get_stats(struct ena_softc *, uint8_t, void *, size_t);
static uint64_t	ena_stat64(const uint32_t *, const uint32_t *);

static int	ena_get_device_attributes(struct ena_softc *, uint8_t *);
static int	ena_get_queue_limits(struct ena_softc *);
static int	ena_dev_init(struct ena_softc *, int, uint8_t *);
static void	ena_hostinfo_init(struct ena_softc *);
static void	ena_hostinfo_set(struct ena_softc *);

static int	ena_aq_create_cq(struct ena_softc *, unsigned int,
		    struct ena_dmamem *, size_t, uint16_t *, bus_size_t *);
static int	ena_aq_destroy_cq(struct ena_softc *, uint16_t);
static int	ena_aq_create_sq(struct ena_softc *, uint8_t, int,
		    uint16_t, unsigned int, struct ena_dmamem *,
		    uint16_t *, bus_size_t *, bus_size_t *);
static int	ena_aq_destroy_sq(struct ena_softc *, uint16_t, uint8_t);

static void	ena_llq_negotiate(struct ena_softc *);

static struct ena_rxr *
		ena_rxr_alloc(struct ena_softc *);
static void	ena_rxr_free(struct ena_softc *, struct ena_rxr *);
static int	ena_rxr_init(struct ena_softc *, struct ena_rxr *);
static void	ena_rxr_deinit(struct ena_softc *, struct ena_rxr *);
static void	ena_rxfill(struct ena_rxr *);
static void	ena_rxrefill(void *);
static void	ena_rxeof(struct ena_rxr *);

static struct ena_txr *
		ena_txr_alloc(struct ena_softc *);
static void	ena_txr_free(struct ena_softc *, struct ena_txr *);
static int	ena_txr_init(struct ena_softc *, struct ena_txr *);
static void	ena_txr_deinit(struct ena_softc *, struct ena_txr *);
static int	ena_load_mbuf(bus_dma_tag_t, bus_dmamap_t, struct mbuf *,
		    int *);
static unsigned int
		ena_tx_submit_host(struct ena_txr *, struct ena_tx_slot *);
static unsigned int
		ena_tx_submit_llq(struct ena_txr *, struct ena_tx_slot *);
static void	ena_tx_kick(struct ena_txr *);
static void	ena_txeof(struct ena_txr *);
static int	ena_txr_stalled(struct ena_txr *);

static int	ena_aenq_alloc(struct ena_softc *);
static void	ena_aenq_register(struct ena_softc *);
static int	ena_aenq_negotiate(struct ena_softc *);
static void	ena_aenq_fini(struct ena_softc *);
static void	ena_aenq_arm(struct ena_softc *);
static void	ena_aenq_task(void *);
static void	ena_link_update(struct ena_softc *, int);
static void	ena_arm(struct ena_softc *);

static int	ena_intr_admin(void *);
static int	ena_intr_queue(void *);

static int	ena_up(struct ena_softc *);
static int	ena_down(struct ena_softc *);
static int	ena_ioctl(struct ifnet *, u_long, caddr_t);
static void	ena_start(struct ifqueue *);
static int	ena_media_change(struct ifnet *);
static void	ena_media_status(struct ifnet *, struct ifmediareq *);
static void	ena_watchdog_tick(void *);
static void	ena_reset_request(struct ena_softc *, int);
static void	ena_reset_task(void *);

static struct kstat *
		ena_kstat_create(struct ena_softc *, const char *, unsigned int,
		    const struct ena_kv_tpl *, unsigned int, void *);
static void	ena_kstat_destroy(struct kstat **);
static int	ena_kstat_kv_read(struct kstat *);
static void	ena_stats_task(void *);
static void	ena_kstat_attach(struct ena_softc *);
static void	ena_kstat_detach(struct ena_softc *);

static void	ena_set_mem_addr(struct ena_mem_addr *, bus_addr_t);

const struct cfattach ena_ca = {
	sizeof(struct ena_softc), ena_match, ena_attach, ena_detach
};

struct cfdriver ena_cd = {
	NULL, "ena", DV_IFNET
};

static const struct pci_matchid ena_devices[] = {
	{ PCI_VENDOR_AMAZON,	PCI_PRODUCT_AMAZON_ENA_PF },
	{ PCI_VENDOR_AMAZON,	PCI_PRODUCT_AMAZON_ENA_PF_LLQ },
	{ PCI_VENDOR_AMAZON,	PCI_PRODUCT_AMAZON_ENA },
	{ PCI_VENDOR_AMAZON,	PCI_PRODUCT_AMAZON_ENA_LLQ },
};

static int
ena_match(struct device *parent, void *match, void *aux)
{
	return (pci_matchbyid(aux, ena_devices, nitems(ena_devices)));
}

/*
 * The MSI-X table lives in a BAR this driver never maps for its own
 * use, and OpenBSD assigns BARs lazily, as drivers map them - so when
 * the platform firmware leaves the table BAR unprogrammed (seen on
 * amd64 EC2 instances), nobody else gives it an address, and amd64's
 * pci_msix_table_map() maps whatever the BAR says without assigning
 * it first: the vectors land nowhere and interrupts are silently
 * lost.  arm64 closes this gap in _pci_intr_map_msix(); this helper
 * closes it for amd64 and duplicates harmlessly elsewhere.
 */
static int
ena_msix_bar_assign(struct pci_attach_args *pa)
{
	pci_chipset_tag_t pc = pa->pa_pc;
	pcitag_t tag = pa->pa_tag;
	pcireg_t table, type;
	int off, bir, bar;

	/*
	 * Mirror the gate in pci_intr_map_msix(): if MSI is off for
	 * this bus, MSI-X will never be established, while the
	 * pci_mapreg_assign() below would still flip MEM and MASTER
	 * enable on - so leave the device alone on a path that can
	 * never use it.
	 */
	if (!ISSET(pa->pa_flags, PCI_FLAGS_MSI_ENABLED))
		return (ENXIO);

	if (pci_get_capability(pc, tag, PCI_CAP_MSIX, &off, NULL) == 0)
		return (ENXIO);

	table = pci_conf_read(pc, tag, off + PCI_MSIX_TABLE);
	bir = table & PCI_MSIX_TABLE_BIR;
	bar = PCI_MAPREG_START + bir * 4;
	type = pci_mapreg_type(pc, tag, bar);

	return (pci_mapreg_assign(pa, bar, type, NULL, NULL));
}

static void
ena_attach(struct device *parent, struct device *self, void *aux)
{
	struct ena_softc *sc = (struct ena_softc *)self;
	struct pci_attach_args *pa = aux;
	struct ifnet *ifp = &sc->sc_ac.ac_if;
	pci_intr_handle_t ih;
	const char *intrstr;
	pcireg_t memtype;
	uint8_t enaddr[ETHER_ADDR_LEN];
	uint32_t ver, caps;

	sc->sc_pc = pa->pa_pc;
	sc->sc_tag = pa->pa_tag;
	sc->sc_dmat = pa->pa_dmat;

	rw_init(&sc->sc_cfg_lock, "enacfg");
	rw_init(&sc->sc_kstat_lock, "enakstat");
	mtx_init(&sc->sc_link_mtx, IPL_NET);
	/*
	 * The ifnet default of LINK_STATE_UNKNOWN counts as up, so TX
	 * flows even if the device never sends the initial link event;
	 * this cache only drives the media status display.
	 */
	sc->sc_link_state = LINK_STATE_DOWN;
	/* These tasks share systq, which serializes them cheaply. */
	task_set(&sc->sc_aenq_task, ena_aenq_task, sc);
	task_set(&sc->sc_reset_task, ena_reset_task, sc);
	task_set(&sc->sc_stats_task, ena_stats_task, sc);
	timeout_set(&sc->sc_watchdog_tmo, ena_watchdog_tick, sc);

	memtype = pci_mapreg_type(pa->pa_pc, pa->pa_tag, ENA_PCI_BAR0);
	if (pci_mapreg_map(pa, ENA_PCI_BAR0, memtype, 0,
	    &sc->sc_memt, &sc->sc_memh, NULL, &sc->sc_mems, 0) != 0) {
		printf(": unable to map registers\n");
		return;
	}

	/*
	 * The prefetchable BAR is the LLQ window and must be mapped
	 * write-combining: the device latches LLQ entries at burst
	 * granularity, so pushing them as individual device-memory
	 * stores hands it a partial entry (correct descriptors, stale
	 * payload).  Missing window simply means host mode.
	 */
	memtype = pci_mapreg_type(pa->pa_pc, pa->pa_tag, ENA_PCI_BAR2);
	if (pci_mapreg_map(pa, ENA_PCI_BAR2, memtype,
	    BUS_SPACE_MAP_LINEAR | BUS_SPACE_MAP_PREFETCHABLE,
	    &sc->sc_llq_memt, &sc->sc_llq_memh, NULL,
	    &sc->sc_llq_mems, 0) != 0)
		sc->sc_llq_mems = 0;

	/* ENA is MSI-X only; make sure the vector table BAR is backed. */
	if (ena_msix_bar_assign(pa) != 0) {
		printf(": unable to assign MSI-X table BAR\n");
		goto unmap;
	}

	ver = ena_rd(sc, ENA_VERSION);
	caps = ena_rd(sc, ENA_CAPS);
	if (ENA_CAPS_RESET_TIMEOUT(caps) == 0) {
		printf(": bogus caps %08x\n", caps);
		goto unmap;
	}
	sc->sc_aq_timeout_us = ENA_CAPS_AQ_TIMEOUT(caps) ?
	    ENA_CAPS_AQ_TIMEOUT(caps) * 100000 : ENA_AQ_TIMEOUT_US;

	if (ena_aq_alloc(sc) != 0) {
		printf(": unable to allocate admin queue\n");
		goto unmap;
	}
	if (ena_aenq_alloc(sc) != 0) {
		printf(": unable to allocate event queue\n");
		goto free_aq;
	}
	if (ena_dmamem_alloc(sc, &sc->sc_mmio_resp, PAGE_SIZE,
	    PAGE_SIZE) != 0) {
		printf(": unable to allocate mmio response region\n");
		goto free_aenq;
	}

	/*
	 * The host info page is filled once here and handed over by
	 * ena_dev_init() on every pass: firmware adjusts behaviour
	 * based on it and old versions refused to create completion
	 * queues without it.  Allocation failure is not fatal.
	 */
	ena_hostinfo_init(sc);

	if (ena_dev_init(sc, ENA_RESET_NORMAL, enaddr) != 0) {
		printf(": device init failed\n");
		goto shutdown;
	}
	memcpy(sc->sc_ac.ac_enaddr, enaddr, ETHER_ADDR_LEN);

	/* ENA is MSI-X only: vector 0 admin/AENQ, vector 1 the IO pair. */
	if (pci_intr_map_msix(pa, 0, &ih) != 0) {
		printf(": unable to map admin interrupt\n");
		goto shutdown;
	}
	intrstr = pci_intr_string(pa->pa_pc, ih);
	sc->sc_ih_admin = pci_intr_establish(pa->pa_pc, ih,
	    IPL_NET | IPL_MPSAFE, ena_intr_admin, sc, DEVNAME(sc));
	if (sc->sc_ih_admin == NULL) {
		printf(": unable to establish admin interrupt\n");
		goto shutdown;
	}

	if (pci_intr_map_msix(pa, 1, &ih) != 0) {
		printf(": unable to map queue interrupt\n");
		goto free_admin_intr;
	}
	snprintf(sc->sc_qintr_name, sizeof(sc->sc_qintr_name), "%s:0",
	    DEVNAME(sc));
	sc->sc_ih_queue = pci_intr_establish(pa->pa_pc, ih,
	    IPL_NET | IPL_MPSAFE, ena_intr_queue, sc, sc->sc_qintr_name);
	if (sc->sc_ih_queue == NULL) {
		printf(": unable to establish queue interrupt\n");
		goto free_admin_intr;
	}

	printf(": v%u.%u, %s%s, address %s\n", ENA_VERSION_MAJOR(ver),
	    ENA_VERSION_MINOR(ver), intrstr, sc->sc_llq_on ?
	    (sc->sc_llq_entry_size == ENA_LLQ_ENTRY_MAX ?
	    ", llq wide" : ", llq") : "",
	    ether_sprintf(sc->sc_ac.ac_enaddr));

	ifp->if_softc = sc;
	strlcpy(ifp->if_xname, DEVNAME(sc), IFNAMSIZ);
	ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST;
	/*
	 * When porting to 8.0, OR in IFXF_MBUF_64BIT here: the device
	 * handles 64-bit DMA addresses, but the 7.9 tree lacks the flag.
	 */
	ifp->if_xflags = IFXF_MPSAFE;
	ifp->if_ioctl = ena_ioctl;
	ifp->if_qstart = ena_start;
	/*
	 * Anything beyond 1500 needs SET_FEATURE(MTU) on the device;
	 * jumbo support is deliberately out of the MVP scope.
	 */
	ifp->if_hardmtu = MIN(ETHERMTU, sc->sc_max_mtu);
	ifq_init_maxlen(&ifp->if_snd, sc->sc_tx_ndescs);

	ifmedia_init(&sc->sc_media, 0, ena_media_change, ena_media_status);
	ifmedia_add(&sc->sc_media, IFM_ETHER | IFM_AUTO, 0, NULL);
	ifmedia_set(&sc->sc_media, IFM_ETHER | IFM_AUTO);

	if_attach(ifp);
	ether_ifattach(ifp);
	sc->sc_attached = 1;

	/* Device-lifetime statistics; per-ring kstats come up with the rings. */
	ena_kstat_attach(sc);

	/* From here on the device may raise events at us. */
	ena_arm(sc);

	return;

free_admin_intr:
	pci_intr_disestablish(pa->pa_pc, sc->sc_ih_admin);
shutdown:
	/* Quiesce the device before freeing memory it may still read. */
	ena_dev_reset(sc, ENA_RESET_SHUTDOWN);
	if (ENA_DMA_LEN(&sc->sc_hostinfo) != 0)
		ena_dmamem_free(sc, &sc->sc_hostinfo);
	ena_dmamem_free(sc, &sc->sc_mmio_resp);
free_aenq:
	ena_aenq_fini(sc);
free_aq:
	ena_aq_fini(sc);
unmap:
	if (sc->sc_llq_mems != 0) {
		bus_space_unmap(sc->sc_llq_memt, sc->sc_llq_memh,
		    sc->sc_llq_mems);
		sc->sc_llq_mems = 0;
	}
	bus_space_unmap(sc->sc_memt, sc->sc_memh, sc->sc_mems);
	sc->sc_mems = 0;
}

static int
ena_detach(struct device *self, int flags)
{
	struct ena_softc *sc = (struct ena_softc *)self;
	struct ifnet *ifp = &sc->sc_ac.ac_if;

	if (sc->sc_mems == 0)
		return (0);

	/*
	 * Quiesce first, detach the ifnet last: a task queued before
	 * the gate closed must find the interface still attached.
	 */
	sc->sc_attached = 0;

	NET_LOCK();
	if (ISSET(ifp->if_flags, IFF_RUNNING))
		ena_down(sc);
	NET_UNLOCK();

	ena_wr(sc, ENA_INTR_MASK, ENA_INTR_MASK_ADMIN);
	intr_barrier(sc->sc_ih_queue);
	intr_barrier(sc->sc_ih_admin);
	pci_intr_disestablish(sc->sc_pc, sc->sc_ih_queue);
	pci_intr_disestablish(sc->sc_pc, sc->sc_ih_admin);
	task_del(systq, &sc->sc_aenq_task);
	task_del(systq, &sc->sc_reset_task);
	task_del(systq, &sc->sc_stats_task);
	/* Wait out a task that was already running. */
	taskq_barrier(systq);

	/*
	 * The stats task, the only stats path that issues admin commands,
	 * is drained above; the kstats left here are pure offset copies of
	 * softc memory, so their teardown order carries no admin hazard.
	 */
	ena_kstat_detach(sc);

	ether_ifdetach(ifp);
	if_detach(ifp);

	ena_dev_reset(sc, ENA_RESET_SHUTDOWN);
	ena_aenq_fini(sc);
	if (ENA_DMA_LEN(&sc->sc_hostinfo) != 0)
		ena_dmamem_free(sc, &sc->sc_hostinfo);
	ena_dmamem_free(sc, &sc->sc_mmio_resp);
	ena_aq_fini(sc);
	if (sc->sc_llq_mems != 0) {
		bus_space_unmap(sc->sc_llq_memt, sc->sc_llq_memh,
		    sc->sc_llq_mems);
		sc->sc_llq_mems = 0;
	}
	bus_space_unmap(sc->sc_memt, sc->sc_memh, sc->sc_mems);
	sc->sc_mems = 0;

	return (0);
}

/*
 * Device reset: request it in DEV_CTL, wait for the device to raise
 * and then drop the in-progress bit.  The timeout comes from CAPS in
 * units of 100ms.  After a reset all device state (admin queue, AENQ,
 * IO queues) is gone.
 */
static int
ena_dev_reset(struct ena_softc *sc, int reason)
{
	uint32_t caps, sts;
	unsigned int tmo_us;

	sts = ena_rd(sc, ENA_DEV_STS);
	if (!ISSET(sts, ENA_DEV_STS_READY))
		return (EBUSY);

	caps = ena_rd(sc, ENA_CAPS);
	tmo_us = ENA_CAPS_RESET_TIMEOUT(caps) * 100000;

	ena_wr(sc, ENA_DEV_CTL,
	    ENA_DEV_CTL_DEV_RESET | ENA_DEV_CTL_RESET_REASON(reason));
	if (ena_reset_wait(sc, ENA_DEV_STS_RESET_IN_PROGRESS,
	    ENA_DEV_STS_RESET_IN_PROGRESS, tmo_us) != 0)
		return (ETIMEDOUT);

	ena_wr(sc, ENA_DEV_CTL, 0);
	if (ena_reset_wait(sc, ENA_DEV_STS_RESET_IN_PROGRESS, 0,
	    tmo_us) != 0)
		return (ETIMEDOUT);

	return (0);
}

static int
ena_reset_wait(struct ena_softc *sc, uint32_t mask, uint32_t want,
    unsigned int tmo_us)
{
	unsigned int us = ENA_POLL_MIN_US, waited = 0;

	while ((ena_rd(sc, ENA_DEV_STS) & mask) != want) {
		if (waited >= tmo_us)
			return (ETIMEDOUT);
		delay(us);
		waited += us;
		us = MIN(us * 2, ENA_POLL_MAX_US);
	}

	return (0);
}

static void
ena_set_mem_addr(struct ena_mem_addr *ema, bus_addr_t addr)
{
	htolem32(&ema->ema_lo, addr);
	htolem16(&ema->ema_hi, ena_addr_hi(addr));
	ema->ema_rsvd = 0;
}

static int
ena_dmamem_alloc(struct ena_softc *sc, struct ena_dmamem *edm,
    bus_size_t size, u_int align)
{
	int nsegs;

	edm->edm_size = size;

	if (bus_dmamap_create(sc->sc_dmat, size, 1, size, 0,
	    BUS_DMA_WAITOK | BUS_DMA_ALLOCNOW | BUS_DMA_64BIT,
	    &edm->edm_map) != 0)
		return (1);
	if (bus_dmamem_alloc(sc->sc_dmat, size, align, 0,
	    &edm->edm_seg, 1, &nsegs,
	    BUS_DMA_WAITOK | BUS_DMA_ZERO) != 0)
		goto destroy;
	if (bus_dmamem_map(sc->sc_dmat, &edm->edm_seg, nsegs,
	    size, &edm->edm_kva, BUS_DMA_WAITOK) != 0)
		goto free;
	if (bus_dmamap_load(sc->sc_dmat, edm->edm_map, edm->edm_kva,
	    size, NULL, BUS_DMA_WAITOK) != 0)
		goto unmap;

	return (0);
unmap:
	bus_dmamem_unmap(sc->sc_dmat, edm->edm_kva, size);
free:
	bus_dmamem_free(sc->sc_dmat, &edm->edm_seg, 1);
destroy:
	bus_dmamap_destroy(sc->sc_dmat, edm->edm_map);
	edm->edm_size = 0;
	return (1);
}

static void
ena_dmamem_free(struct ena_softc *sc, struct ena_dmamem *edm)
{
	bus_dmamap_unload(sc->sc_dmat, edm->edm_map);
	bus_dmamem_unmap(sc->sc_dmat, edm->edm_kva, edm->edm_size);
	bus_dmamem_free(sc->sc_dmat, &edm->edm_seg, 1);
	bus_dmamap_destroy(sc->sc_dmat, edm->edm_map);
	edm->edm_size = 0;
}
/*
 * Admin queue.
 *
 * A pair of physically contiguous rings of 64-byte entries: the driver
 * produces commands in the AQ and rings the doorbell with the absolute
 * tail counter; the device produces completions in the ACQ, marked
 * fresh with the phase bit that flips on every ring wrap-around.
 */

static int
ena_aq_alloc(struct ena_softc *sc)
{
	mtx_init(&sc->sc_aq_mtx, IPL_NET);

	if (ena_dmamem_alloc(sc, &sc->sc_aq_ring,
	    ENA_AQ_NUM * sizeof(union ena_aq_cmd), PAGE_SIZE) != 0)
		return (ENOMEM);
	if (ena_dmamem_alloc(sc, &sc->sc_acq_ring,
	    ENA_AQ_NUM * sizeof(struct ena_acq_desc), PAGE_SIZE) != 0) {
		ena_dmamem_free(sc, &sc->sc_aq_ring);
		return (ENOMEM);
	}

	return (0);
}

/*
 * Program the control rings into the device.  Also the second half of
 * recovery: after a device reset the rings are re-registered as they
 * are, only the driver-side state needs rewinding.  The AENQ ring is
 * part of this handshake on purpose; see ena_aenq_register().
 */
static void
ena_admin_init(struct ena_softc *sc)
{
	/*
	 * Hand over the response region for readless register reads
	 * first; a reset clears it.  This driver reads its registers
	 * directly, but a device that was never handed a valid region
	 * silently drops later admin operations.
	 */
	ena_wr_base(sc, ENA_MMIO_RESP_LO, ENA_DMA_DVA(&sc->sc_mmio_resp));

	sc->sc_aq_prod = 0;
	sc->sc_aq_phase = 1;
	sc->sc_acq_cons = 0;
	sc->sc_acq_phase = 1;
	sc->sc_aq_dead = 0;

	memset(ENA_DMA_KVA(&sc->sc_aq_ring), 0,
	    ENA_DMA_LEN(&sc->sc_aq_ring));
	memset(ENA_DMA_KVA(&sc->sc_acq_ring), 0,
	    ENA_DMA_LEN(&sc->sc_acq_ring));

	ENA_DMA_SYNC(sc, &sc->sc_aq_ring, BUS_DMASYNC_PREWRITE);
	ENA_DMA_SYNC(sc, &sc->sc_acq_ring, BUS_DMASYNC_PREREAD);

	ena_wr_base(sc, ENA_AQ_BASE_LO, ENA_DMA_DVA(&sc->sc_aq_ring));
	ena_wr_base(sc, ENA_ACQ_BASE_LO, ENA_DMA_DVA(&sc->sc_acq_ring));

	ena_wr(sc, ENA_AQ_CAPS,
	    ENA_RING_CAPS(ENA_AQ_NUM, sizeof(union ena_aq_cmd)));
	/* Writing ACQ_CAPS is what arms the admin queue. */
	ena_wr(sc, ENA_ACQ_CAPS,
	    ENA_RING_CAPS(ENA_AQ_NUM, sizeof(struct ena_acq_desc)));

	ena_aenq_register(sc);
}

static void
ena_aq_fini(struct ena_softc *sc)
{
	ena_wr(sc, ENA_AQ_CAPS, 0);
	ena_wr(sc, ENA_ACQ_CAPS, 0);

	ENA_DMA_SYNC(sc, &sc->sc_acq_ring, BUS_DMASYNC_POSTREAD);
	ENA_DMA_SYNC(sc, &sc->sc_aq_ring, BUS_DMASYNC_POSTWRITE);

	ena_dmamem_free(sc, &sc->sc_acq_ring);
	ena_dmamem_free(sc, &sc->sc_aq_ring);
}

static int
ena_aq_status_to_errno(uint8_t status)
{
	switch (status) {
	case ENA_ACQ_RC_SUCCESS:
		return (0);
	case ENA_ACQ_RC_RESOURCE_ALLOC_FAIL:
	case ENA_ACQ_RC_RESOURCE_BUSY:
		return (ENOMEM);
	case ENA_ACQ_RC_UNSUPPORTED_OPCODE:
		return (EOPNOTSUPP);
	case ENA_ACQ_RC_BAD_OPCODE:
	case ENA_ACQ_RC_MALFORMED_REQUEST:
	case ENA_ACQ_RC_ILLEGAL_PARAMETER:
		return (EINVAL);
	default:
		return (EIO);
	}
}

static const char *
ena_aq_opcode_str(uint8_t opcode)
{
	switch (opcode) {
	case ENA_AQ_OP_CREATE_SQ:
		return ("CREATE_SQ");
	case ENA_AQ_OP_DESTROY_SQ:
		return ("DESTROY_SQ");
	case ENA_AQ_OP_CREATE_CQ:
		return ("CREATE_CQ");
	case ENA_AQ_OP_DESTROY_CQ:
		return ("DESTROY_CQ");
	case ENA_AQ_OP_GET_FEATURE:
		return ("GET_FEATURE");
	case ENA_AQ_OP_SET_FEATURE:
		return ("SET_FEATURE");
	case ENA_AQ_OP_GET_STATS:
		return ("GET_STATS");
	default:
		return ("unknown");
	}
}

static const char *ena_aq_status_names[] = {
	"success",
	"resource allocation failure",
	"bad opcode",
	"unsupported opcode",
	"malformed request",
	"illegal parameter",
	"unknown error",
	"resource busy",
};

static const char *
ena_aq_status_str(uint8_t status)
{
	if (status >= nitems(ena_aq_status_names))
		return ("unknown");
	return (ena_aq_status_names[status]);
}

/*
 * Submit one admin command and poll for its completion.  Sleeping
 * context only: polls with delay() for up to sc_aq_timeout_us.  A
 * timeout means the device stopped talking to us; the queue is marked
 * dead and a device reset is requested from here.  Failures of any
 * kind are logged here, so callers only need the errno.
 * Every caller runs at attach or under the cfg lock (the up/down/reset
 * path and the stats task), so commands never overlap; the mutex is
 * belt and suspenders, not a hot lock.
 */
static int
ena_aq_exec(struct ena_softc *sc, union ena_aq_cmd *cmd,
    struct ena_acq_desc *resp)
{
	union ena_aq_cmd *aq = ENA_DMA_KVA(&sc->sc_aq_ring);
	struct ena_acq_desc *acq = ENA_DMA_KVA(&sc->sc_acq_ring);
	union ena_aq_cmd *slot;
	struct ena_acq_desc *comp;
	unsigned int us = ENA_POLL_MIN_US, waited = 0;
	uint16_t cmdid;
	int error;

	mtx_enter(&sc->sc_aq_mtx);

	if (sc->sc_aq_dead) {
		mtx_leave(&sc->sc_aq_mtx);
		return (ENXIO);
	}
	sc->sc_dev_st.admin_cmds++;

	cmdid = sc->sc_aq_prod & (ENA_AQ_NUM - 1);
	slot = &aq[cmdid];

	*slot = *cmd;
	htolem16(&slot->aqc_desc.aqd_command_id, cmdid);
	slot->aqc_desc.aqd_flags &= ~ENA_AQD_F_PHASE;
	slot->aqc_desc.aqd_flags |= sc->sc_aq_phase;

	ENA_DMA_SYNC(sc, &sc->sc_aq_ring, BUS_DMASYNC_PREWRITE);

	sc->sc_aq_prod++;
	if ((sc->sc_aq_prod & (ENA_AQ_NUM - 1)) == 0)
		sc->sc_aq_phase ^= 1;
	ena_wr(sc, ENA_AQ_DB, sc->sc_aq_prod);

	comp = &acq[sc->sc_acq_cons & (ENA_AQ_NUM - 1)];
	for (;;) {
		ENA_DMA_SYNC(sc, &sc->sc_acq_ring, BUS_DMASYNC_POSTREAD);
		if ((comp->acqd_flags & ENA_ACQD_F_PHASE) ==
		    sc->sc_acq_phase)
			break;

		if (waited >= sc->sc_aq_timeout_us) {
			sc->sc_aq_dead = 1;
			sc->sc_dev_st.admin_timeouts++;
			mtx_leave(&sc->sc_aq_mtx);
			printf("%s: admin command %s timeout\n", DEVNAME(sc),
			    ena_aq_opcode_str(cmd->aqc_desc.aqd_opcode));
			ena_reset_request(sc, ENA_RESET_ADMIN_TO);
			return (ETIMEDOUT);
		}
		delay(us);
		waited += us;
		us = MIN(us * 2, ENA_POLL_MAX_US);
	}

	/* The phase bit is written last; order the rest after it. */
	membar_consumer();

	sc->sc_acq_cons++;
	if ((sc->sc_acq_cons & (ENA_AQ_NUM - 1)) == 0)
		sc->sc_acq_phase ^= 1;

	if ((lemtoh16(&comp->acqd_command) & ENA_AQ_CMD_ID_MASK) !=
	    cmdid) {
		sc->sc_aq_dead = 1;
		sc->sc_dev_st.admin_errors++;
		mtx_leave(&sc->sc_aq_mtx);
		printf("%s: admin completion out of order\n", DEVNAME(sc));
		return (EIO);
	}

	if (resp != NULL)
		*resp = *comp;
	error = ena_aq_status_to_errno(comp->acqd_status);
	if (error != 0) {
		sc->sc_dev_st.admin_errors++;
		/*
		 * The one place every failed command of every current
		 * and future caller reports itself; the callers only
		 * see the errno.
		 */
		printf("%s: admin command %s failed: %s (ext %u)\n",
		    DEVNAME(sc), ena_aq_opcode_str(cmd->aqc_desc.aqd_opcode),
		    ena_aq_status_str(comp->acqd_status),
		    lemtoh16(&comp->acqd_ext_status));
	}

	mtx_leave(&sc->sc_aq_mtx);
	return (error);
}

static int
ena_aq_get_feature(struct ena_softc *sc, uint8_t id, uint8_t version,
    void *buf, size_t len)
{
	union ena_aq_cmd cmd;
	struct ena_acq_desc resp;
	int error;

	KASSERT(len <= sizeof(resp.acqd_data));

	memset(&cmd, 0, sizeof(cmd));
	cmd.aqc_feat.afc_opcode = ENA_AQ_OP_GET_FEATURE;
	cmd.aqc_feat.afc_feature_id = id;
	cmd.aqc_feat.afc_feature_version = version;

	error = ena_aq_exec(sc, &cmd, &resp);
	if (error != 0)
		return (error);

	memcpy(buf, resp.acqd_data, len);
	return (0);
}

static int
ena_aq_set_feature(struct ena_softc *sc, uint8_t id, uint8_t version,
    const void *buf, size_t len)
{
	union ena_aq_cmd cmd;

	KASSERT(len <= sizeof(cmd.aqc_feat.afc_data));

	memset(&cmd, 0, sizeof(cmd));
	cmd.aqc_feat.afc_opcode = ENA_AQ_OP_SET_FEATURE;
	cmd.aqc_feat.afc_feature_id = id;
	cmd.aqc_feat.afc_feature_version = version;
	memcpy(cmd.aqc_feat.afc_data, buf, len);

	return (ena_aq_exec(sc, &cmd, NULL));
}

/*
 * Fetch device-side counters.  BASIC and ENI both come back inline in
 * the completion, so this mirrors ena_aq_get_feature(): copy the right
 * number of bytes out of acqd_data.  The caller decodes the payload.
 */
static int
ena_aq_get_stats(struct ena_softc *sc, uint8_t type, void *buf, size_t len)
{
	union ena_aq_cmd cmd;
	struct ena_acq_desc resp;
	int error;

	KASSERT(len <= sizeof(resp.acqd_data));

	memset(&cmd, 0, sizeof(cmd));
	cmd.aqc_get_stats.egs_opcode = ENA_AQ_OP_GET_STATS;
	cmd.aqc_get_stats.egs_type = type;
	cmd.aqc_get_stats.egs_scope = ENA_STATS_SCOPE_ETH;
	htolem16(&cmd.aqc_get_stats.egs_device_id, ENA_STATS_DEVICE_MINE);

	error = ena_aq_exec(sc, &cmd, &resp);
	if (error != 0)
		return (error);

	memcpy(buf, resp.acqd_data, len);
	return (0);
}

/* Reassemble a device counter from its little-endian 32-bit halves. */
static uint64_t
ena_stat64(const uint32_t *lo, const uint32_t *hi)
{
	return (((uint64_t)lemtoh32(hi) << 32) | lemtoh32(lo));
}

/*
 * IO queue admin commands.
 */

static int
ena_aq_create_cq(struct ena_softc *sc, unsigned int depth,
    struct ena_dmamem *ring, size_t entry_size, uint16_t *idx,
    bus_size_t *unmask_off)
{
	union ena_aq_cmd cmd;
	struct ena_acq_desc resp;
	struct ena_create_cq_resp ccr;
	int error;

	memset(&cmd, 0, sizeof(cmd));
	cmd.aqc_create_cq.ecq_opcode = ENA_AQ_OP_CREATE_CQ;
	cmd.aqc_create_cq.ecq_caps1 = ENA_CREATE_CQ_INTR_MODE;
	cmd.aqc_create_cq.ecq_caps2 = entry_size / 4;
	htolem16(&cmd.aqc_create_cq.ecq_depth, depth);
	htolem32(&cmd.aqc_create_cq.ecq_msix_vector, ENA_IO_VECTOR);
	ena_set_mem_addr(&cmd.aqc_create_cq.ecq_ba, ENA_DMA_DVA(ring));

	error = ena_aq_exec(sc, &cmd, &resp);
	if (error != 0)
		return (error);

	memcpy(&ccr, resp.acqd_data, sizeof(ccr));
	*idx = lemtoh16(&ccr.eccr_idx);
	if (unmask_off != NULL)
		*unmask_off = lemtoh32(&ccr.eccr_intr_unmask_off);

	return (0);
}

static int
ena_aq_destroy_cq(struct ena_softc *sc, uint16_t idx)
{
	union ena_aq_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.aqc_destroy_cq.edcq_opcode = ENA_AQ_OP_DESTROY_CQ;
	htolem16(&cmd.aqc_destroy_cq.edcq_idx, idx);

	return (ena_aq_exec(sc, &cmd, NULL));
}

static int
ena_aq_create_sq(struct ena_softc *sc, uint8_t direction, int placement,
    uint16_t cq_idx, unsigned int depth, struct ena_dmamem *ring,
    uint16_t *idx, bus_size_t *db_off, bus_size_t *llq_off)
{
	union ena_aq_cmd cmd;
	struct ena_acq_desc resp;
	struct ena_create_sq_resp csr;
	int error;

	memset(&cmd, 0, sizeof(cmd));
	cmd.aqc_create_sq.esq_opcode = ENA_AQ_OP_CREATE_SQ;
	cmd.aqc_create_sq.esq_direction = direction;
	cmd.aqc_create_sq.esq_caps2 = placement;
	cmd.aqc_create_sq.esq_caps3 = ENA_SQ_CONTIGUOUS;
	htolem16(&cmd.aqc_create_sq.esq_cq_idx, cq_idx);
	htolem16(&cmd.aqc_create_sq.esq_depth, depth);
	/* In LLQ placement the ring lives in the device, not in RAM. */
	if (placement == ENA_SQ_PLACEMENT_HOST)
		ena_set_mem_addr(&cmd.aqc_create_sq.esq_ba,
		    ENA_DMA_DVA(ring));

	error = ena_aq_exec(sc, &cmd, &resp);
	if (error != 0)
		return (error);

	memcpy(&csr, resp.acqd_data, sizeof(csr));
	*idx = lemtoh16(&csr.ecsr_idx);
	*db_off = lemtoh32(&csr.ecsr_db_off);
	if (llq_off != NULL)
		*llq_off = lemtoh32(&csr.ecsr_llq_desc_off);

	return (0);
}

static int
ena_aq_destroy_sq(struct ena_softc *sc, uint16_t idx, uint8_t direction)
{
	union ena_aq_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.aqc_destroy_sq.edsq_opcode = ENA_AQ_OP_DESTROY_SQ;
	htolem16(&cmd.aqc_destroy_sq.edsq_idx, idx);
	cmd.aqc_destroy_sq.edsq_direction = direction;

	return (ena_aq_exec(sc, &cmd, NULL));
}

static int
ena_get_device_attributes(struct ena_softc *sc, uint8_t *enaddr)
{
	struct ena_feat_device_attr attr;
	int error;

	error = ena_aq_get_feature(sc, ENA_FEAT_DEVICE_ATTRIBUTES, 0,
	    &attr, sizeof(attr));
	if (error != 0)
		return (error);

	memcpy(enaddr, attr.eda_mac_addr, ETHER_ADDR_LEN);
	sc->sc_supported_features = lemtoh32(&attr.eda_supported_features);
	sc->sc_capabilities = lemtoh32(&attr.eda_capabilities);
	sc->sc_max_mtu = lemtoh32(&attr.eda_max_mtu);

	return (0);
}

/*
 * Only queue depths and per-packet limits are consumed today; the
 * queue counts (max_*_num fields) become interesting with multiqueue.
 */
static int
ena_get_queue_limits(struct ena_softc *sc)
{
	int error;

	if (ISSET(sc->sc_supported_features,
	    1U << ENA_FEAT_MAX_QUEUES_EXT)) {
		struct ena_feat_max_queues_ext ext;

		error = ena_aq_get_feature(sc, ENA_FEAT_MAX_QUEUES_EXT, 1,
		    &ext, sizeof(ext));
		if (error != 0)
			return (error);

		sc->sc_max_tx_sq_depth = lemtoh32(&ext.emqe_max_tx_sq_depth);
		sc->sc_max_rx_sq_depth = lemtoh32(&ext.emqe_max_rx_sq_depth);
		sc->sc_max_tx_segs =
		    lemtoh16(&ext.emqe_max_per_packet_tx_descs);
		sc->sc_tx_max_hdr = lemtoh32(&ext.emqe_max_tx_header_size);
	} else {
		struct ena_feat_max_queues legacy;

		error = ena_aq_get_feature(sc, ENA_FEAT_MAX_QUEUES_NUM, 0,
		    &legacy, sizeof(legacy));
		if (error != 0)
			return (error);

		sc->sc_max_tx_sq_depth = lemtoh32(&legacy.emq_max_sq_depth);
		sc->sc_max_rx_sq_depth = lemtoh32(&legacy.emq_max_sq_depth);
		sc->sc_max_tx_segs =
		    lemtoh16(&legacy.emq_max_packet_tx_descs);
		sc->sc_tx_max_hdr = lemtoh32(&legacy.emq_max_header_size);
	}

	/* Clamp the device facts to what the data path can actually use. */
	if (sc->sc_max_tx_segs == 0 || sc->sc_max_tx_segs > ENA_TX_NSEGS)
		sc->sc_max_tx_segs = ENA_TX_NSEGS;
	/*
	 * sc_tx_max_hdr is clamped in ena_llq_negotiate() once the
	 * entry size, and with it the inline header space, is known.
	 */

	/* Absurd limits would corrupt the ring math further down. */
	if (sc->sc_max_tx_sq_depth < ENA_NDESCS_MIN ||
	    sc->sc_max_rx_sq_depth < ENA_NDESCS_MIN)
		return (EIO);

	return (0);
}

/*
 * Bring the device from freshly-reset to a ready (but still masked)
 * control plane.  This is the single ladder both attach and recovery
 * climb: reset with an honest reason, re-register the control rings
 * (admin and event), hand over host info, re-read device facts and
 * limits, renegotiate LLQ, re-subscribe the event groups.  The caller
 * owns applying the MAC address and unmasking interrupts at its right
 * moment.
 */
static int
ena_dev_init(struct ena_softc *sc, int reason, uint8_t *enaddr)
{
	uint32_t tx_cap;
	int error;

	/* The caller logs; the module just returns the errno. */
	error = ena_dev_reset(sc, reason);
	if (error != 0)
		return (error);

	/*
	 * The reset returned the device to host-memory TX placement:
	 * the LLQ commitment died with it and must not outlive it, or
	 * a queue created against the stale state breaks TX silently.
	 * ena_llq_negotiate() re-commits further down the ladder.
	 */
	sc->sc_llq_on = 0;
	sc->sc_llq_meta = 0;
	sc->sc_llq_burst = 0;
	sc->sc_llq_entry_size = 0;

	ena_admin_init(sc);
	ena_hostinfo_set(sc);

	error = ena_get_device_attributes(sc, enaddr);
	if (error != 0)
		return (error);
	error = ena_get_queue_limits(sc);
	if (error != 0)
		return (error);

	/*
	 * Ring depths are decided here, once, after negotiation has
	 * reported the LLQ entry cap: in LLQ mode the TX ring counts
	 * device entries, so it is bounded by both limits.  Walks mask
	 * with (ndescs - 1), hence the round down to a power of two.
	 */
	ena_llq_negotiate(sc);
	tx_cap = sc->sc_max_tx_sq_depth;
	if (sc->sc_llq_on)
		tx_cap = MIN(tx_cap, sc->sc_llq_max_depth);
	sc->sc_rx_ndescs = 1U <<
	    (fls(MIN(ENA_NDESCS_MAX, sc->sc_max_rx_sq_depth)) - 1);
	sc->sc_tx_ndescs = 1U << (fls(MIN(ENA_NDESCS_MAX, tx_cap)) - 1);
	sc->sc_rx_buf_len = MCLBYTES;

	return (ena_aenq_negotiate(sc));
}

/*
 * LLQ negotiation (see docs/adr/0003): pick the plain configuration -
 * inline header, 128-byte entries, two descriptors before the header,
 * multiple-descs-per-entry stride - and fall back to host mode if the
 * device does not support any part of it.  Host mode is legal on the
 * whole fleet, so refusing an exotic LLQ flavour costs nothing but
 * latency.
 */
static void
ena_llq_negotiate(struct ena_softc *sc)
{
	struct ena_feat_llq llq, set;
	unsigned int esize;
	uint32_t depth;
	uint16_t esize_bit, accel;
	int meta;

	/*
	 * The LLQ state was already invalidated at the reset; it is
	 * computed into locals and committed to the softc only on full
	 * success, so no bail path can leave a half-configured mode
	 * behind and host mode remains the default.
	 */
	if (sc->sc_llq_mems == 0 ||
	    !ISSET(sc->sc_supported_features, 1U << ENA_FEAT_LLQ))
		return;

	if (ena_aq_get_feature(sc, ENA_FEAT_LLQ, 1, &llq, sizeof(llq)) != 0)
		return;

	if (!ISSET(lemtoh16(&llq.efl_hdr_supported), ENA_LLQ_HDR_INLINE) ||
	    !ISSET(lemtoh16(&llq.efl_descs_before_hdr_supported),
	    ENA_LLQ_TWO_DESCS_BEFORE_HDR) ||
	    !ISSET(lemtoh16(&llq.efl_stride_supported),
	    ENA_LLQ_STRIDE_MULTIPLE)) {
		/* Attach reports the outcome; silence keeps dmesg sane. */
		return;
	}

	/*
	 * Pick 128-byte entries whenever the device offers them, and fall
	 * back to wide 256-byte entries only when it does not.  128-byte
	 * entries inline a standard L2/L3/L4 header and are the size this
	 * driver has been exercised with end to end.  The device may
	 * recommend wide entries (Linux enables Large LLQ on this
	 * generation) for the larger inline header they carry; following
	 * that recommendation is a later step once the wide path is
	 * validated, not a correctness requirement - the device also lists
	 * 128-byte entries as supported and accepts a SET asking for them.
	 */
	if (ISSET(lemtoh16(&llq.efl_entry_size_supported),
	    ENA_LLQ_ENTRY_128)) {
		esize = ENA_LLQ_ENTRY_MIN;
		esize_bit = ENA_LLQ_ENTRY_128;
	} else if (ISSET(lemtoh16(&llq.efl_entry_size_supported),
	    ENA_LLQ_ENTRY_256)) {
		esize = ENA_LLQ_ENTRY_MAX;
		esize_bit = ENA_LLQ_ENTRY_256;
	} else
		return;

	/*
	 * Wide entries have their own depth cap; halving the normal
	 * one is the documented fallback when the device names none.
	 */
	if (esize == ENA_LLQ_ENTRY_MAX) {
		depth = lemtoh16(&llq.efl_max_wide_depth);
		if (depth == 0)
			depth = lemtoh32(&llq.efl_max_depth) / 2;
	} else
		depth = lemtoh32(&llq.efl_max_depth);

	/* The ring math needs a usable power of two. */
	if (depth < ENA_NDESCS_MIN)
		return;

	/*
	 * DISABLE_META_CACHING is the one accel mode we must honor: the
	 * device keeps no meta descriptor across packets, so each packet
	 * carries its own or the device transmits every frame against a
	 * stale meta and drops it before the wire.  LIMIT_TX_BURST is left
	 * off deliberately - enabling it puts the device into a burst read
	 * mode where a single pushed entry makes it walk on through the
	 * ring, so the burst budget stays disabled and doorbells are free.
	 */
	accel = lemtoh16(&llq.efl_accel_flags);
	meta = ISSET(accel, ENA_LLQ_ACCEL_DISABLE_META_CACHING) ? 1 : 0;

	/*
	 * The SET carries only the driver's choices, everything else zero:
	 * the GET buffer with its supported bitmaps and device facts is not
	 * echoed back.
	 */
	memset(&set, 0, sizeof(set));
	htolem16(&set.efl_hdr_enabled, ENA_LLQ_HDR_INLINE);
	htolem16(&set.efl_entry_size_enabled, esize_bit);
	htolem16(&set.efl_descs_before_hdr_enabled,
	    ENA_LLQ_TWO_DESCS_BEFORE_HDR);
	htolem16(&set.efl_stride_enabled, ENA_LLQ_STRIDE_MULTIPLE);
	htolem16(&set.efl_accel_flags, ENA_LLQ_ACCEL_DISABLE_META_CACHING);

	if (ena_aq_set_feature(sc, ENA_FEAT_LLQ, 1, &set, sizeof(set)) != 0)
		return;

	/* The caller folds this entry cap into the TX ring depth. */
	sc->sc_llq_max_depth = depth;
	sc->sc_llq_entry_size = esize;
	sc->sc_llq_meta = meta;
	sc->sc_llq_burst = 0;
	/* Zero from the device means "no hint"; the entry is the cap. */
	if (sc->sc_tx_max_hdr == 0 ||
	    sc->sc_tx_max_hdr > esize - ENA_LLQ_HDR_OFF)
		sc->sc_tx_max_hdr = esize - ENA_LLQ_HDR_OFF;
	sc->sc_llq_on = 1;
}

/*
 * Fill and hand over the host info page.  The page must outlive the
 * command: firmware keeps reading it, so it is freed only on detach.
 * The identity is the minimal one proven on this fleet: Linux 2.0.0
 * with nothing else filled in.
 */
static void
ena_hostinfo_init(struct ena_softc *sc)
{
	struct ena_host_info *hi;

	if (ena_dmamem_alloc(sc, &sc->sc_hostinfo, PAGE_SIZE,
	    PAGE_SIZE) != 0)
		return;

	hi = ENA_DMA_KVA(&sc->sc_hostinfo);
	htolem32(&hi->ehi_os_type, ENA_HOST_OS_LINUX);
	htolem32(&hi->ehi_driver_version, ENA_DRIVER_VERSION);
	htolem16(&hi->ehi_spec_version, ENA_HOST_SPEC_VERSION);
	htolem16(&hi->ehi_num_cpus, ncpus);

	ENA_DMA_SYNC(sc, &sc->sc_hostinfo, BUS_DMASYNC_PREWRITE);
}

/* Hand the page over; re-run after device reset (firmware forgets). */
static void
ena_hostinfo_set(struct ena_softc *sc)
{
	struct ena_feat_host_attr attr;

	if (ENA_DMA_LEN(&sc->sc_hostinfo) == 0)
		return;

	memset(&attr, 0, sizeof(attr));
	ena_set_mem_addr(&attr.eha_os_info_ba,
	    ENA_DMA_DVA(&sc->sc_hostinfo));

	/*
	 * Failure is not fatal (ena_aq_exec logs it); a firmware
	 * unhappy about missing host info fails CREATE_CQ later anyway.
	 */
	(void)ena_aq_set_feature(sc, ENA_FEAT_HOST_ATTR_CONFIG, 0,
	    &attr, sizeof(attr));
}

/*
 * AENQ.
 *
 * The interrupt handler for vector 0 only defers to sc_aenq_task:
 * event handling wants process context (link state updates, and later
 * the reset machinery), and task_add() collapses bursts of interrupts
 * into one run.  The ring is returned to the device by writing the
 * absolute head counter; the initial write of the ring depth is what
 * arms the queue.
 */

static int
ena_aenq_alloc(struct ena_softc *sc)
{
	if (ena_dmamem_alloc(sc, &sc->sc_aenq_ring,
	    ENA_AENQ_NUM * sizeof(struct ena_aenq_desc), PAGE_SIZE) != 0)
		return (ENOMEM);

	return (0);
}

/*
 * Register the AENQ ring: seed the host consumer state, hand the ring
 * base and caps to the device.  Called from ena_admin_init(): the device
 * brings its AENQ subsystem up during the admin queue handshake, and a
 * ring registered after that handshake is only half-adopted - the later
 * head doorbell write trips DEV_STS FATAL_ERROR, after which the device
 * silently drops CREATE_CQ commands.
 */
static void
ena_aenq_register(struct ena_softc *sc)
{
	sc->sc_aenq_head = ENA_AENQ_NUM;
	sc->sc_aenq_phase = 1;

	memset(ENA_DMA_KVA(&sc->sc_aenq_ring), 0,
	    ENA_DMA_LEN(&sc->sc_aenq_ring));
	ENA_DMA_SYNC(sc, &sc->sc_aenq_ring, BUS_DMASYNC_PREREAD);

	ena_wr_base(sc, ENA_AENQ_BASE_LO, ENA_DMA_DVA(&sc->sc_aenq_ring));
	ena_wr(sc, ENA_AENQ_CAPS,
	    ENA_RING_CAPS(ENA_AENQ_NUM, sizeof(struct ena_aenq_desc)));
}

/*
 * Subscribe to the event groups the driver handles.  A failure fails
 * the whole device init, so the ring registration is not unwound here.
 */
static int
ena_aenq_negotiate(struct ena_softc *sc)
{
	struct ena_feat_aenq aenq, set;
	uint32_t groups;

	/* Enable what we handle and the device can deliver, no more. */
	if (ena_aq_get_feature(sc, ENA_FEAT_AENQ_CONFIG, 0,
	    &aenq, sizeof(aenq)) != 0)
		return (EIO);
	groups = lemtoh32(&aenq.efa_supported_groups) & ENA_AENQ_GROUPS_MVP;

	/* A clean SET, not the echoed GET buffer; see ena_llq_negotiate(). */
	memset(&set, 0, sizeof(set));
	htolem32(&set.efa_enabled_groups, groups);
	if (ena_aq_set_feature(sc, ENA_FEAT_AENQ_CONFIG, 0,
	    &set, sizeof(set)) != 0)
		return (EIO);

	return (0);
}

static void
ena_aenq_fini(struct ena_softc *sc)
{
	ena_wr(sc, ENA_AENQ_CAPS, 0);
	ENA_DMA_SYNC(sc, &sc->sc_aenq_ring, BUS_DMASYNC_POSTREAD);
	ena_dmamem_free(sc, &sc->sc_aenq_ring);
}

static void
ena_aenq_arm(struct ena_softc *sc)
{
	/* Finish reading returned entries before the device reuses them. */
	membar_consumer();
	ena_wr(sc, ENA_AENQ_HEAD_DB, sc->sc_aenq_head);
}

/*
 * Unmask the event machinery and start the keepalive clock.  The last
 * step of every bring-up (attach and recovery), kept in one place so
 * the two callers can't drift.
 */
static void
ena_arm(struct ena_softc *sc)
{
	sc->sc_keepalive_ts = getuptime();
	ena_wr(sc, ENA_INTR_MASK, 0);
	ena_aenq_arm(sc);
}

/* The single place link state changes; callers pass LINK_STATE_*. */
static void
ena_link_update(struct ena_softc *sc, int link)
{
	struct ifnet *ifp = &sc->sc_ac.ac_if;

	mtx_enter(&sc->sc_link_mtx);
	sc->sc_link_state = link;
	mtx_leave(&sc->sc_link_mtx);

	if (ifp->if_link_state != link) {
		ifp->if_link_state = link;
		if_link_state_change(ifp);
		sc->sc_dev_st.link_changes++;
	}
}

static void
ena_aenq_task(void *xsc)
{
	struct ena_softc *sc = xsc;
	struct ena_aenq_desc *ring = ENA_DMA_KVA(&sc->sc_aenq_ring);
	struct ena_aenq_desc *d;
	unsigned int processed = 0;
	uint16_t group;

	for (;;) {
		ENA_DMA_SYNC(sc, &sc->sc_aenq_ring, BUS_DMASYNC_POSTREAD);
		d = &ring[sc->sc_aenq_head & (ENA_AENQ_NUM - 1)];
		if ((d->ead_flags & ENA_AENQD_F_PHASE) != sc->sc_aenq_phase)
			break;

		/* The phase bit is written last; order the rest after. */
		membar_consumer();

		group = lemtoh16(&d->ead_group);
		switch (group) {
		case ENA_AENQ_GROUP_LINK_CHANGE:
			sc->sc_dev_st.aenq_link++;
			ena_link_update(sc,
			    ISSET(lemtoh32(&d->ead_u.eadu_link.eal_flags),
			    ENA_AENQ_LINK_UP) ?
			    LINK_STATE_FULL_DUPLEX : LINK_STATE_DOWN);
			break;
		case ENA_AENQ_GROUP_KEEP_ALIVE:
			sc->sc_keepalive_ts = getuptime();
			sc->sc_dev_st.aenq_keepalive++;
			break;
		case ENA_AENQ_GROUP_FATAL_ERROR:
			sc->sc_dev_st.aenq_fatal++;
			printf("%s: fatal device error, syndrome %u\n",
			    DEVNAME(sc), lemtoh16(&d->ead_syndrome));
			ena_reset_request(sc, ENA_RESET_GENERIC);
			break;
		case ENA_AENQ_GROUP_WARNING:
		case ENA_AENQ_GROUP_NOTIFICATION:
			if (group == ENA_AENQ_GROUP_WARNING)
				sc->sc_dev_st.aenq_warning++;
			else
				sc->sc_dev_st.aenq_notify++;
			printf("%s: device event group %u syndrome %u\n",
			    DEVNAME(sc), group, lemtoh16(&d->ead_syndrome));
			break;
		default:
			/* Unknown events are ignored on purpose. */
			sc->sc_dev_st.aenq_unknown++;
			break;
		}

		sc->sc_aenq_head++;
		if ((sc->sc_aenq_head & (ENA_AENQ_NUM - 1)) == 0)
			sc->sc_aenq_phase ^= 1;
		processed++;
	}

	if (processed)
		ena_aenq_arm(sc);
}

static int
ena_intr_admin(void *xsc)
{
	struct ena_softc *sc = xsc;

	task_add(systq, &sc->sc_aenq_task);
	return (1);
}

static int
ena_intr_queue(void *xsc)
{
	struct ena_softc *sc = xsc;
	struct ifnet *ifp = &sc->sc_ac.ac_if;
	struct ena_rxr *rxr = sc->sc_rxr;

	if (rxr != NULL && ISSET(ifp->if_flags, IFF_RUNNING)) {
		ena_txeof(sc->sc_txr);
		ena_rxeof(rxr);

		/* Re-arm the vector; the device masked it for us. */
		ena_wr(sc, rxr->rxr_unmask_off,
		    ENA_INTR_CTRL_UNMASK | ENA_INTR_CTRL_NO_MOD);
	}

	return (1);
}

/*
 * Statistics via kstat(4).
 *
 * Three device-lifetime kstats (created at attach) and two per-ring
 * kstats (created with the rings, on up).  All are KSTAT_T_KV arrays
 * of COUNTER64, and all read the same way: ena_kstat_kv_read() copies
 * each value from its template offset into the struct the kstat points
 * at.  The device's own counters (basic, eni) are refreshed into a
 * cache by the stats task, so even those reads touch only memory.
 */

/* One counter: kstat key is the struct field name, value at its offset. */
#define ENA_KV(_st, _field, _unit) \
	{ #_field, _unit, offsetof(struct _st, _field) }

/* One row per struct ena_device_stats field; reset_* also in ena_reset_reasons[]. */
static const struct ena_kv_tpl ena_kstat_device_tpl[] = {
	ENA_KV(ena_device_stats, resets,		KSTAT_KV_U_NONE),
	ENA_KV(ena_device_stats, reset_keepalive,	KSTAT_KV_U_NONE),
	ENA_KV(ena_device_stats, reset_admin_to,	KSTAT_KV_U_NONE),
	ENA_KV(ena_device_stats, reset_miss_tx,		KSTAT_KV_U_NONE),
	ENA_KV(ena_device_stats, reset_rx_reqid,	KSTAT_KV_U_NONE),
	ENA_KV(ena_device_stats, reset_tx_reqid,	KSTAT_KV_U_NONE),
	ENA_KV(ena_device_stats, reset_dev_err,		KSTAT_KV_U_NONE),
	ENA_KV(ena_device_stats, reset_user,		KSTAT_KV_U_NONE),
	ENA_KV(ena_device_stats, admin_cmds,		KSTAT_KV_U_NONE),
	ENA_KV(ena_device_stats, admin_errors,		KSTAT_KV_U_NONE),
	ENA_KV(ena_device_stats, admin_timeouts,	KSTAT_KV_U_NONE),
	ENA_KV(ena_device_stats, aenq_link,		KSTAT_KV_U_NONE),
	ENA_KV(ena_device_stats, aenq_keepalive,	KSTAT_KV_U_NONE),
	ENA_KV(ena_device_stats, aenq_warning,		KSTAT_KV_U_NONE),
	ENA_KV(ena_device_stats, aenq_notify,		KSTAT_KV_U_NONE),
	ENA_KV(ena_device_stats, aenq_fatal,		KSTAT_KV_U_NONE),
	ENA_KV(ena_device_stats, aenq_unknown,		KSTAT_KV_U_NONE),
	ENA_KV(ena_device_stats, link_changes,		KSTAT_KV_U_NONE),
};

static const struct ena_kv_tpl ena_kstat_txq_tpl[] = {
	ENA_KV(ena_txq_stats, packets,		KSTAT_KV_U_PACKETS),
	ENA_KV(ena_txq_stats, bytes,		KSTAT_KV_U_BYTES),
	ENA_KV(ena_txq_stats, doorbells,	KSTAT_KV_U_NONE),
	ENA_KV(ena_txq_stats, dma_map_err,	KSTAT_KV_U_NONE),
	ENA_KV(ena_txq_stats, defrags,		KSTAT_KV_U_NONE),
	ENA_KV(ena_txq_stats, stalls,		KSTAT_KV_U_NONE),
	ENA_KV(ena_txq_stats, bad_reqid,	KSTAT_KV_U_NONE),
	ENA_KV(ena_txq_stats, desc_err,		KSTAT_KV_U_NONE),
};

static const struct ena_kv_tpl ena_kstat_rxq_tpl[] = {
	ENA_KV(ena_rxq_stats, packets,		KSTAT_KV_U_PACKETS),
	ENA_KV(ena_rxq_stats, bytes,		KSTAT_KV_U_BYTES),
	ENA_KV(ena_rxq_stats, mbuf_alloc_err,	KSTAT_KV_U_NONE),
	ENA_KV(ena_rxq_stats, dma_map_err,	KSTAT_KV_U_NONE),
	ENA_KV(ena_rxq_stats, ring_empty,	KSTAT_KV_U_NONE),
	ENA_KV(ena_rxq_stats, bad_reqid,	KSTAT_KV_U_NONE),
	ENA_KV(ena_rxq_stats, desc_err,		KSTAT_KV_U_NONE),
};

static const struct ena_kv_tpl ena_kstat_basic_tpl[] = {
	ENA_KV(ena_basic_cache, tx_bytes,	KSTAT_KV_U_BYTES),
	ENA_KV(ena_basic_cache, tx_packets,	KSTAT_KV_U_PACKETS),
	ENA_KV(ena_basic_cache, rx_bytes,	KSTAT_KV_U_BYTES),
	ENA_KV(ena_basic_cache, rx_packets,	KSTAT_KV_U_PACKETS),
	ENA_KV(ena_basic_cache, rx_drops,	KSTAT_KV_U_PACKETS),
	ENA_KV(ena_basic_cache, tx_drops,	KSTAT_KV_U_PACKETS),
	ENA_KV(ena_basic_cache, rx_overruns,	KSTAT_KV_U_PACKETS),
};

static const struct ena_kv_tpl ena_kstat_eni_tpl[] = {
	ENA_KV(ena_eni_cache, bw_in_exceeded,	KSTAT_KV_U_PACKETS),
	ENA_KV(ena_eni_cache, bw_out_exceeded,	KSTAT_KV_U_PACKETS),
	ENA_KV(ena_eni_cache, pps_exceeded,	KSTAT_KV_U_PACKETS),
	ENA_KV(ena_eni_cache, conntrack_excd,	KSTAT_KV_U_PACKETS),
	ENA_KV(ena_eni_cache, linklocal_excd,	KSTAT_KV_U_PACKETS),
};

#undef ENA_KV

static struct kstat *
ena_kstat_create(struct ena_softc *sc, const char *name, unsigned int unit,
    const struct ena_kv_tpl *tpl, unsigned int n, void *base)
{
	struct kstat *ks;
	struct kstat_kv *kvs;
	unsigned int i;

	ks = kstat_create(DEVNAME(sc), 0, name, unit, KSTAT_T_KV, 0);
	if (ks == NULL)
		return (NULL);

	kvs = mallocarray(n, sizeof(*kvs), M_DEVBUF, M_WAITOK | M_ZERO);
	for (i = 0; i < n; i++)
		kstat_kv_unit_init(&kvs[i], tpl[i].name,
		    KSTAT_KV_T_COUNTER64, tpl[i].unit);

	/* ks_softc is the stats-struct base ena_kstat_kv_read() offsets into. */
	ks->ks_softc = base;
	ks->ks_ptr = (void *)tpl;
	ks->ks_data = kvs;
	ks->ks_datalen = n * sizeof(*kvs);
	ks->ks_read = ena_kstat_kv_read;
	kstat_set_wlock(ks, &sc->sc_kstat_lock);
	kstat_install(ks);

	return (ks);
}

static void
ena_kstat_destroy(struct kstat **ksp)
{
	struct kstat *ks = *ksp;
	void *data;
	size_t len;

	if (ks == NULL)
		return;

	/*
	 * kstat_destroy waits out any in-flight read (both take the
	 * global kstat lock), so the kv buffer is unreferenced once it
	 * returns.  Grab the pointers first: kstat_destroy frees ks.
	 */
	data = ks->ks_data;
	len = ks->ks_datalen;
	kstat_destroy(ks);
	free(data, M_DEVBUF, len);
	*ksp = NULL;
}

/*
 * The one kstat read: every value is a uint64_t at its template offset
 * into the struct ks_softc points at.  All five kstats share it - the
 * device/txq/rxq software counters and the basic/eni caches alike.
 */
static int
ena_kstat_kv_read(struct kstat *ks)
{
	const struct ena_kv_tpl *tpl = ks->ks_ptr;
	struct kstat_kv *kvs = ks->ks_data;
	const uint8_t *base = ks->ks_softc;
	unsigned int i, n = ks->ks_datalen / sizeof(*kvs);

	for (i = 0; i < n; i++)
		kstat_kv_u64(&kvs[i]) =
		    *(const uint64_t *)(base + tpl[i].offset);

	nanouptime(&ks->ks_updated);
	return (0);
}

/*
 * Refresh the device's own counters into the caches the basic/eni
 * kstats read, and feed the drop deltas into the ifnet counters that
 * netstat -in shows.  Runs on systq (kicked once a second from the
 * watchdog), so it is serialized against the reset task; it also takes
 * the cfg lock so it serializes against an ioctl up/down exactly like
 * every other admin caller, keeping the admin queue single-owner.
 * sc_reset_pending bails early so a queued reset behind us on systq
 * isn't delayed, and a failed GET_STATS just leaves the last cache in
 * place.
 */
static void
ena_stats_task(void *xsc)
{
	struct ena_softc *sc = xsc;
	struct ifnet *ifp = &sc->sc_ac.ac_if;
	struct ena_basic_stats bs;
	struct ena_eni_stats es;

	if (sc->sc_reset_pending)
		return;

	rw_enter_read(&sc->sc_cfg_lock);

	if (ena_aq_get_stats(sc, ENA_STATS_TYPE_BASIC, &bs, sizeof(bs)) == 0) {
		uint64_t rx_drops =
		    ena_stat64(&bs.ebs_rx_drops_lo, &bs.ebs_rx_drops_hi);
		uint64_t tx_drops =
		    ena_stat64(&bs.ebs_tx_drops_lo, &bs.ebs_tx_drops_hi);
		uint64_t rx_overruns =
		    ena_stat64(&bs.ebs_rx_overruns_lo, &bs.ebs_rx_overruns_hi);

		/*
		 * Feed the delta since the last snapshot into netstat's
		 * columns: rx drops are input queue drops, rx overruns (no
		 * armed RX buffer) are input errors, tx drops are output
		 * queue drops.  sc_stats_seen skips the first sample after
		 * attach or an up, when sc_basic holds no real baseline yet
		 * and a device reset may have zeroed the counters.
		 */
		if (sc->sc_stats_seen) {
			if (rx_drops >= sc->sc_basic.rx_drops)
				ifp->if_iqdrops += rx_drops - sc->sc_basic.rx_drops;
			if (rx_overruns >= sc->sc_basic.rx_overruns)
				ifp->if_ierrors +=
				    rx_overruns - sc->sc_basic.rx_overruns;
			if (tx_drops >= sc->sc_basic.tx_drops)
				ifp->if_oqdrops += tx_drops - sc->sc_basic.tx_drops;
		}

		/*
		 * Update the cache only after the delta feed above: sc_basic
		 * is that feed's baseline, so these stores must not move ahead
		 * of it or every delta silently reads zero.
		 */
		sc->sc_basic.tx_bytes =
		    ena_stat64(&bs.ebs_tx_bytes_lo, &bs.ebs_tx_bytes_hi);
		sc->sc_basic.tx_packets =
		    ena_stat64(&bs.ebs_tx_pkts_lo, &bs.ebs_tx_pkts_hi);
		sc->sc_basic.rx_bytes =
		    ena_stat64(&bs.ebs_rx_bytes_lo, &bs.ebs_rx_bytes_hi);
		sc->sc_basic.rx_packets =
		    ena_stat64(&bs.ebs_rx_pkts_lo, &bs.ebs_rx_pkts_hi);
		sc->sc_basic.rx_drops = rx_drops;
		sc->sc_basic.tx_drops = tx_drops;
		sc->sc_basic.rx_overruns = rx_overruns;
		sc->sc_stats_seen = 1;
	}

	if (ISSET(sc->sc_capabilities, ENA_CAP_ENI_STATS) &&
	    ena_aq_get_stats(sc, ENA_STATS_TYPE_ENI, &es, sizeof(es)) == 0) {
		sc->sc_eni.bw_in_exceeded = lemtoh64(&es.ees_bw_in_exceeded);
		sc->sc_eni.bw_out_exceeded = lemtoh64(&es.ees_bw_out_exceeded);
		sc->sc_eni.pps_exceeded = lemtoh64(&es.ees_pps_exceeded);
		sc->sc_eni.conntrack_excd = lemtoh64(&es.ees_conntrack_exceeded);
		sc->sc_eni.linklocal_excd = lemtoh64(&es.ees_linklocal_exceeded);
	}

	rw_exit_read(&sc->sc_cfg_lock);
}

/*
 * Device-lifetime kstats.  The eni kstat exists only when the device
 * advertises ENI stats; on a device without that capability GET_STATS
 * (ENI) would just fail, so there is no point in the kstat.
 */
static void
ena_kstat_attach(struct ena_softc *sc)
{
	sc->sc_kstat_device = ena_kstat_create(sc, "device", 0,
	    ena_kstat_device_tpl, nitems(ena_kstat_device_tpl), &sc->sc_dev_st);
	sc->sc_kstat_basic = ena_kstat_create(sc, "basic", 0,
	    ena_kstat_basic_tpl, nitems(ena_kstat_basic_tpl), &sc->sc_basic);
	if (ISSET(sc->sc_capabilities, ENA_CAP_ENI_STATS)) {
		sc->sc_kstat_eni = ena_kstat_create(sc, "eni", 0,
		    ena_kstat_eni_tpl, nitems(ena_kstat_eni_tpl), &sc->sc_eni);
	}
}

static void
ena_kstat_detach(struct ena_softc *sc)
{
	ena_kstat_destroy(&sc->sc_kstat_device);
	ena_kstat_destroy(&sc->sc_kstat_basic);
	ena_kstat_destroy(&sc->sc_kstat_eni);
}

/*
 * RX ring.
 */

static struct ena_rxr *
ena_rxr_alloc(struct ena_softc *sc)
{
	struct ena_rxr *rxr;
	struct ena_rx_slot *slot;
	unsigned int i;

	rxr = malloc(sizeof(*rxr), M_DEVBUF, M_WAITOK | M_ZERO);
	rxr->rxr_sc = sc;
	rxr->rxr_ndescs = sc->sc_rx_ndescs;
	mtx_init(&rxr->rxr_mtx, IPL_NET);
	timeout_set(&rxr->rxr_refill, ena_rxrefill, rxr);

	if (ena_dmamem_alloc(sc, &rxr->rxr_sq_ring,
	    rxr->rxr_ndescs * sizeof(struct ena_rx_desc), PAGE_SIZE) != 0)
		goto free_rxr;
	if (ena_dmamem_alloc(sc, &rxr->rxr_cq_ring,
	    rxr->rxr_ndescs * sizeof(struct ena_rx_cdesc), PAGE_SIZE) != 0)
		goto free_sq;

	rxr->rxr_slots = mallocarray(rxr->rxr_ndescs, sizeof(*slot),
	    M_DEVBUF, M_WAITOK | M_ZERO);
	rxr->rxr_ids = mallocarray(rxr->rxr_ndescs, sizeof(*rxr->rxr_ids),
	    M_DEVBUF, M_WAITOK);

	for (i = 0; i < rxr->rxr_ndescs; i++) {
		rxr->rxr_ids[i] = i;
		slot = &rxr->rxr_slots[i];
		if (bus_dmamap_create(sc->sc_dmat, sc->sc_rx_buf_len, 1,
		    sc->sc_rx_buf_len, 0,
		    BUS_DMA_WAITOK | BUS_DMA_64BIT, &slot->ers_map) != 0)
			goto free_maps;
	}

	return (rxr);

free_maps:
	while (i-- > 0)
		bus_dmamap_destroy(sc->sc_dmat, rxr->rxr_slots[i].ers_map);
	free(rxr->rxr_ids, M_DEVBUF,
	    rxr->rxr_ndescs * sizeof(*rxr->rxr_ids));
	free(rxr->rxr_slots, M_DEVBUF,
	    rxr->rxr_ndescs * sizeof(*slot));
	ena_dmamem_free(sc, &rxr->rxr_cq_ring);
free_sq:
	ena_dmamem_free(sc, &rxr->rxr_sq_ring);
free_rxr:
	free(rxr, M_DEVBUF, sizeof(*rxr));
	return (NULL);
}

static void
ena_rxr_free(struct ena_softc *sc, struct ena_rxr *rxr)
{
	struct ena_rx_slot *slot;
	unsigned int i;

	/* ena_rxfill() may have armed the refill timeout. */
	timeout_del_barrier(&rxr->rxr_refill);

	for (i = 0; i < rxr->rxr_ndescs; i++) {
		slot = &rxr->rxr_slots[i];
		if (slot->ers_m != NULL) {
			bus_dmamap_sync(sc->sc_dmat, slot->ers_map, 0,
			    slot->ers_map->dm_mapsize, BUS_DMASYNC_POSTREAD);
			bus_dmamap_unload(sc->sc_dmat, slot->ers_map);
			m_freem(slot->ers_m);
			slot->ers_m = NULL;
		}
		bus_dmamap_destroy(sc->sc_dmat, slot->ers_map);
	}

	m_freem(rxr->rxr_m_head);

	free(rxr->rxr_ids, M_DEVBUF,
	    rxr->rxr_ndescs * sizeof(*rxr->rxr_ids));
	free(rxr->rxr_slots, M_DEVBUF,
	    rxr->rxr_ndescs * sizeof(*slot));
	ena_dmamem_free(sc, &rxr->rxr_cq_ring);
	ena_dmamem_free(sc, &rxr->rxr_sq_ring);
	free(rxr, M_DEVBUF, sizeof(*rxr));
}

/* Create the CQ+SQ pair on the device.  CQ first: the SQ refers to it. */
static int
ena_rxr_init(struct ena_softc *sc, struct ena_rxr *rxr)
{
	int error;

	rxr->rxr_prod = 0;
	rxr->rxr_cons = 0;
	rxr->rxr_sq_phase = 1;
	rxr->rxr_cq_phase = 1;
	rxr->rxr_m_head = NULL;
	rxr->rxr_m_tail = &rxr->rxr_m_head;
	rxr->rxr_m_len = 0;
	/*
	 * Pin the RX ring full and disable if_rxr's adaptive scaling by
	 * equating the low- and high-water marks: the current watermark is
	 * then nailed at a full ring (ndescs - 1), and neither the per-tick
	 * grow (if_rxr_adjust_cwm) nor the livelock shrink (if_rxr_livelocked)
	 * can move it.
	 *
	 * This is a correctness requirement of the device, not tuning.  On
	 * Nitro v4+/v5 (sixth-generation) hardware the RX engine fetches SQ
	 * descriptors lazily and silently drops every inbound frame it has
	 * no armed buffer for, returning neither a completion nor an
	 * interrupt.  The drop rate scales directly with how empty the ring
	 * is kept, and with only a couple of buffers posted the device
	 * delivers nothing at all.  Because a starved ring yields no
	 * completions, the adaptive path (which grows only as completions
	 * arrive) can never climb back out, so the ring has to be handed its
	 * full complement up front and held there.  Every other ENA driver
	 * (Linux, FreeBSD, illumos, DPDK, iPXE) does the same and none uses
	 * an adaptive RX fill.  Amazon confirms the silent, unreported drops
	 * on this generation:
	 *   https://github.com/amzn/amzn-drivers/issues/235
	 * FreeBSD carries an empty-ring recovery watchdog for the same
	 * reason (review D12856):
	 *   https://reviews.freebsd.org/D12856
	 *
	 * The one-slot gap (ndescs - 1, never ndescs) is mandatory as well:
	 * besides the usual producer/consumer full-versus-empty gap, this
	 * device faults - sets the fatal-error bit and wedges - if the SQ
	 * doorbell ever reaches head + ring depth.  See illumos 14845:
	 *   https://www.illumos.org/issues/14845
	 */
	if_rxr_init(&rxr->rxr_acct, rxr->rxr_ndescs - 1, rxr->rxr_ndescs - 1);

	ENA_DMA_SYNC(sc, &rxr->rxr_cq_ring, BUS_DMASYNC_PREREAD);

	error = ena_aq_create_cq(sc, rxr->rxr_ndescs, &rxr->rxr_cq_ring,
	    sizeof(struct ena_rx_cdesc), &rxr->rxr_cq_idx,
	    &rxr->rxr_unmask_off);
	if (error != 0)
		return (error);

	error = ena_aq_create_sq(sc, ENA_SQ_DIR_RX, ENA_SQ_PLACEMENT_HOST,
	    rxr->rxr_cq_idx, rxr->rxr_ndescs, &rxr->rxr_sq_ring,
	    &rxr->rxr_sq_idx, &rxr->rxr_db_off, NULL);
	if (error != 0) {
		ena_aq_destroy_cq(sc, rxr->rxr_cq_idx);
		return (error);
	}

	ena_rxfill(rxr);

	/* unit is the queue index; single RX ring today. */
	rxr->rxr_kstat = ena_kstat_create(sc, "rxq", 0, ena_kstat_rxq_tpl,
	    nitems(ena_kstat_rxq_tpl), &rxr->rxr_st);

	return (0);
}

static void
ena_rxr_deinit(struct ena_softc *sc, struct ena_rxr *rxr)
{
	ena_kstat_destroy(&rxr->rxr_kstat);

	/* If the admin queue died these fail quietly; reset cleans up. */
	ena_aq_destroy_sq(sc, rxr->rxr_sq_idx, ENA_SQ_DIR_RX);
	ena_aq_destroy_cq(sc, rxr->rxr_cq_idx);

	ENA_DMA_SYNC(sc, &rxr->rxr_cq_ring, BUS_DMASYNC_POSTREAD);
}

static void
ena_rxfill(struct ena_rxr *rxr)
{
	struct ena_softc *sc = rxr->rxr_sc;
	struct ena_rx_desc *ring = ENA_DMA_KVA(&rxr->rxr_sq_ring);
	struct ena_rx_desc *rxd;
	struct ena_rx_slot *slot;
	struct mbuf *m;
	u_int slots, filled = 0, mask = rxr->rxr_ndescs - 1;
	uint16_t prod, req_id;
	uint8_t phase;

	mtx_enter(&rxr->rxr_mtx);

	slots = if_rxr_get(&rxr->rxr_acct, rxr->rxr_ndescs);
	if (slots == 0) {
		mtx_leave(&rxr->rxr_mtx);
		return;
	}

	prod = rxr->rxr_prod;
	phase = rxr->rxr_sq_phase;

	while (slots > 0) {
		req_id = rxr->rxr_ids[prod & mask];
		slot = &rxr->rxr_slots[req_id];
		KASSERT(slot->ers_m == NULL);

		/*
		 * Hand the buffer over at its natural alignment, without
		 * the traditional ETHER_ALIGN shift: ENA takes no buffer
		 * offset, and its sanctioned way to align the payload is
		 * the device-applied RX_OFFSET feature, which ena_rxeof()
		 * already honors.
		 */
		m = MCLGETL(NULL, M_DONTWAIT, sc->sc_rx_buf_len);
		if (m == NULL) {
			rxr->rxr_st.mbuf_alloc_err++;
			break;
		}
		m->m_len = m->m_pkthdr.len = sc->sc_rx_buf_len;

		if (bus_dmamap_load_mbuf(sc->sc_dmat, slot->ers_map, m,
		    BUS_DMA_NOWAIT) != 0) {
			rxr->rxr_st.dma_map_err++;
			m_freem(m);
			break;
		}
		bus_dmamap_sync(sc->sc_dmat, slot->ers_map, 0,
		    slot->ers_map->dm_mapsize, BUS_DMASYNC_PREREAD);
		slot->ers_m = m;

		rxd = &ring[prod & mask];
		htolem16(&rxd->erd_length, slot->ers_map->dm_segs[0].ds_len);
		htolem16(&rxd->erd_req_id, req_id);
		htolem32(&rxd->erd_addr_lo, slot->ers_map->dm_segs[0].ds_addr);
		htolem16(&rxd->erd_addr_hi,
		    ena_addr_hi(slot->ers_map->dm_segs[0].ds_addr));
		rxd->erd_ctrl = phase | ENA_RXD_CTRL_FIRST |
		    ENA_RXD_CTRL_LAST | ENA_RXD_CTRL_COMP_REQ;

		prod++;
		if ((prod & mask) == 0)
			phase ^= 1;
		slots--;
		filled++;
	}

	if_rxr_put(&rxr->rxr_acct, slots);

	if (filled > 0) {
		ENA_DMA_SYNC(sc, &rxr->rxr_sq_ring, BUS_DMASYNC_PREWRITE);
		rxr->rxr_prod = prod;
		rxr->rxr_sq_phase = phase;
		ena_wr(sc, rxr->rxr_db_off, prod);
	}

	/* Out of clusters entirely: retry from the refill timeout. */
	if (if_rxr_inuse(&rxr->rxr_acct) == 0) {
		rxr->rxr_st.ring_empty++;
		timeout_add(&rxr->rxr_refill, 1);
	}

	mtx_leave(&rxr->rxr_mtx);
}

static void
ena_rxrefill(void *xrxr)
{
	ena_rxfill(xrxr);
}

static void
ena_rxeof(struct ena_rxr *rxr)
{
	struct ena_softc *sc = rxr->rxr_sc;
	struct ifnet *ifp = &sc->sc_ac.ac_if;
	struct mbuf_list ml = MBUF_LIST_INITIALIZER();
	struct ena_rx_cdesc *ring = ENA_DMA_KVA(&rxr->rxr_cq_ring);
	struct ena_rx_cdesc *rxc;
	struct ena_rx_slot *slot;
	struct mbuf *m;
	unsigned int mask = rxr->rxr_ndescs - 1;
	uint32_t status;
	uint16_t req_id, len;
	int first;

	/* One sync covers the whole batch; new arrivals raise a fresh intr. */
	ENA_DMA_SYNC(sc, &rxr->rxr_cq_ring, BUS_DMASYNC_POSTREAD);

	for (;;) {
		rxc = &ring[rxr->rxr_cons & mask];
		status = lemtoh32(&rxc->erc_status);
		if (((status & ENA_RXC_PHASE) != 0) != rxr->rxr_cq_phase)
			break;

		/* The phase bit is written last; order the rest after. */
		membar_consumer();

		if (ISSET(sc->sc_capabilities, ENA_CAP_CDESC_MBZ) &&
		    ISSET(status, ENA_RXC_MBZ7 | ENA_RXC_MBZ17)) {
			rxr->rxr_st.desc_err++;
			printf("%s: corrupted rx completion\n", DEVNAME(sc));
			ena_reset_request(sc, ENA_RESET_GENERIC);
			break;
		}

		req_id = lemtoh16(&rxc->erc_req_id);
		if (req_id >= rxr->rxr_ndescs ||
		    rxr->rxr_slots[req_id].ers_m == NULL) {
			rxr->rxr_st.bad_reqid++;
			printf("%s: invalid rx req_id %u\n", DEVNAME(sc),
			    req_id);
			ena_reset_request(sc, ENA_RESET_INV_RX_REQ_ID);
			break;
		}

		first = (rxr->rxr_m_head == NULL);
		if (first != !!ISSET(status, ENA_RXC_FIRST)) {
			rxr->rxr_st.desc_err++;
			printf("%s: rx chain out of sync\n", DEVNAME(sc));
			ena_reset_request(sc, ENA_RESET_GENERIC);
			break;
		}

		slot = &rxr->rxr_slots[req_id];
		bus_dmamap_sync(sc->sc_dmat, slot->ers_map, 0,
		    slot->ers_map->dm_mapsize, BUS_DMASYNC_POSTREAD);
		bus_dmamap_unload(sc->sc_dmat, slot->ers_map);
		m = slot->ers_m;
		slot->ers_m = NULL;
		if_rxr_put(&rxr->rxr_acct, 1);

		len = lemtoh16(&rxc->erc_length);
		m->m_len = len;
		if (first)
			m->m_data += rxc->erc_offset;

		*rxr->rxr_m_tail = m;
		rxr->rxr_m_tail = &m->m_next;
		rxr->rxr_m_len += len;

		if (ISSET(status, ENA_RXC_LAST)) {
			m = rxr->rxr_m_head;
			m->m_pkthdr.len = rxr->rxr_m_len;
			ml_enqueue(&ml, m);

			rxr->rxr_st.packets++;
			rxr->rxr_st.bytes += rxr->rxr_m_len;

			rxr->rxr_m_head = NULL;
			rxr->rxr_m_tail = &rxr->rxr_m_head;
			rxr->rxr_m_len = 0;
		}

		/* The id returns to the free ring for a future refill. */
		rxr->rxr_ids[rxr->rxr_cons & mask] = req_id;

		rxr->rxr_cons++;
		if ((rxr->rxr_cons & mask) == 0)
			rxr->rxr_cq_phase ^= 1;
	}

	if (!ml_empty(&ml)) {
		if (ifiq_input(&ifp->if_rcv, &ml))
			if_rxr_livelocked(&rxr->rxr_acct);
	}

	ena_rxfill(rxr);
}

/*
 * TX ring.
 */

static struct ena_txr *
ena_txr_alloc(struct ena_softc *sc)
{
	struct ena_txr *txr;
	struct ena_tx_slot *slot;
	unsigned int i;

	txr = malloc(sizeof(*txr), M_DEVBUF, M_WAITOK | M_ZERO);
	txr->txr_sc = sc;
	txr->txr_ndescs = sc->sc_tx_ndescs;

	/* In LLQ mode the SQ lives in device memory, not in RAM. */
	if (!sc->sc_llq_on &&
	    ena_dmamem_alloc(sc, &txr->txr_sq_ring,
	    txr->txr_ndescs * sizeof(struct ena_tx_desc), PAGE_SIZE) != 0)
		goto free_txr;
	if (ena_dmamem_alloc(sc, &txr->txr_cq_ring,
	    txr->txr_ndescs * sizeof(struct ena_tx_cdesc), PAGE_SIZE) != 0)
		goto free_sq;

	txr->txr_slots = mallocarray(txr->txr_ndescs, sizeof(*slot),
	    M_DEVBUF, M_WAITOK | M_ZERO);

	for (i = 0; i < txr->txr_ndescs; i++) {
		slot = &txr->txr_slots[i];
		if (bus_dmamap_create(sc->sc_dmat, MAXMCLBYTES,
		    sc->sc_max_tx_segs, ENA_TXD_LEN_MASK, 0,
		    BUS_DMA_WAITOK | BUS_DMA_64BIT, &slot->ets_map) != 0)
			goto free_maps;
	}

	return (txr);

free_maps:
	while (i-- > 0)
		bus_dmamap_destroy(sc->sc_dmat, txr->txr_slots[i].ets_map);
	free(txr->txr_slots, M_DEVBUF,
	    txr->txr_ndescs * sizeof(*slot));
	ena_dmamem_free(sc, &txr->txr_cq_ring);
free_sq:
	if (ENA_DMA_LEN(&txr->txr_sq_ring) != 0)
		ena_dmamem_free(sc, &txr->txr_sq_ring);
free_txr:
	free(txr, M_DEVBUF, sizeof(*txr));
	return (NULL);
}

static void
ena_txr_free(struct ena_softc *sc, struct ena_txr *txr)
{
	struct ena_tx_slot *slot;
	unsigned int i;

	for (i = 0; i < txr->txr_ndescs; i++) {
		slot = &txr->txr_slots[i];
		if (slot->ets_m != NULL) {
			bus_dmamap_sync(sc->sc_dmat, slot->ets_map, 0,
			    slot->ets_map->dm_mapsize,
			    BUS_DMASYNC_POSTWRITE);
			bus_dmamap_unload(sc->sc_dmat, slot->ets_map);
			m_freem(slot->ets_m);
			slot->ets_m = NULL;
		}
		bus_dmamap_destroy(sc->sc_dmat, slot->ets_map);
	}

	free(txr->txr_slots, M_DEVBUF,
	    txr->txr_ndescs * sizeof(*slot));
	ena_dmamem_free(sc, &txr->txr_cq_ring);
	if (ENA_DMA_LEN(&txr->txr_sq_ring) != 0)
		ena_dmamem_free(sc, &txr->txr_sq_ring);
	free(txr, M_DEVBUF, sizeof(*txr));
}

static int
ena_txr_init(struct ena_softc *sc, struct ena_txr *txr)
{
	int error;

	txr->txr_prod = 0;
	txr->txr_cq_cons = 0;
	txr->txr_sq_phase = 1;
	txr->txr_cq_phase = 1;
	txr->txr_used = 0;
	txr->txr_last_cq_cons = 0;
	txr->txr_stuck = 0;

	ENA_DMA_SYNC(sc, &txr->txr_cq_ring, BUS_DMASYNC_PREREAD);

	/*
	 * The unmask register from the TX CQ is unused: the intr_reg
	 * serves the whole vector and the RX CQ's copy is the one we
	 * write, so NULL it away here.
	 */
	error = ena_aq_create_cq(sc, txr->txr_ndescs, &txr->txr_cq_ring,
	    sizeof(struct ena_tx_cdesc), &txr->txr_cq_idx, NULL);
	if (error != 0)
		return (error);

	if (sc->sc_llq_on) {
		bus_size_t llq_off;

		error = ena_aq_create_sq(sc, ENA_SQ_DIR_TX,
		    ENA_SQ_PLACEMENT_DEV, txr->txr_cq_idx, txr->txr_ndescs,
		    NULL, &txr->txr_sq_idx, &txr->txr_db_off, &llq_off);
		if (error == 0) {
			txr->txr_llq_win = (caddr_t)bus_space_vaddr(
			    sc->sc_llq_memt, sc->sc_llq_memh) + llq_off;
			txr->txr_burst_left = sc->sc_llq_burst;
		}
	} else {
		error = ena_aq_create_sq(sc, ENA_SQ_DIR_TX,
		    ENA_SQ_PLACEMENT_HOST, txr->txr_cq_idx, txr->txr_ndescs,
		    &txr->txr_sq_ring, &txr->txr_sq_idx, &txr->txr_db_off,
		    NULL);
	}
	if (error != 0) {
		ena_aq_destroy_cq(sc, txr->txr_cq_idx);
		return (error);
	}

	/* unit is the queue index; single TX ring today. */
	txr->txr_kstat = ena_kstat_create(sc, "txq", 0, ena_kstat_txq_tpl,
	    nitems(ena_kstat_txq_tpl), &txr->txr_st);

	return (0);
}

static void
ena_txr_deinit(struct ena_softc *sc, struct ena_txr *txr)
{
	ena_kstat_destroy(&txr->txr_kstat);

	/* If the admin queue died these fail quietly; reset cleans up. */
	ena_aq_destroy_sq(sc, txr->txr_sq_idx, ENA_SQ_DIR_TX);
	ena_aq_destroy_cq(sc, txr->txr_cq_idx);

	ENA_DMA_SYNC(sc, &txr->txr_cq_ring, BUS_DMASYNC_POSTREAD);
}

static int
ena_load_mbuf(bus_dma_tag_t dmat, bus_dmamap_t map, struct mbuf *m,
    int *defragged)
{
	*defragged = 0;

	switch (bus_dmamap_load_mbuf(dmat, map, m,
	    BUS_DMA_STREAMING | BUS_DMA_NOWAIT)) {
	case 0:
		return (0);
	case EFBIG:
		/* Too many segments; collapse and retry once. */
		*defragged = 1;
		if (m_defrag(m, M_DONTWAIT) == 0 &&
		    bus_dmamap_load_mbuf(dmat, map, m,
		    BUS_DMA_STREAMING | BUS_DMA_NOWAIT) == 0)
			return (0);
		break;
	}

	return (1);
}

/* The 16-bit req_id is split across the two TX control words. */
static inline void
ena_tx_req_id(uint32_t *len_ctrl, uint32_t *meta_ctrl, uint16_t req_id)
{
	*len_ctrl |= (req_id >> 10) << ENA_TXD_REQ_ID_HI_SHIFT;
	*meta_ctrl |= (uint32_t)(req_id & 0x3ff) << ENA_TXD_REQ_ID_LO_SHIFT;
}

/*
 * Host mode submission: one descriptor per DMA segment, written into
 * the SQ ring in RAM.  The first descriptor carries first|comp_req and
 * the req_id (the slot index), the last carries last, all carry the
 * phase.  header_length stays zero: the device parses headers itself.
 */
static unsigned int
ena_tx_submit_host(struct ena_txr *txr, struct ena_tx_slot *slot)
{
	struct ena_tx_desc *ring = ENA_DMA_KVA(&txr->txr_sq_ring);
	struct ena_tx_desc *txd;
	bus_dmamap_t map = slot->ets_map;
	uint32_t len_ctrl, meta_ctrl;
	uint16_t req_id = slot - txr->txr_slots;
	uint64_t addr;
	int i;

	for (i = 0; i < map->dm_nsegs; i++) {
		txd = &ring[txr->txr_prod & (txr->txr_ndescs - 1)];

		len_ctrl = map->dm_segs[i].ds_len & ENA_TXD_LEN_MASK;
		if (txr->txr_sq_phase)
			len_ctrl |= ENA_TXD_PHASE;
		meta_ctrl = 0;

		if (i == 0) {
			len_ctrl |= ENA_TXD_FIRST | ENA_TXD_COMP_REQ;
			ena_tx_req_id(&len_ctrl, &meta_ctrl, req_id);
		}
		if (i == map->dm_nsegs - 1)
			len_ctrl |= ENA_TXD_LAST;

		addr = map->dm_segs[i].ds_addr;
		htolem32(&txd->etd_len_ctrl, len_ctrl);
		htolem32(&txd->etd_meta_ctrl, meta_ctrl);
		htolem32(&txd->etd_addr_lo, addr);
		htolem32(&txd->etd_addr_hi_hdr,
		    ena_addr_hi(addr) & ENA_TXD_ADDR_HI_MASK);

		txr->txr_prod++;
		if ((txr->txr_prod & (txr->txr_ndescs - 1)) == 0)
			txr->txr_sq_phase ^= 1;
	}

	return (map->dm_nsegs);
}

/*
 * LLQ submission.  The whole packet becomes one or more entries of
 * the negotiated size, composed in a stack buffer and then copied
 * into the device window with 64-bit stores.  The first entry holds
 * the (mandatory with meta caching disabled) meta descriptor, the
 * first data descriptor and the pushed header bytes filling the rest
 * of the entry; if more descriptors are needed they continue in
 * follow-up entries, entry_size / 16 per entry.  Write-combining is
 * safe here because the device reads entries only after the doorbell;
 * an entry must never be touched again once its successor exists
 * (see docs/research/ena-llq.md).
 */

static void
ena_llq_flush(struct ena_txr *txr, uint64_t *entry)
{
	struct ena_softc *sc = txr->txr_sc;
	volatile uint64_t *dst = (volatile uint64_t *)(txr->txr_llq_win +
	    (txr->txr_prod & (txr->txr_ndescs - 1)) * sc->sc_llq_entry_size);
	unsigned int i;

	for (i = 0; i < sc->sc_llq_entry_size / 8; i++)
		dst[i] = entry[i];

	txr->txr_prod++;
	if ((txr->txr_prod & (txr->txr_ndescs - 1)) == 0)
		txr->txr_sq_phase ^= 1;
}

static unsigned int
ena_tx_submit_llq(struct ena_txr *txr, struct ena_tx_slot *slot)
{
	struct ena_softc *sc = txr->txr_sc;
	uint64_t entry[ENA_LLQ_ENTRY_MAX / 8];
	struct ena_tx_desc *descs = (struct ena_tx_desc *)entry;
	unsigned int descs_entry = sc->sc_llq_entry_size /
	    sizeof(struct ena_tx_desc);
	struct ena_tx_desc *txd;
	bus_dmamap_t map = slot->ets_map;
	struct mbuf *m = slot->ets_m;
	uint32_t len_ctrl, meta_ctrl, hi_hdr;
	uint16_t req_id = slot - txr->txr_slots;
	uint64_t addr;
	unsigned int units = 0, di = 0, cap = ENA_LLQ_DESCS_BEFORE_HDR;
	unsigned int push, skip, seglen, ndescs, need;
	int i;

	/*
	 * Doorbells may only happen on packet boundaries, so make sure
	 * the whole packet fits into the remaining burst budget before
	 * writing anything.  dm_nsegs overestimates the descriptor
	 * count when the pushed header swallows whole segments, which
	 * errs on the safe side.
	 */
	if (sc->sc_llq_burst != 0) {
		ndescs = (sc->sc_llq_meta ? 1 : 0) + map->dm_nsegs;
		need = 1;
		if (ndescs > ENA_LLQ_DESCS_BEFORE_HDR) {
			need += howmany(ndescs - ENA_LLQ_DESCS_BEFORE_HDR,
			    descs_entry);
		}
		if (txr->txr_burst_left < need)
			ena_tx_kick(txr);
	}

	memset(entry, 0, sizeof(entry));

	/* Push the packet head right into the first entry. */
	push = MIN(m->m_pkthdr.len, sc->sc_tx_max_hdr);
	m_copydata(m, 0, push, (caddr_t)entry + ENA_LLQ_HDR_OFF);

	if (sc->sc_llq_meta) {
		txd = &descs[di++];
		len_ctrl = ENA_TXD_META_DESC | ENA_TXM_EXT_VALID |
		    ENA_TXM_ETH_META_TYPE | ENA_TXM_META_STORE |
		    ENA_TXD_FIRST;
		if (txr->txr_sq_phase)
			len_ctrl |= ENA_TXD_PHASE;
		htolem32(&txd->etd_len_ctrl, len_ctrl);
	}

	/*
	 * The first data descriptor covers the first chunk of payload
	 * beyond the pushed bytes - an empty chunk when the push
	 * swallowed the whole packet, in which case the descriptor
	 * still must exist to carry comp_req and the req_id.
	 */
	skip = push;
	addr = 0;
	seglen = 0;
	for (i = 0; i < map->dm_nsegs; i++) {
		if (skip < map->dm_segs[i].ds_len) {
			addr = map->dm_segs[i].ds_addr + skip;
			seglen = map->dm_segs[i].ds_len - skip;
			i++;
			break;
		}
		skip -= map->dm_segs[i].ds_len;
	}

	txd = &descs[di++];
	len_ctrl = (seglen & ENA_TXD_LEN_MASK) | ENA_TXD_COMP_REQ;
	if (!sc->sc_llq_meta)
		len_ctrl |= ENA_TXD_FIRST;
	if (txr->txr_sq_phase)
		len_ctrl |= ENA_TXD_PHASE;
	meta_ctrl = 0;
	ena_tx_req_id(&len_ctrl, &meta_ctrl, req_id);
	hi_hdr = (push << ENA_TXD_HDR_LEN_SHIFT) |
	    (ena_addr_hi(addr) & ENA_TXD_ADDR_HI_MASK);
	htolem32(&txd->etd_len_ctrl, len_ctrl);
	htolem32(&txd->etd_meta_ctrl, meta_ctrl);
	htolem32(&txd->etd_addr_lo, addr);
	htolem32(&txd->etd_addr_hi_hdr, hi_hdr);

	/* The remaining segments spill into continuation entries. */
	for (; i < map->dm_nsegs; i++) {
		addr = map->dm_segs[i].ds_addr;
		seglen = map->dm_segs[i].ds_len;

		if (di == cap) {
			ena_llq_flush(txr, entry);
			units++;
			memset(entry, 0, sizeof(entry));
			di = 0;
			cap = descs_entry;
		}
		txd = &descs[di++];

		len_ctrl = seglen & ENA_TXD_LEN_MASK;
		if (txr->txr_sq_phase)
			len_ctrl |= ENA_TXD_PHASE;
		/* The entry is pre-zeroed; only non-zero fields are set. */
		htolem32(&txd->etd_len_ctrl, len_ctrl);
		htolem32(&txd->etd_addr_lo, addr);
		htolem32(&txd->etd_addr_hi_hdr,
		    ena_addr_hi(addr) & ENA_TXD_ADDR_HI_MASK);
	}

	/* Mark the last descriptor of the packet, then flush. */
	htolem32(&descs[di - 1].etd_len_ctrl,
	    lemtoh32(&descs[di - 1].etd_len_ctrl) | ENA_TXD_LAST);
	ena_llq_flush(txr, entry);
	units++;

	if (sc->sc_llq_burst != 0)
		txr->txr_burst_left -= units;

	return (units);
}

/*
 * The other half of the submission seam: publish what the adapters
 * wrote.  For LLQ the membar orders the entry stores into the
 * write-combining window before the doorbell reaches the device; for
 * host mode the sync plays that role for the descriptor ring.  Every
 * doorbell refills the LLQ burst budget.
 */
static void
ena_tx_kick(struct ena_txr *txr)
{
	struct ena_softc *sc = txr->txr_sc;

	if (sc->sc_llq_on) {
		membar_producer();
		txr->txr_burst_left = sc->sc_llq_burst;
	} else
		ENA_DMA_SYNC(sc, &txr->txr_sq_ring, BUS_DMASYNC_PREWRITE);

	ena_wr(sc, txr->txr_db_off, txr->txr_prod);
	txr->txr_st.doorbells++;
}

static void
ena_start(struct ifqueue *ifq)
{
	struct ifnet *ifp = ifq->ifq_if;
	struct ena_softc *sc = ifp->if_softc;
	struct ena_txr *txr = sc->sc_txr;
	struct ena_tx_slot *slot;
	struct mbuf *m;
	unsigned int free, post = 0;
	int rv, defragged;

	if (!LINK_STATE_IS_UP(ifp->if_link_state)) {
		ifq_purge(ifq);
		return;
	}

	/*
	 * The host SQ ring is producer-only (completions land in the
	 * separate CQ ring), so it needs no POSTWRITE reclaim here;
	 * the PREWRITE before the doorbell lives in ena_tx_kick().
	 */
	for (;;) {
		/* One spare slot distinguishes a full ring from empty. */
		free = txr->txr_ndescs - 1 - txr->txr_used;
		if (free < ENA_TX_NSEGS) {
			txr->txr_st.stalls++;
			ifq_set_oactive(ifq);
			break;
		}

		slot = &txr->txr_slots[txr->txr_prod &
		    (txr->txr_ndescs - 1)];
		if (slot->ets_m != NULL) {
			/*
			 * The device completes packets in submission
			 * order (an assumption every ENA driver makes);
			 * a busy slot here means completions lag a
			 * whole ring behind - back off.
			 */
			txr->txr_st.stalls++;
			ifq_set_oactive(ifq);
			break;
		}

		m = ifq_dequeue(ifq);
		if (m == NULL)
			break;

		rv = ena_load_mbuf(sc->sc_dmat, slot->ets_map, m, &defragged);
		if (defragged)
			txr->txr_st.defrags++;
		if (rv != 0) {
			txr->txr_st.dma_map_err++;
			ifq->ifq_errors++;
			m_freem(m);
			continue;
		}

#if NBPFILTER > 0
		if (ifp->if_bpf != NULL)
			bpf_mtap_ether(ifp->if_bpf, m, BPF_DIRECTION_OUT);
#endif

		bus_dmamap_sync(sc->sc_dmat, slot->ets_map, 0,
		    slot->ets_map->dm_mapsize, BUS_DMASYNC_PREWRITE);

		slot->ets_m = m;
		slot->ets_ndescs = (*sc->sc_tx_submit)(txr, slot);
		atomic_add_int(&txr->txr_used, slot->ets_ndescs);
		txr->txr_st.packets++;
		txr->txr_st.bytes += m->m_pkthdr.len;
		post = 1;
	}

	if (post)
		ena_tx_kick(txr);
}

static void
ena_txeof(struct ena_txr *txr)
{
	struct ena_softc *sc = txr->txr_sc;
	struct ifnet *ifp = &sc->sc_ac.ac_if;
	struct ena_tx_cdesc *ring = ENA_DMA_KVA(&txr->txr_cq_ring);
	struct ena_tx_cdesc *txc;
	struct ena_tx_slot *slot;
	unsigned int mask = txr->txr_ndescs - 1;
	uint16_t req_id;
	int done = 0;

	/* One sync covers the whole batch; new arrivals raise a fresh intr. */
	ENA_DMA_SYNC(sc, &txr->txr_cq_ring, BUS_DMASYNC_POSTREAD);

	for (;;) {
		txc = &ring[txr->txr_cq_cons & mask];
		if ((txc->etc_flags & ENA_TXC_F_PHASE) != txr->txr_cq_phase)
			break;

		/* The phase bit is written last; order the rest after. */
		membar_consumer();

		if (ISSET(sc->sc_capabilities, ENA_CAP_CDESC_MBZ) &&
		    ISSET(txc->etc_flags, ENA_TXC_F_MBZ)) {
			txr->txr_st.desc_err++;
			printf("%s: corrupted tx completion\n", DEVNAME(sc));
			ena_reset_request(sc, ENA_RESET_GENERIC);
			break;
		}

		req_id = lemtoh16(&txc->etc_req_id);
		if (req_id >= txr->txr_ndescs ||
		    txr->txr_slots[req_id].ets_m == NULL) {
			txr->txr_st.bad_reqid++;
			printf("%s: invalid tx req_id %u\n", DEVNAME(sc),
			    req_id);
			ena_reset_request(sc, ENA_RESET_INV_TX_REQ_ID);
			break;
		}

		slot = &txr->txr_slots[req_id];
		bus_dmamap_sync(sc->sc_dmat, slot->ets_map, 0,
		    slot->ets_map->dm_mapsize, BUS_DMASYNC_POSTWRITE);
		bus_dmamap_unload(sc->sc_dmat, slot->ets_map);
		m_freem(slot->ets_m);
		slot->ets_m = NULL;
		atomic_sub_int(&txr->txr_used, slot->ets_ndescs);

		txr->txr_cq_cons++;
		if ((txr->txr_cq_cons & mask) == 0)
			txr->txr_cq_phase ^= 1;
		done = 1;
	}

	if (done && ifq_is_oactive(&ifp->if_snd))
		ifq_restart(&ifp->if_snd);
}

/*
 * TX stall sensor for the watchdog: true when descriptors are
 * outstanding but the completion cursor has not moved for several
 * ticks.  Owns the stall bookkeeping so the watchdog need not reach
 * into ring internals.
 */
static int
ena_txr_stalled(struct ena_txr *txr)
{
	if (txr->txr_used == 0 || txr->txr_cq_cons != txr->txr_last_cq_cons) {
		txr->txr_stuck = 0;
		txr->txr_last_cq_cons = txr->txr_cq_cons;
		return (0);
	}

	return (++txr->txr_stuck >= ENA_TX_STUCK_TIMEOUT);
}

/*
 * ifnet glue.
 */

static int
ena_up(struct ena_softc *sc)
{
	struct ifnet *ifp = &sc->sc_ac.ac_if;
	struct ena_rxr *rxr;
	struct ena_txr *txr;
	int error = EIO;

	rw_enter_write(&sc->sc_cfg_lock);
	/*
	 * sc_attached closes the last detach window: an in-flight
	 * recovery must not resurrect rings and the watchdog on an
	 * interface that detach already committed to tearing down.
	 */
	if (sc->sc_dead || !sc->sc_attached) {
		error = ENXIO;
		goto unlock;
	}
	/*
	 * While recovery is pending only the reset task itself may
	 * bring the interface up (it clears the flag first); anyone
	 * else slipping through ena_down's unlocked window would
	 * double-initialize the rings.
	 */
	if (sc->sc_reset_pending) {
		error = EBUSY;
		goto unlock;
	}

	/* Allocation first: it is the only step that is allowed to sleep. */
	rxr = ena_rxr_alloc(sc);
	if (rxr == NULL) {
		error = ENOMEM;
		goto unlock;
	}
	txr = ena_txr_alloc(sc);
	if (txr == NULL) {
		error = ENOMEM;
		goto free_rxr;
	}

	if (ena_rxr_init(sc, rxr) != 0)
		goto free_txr;
	if (ena_txr_init(sc, txr) != 0)
		goto deinit_rxr;

	sc->sc_rxr = rxr;
	sc->sc_txr = txr;
	sc->sc_tx_submit = sc->sc_llq_on ?
	    ena_tx_submit_llq : ena_tx_submit_host;

	sc->sc_keepalive_ts = getuptime();
	/* Re-baseline the device drop delta; a reset zeroed the counters. */
	sc->sc_stats_seen = 0;
	SET(ifp->if_flags, IFF_RUNNING);
	timeout_add_sec(&sc->sc_watchdog_tmo, 1);

	/* Arm the IO vector last, when there is something to handle. */
	ena_wr(sc, rxr->rxr_unmask_off,
	    ENA_INTR_CTRL_UNMASK | ENA_INTR_CTRL_NO_MOD);

	rw_exit_write(&sc->sc_cfg_lock);
	return (ENETRESET);

deinit_rxr:
	ena_rxr_deinit(sc, rxr);
free_txr:
	ena_txr_free(sc, txr);
free_rxr:
	ena_rxr_free(sc, rxr);
unlock:
	rw_exit_write(&sc->sc_cfg_lock);
	return (error);
}

static int
ena_down(struct ena_softc *sc)
{
	struct ifnet *ifp = &sc->sc_ac.ac_if;
	struct ena_rxr *rxr = sc->sc_rxr;
	struct ena_txr *txr = sc->sc_txr;

	rw_enter_write(&sc->sc_cfg_lock);
	CLR(ifp->if_flags, IFF_RUNNING);

	/*
	 * The teardown below waits on barriers and runs polled admin
	 * commands; don't make the whole stack wait with us.  The
	 * caller's NET_LOCK is re-taken after the config lock is
	 * dropped, so the lock order stays NET_LOCK -> cfg_lock.
	 */
	NET_UNLOCK();

	timeout_del_barrier(&sc->sc_watchdog_tmo);

	/* Barriers first, teardown second. */
	intr_barrier(sc->sc_ih_queue);
	ifq_barrier(&ifp->if_snd);
	timeout_del_barrier(&rxr->rxr_refill);

	ena_txr_deinit(sc, txr);
	ena_rxr_deinit(sc, rxr);
	sc->sc_rxr = NULL;
	sc->sc_txr = NULL;
	ena_rxr_free(sc, rxr);
	ena_txr_free(sc, txr);

	ifq_purge(&ifp->if_snd);
	ifq_clr_oactive(&ifp->if_snd);

	rw_exit_write(&sc->sc_cfg_lock);
	NET_LOCK();
	return (0);
}

static int
ena_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	struct ena_softc *sc = ifp->if_softc;
	struct ifreq *ifr = (struct ifreq *)data;
	int error = 0, s;

	s = splnet();

	switch (cmd) {
	case SIOCSIFADDR:
		SET(ifp->if_flags, IFF_UP);
		/* FALLTHROUGH */
	case SIOCSIFFLAGS:
		if (ISSET(ifp->if_flags, IFF_UP)) {
			if (ISSET(ifp->if_flags, IFF_RUNNING))
				error = ENETRESET;
			else
				error = ena_up(sc);
		} else {
			if (ISSET(ifp->if_flags, IFF_RUNNING))
				error = ena_down(sc);
		}
		break;
	case SIOCGIFMEDIA:
	case SIOCSIFMEDIA:
		error = ifmedia_ioctl(ifp, ifr, &sc->sc_media, cmd);
		break;
	case SIOCGIFRXR:
		/*
		 * IFF_RUNNING is cleared while NET_LOCK is still held,
		 * so under it the check also guarantees sc_rxr is not
		 * being torn down in ena_down's unlocked window.
		 */
		if (!ISSET(ifp->if_flags, IFF_RUNNING))
			error = ENOTTY;
		else {
			error = if_rxr_ioctl((struct if_rxrinfo *)
			    ifr->ifr_data, NULL, sc->sc_rx_buf_len,
			    &sc->sc_rxr->rxr_acct);
		}
		break;
	default:
		error = ether_ioctl(ifp, &sc->sc_ac, cmd, data);
		break;
	}

	if (error == ENETRESET) {
		/* Unicast/multicast filtering is done by the fabric. */
		error = 0;
	}

	splx(s);
	return (error);
}

static int
ena_media_change(struct ifnet *ifp)
{
	return (EOPNOTSUPP);
}

static void
ena_media_status(struct ifnet *ifp, struct ifmediareq *imr)
{
	struct ena_softc *sc = ifp->if_softc;

	imr->ifm_active = IFM_ETHER | IFM_AUTO;
	imr->ifm_status = IFM_AVALID;
	mtx_enter(&sc->sc_link_mtx);
	if (sc->sc_link_state == LINK_STATE_FULL_DUPLEX)
		SET(imr->ifm_status, IFM_ACTIVE);
	mtx_leave(&sc->sc_link_mtx);
}

/*
 * Reset machinery.
 *
 * Any context that catches the device misbehaving requests a reset
 * with an honest reason code; the heavy lifting happens in a task on
 * systq where sleeping is allowed.  Requests arriving while recovery
 * is pending are collapsed into it.  Recovery is a full pass: tear
 * down the IO side, reset the device, rebuild the control plane the
 * same way attach did, bring the IO side back.  If any step fails the
 * device is declared dead for good - honest degradation instead of a
 * reset loop.
 *
 * The watchdog below is the reset machinery's sensor: it ticks once a
 * second while the interface runs, checking that keepalive events
 * keep coming and that TX completions make progress.
 */
static void
ena_watchdog_tick(void *xsc)
{
	struct ena_softc *sc = xsc;
	struct ifnet *ifp = &sc->sc_ac.ac_if;
	struct ena_txr *txr = sc->sc_txr;

	if (!ISSET(ifp->if_flags, IFF_RUNNING))
		return;

	if (getuptime() - sc->sc_keepalive_ts > ENA_KEEPALIVE_TIMEOUT)
		ena_reset_request(sc, ENA_RESET_KEEP_ALIVE_TO);

	/*
	 * Debug hook for exercising the recovery path: setting the
	 * debug flag on the interface fires one forced reset.
	 * XXX remove before any upstream submission.
	 */
	if (ISSET(ifp->if_flags, IFF_DEBUG)) {
		if (!sc->sc_debug_reset) {
			sc->sc_debug_reset = 1;
			ena_reset_request(sc, ENA_RESET_USER_TRIGGER);
		}
	} else
		sc->sc_debug_reset = 0;

	if (txr != NULL && ena_txr_stalled(txr))
		ena_reset_request(sc, ENA_RESET_MISS_TX_CMPL);

	/*
	 * Refresh the device counters for the basic/eni kstats.  The work
	 * runs on systq so it can issue admin commands and stays serialized
	 * with the reset task; skip queuing it while recovery is pending so
	 * it never lands in the middle of one.
	 */
	if (!sc->sc_reset_pending)
		task_add(systq, &sc->sc_stats_task);

	timeout_add_sec(&sc->sc_watchdog_tmo, 1);
}

/*
 * Everything the driver knows about a reset reason: its name and which
 * per-reason counter it bumps.  Indexed by the ENA_RESET_* value (a
 * sparse hardware enum, so gaps zero-init to {NULL, 0}).  stat_off is an
 * offset into ena_device_stats (the same field ena_kstat_device_tpl
 * exports); 0 means no dedicated counter, safe as a sentinel because the
 * always-bumped `resets` sits at offset 0 and is never a reason's own
 * counter.  Only reasons that reach ena_reset_request() need a row; the
 * rest fall through to "unknown".
 */
static const struct {
	const char	*name;
	size_t		 stat_off;
} ena_reset_reasons[] = {
	[ENA_RESET_KEEP_ALIVE_TO] = { "keepalive timeout",
	    offsetof(struct ena_device_stats, reset_keepalive) },
	[ENA_RESET_ADMIN_TO]      = { "admin command timeout",
	    offsetof(struct ena_device_stats, reset_admin_to) },
	[ENA_RESET_MISS_TX_CMPL]  = { "tx completions missing",
	    offsetof(struct ena_device_stats, reset_miss_tx) },
	[ENA_RESET_INV_RX_REQ_ID] = { "invalid rx req_id",
	    offsetof(struct ena_device_stats, reset_rx_reqid) },
	[ENA_RESET_INV_TX_REQ_ID] = { "invalid tx req_id",
	    offsetof(struct ena_device_stats, reset_tx_reqid) },
	[ENA_RESET_USER_TRIGGER]  = { "user trigger",
	    offsetof(struct ena_device_stats, reset_user) },
	[ENA_RESET_GENERIC]       = { "device error",
	    offsetof(struct ena_device_stats, reset_dev_err) },
};

static const char *
ena_reset_reason_str(int reason)
{
	if (reason >= 0 && reason < (int)nitems(ena_reset_reasons) &&
	    ena_reset_reasons[reason].name != NULL)
		return (ena_reset_reasons[reason].name);
	return ("unknown");
}

static void
ena_reset_request(struct ena_softc *sc, int reason)
{
	/*
	 * Before the interface is attached (or once detach started)
	 * there is no recovery: attach handles its own errors, and a
	 * stray task would run on a torn-down softc.
	 */
	if (!sc->sc_attached || sc->sc_dead || sc->sc_reset_pending)
		return;
	sc->sc_reset_pending = 1;
	sc->sc_reset_reason = reason;

	printf("%s: device reset requested: %s\n", DEVNAME(sc),
	    ena_reset_reason_str(reason));
	task_add(systq, &sc->sc_reset_task);
}

static void
ena_reset_task(void *xsc)
{
	struct ena_softc *sc = xsc;
	struct ifnet *ifp = &sc->sc_ac.ac_if;
	uint8_t enaddr[ETHER_ADDR_LEN];
	int was_up = 0, link_state, mac_changed = 0;

	NET_LOCK();
	/* A task queued before detach closed the gate must not run. */
	if (sc->sc_dead || !sc->sc_attached) {
		NET_UNLOCK();
		return;
	}

	/*
	 * Count the reset here, not at the request site: this runs once
	 * per reset actually performed and is serialized on systq, so the
	 * counters stay single-writer and never double-count a reset that
	 * several contexts requested at the same time.
	 */
	sc->sc_dev_st.resets++;
	if (sc->sc_reset_reason >= 0 &&
	    sc->sc_reset_reason < (int)nitems(ena_reset_reasons) &&
	    ena_reset_reasons[sc->sc_reset_reason].stat_off != 0) {
		uint64_t *ctr = (uint64_t *)((char *)&sc->sc_dev_st +
		    ena_reset_reasons[sc->sc_reset_reason].stat_off);
		(*ctr)++;
	}

	link_state = ifp->if_link_state;

	/* A reset is a link loss, tell the stack up front. */
	ena_link_update(sc, LINK_STATE_DOWN);

	if (ISSET(ifp->if_flags, IFF_RUNNING)) {
		was_up = 1;
		ena_down(sc);
	}

	rw_enter_write(&sc->sc_cfg_lock);

	/* One ladder for attach and recovery: see ena_dev_init(). */
	if (ena_dev_init(sc, sc->sc_reset_reason, enaddr) != 0)
		goto failed;
	/* Applied after recovery: ifnewlladdr() re-enters our ioctl. */
	if (memcmp(enaddr, sc->sc_ac.ac_enaddr, ETHER_ADDR_LEN) != 0)
		mac_changed = 1;

	sc->sc_reset_pending = 0;
	rw_exit_write(&sc->sc_cfg_lock);

	ena_arm(sc);

	if (was_up && ena_up(sc) != ENETRESET)
		goto died;

	/*
	 * Restore the link state we clobbered: the device is not
	 * guaranteed to resend a link event after reset, and a fresh
	 * AENQ event will correct us if reality moved on.
	 */
	ena_link_update(sc, link_state);

	/*
	 * A changed address is applied last: ifnewlladdr() drives our
	 * own ioctl (a full down/up cycle), which must see recovery
	 * finished and no locks held beyond NET_LOCK.
	 */
	if (mac_changed) {
		printf("%s: address changed to %s\n", DEVNAME(sc),
		    ether_sprintf(enaddr));
		if_setlladdr(ifp, enaddr);
		ifnewlladdr(ifp);
	}

	NET_UNLOCK();
	printf("%s: device reset complete\n", DEVNAME(sc));
	return;

died:
	/* ena_up() failed with the lock released; retake it and join. */
	rw_enter_write(&sc->sc_cfg_lock);
failed:
	/* Reached with the config lock held; one epilogue for both. */
	sc->sc_dead = 1;
	sc->sc_reset_pending = 0;
	rw_exit_write(&sc->sc_cfg_lock);
	NET_UNLOCK();
	log(LOG_CRIT, "%s: device recovery failed, giving up\n",
	    DEVNAME(sc));
}
