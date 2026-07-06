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

/*
 * AWS Elastic Network Adapter (ENA) hardware definitions, written from
 * the ENA specification headers published in the amzn-drivers repository.
 * The device is little-endian; all multi-byte fields in the structures
 * below must be accessed with htolem*()/lemtoh*().
 */

#ifndef _DEV_PCI_IF_ENAREG_H_
#define _DEV_PCI_IF_ENAREG_H_

/*
 * Control registers, BAR0.
 */

#define ENA_VERSION			0x00
#define  ENA_VERSION_MINOR(_v)		((_v) & 0xff)
#define  ENA_VERSION_MAJOR(_v)		(((_v) >> 8) & 0xff)
#define ENA_CONTROLLER_VERSION		0x04

#define ENA_CAPS			0x08
#define  ENA_CAPS_CONTIG_QUEUE_REQ	(1U << 0)
#define  ENA_CAPS_RESET_TIMEOUT(_c)	(((_c) >> 1) & 0x1f)	/* x100ms */
#define  ENA_CAPS_DMA_ADDR_WIDTH(_c)	(((_c) >> 8) & 0xff)	/* bits */
#define  ENA_CAPS_AQ_TIMEOUT(_c)	(((_c) >> 16) & 0xf)	/* x100ms */

#define ENA_AQ_BASE_LO			0x10	/* HI = LO + 4 for all rings */
#define ENA_AQ_BASE_HI			0x14
#define ENA_AQ_CAPS			0x18
#define ENA_ACQ_BASE_LO			0x20
#define ENA_ACQ_BASE_HI			0x24
#define ENA_ACQ_CAPS			0x28
#define ENA_AQ_DB			0x2c	/* absolute AQ tail counter */

#define ENA_AENQ_CAPS			0x34
#define ENA_AENQ_BASE_LO		0x38
#define ENA_AENQ_BASE_HI		0x3c
#define ENA_AENQ_HEAD_DB		0x40	/* absolute head counter */

/* Ring CAPS registers all encode depth in entries and entry size in bytes. */
#define ENA_RING_CAPS(_depth, _entsz)	((_depth) | ((_entsz) << 16))

#define ENA_INTR_MASK			0x4c
#define  ENA_INTR_MASK_ADMIN		(1U << 0) /* masks MSI-X vector 0 */

#define ENA_DEV_CTL			0x54
#define  ENA_DEV_CTL_DEV_RESET		(1U << 0)
/*
 * Reason codes 0..15 fit this 4-bit field; the extended field in bits
 * 27:24 (gated by ENA_CAP_EXT_RESET_REASONS) is only for codes >= 16,
 * which this driver never uses, so it never touches that capability.
 */
#define  ENA_DEV_CTL_RESET_REASON(_r)	(((uint32_t)(_r) & 0xf) << 28)

#define ENA_DEV_STS			0x58
#define  ENA_DEV_STS_READY		(1U << 0)
#define  ENA_DEV_STS_RESET_IN_PROGRESS	(1U << 3)
#define  ENA_DEV_STS_FATAL_ERROR	(1U << 5)

/* Response region for readless register reads, HI = LO + 4. */
#define ENA_MMIO_RESP_LO		0x60

/*
 * Reset reasons, written into ENA_DEV_CTL on device reset.  The device
 * reports them out-of-band (CloudWatch), so honest codes help debugging.
 */
#define ENA_RESET_NORMAL		0
#define ENA_RESET_KEEP_ALIVE_TO		1
#define ENA_RESET_ADMIN_TO		2
#define ENA_RESET_MISS_TX_CMPL		3
#define ENA_RESET_INV_RX_REQ_ID		4
#define ENA_RESET_INV_TX_REQ_ID		5
#define ENA_RESET_INIT_ERR		7
#define ENA_RESET_OS_TRIGGER		9
#define ENA_RESET_SHUTDOWN		11
#define ENA_RESET_USER_TRIGGER		12
#define ENA_RESET_GENERIC		13

/*
 * The device addresses host memory with 48-bit addresses passed in this
 * form.  The reserved word must be zero.
 */
struct ena_mem_addr {
	uint32_t		 ema_lo;
	uint16_t		 ema_hi;
	uint16_t		 ema_rsvd;
} __packed;

/*
 * Admin queue (AQ): 64-byte commands submitted by the driver.  The
 * completion for every command arrives in the admin completion queue
 * (ACQ) below.  Commands carry a rotating command id in bits 11:0 and
 * the producer's phase bit in flags.
 */

#define ENA_AQ_OP_CREATE_SQ		1
#define ENA_AQ_OP_DESTROY_SQ		2
#define ENA_AQ_OP_CREATE_CQ		3
#define ENA_AQ_OP_DESTROY_CQ		4
#define ENA_AQ_OP_GET_FEATURE		8
#define ENA_AQ_OP_SET_FEATURE		9
#define ENA_AQ_OP_GET_STATS		11

/* Command ids sit in bits 11:0 both in commands and completions. */
#define ENA_AQ_CMD_ID_MASK		0x0fff
#define ENA_AQD_F_PHASE			(1U << 0)
#define ENA_AQD_F_CTRL_DATA		(1U << 1)
#define ENA_AQD_F_CTRL_DATA_INDIRECT	(1U << 2)

/* Generic admin command layout. */
struct ena_aq_desc {
	uint16_t		 aqd_command_id;
	uint8_t			 aqd_opcode;
	uint8_t			 aqd_flags;
	uint32_t		 aqd_data[15];
} __packed __aligned(8);

/*
 * GET_FEATURE/SET_FEATURE command.  The payload is inline; the control
 * buffer fields exist for indirect commands which this driver never
 * issues.  afc_select 0 reads the current value.
 */
struct ena_aq_feat_cmd {
	uint16_t		 afc_command_id;
	uint8_t			 afc_opcode;
	uint8_t			 afc_flags;
	uint32_t		 afc_ctrl_len;
	struct ena_mem_addr	 afc_ctrl_addr;
	uint8_t			 afc_select;
	uint8_t			 afc_feature_id;
	uint8_t			 afc_feature_version;
	uint8_t			 afc_rsvd;
	uint8_t			 afc_data[44];
} __packed __aligned(8);

/*
 * IO queue creation.  A CQ must exist before the SQ that will feed it;
 * destruction goes the other way around.  The interesting parts of the
 * responses are register offsets: the SQ doorbell and the per-CQ
 * interrupt unmask register, both relative to BAR0.
 */

#define ENA_CREATE_CQ_INTR_MODE		(1U << 5)	/* ecq_caps1 */

struct ena_aq_create_cq_cmd {
	uint16_t		 ecq_command_id;
	uint8_t			 ecq_opcode;
	uint8_t			 ecq_flags;
	uint8_t			 ecq_caps1;
	uint8_t			 ecq_caps2;	/* 4:0 entry size, words */
	uint16_t		 ecq_depth;	/* power of two */
	uint32_t		 ecq_msix_vector;
	struct ena_mem_addr	 ecq_ba;
	uint8_t			 ecq_rsvd[44];
} __packed __aligned(8);

#define ENA_SQ_DIR_TX			(1U << 5)	/* esq_direction */
#define ENA_SQ_DIR_RX			(2U << 5)
#define ENA_SQ_PLACEMENT_HOST		1		/* esq_caps2 3:0 */
#define ENA_SQ_PLACEMENT_DEV		3		/* LLQ */
#define ENA_SQ_CONTIGUOUS		(1U << 0)	/* esq_caps3 */

struct ena_aq_create_sq_cmd {
	uint16_t		 esq_command_id;
	uint8_t			 esq_opcode;
	uint8_t			 esq_flags;
	uint8_t			 esq_direction;
	uint8_t			 esq_rsvd0;
	uint8_t			 esq_caps2;
	uint8_t			 esq_caps3;
	uint16_t		 esq_cq_idx;
	uint16_t		 esq_depth;	/* power of two */
	struct ena_mem_addr	 esq_ba;	/* host mode only */
	struct ena_mem_addr	 esq_head_writeback; /* unused */
	uint8_t			 esq_rsvd1[36];
} __packed __aligned(8);

struct ena_aq_destroy_sq_cmd {
	uint16_t		 edsq_command_id;
	uint8_t			 edsq_opcode;
	uint8_t			 edsq_flags;
	uint16_t		 edsq_idx;
	uint8_t			 edsq_direction; /* as in esq_direction */
	uint8_t			 edsq_rsvd0;
	uint8_t			 edsq_rsvd1[56];
} __packed __aligned(8);

struct ena_aq_destroy_cq_cmd {
	uint16_t		 edcq_command_id;
	uint8_t			 edcq_opcode;
	uint8_t			 edcq_flags;
	uint16_t		 edcq_idx;
	uint16_t		 edcq_rsvd0;
	uint8_t			 edcq_rsvd1[56];
} __packed __aligned(8);

/*
 * GET_STATS: device-side counters.  BASIC (traffic and drops) is
 * always available; ENI (traffic-shaping allowance counters) is gated
 * on the ENI_STATS capability.  Both payloads fit inline in the
 * 56-byte completion, so no control buffer is needed.  Scope ETH and
 * device_id "mine" ask for this device's aggregate counters.
 */
#define ENA_STATS_TYPE_BASIC		0
#define ENA_STATS_TYPE_ENI		2
#define ENA_STATS_SCOPE_ETH		1
#define ENA_STATS_DEVICE_MINE		0xffff	/* egs_device_id */

struct ena_aq_get_stats_cmd {
	uint16_t		 egs_command_id;
	uint8_t			 egs_opcode;
	uint8_t			 egs_flags;
	uint32_t		 egs_ctrl[3];	/* control buffer, unused */
	uint8_t			 egs_type;
	uint8_t			 egs_scope;
	uint16_t		 egs_rsvd0;
	uint16_t		 egs_queue_idx;
	uint16_t		 egs_device_id;
	uint8_t			 egs_rsvd1[40];
} __packed __aligned(8);

/* GET_STATS(BASIC) payload, overlaid on acqd_data.  64-bit lo/hi pairs. */
struct ena_basic_stats {
	uint32_t		 ebs_tx_bytes_lo;
	uint32_t		 ebs_tx_bytes_hi;
	uint32_t		 ebs_tx_pkts_lo;
	uint32_t		 ebs_tx_pkts_hi;
	uint32_t		 ebs_rx_bytes_lo;
	uint32_t		 ebs_rx_bytes_hi;
	uint32_t		 ebs_rx_pkts_lo;
	uint32_t		 ebs_rx_pkts_hi;
	uint32_t		 ebs_rx_drops_lo;
	uint32_t		 ebs_rx_drops_hi;
	uint32_t		 ebs_tx_drops_lo;
	uint32_t		 ebs_tx_drops_hi;
	uint32_t		 ebs_rx_overruns_lo;
	uint32_t		 ebs_rx_overruns_hi;
} __packed;

/* GET_STATS(ENI) payload, overlaid on acqd_data.  Native 64-bit. */
struct ena_eni_stats {
	uint64_t		 ees_bw_in_exceeded;
	uint64_t		 ees_bw_out_exceeded;
	uint64_t		 ees_pps_exceeded;
	uint64_t		 ees_conntrack_exceeded;
	uint64_t		 ees_linklocal_exceeded;
} __packed;

union ena_aq_cmd {
	struct ena_aq_desc		 aqc_desc;
	struct ena_aq_feat_cmd		 aqc_feat;
	struct ena_aq_create_cq_cmd	 aqc_create_cq;
	struct ena_aq_create_sq_cmd	 aqc_create_sq;
	struct ena_aq_destroy_cq_cmd	 aqc_destroy_cq;
	struct ena_aq_destroy_sq_cmd	 aqc_destroy_sq;
	struct ena_aq_get_stats_cmd	 aqc_get_stats;
};

/*
 * Admin completion queue (ACQ): 64-byte completions written by the
 * device.  acqd_command echoes the command id in bits 11:0, the phase
 * bit in flags tells fresh completions from stale ones.
 */

#define ENA_ACQ_RC_SUCCESS		0
#define ENA_ACQ_RC_RESOURCE_ALLOC_FAIL	1
#define ENA_ACQ_RC_BAD_OPCODE		2
#define ENA_ACQ_RC_UNSUPPORTED_OPCODE	3
#define ENA_ACQ_RC_MALFORMED_REQUEST	4
#define ENA_ACQ_RC_ILLEGAL_PARAMETER	5
#define ENA_ACQ_RC_UNKNOWN_ERROR	6
#define ENA_ACQ_RC_RESOURCE_BUSY	7

#define ENA_ACQD_F_PHASE		(1U << 0)

struct ena_acq_desc {
	uint16_t		 acqd_command;
	uint8_t			 acqd_status;
	uint8_t			 acqd_flags;
	uint16_t		 acqd_ext_status;
	uint16_t		 acqd_sq_head;
	uint32_t		 acqd_data[14];
} __packed __aligned(8);

/* CREATE_CQ/CREATE_SQ response payloads, overlaid on acqd_data. */
struct ena_create_cq_resp {
	uint16_t		 eccr_idx;
	uint16_t		 eccr_actual_depth;
	uint32_t		 eccr_numa_reg_off;
	uint32_t		 eccr_head_db_off;
	uint32_t		 eccr_intr_unmask_off;
} __packed;

struct ena_create_sq_resp {
	uint16_t		 ecsr_idx;
	uint16_t		 ecsr_rsvd;
	uint32_t		 ecsr_db_off;
	uint32_t		 ecsr_llq_desc_off;
	uint32_t		 ecsr_llq_hdr_off;
} __packed;

/*
 * Features: subcommands of GET_FEATURE/SET_FEATURE.  Support for a
 * feature is bit (1 << id) in the supported_features bitmap from
 * DEVICE_ATTRIBUTES; DEVICE_ATTRIBUTES itself is always supported.
 */

#define ENA_FEAT_DEVICE_ATTRIBUTES	1
#define ENA_FEAT_MAX_QUEUES_NUM		2
#define ENA_FEAT_HW_HINTS		3
#define ENA_FEAT_LLQ			4
#define ENA_FEAT_MAX_QUEUES_EXT		7
#define ENA_FEAT_STATELESS_OFFLOAD	11
#define ENA_FEAT_MTU			14
#define ENA_FEAT_AENQ_CONFIG		26
#define ENA_FEAT_LINK_CONFIG		27
#define ENA_FEAT_HOST_ATTR_CONFIG	28

/* DEVICE_ATTRIBUTES (get) */
struct ena_feat_device_attr {
	uint32_t		 eda_impl_id;
	uint32_t		 eda_device_version;
	uint32_t		 eda_supported_features;
	uint32_t		 eda_capabilities;
	uint32_t		 eda_phys_addr_width;
	uint32_t		 eda_virt_addr_width;
	uint8_t			 eda_mac_addr[6];
	uint16_t		 eda_flow_steering_max;
	uint32_t		 eda_max_mtu;
} __packed;

/* eda_capabilities bits */
#define ENA_CAP_ENI_STATS		(1U << 0)
#define ENA_CAP_EXT_RESET_REASONS	(1U << 3)
#define ENA_CAP_CDESC_MBZ		(1U << 4)

/* MAX_QUEUES_EXT (get, feature version 1) */
struct ena_feat_max_queues_ext {
	uint8_t			 emqe_version;
	uint8_t			 emqe_rsvd[3];
	uint32_t		 emqe_max_tx_sq_num;
	uint32_t		 emqe_max_tx_cq_num;
	uint32_t		 emqe_max_rx_sq_num;
	uint32_t		 emqe_max_rx_cq_num;
	uint32_t		 emqe_max_tx_sq_depth;
	uint32_t		 emqe_max_tx_cq_depth;
	uint32_t		 emqe_max_rx_sq_depth;
	uint32_t		 emqe_max_rx_cq_depth;
	uint32_t		 emqe_max_tx_header_size;
	uint16_t		 emqe_max_per_packet_tx_descs;
	uint16_t		 emqe_max_per_packet_rx_descs;
} __packed;

/* MAX_QUEUES_NUM (get, legacy fallback) */
struct ena_feat_max_queues {
	uint32_t		 emq_max_sq_num;
	uint32_t		 emq_max_sq_depth;
	uint32_t		 emq_max_cq_num;
	uint32_t		 emq_max_cq_depth;
	uint32_t		 emq_max_legacy_llq_num;
	uint32_t		 emq_max_legacy_llq_depth;
	uint32_t		 emq_max_header_size;
	uint16_t		 emq_max_packet_tx_descs;
	uint16_t		 emq_max_packet_rx_descs;
} __packed;

/* MTU (set), excludes L2 */
struct ena_feat_mtu {
	uint32_t		 emtu_mtu;
} __packed;

/* AENQ_CONFIG (get/set) */
struct ena_feat_aenq {
	uint32_t		 efa_supported_groups;
	uint32_t		 efa_enabled_groups;
} __packed;

/*
 * LLQ (get/set, feature version 1).  The supported/enabled pairs are
 * bitmasks whose bits are the enum values themselves: header location
 * inline = 0x1, entry size 128B = 0x1, two descriptors before the
 * header = 0x2, multiple-descs-per-entry stride = 0x2.  The accel
 * fields read as {supported flags, max burst bytes} and are written
 * as {enabled flags, zero}.
 */

#define ENA_LLQ_HDR_INLINE		0x1
#define ENA_LLQ_ENTRY_128		0x1
#define ENA_LLQ_ENTRY_256		0x4
#define ENA_LLQ_TWO_DESCS_BEFORE_HDR	0x2
#define ENA_LLQ_STRIDE_MULTIPLE		0x2

#define ENA_LLQ_ACCEL_DISABLE_META_CACHING	(1U << 0)
#define ENA_LLQ_ACCEL_LIMIT_TX_BURST		(1U << 1)

struct ena_feat_llq {
	uint32_t		 efl_max_num;
	uint32_t		 efl_max_depth;	/* in entries */
	uint16_t		 efl_hdr_supported;
	uint16_t		 efl_hdr_enabled;
	uint16_t		 efl_entry_size_supported;
	uint16_t		 efl_entry_size_enabled;
	uint16_t		 efl_descs_before_hdr_supported;
	uint16_t		 efl_descs_before_hdr_enabled;
	uint16_t		 efl_stride_supported;
	uint16_t		 efl_stride_enabled;
	uint8_t			 efl_feature_version;
	uint8_t			 efl_entry_size_recommended;
	uint16_t		 efl_max_wide_depth;
	uint16_t		 efl_accel_flags;
	uint16_t		 efl_accel_burst;
	uint32_t		 efl_accel_rsvd;
} __packed;

/* HOST_ATTR_CONFIG (set) */
struct ena_feat_host_attr {
	struct ena_mem_addr	 eha_os_info_ba;
	struct ena_mem_addr	 eha_debug_ba;
	uint32_t		 eha_debug_area_size;
} __packed;

/*
 * Host info page, handed to the device with HOST_ATTR_CONFIG.  Must be
 * a physically contiguous 4KB page and stay allocated while the device
 * is alive: firmware reads it after the command completes and is known
 * to change behaviour based on the contents, so this is effectively
 * mandatory (older firmware refused CREATE_CQ without it).
 */

#define ENA_HOST_OS_LINUX		1
#define ENA_HOST_OS_DPDK		3
#define ENA_HOST_OS_FREEBSD		4
#define ENA_HOST_OS_IPXE		5

#define ENA_HOST_SPEC_VERSION		0x0200	/* spec 2.0 */

struct ena_host_info {
	uint32_t		 ehi_os_type;
	char			 ehi_os_dist_str[128];
	uint32_t		 ehi_os_dist;
	char			 ehi_kernel_ver_str[32];
	uint32_t		 ehi_kernel_ver;
	uint32_t		 ehi_driver_version; /* maj | min<<8 | sub<<16 */
	uint32_t		 ehi_supported_net_features[2];
	uint16_t		 ehi_spec_version;
	uint16_t		 ehi_bdf;	/* fn 2:0, dev 7:3, bus 15:8 */
	uint16_t		 ehi_num_cpus;
	uint16_t		 ehi_rsvd;
	uint32_t		 ehi_driver_supported_features;
} __packed;

/*
 * Async event notification queue (AENQ): 64-byte events written by the
 * device into a host ring.  Which event groups are delivered is
 * negotiated with AENQ_CONFIG; the driver returns consumed entries by
 * writing the absolute head counter into ENA_AENQ_HEAD_DB.  Events of
 * enabled groups raise MSI-X vector 0.
 */

#define ENA_AENQ_GROUP_LINK_CHANGE	0
#define ENA_AENQ_GROUP_FATAL_ERROR	1
#define ENA_AENQ_GROUP_WARNING		2
#define ENA_AENQ_GROUP_NOTIFICATION	3
#define ENA_AENQ_GROUP_KEEP_ALIVE	4
#define ENA_AENQ_GROUP_BIT(_g)		(1U << (_g))

#define ENA_AENQD_F_PHASE		(1U << 0)

struct ena_aenq_link {
	uint32_t		 eal_flags;
#define ENA_AENQ_LINK_UP		(1U << 0)
} __packed;

/*
 * Keepalive events carry device-side drop counters as 32-bit halves.
 * The driver does not read them (it takes the same counters from
 * GET_STATS(BASIC) instead, on the stats task); this documents the
 * event's wire layout for reference only.
 */
struct ena_aenq_keepalive {
	uint32_t		 eak_rx_drops_lo;
	uint32_t		 eak_rx_drops_hi;
	uint32_t		 eak_tx_drops_lo;
	uint32_t		 eak_tx_drops_hi;
	uint32_t		 eak_rx_overruns_lo;
	uint32_t		 eak_rx_overruns_hi;
} __packed;

struct ena_aenq_desc {
	uint16_t		 ead_group;
	uint16_t		 ead_syndrome;
	uint8_t			 ead_flags;
	uint8_t			 ead_rsvd[3];
	uint32_t		 ead_ts_lo;
	uint32_t		 ead_ts_hi;
	union {
		uint32_t			 eadu_raw[12];
		struct ena_aenq_link		 eadu_link;
		struct ena_aenq_keepalive	 eadu_keepalive;
	}			 ead_u;
} __packed __aligned(8);

/*
 * RX data path.
 *
 * The RX SQ is filled with 16-byte buffer descriptors; every buffer is
 * its own transaction (first|last|comp_req on each).  Completions are
 * 16-byte entries; a received packet comes back as a chain of
 * completions marked first..last, one per buffer used.  With the
 * CDESC_MBZ capability the device promises the MBZ bits are zero -
 * anything else means a corrupted completion.
 */

#define ENA_RXD_CTRL_PHASE		(1U << 0)
#define ENA_RXD_CTRL_FIRST		(1U << 2)
#define ENA_RXD_CTRL_LAST		(1U << 3)
#define ENA_RXD_CTRL_COMP_REQ		(1U << 4)

struct ena_rx_desc {
	uint16_t		 erd_length;	/* 0 means 64KB */
	uint8_t			 erd_rsvd0;
	uint8_t			 erd_ctrl;
	uint16_t		 erd_req_id;
	uint16_t		 erd_rsvd1;
	uint32_t		 erd_addr_lo;
	uint16_t		 erd_addr_hi;
	uint16_t		 erd_rsvd2;
} __packed __aligned(8);

#define ENA_RXC_MBZ7			(1U << 7)
#define ENA_RXC_MBZ17			(1U << 17)
#define ENA_RXC_PHASE			(1U << 24)
#define ENA_RXC_FIRST			(1U << 26)
#define ENA_RXC_LAST			(1U << 27)

struct ena_rx_cdesc {
	uint32_t		 erc_status;
	uint16_t		 erc_length;
	uint16_t		 erc_req_id;
	uint32_t		 erc_hash;
	uint16_t		 erc_sub_qid;
	uint8_t			 erc_offset;	/* data start in buffer */
	uint8_t			 erc_rsvd;
} __packed __aligned(4);

/*
 * Per-CQ interrupt control register (offset from CREATE_CQ response).
 * Bits 14:0 and 29:15 are moderation delays which we never touch.
 */
#define ENA_INTR_CTRL_UNMASK		(1U << 30)
#define ENA_INTR_CTRL_NO_MOD		(1U << 31)

/*
 * TX data path.
 *
 * A packet occupies one 16-byte descriptor per DMA segment: the first
 * carries first|comp_req and the req_id (split between the two control
 * words), every descriptor carries the phase, the final one carries
 * last.  The 16-bit req_id is split: bits 9:0 live in etd_meta_ctrl
 * 31:22, bits 15:10 in etd_len_ctrl 21:16.  header_length is zero in
 * host mode - the device parses headers itself; LLQ gives the field a
 * different meaning (number of pushed bytes).
 *
 * With checksum offload disabled all checksum and DF control bits
 * stay zero: ena-com sets them only for packets that carry an offload
 * context, and the descriptors here mirror the reference byte for
 * byte.
 */

#define ENA_TXD_LEN_MASK		0xffff		/* etd_len_ctrl */
#define ENA_TXD_REQ_ID_HI_SHIFT		16		/* req_id 15:10 */
#define ENA_TXD_META_DESC		(1U << 23)
#define ENA_TXD_PHASE			(1U << 24)
#define ENA_TXD_FIRST			(1U << 26)
#define ENA_TXD_LAST			(1U << 27)
#define ENA_TXD_COMP_REQ		(1U << 28)

#define ENA_TXD_DF			(1U << 4)	/* etd_meta_ctrl */
#define ENA_TXD_L4_CSUM_PARTIAL		(1U << 17)
#define ENA_TXD_REQ_ID_LO_SHIFT		22		/* req_id 9:0 */

#define ENA_TXD_ADDR_HI_MASK		0xffff		/* etd_addr_hi_hdr */
#define ENA_TXD_HDR_LEN_SHIFT		24

struct ena_tx_desc {
	uint32_t		 etd_len_ctrl;
	uint32_t		 etd_meta_ctrl;
	uint32_t		 etd_addr_lo;
	uint32_t		 etd_addr_hi_hdr;
} __packed __aligned(8);

/*
 * TX meta descriptor: same 16 bytes, marked with ENA_TXD_META_DESC in
 * the first word.  With the disable-meta-caching accel mode the device
 * wants one in front of every packet; without offloads it is almost
 * empty.  The bit set below matches what ena_com_create_meta() writes.
 * The meta descriptor takes the first|phase bits of the packet; the
 * comp_req and req_id stay on the first data descriptor.
 */
#define ENA_TXM_EXT_VALID		(1U << 14)	/* etd_len_ctrl */
#define ENA_TXM_ETH_META_TYPE		(1U << 20)
#define ENA_TXM_META_STORE		(1U << 21)

/* One 8-byte completion per packet, carrying its req_id. */
#define ENA_TXC_F_PHASE			(1U << 0)
#define ENA_TXC_F_MBZ			(0x3U << 6)

struct ena_tx_cdesc {
	uint16_t		 etc_req_id;
	uint8_t			 etc_status;
	uint8_t			 etc_flags;
	uint16_t		 etc_sub_qid;
	uint16_t		 etc_sq_head;
} __packed __aligned(4);

#endif /* _DEV_PCI_IF_ENAREG_H_ */
