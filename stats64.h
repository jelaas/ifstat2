#include <linux/types.h>

struct ifstats64 {
	__u64	rx_packets;		/* total packets received	*/
	__u64	tx_packets;		/* total packets transmitted	*/
	__u64	rx_bytes;		/* total bytes received 	*/
	__u64	tx_bytes;		/* total bytes transmitted	*/
	__u64	rx_errors;		/* bad packets received		*/
	__u64	tx_errors;		/* packet transmit problems	*/
	__u64	rx_dropped;		/* no space in linux buffers	*/
	__u64	tx_dropped;		/* no space available in linux	*/
	__u64	multicast;		/* multicast packets received	*/
	__u64	collisions;

	/* detailed rx_errors: */
	__u64	rx_length_errors;
	__u64	rx_over_errors;		/* receiver ring buff overflow	*/
	__u64	rx_crc_errors;		/* recved pkt with crc error	*/
	__u64	rx_frame_errors;	/* recv'd frame alignment error */
	__u64	rx_fifo_errors;		/* recv'r fifo overrun		*/
	__u64	rx_missed_errors;	/* receiver missed packet	*/

	/* detailed tx_errors */
	__u64	tx_aborted_errors;
	__u64	tx_carrier_errors;
	__u64	tx_fifo_errors;
	__u64	tx_heartbeat_errors;
	__u64	tx_window_errors;

	/* for cslip etc */
	__u64	rx_compressed;
	__u64	tx_compressed;
};

int ifla_stats64_enum();
struct ifstats64 *ifla_stats64(void *rtadata);
