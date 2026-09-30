/* SPDX-License-Identifier: GPL-2.0-only OR MIT */
/*
 * Mesa sensor transport, exported by apple-mesa.ko to the SEP driver.
 * The Rust side (sep/mesa.rs) declares these with matching values.
 */

#ifndef _APPLE_MESA_H
#define _APPLE_MESA_H

#include <linux/types.h>

struct device_node;
struct apple_mesa;

#define APPLE_MESA_POWER_OFF	0
#define APPLE_MESA_POWER_ON	1
#define APPLE_MESA_POWER_CYCLE	2

#define APPLE_MESA_XFER_DUPLEX	0	/* tx and rx, same length, one transfer */
#define APPLE_MESA_XFER_TX	1	/* transmit only, no rx buffer */
#define APPLE_MESA_XFER_TX_RX	2	/* tx, then rx, one CS assertion */

/*
 * The sensor bound at @np, or ERR_PTR(-EPROBE_DEFER) until it is. Takes a
 * device reference that is never dropped: like the SEP state, the handle
 * lives until reboot (the driver suppresses unbind).
 */
struct apple_mesa *apple_mesa_get(struct device_node *np);

int apple_mesa_power(struct apple_mesa *m, int op);

/* -ENODEV while the sensor is powered off. */
int apple_mesa_xfer(struct apple_mesa *m, int mode, const void *tx,
		    size_t tx_len, void *rx, size_t rx_len);

#endif
