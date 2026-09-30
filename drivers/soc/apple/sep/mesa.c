// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Apple "Mesa" Touch ID sensor: SPI transport for the SEP driver.
 *
 * The sensor talks to the SEP; the AP only moves bytes between the two. This
 * driver owns the SPI device and the sensor's power line, and exports a small
 * transfer API to the SEP driver (apple-mesa.h). It has no userspace
 * interface of its own.
 *
 * All board facts come from the device tree: the power line (enable-gpios),
 * the SPI mode and speed, and the 20 ns chip-select setup/hold, which the
 * sensor needs applied by the controller in hardware. Probe refuses a bus
 * that would silently emulate that timing in software.
 *
 * Copyright (C) The Asahi Linux Contributors
 */

#include <linux/delay.h>
#include <linux/device.h>
#include <linux/gpio/consumer.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/spi/spi.h>

#include "apple-mesa.h"

/* J314s ADT /arm-io/spi2/mesa: power-on-delay 7, power-off-delay 10 (ms). */
#define MESA_ON_DELAY_MS	7
#define MESA_OFF_DELAY_MS	10

struct apple_mesa {
	struct spi_device *spi;
	struct gpio_desc *enable;
	struct mutex lock;	/* serialises transfers and power changes */
	bool powered;
};

static struct spi_driver apple_mesa_driver;

static void mesa_set_power(struct apple_mesa *m, bool on)
{
	gpiod_set_value_cansleep(m->enable, on);
	msleep(on ? MESA_ON_DELAY_MS : MESA_OFF_DELAY_MS);
	m->powered = on;
}

int apple_mesa_power(struct apple_mesa *m, int op)
{
	mutex_lock(&m->lock);
	switch (op) {
	case APPLE_MESA_POWER_OFF:
		mesa_set_power(m, false);
		break;
	case APPLE_MESA_POWER_ON:
		mesa_set_power(m, true);
		break;
	case APPLE_MESA_POWER_CYCLE:
		mesa_set_power(m, false);
		mesa_set_power(m, true);
		break;
	default:
		mutex_unlock(&m->lock);
		return -EINVAL;
	}
	mutex_unlock(&m->lock);
	return 0;
}
EXPORT_SYMBOL_GPL(apple_mesa_power);

int apple_mesa_xfer(struct apple_mesa *m, int mode, const void *tx,
		    size_t tx_len, void *rx, size_t rx_len)
{
	struct spi_transfer x[2] = {};
	int n, ret;

	if (!tx || !tx_len)
		return -EINVAL;

	switch (mode) {
	case APPLE_MESA_XFER_DUPLEX:
		/* One CS assertion, tx_len clocks; the caller pads tx. */
		if (!rx || rx_len != tx_len)
			return -EINVAL;
		x[0].tx_buf = tx;
		x[0].rx_buf = rx;
		x[0].len = tx_len;
		n = 1;
		break;
	case APPLE_MESA_XFER_TX:
		/*
		 * Transmit only, with no receive buffer at all: a simultaneous
		 * receive changes the pacing of long transfers and the sensor
		 * then rejects the patch blob (reference driver).
		 */
		if (rx || rx_len)
			return -EINVAL;
		x[0].tx_buf = tx;
		x[0].len = tx_len;
		n = 1;
		break;
	case APPLE_MESA_XFER_TX_RX:
		/* Command out, then read in, under one CS assertion. */
		if (!rx || !rx_len)
			return -EINVAL;
		x[0].tx_buf = tx;
		x[0].len = tx_len;
		x[1].rx_buf = rx;
		x[1].len = rx_len;
		n = 2;
		break;
	default:
		return -EINVAL;
	}

	mutex_lock(&m->lock);
	ret = m->powered ? spi_sync_transfer(m->spi, x, n) : -ENODEV;
	mutex_unlock(&m->lock);
	return ret;
}
EXPORT_SYMBOL_GPL(apple_mesa_xfer);

struct apple_mesa *apple_mesa_get(struct device_node *np)
{
	struct device *dev;
	struct apple_mesa *m;

	dev = bus_find_device_by_of_node(&spi_bus_type, np);
	if (!dev)
		return ERR_PTR(-EPROBE_DEFER);

	/* Only a device bound to this driver carries our drvdata. */
	device_lock(dev);
	m = dev->driver == &apple_mesa_driver.driver ? dev_get_drvdata(dev) : NULL;
	device_unlock(dev);
	if (!m) {
		put_device(dev);
		return ERR_PTR(-EPROBE_DEFER);
	}
	return m;
}
EXPORT_SYMBOL_GPL(apple_mesa_get);

static int apple_mesa_probe(struct spi_device *spi)
{
	struct device *dev = &spi->dev;
	struct apple_mesa *m;
	int ret;

	/*
	 * The sensor needs its CS setup/hold applied by the controller. The
	 * SPI core emulates the delays in software when the controller has
	 * no set_cs_timing hook or CS is a GPIO; that looks like success and
	 * the sensor stays silent, so refuse it here.
	 */
	if (!spi->controller->set_cs_timing || spi_get_csgpiod(spi, 0))
		return dev_err_probe(dev, -EINVAL,
				     "chip-select timing would be emulated in software; the sensor needs it in hardware\n");
	if (!spi->cs_setup.value || !spi->cs_hold.value)
		return dev_err_probe(dev, -EINVAL,
				     "spi-cs-setup-delay-ns / spi-cs-hold-delay-ns missing\n");

	m = devm_kzalloc(dev, sizeof(*m), GFP_KERNEL);
	if (!m)
		return -ENOMEM;
	m->spi = spi;
	mutex_init(&m->lock);

	/* Driven low (off) from the start: a bring-up begins with a power cycle. */
	m->enable = devm_gpiod_get(dev, "enable", GPIOD_OUT_LOW);
	if (IS_ERR(m->enable))
		return dev_err_probe(dev, PTR_ERR(m->enable), "no enable-gpios\n");

	spi->bits_per_word = 8;
	ret = spi_setup(spi);	/* also programs the hardware CS timing */
	if (ret)
		return dev_err_probe(dev, ret, "spi_setup failed\n");

	spi_set_drvdata(spi, m);
	dev_info(dev, "Mesa sensor: %u Hz, mode %u, CS setup/hold %u/%u ns (hardware)\n",
		 spi->max_speed_hz, (unsigned int)(spi->mode & (SPI_CPOL | SPI_CPHA)),
		 spi->cs_setup.value, spi->cs_hold.value);
	return 0;
}

static void apple_mesa_remove(struct spi_device *spi)
{
	struct apple_mesa *m = spi_get_drvdata(spi);

	mutex_lock(&m->lock);
	mesa_set_power(m, false);
	mutex_unlock(&m->lock);
}

static const struct of_device_id apple_mesa_of_match[] = {
	{ .compatible = "apple,mesa-fingerprint" },
	{}
};
MODULE_DEVICE_TABLE(of, apple_mesa_of_match);

static const struct spi_device_id apple_mesa_spi_ids[] = {
	{ "mesa-fingerprint" },
	{}
};
MODULE_DEVICE_TABLE(spi, apple_mesa_spi_ids);

static struct spi_driver apple_mesa_driver = {
	.driver = {
		.name = "apple-mesa",
		.of_match_table = apple_mesa_of_match,
		/*
		 * The SEP driver holds a pointer to this device for the rest
		 * of the boot; it must not be unbound from under it.
		 */
		.suppress_bind_attrs = true,
	},
	.id_table = apple_mesa_spi_ids,
	.probe = apple_mesa_probe,
	.remove = apple_mesa_remove,
};
module_spi_driver(apple_mesa_driver);

MODULE_DESCRIPTION("Apple Mesa (Touch ID) sensor SPI transport");
MODULE_LICENSE("Dual MIT/GPL");
