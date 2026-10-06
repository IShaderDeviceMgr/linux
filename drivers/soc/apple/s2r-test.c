// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * Apple T6000 suspend-to-RAM experiment (j314s-notes SLEEP.md §3.3).
 *
 * TESTING ONLY. Loading this module registers a "mem" (deep) suspend state
 * and makes it the default, so the next system suspend runs the experiment.
 * There is no resume path in Linux: either the machine resets (S2R entry
 * timed out), or it reaches S2R and a wake re-enters m1n1 at the locked RVBAR,
 * which this module arms through m1n1's resume record (/chosen
 * asahi,s2r-record) so m1n1's s2r_resume() runs and reboots through the
 * watchdog 90 s later. The module cannot be unloaded.
 *
 * What it does, after Linux has suspended every device:
 *   .prepare (after device suspend, device IRQs still on):
 *     SMC  MBSE = 'slpw'               (AppleSMCPMU, capability change)
 *     PMP (with aop=1 also AOP, with extra=1 DCP, SIO, NVMe if running):
 *          RTKit AP power state 0x201 (RTBuddy setPowerState(0) ->
 *          _signalApPowerGated)
 *     SMC  MBSE = 'slpa', AP power 0x201 (AppleSMC sleep action)
 *   .prepare_late (after the noirq phase):
 *     arm m1n1's resume record; park every secondary CPU in deep sleep
 *     (PMGR CPU stop request + ACC_OVRD/CYC_OVRD as XNU's
 *     arm64_prepare_for_sleep); on CPU 0: P-clusters off (enableCluster),
 *     AppleT6000PMGR::quiesceHW steps, all AIC interrupts masked
 *     (AppleInterruptControllerV2 quiesce action), startS2RTimer, deep WFI.
 * Register addresses are T6000 die 0 (see SLEEP.md §3.2).
 *
 * preflight=1: only send AP sleep then AP on to each coprocessor at load and
 * log the results; suspend is not touched. Safe to run on a live system.
 *
 * stop=N: locate a stall. At stage N the module turns the keyboard backlight
 * fully on (powering SIO and fpwm0 itself) and arms the watchdog for 5 s, then
 * spins. The backlight coming on means stage N was reached, independently of
 * whether the watchdog can still reset the machine at that point:
 *  99 at module load, on a running system (control: backlight + reset ~5 s)
 * Every stage (and each step of .prepare) is also printed to the dockchannel
 * UART (ADT /arm-io/dockchannel-uart, always-on block next to the AOP), so a
 * DebugUSB host running kisd sees how far the sequence got; bytes are dropped
 * if nobody drains the FIFO.
 * beacon_test=1: at load, log the SIO/fpwm0 PS and fpwm0 registers, run the
 * backlight writes only (no watchdog, no spin), log them again, and unload.
 *  10 .prepare entered (nothing sent)     12 PMP (and AOP) told AP sleep
 *  11 SMC MBSE = slpw                      13 SMC MBSE = slpa
 *   1 .prepare done (SMC told AP sleep)    4 quiesceHW done (before PLL)
 *   2 s2r_final on CPU 0, others parked    5 PLL off mode done
 *   3 P-clusters off                       6 AIC masked
 *   7 startS2RTimer written, then spin with a 120 s watchdog: a reset at
 *     ~30 s means the S2R entry timer still runs as under m1n1
 *   8 full sequence into deep WFI with a 120 s watchdog: a reset at 120 s
 *     means the watchdog kept counting (no S2R)
 */

#include <linux/bitfield.h>
#include <linux/bits.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/mfd/macsmc.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/smp.h>
#include <linux/soc/apple/rtkit.h>
#include <linux/suspend.h>
#include <asm/cputype.h>
#include <asm/sysreg.h>

#define RTKIT_AP_SLEEP 0x201
#define RTKIT_AP_ON    0x20

static bool preflight;
module_param(preflight, bool, 0444);
MODULE_PARM_DESC(preflight, "Only test AP power messages at load; do not arm suspend");
static bool aop;
module_param(aop, bool, 0444);
MODULE_PARM_DESC(aop, "Also send AP sleep to the AOP (needs its AFK endpoints quiet: it crashes on a report after AP sleep)");
static bool extra;
module_param(extra, bool, 0444);
MODULE_PARM_DESC(extra, "Also send AP sleep to DCP, SIO and NVMe if they are running");
static bool beacon_test;
module_param(beacon_test, bool, 0444);
MODULE_PARM_DESC(beacon_test, "Only test the keyboard-backlight beacon at load, logging registers");
static unsigned int stop;
module_param(stop, uint, 0444);
MODULE_PARM_DESC(stop, "Stage at which to arm the watchdog and spin (see the top of s2r-test.c)");

/* Coprocessors told that the AP sleeps, besides the SMC */
enum { IOP_ALWAYS, IOP_AOP, IOP_EXTRA };
static const struct {
	const char *compat;
	const char *name;
	int group;
} iops[] = {
	{"apple,t6000-pmp-v2", "PMP", IOP_ALWAYS},
	{"apple,t6000-aop", "AOP", IOP_AOP},
	{"apple,dcp", "DCP", IOP_EXTRA},
	{"apple,dcpext", "DCPEXT", IOP_EXTRA},
	{"apple,sio", "SIO", IOP_EXTRA},
	{"apple,nvme-ans2", "ANS", IOP_EXTRA},
};
static u32 iops_asleep; /* bit i: iops[i] was told AP sleep */

/* PMGR, T6000 die 0 */
#define CPU_START       0x28e0d4000 /* pmgr reg 0 + 0x54000; +0 = stop request */
#define CLUSTER_CTL     0x28e098000 /* reg group 2: + 4 * physical cluster */
#define PMGR0           0x28e080000 /* regmap 0 */
#define PS_AFR          0x1e8
#define SEP_PG          0x4c200
#define SOC_EAST        0x28e580000 /* regmap 2 */
#define PS_SIO          0x180
#define PS_SIO_CPU      0x188
#define CLKGEN          0x28e038000 /* regmap 0x3f + 0x38000 */
#define PLL_OFF_MODE    0x28e224000 /* regmap 0x37 */
#define MINIPMGR_S2R    0x2925c4000
#define AIC_MASK_SET    0x28e106400 /* AIC2 die 0, 128 words, write 1 = mask */
#define PS_FPWM0        0x190       /* in SOC_EAST, child of PS_SIO */
#define FPWM0           0x39b030000 /* kbd_backlight, 24 MHz, pwm-apple.c */
#define DOCKCHANNEL     0x292528000 /* + m1n1 dockchannel_uart.c offsets */
#define DC_TX8          0x4004
#define DC_TX_FREE      0x4014
#define WDT             0x2922b0000 /* m1n1 wdt.c: COUNT 0x10, ALARM 0x14, CTL 0x1c */

#define PS_TARGET       GENMASK(3, 0)
#define PS_ACTUAL       GENMASK(7, 4)
#define PS_AUTO_ENABLE  BIT(28)
#define QUIESCE_TIMEOUT 192000 /* us, quiesceHW's 0x2ee00 */

/* Apple CPU sleep controls (m1n1 cpu_regs.h) */
#define SYS_CYC_OVRD    sys_reg(3, 5, 15, 5, 0)
#define SYS_ACC_OVRD    sys_reg(3, 5, 15, 6, 0)

/* m1n1 s2r.c struct s2r_record */
#define S2R_MAGIC       0x5332522d74657374UL
#define REC_MAGIC       0x00
#define REC_MODE        0x08
#define REC_ARMED       0x10
#define REC_FAILED      0x38
#define FAIL_SLPW       BIT(4)
#define FAIL_SLPA       BIT(5)
#define FAIL_APPWR      BIT(6)
#define FAIL_PMP        BIT(8) /* any of iops[] */

static void __iomem *cpu_start, *cluster_ctl, *pmgr0, *soc_east, *clkgen,
	*pll, *minipmgr, *aic_mask_set, *wdt, *fpwm, *dc;
static void *rec;
static u32 failed;

/* Reset the machine @seconds from now (24 MHz reference), as m1n1 wdt_arm() */
static void wdt_arm(u32 seconds)
{
	writel(seconds * 24000000, wdt + 0x14);
	writel(0, wdt + 0x10);
	writel(4, wdt + 0x1c);
}

/* Dockchannel UART output; drops a byte if the FIFO stays full ~1 ms */
static void dc_putc(char c)
{
	int i;

	for (i = 0; i < 1000 && !readl(dc + DC_TX_FREE); i++)
		udelay(1);
	if (i < 1000)
		writel(c, dc + DC_TX8);
}

static __printf(1, 2) void dc_printf(const char *fmt, ...)
{
	char buf[96];
	va_list ap;
	int i;

	va_start(ap, fmt);
	vscnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	for (i = 0; buf[i]; i++) {
		if (buf[i] == '\n')
			dc_putc('\r');
		dc_putc(buf[i]);
	}
}

static void ps_on(void __iomem *reg)
{
	u32 v;

	writel(readl(reg) | PS_TARGET, reg);
	readl_poll_timeout_atomic(reg, v, (v & PS_ACTUAL) == PS_ACTUAL, 1, QUIESCE_TIMEOUT);
}

/* Keyboard backlight fully on, as pwm-apple.c apple_pwm_apply() */
static void beacon(void)
{
	ps_on(soc_east + PS_SIO);
	ps_on(soc_east + PS_FPWM0);
	writel(959, fpwm + 0x1c);	/* on cycles */
	writel(1, fpwm + 0x18);		/* off cycles */
	writel(BIT(0) | BIT(14) | BIT(5), fpwm);	/* enable, output enable, update */
}

static void beacon_dump(const char *when)
{
	int i;

	pr_info("s2r-test: %s: PS sio %#010x fpwm0 %#010x\n", when,
		readl(soc_east + PS_SIO), readl(soc_east + PS_FPWM0));
	for (i = 0; i < 0x20; i += 4)
		pr_info("s2r-test: %s: fpwm0+%#04x = %#010x\n", when, i, readl(fpwm + i));
}

/* stop=N: prove stage N was reached (keyboard backlight, watchdog reset) */
static void stage(unsigned int n)
{
	dc_printf("s2r: stage %u (CPU %d, failed=%#x)\n", n, raw_smp_processor_id(), failed);
	if (stop != n)
		return;
	local_irq_disable();
	beacon();
	dc_printf("s2r: stop=%u: spinning, watchdog armed\n", n);
	wdt_arm(n == 7 ? 120 : 5);
	for (;;)
		cpu_relax();
}

static struct device *find_dev(const char *compat)
{
	struct device_node *np = of_find_compatible_node(NULL, NULL, compat);
	struct platform_device *pdev;

	if (!np)
		return NULL;
	pdev = of_find_device_by_node(np);
	of_node_put(np);
	return pdev ? &pdev->dev : NULL;
}

/* Send @state to every coprocessor in iops[]; returns a bitmask of failures */
static u32 iops_ap_power(unsigned int state)
{
	u32 fail = 0;
	int i;

	for (i = 0; i < ARRAY_SIZE(iops); i++) {
		struct device *dev;
		struct apple_rtkit *rtk;
		int ret;

		if ((iops[i].group == IOP_AOP && !aop) || (iops[i].group == IOP_EXTRA && !extra))
			continue;
		dev = find_dev(iops[i].compat);
		rtk = dev ? apple_rtkit_find(dev) : NULL;
		if (!rtk) {
			pr_info("s2r-test: %s: no RTKit instance\n", iops[i].name);
			continue;
		}
		if (state == RTKIT_AP_ON) {
			/* is_running() is false while the AP state is sleep */
			if (!(iops_asleep & BIT(i)))
				continue;
		} else if (!apple_rtkit_is_running(rtk)) {
			pr_info("s2r-test: %s: not running, skipped\n", iops[i].name);
			continue;
		}
		ret = apple_rtkit_set_ap_power(rtk, state);
		pr_info("s2r-test: %s: AP power %#x: %d\n", iops[i].name, state, ret);
		if (ret)
			fail |= BIT(i);
		else if (state == RTKIT_AP_SLEEP)
			iops_asleep |= BIT(i);
		else
			iops_asleep &= ~BIT(i);
	}
	return fail;
}

static struct apple_smc *find_smc(void)
{
	struct device *dev = find_dev("apple,smc");

	return dev ? dev_get_drvdata(dev) : NULL;
}

static int s2r_prepare(void)
{
	struct apple_smc *smc = find_smc();

	if (!smc) {
		pr_err("s2r-test: no SMC\n");
		return -ENODEV;
	}
	stage(10);

	if (apple_smc_write_u32(smc, SMC_KEY(MBSE), SMC_KEY(slpw)))
		failed |= FAIL_SLPW;
	stage(11);

	if (iops_ap_power(RTKIT_AP_SLEEP))
		failed |= FAIL_PMP;
	stage(12);

	if (apple_smc_write_u32(smc, SMC_KEY(MBSE), SMC_KEY(slpa)))
		failed |= FAIL_SLPA;
	stage(13);
	if (apple_rtkit_set_ap_power(smc->rtk, RTKIT_AP_SLEEP))
		failed |= FAIL_APPWR;

	pr_info("s2r-test: SMC slpw/slpa/AP sleep done, failed=%#x\n", failed);
	stage(1);
	return 0;
}

/* XNU arm64_prepare_for_sleep(deep) / m1n1 cpu_sleep(true) */
static void __noreturn deep_sleep(void)
{
	u64 acc = read_sysreg_s(SYS_ACC_OVRD);
	u64 cyc = read_sysreg_s(SYS_CYC_OVRD);

	acc &= ~GENMASK(16, 15);
	acc |= (3UL << 13) | (2UL << 15) | (3UL << 17) | (3UL << 25) | BIT(32) | BIT(34);
	write_sysreg_s(acc, SYS_ACC_OVRD);

	cyc &= ~(3UL << 24);
	cyc |= (3UL << 24) | BIT(0);
	write_sysreg_s(cyc, SYS_CYC_OVRD);

	for (;;) {
		dsb(sy);
		isb();
		wfi();
	}
}

static void s2r_park(void *unused)
{
	u64 mpidr = read_cpuid_mpidr();
	u32 cluster = MPIDR_AFFINITY_LEVEL(mpidr, 1);
	u32 core = MPIDR_AFFINITY_LEVEL(mpidr, 0);

	local_irq_disable();
	writel(BIT(4 * cluster + core), cpu_start);
	deep_sleep();
}

static void ps_wait(void __iomem *reg, u32 mask, u32 val)
{
	u32 v;

	readl_poll_timeout_atomic(reg, v, (v & mask) == val, 1, QUIESCE_TIMEOUT);
}

static void pll_off_mode(void)
{
	u32 v;

	writel((readl(pll) & ~GENMASK(5, 3)) | (3 << 3), pll);
	writel(readl(pll) | BIT(1), pll);
	writel(readl(pll) & ~BIT(0), pll);
	readl_poll_timeout_atomic(pll, v, !(v & BIT(31)), 1, QUIESCE_TIMEOUT);
}

/* Runs on CPU 0 with every other CPU parked or parking */
static void __noreturn s2r_final(void *unused)
{
	static const u32 clkgen_regs[] = {0x164, 0x16c, 0x168, 0x15c, 0x170};
	void __iomem *sio[] = {soc_east + PS_SIO, soc_east + PS_SIO_CPU};
	int i;

	local_irq_disable();
	mdelay(50);
	stage(2);

	/* enableCluster(c, false) for the P-clusters */
	for (i = 1; i <= 2; i++)
		writel(readl(cluster_ctl + 4 * i) & ~PS_TARGET, cluster_ctl + 4 * i);
	mdelay(10);
	stage(3);

	/* AppleT6000PMGR::quiesceHW() */
	writel(0, pmgr0 + PS_AFR);
	ps_wait(pmgr0 + PS_AFR, PS_ACTUAL, 0);
	for (i = 0; i < 2; i++) {
		u32 v = readl(sio[i]);

		writel(v & ~PS_AUTO_ENABLE, sio[i]);
		ps_wait(sio[i], PS_ACTUAL, FIELD_PREP(PS_ACTUAL, v & PS_TARGET));
	}
	writel(readl(pmgr0 + SEP_PG) & ~BIT(2), pmgr0 + SEP_PG);
	for (i = 0; i < ARRAY_SIZE(clkgen_regs); i++) {
		void __iomem *reg = clkgen + clkgen_regs[i];

		writel((readl(reg) & 0x70ffffff) | 0x80000000, reg);
		ps_wait(reg, BIT(30), 0);
	}
	stage(4);
	pll_off_mode();
	pll_off_mode();
	stage(5);

	for (i = 0; i < 128; i++)
		writel(0xffffffff, aic_mask_set + 4 * i);
	stage(6);

	if (stop == 8)
		wdt_arm(120);
	writel(1, minipmgr); /* startS2RTimer() */
	stage(7);
	deep_sleep();
}

static int s2r_prepare_late(void)
{
	int self = get_cpu();
	cpumask_t others;
	int i;

	if (rec) {
		WRITE_ONCE(*(u32 *)(rec + REC_FAILED), failed);
		WRITE_ONCE(*(u64 *)(rec + REC_MODE), 1);
		WRITE_ONCE(*(u64 *)(rec + REC_MAGIC), S2R_MAGIC);
		WRITE_ONCE(*(u64 *)(rec + REC_ARMED), 1);
		/* cacheable mapping: push the record to DRAM, m1n1 reads it with the MMU off */
		for (i = 0; i < 0x100; i += 64)
			asm volatile("dc civac, %0" : : "r"(rec + i) : "memory");
		dsb(sy);
	}

	pr_info("s2r-test: going down from CPU %d\n", self);

	cpumask_copy(&others, cpu_online_mask);
	cpumask_clear_cpu(self, &others);
	cpumask_clear_cpu(0, &others);
	smp_call_function_many(&others, s2r_park, NULL, false);

	if (self == 0)
		s2r_final(NULL);

	smp_call_function_single(0, (smp_call_func_t)s2r_final, NULL, false);
	s2r_park(NULL);
	return 0; /* not reached */
}

static int s2r_enter(suspend_state_t state)
{
	return -EINVAL; /* never reached */
}

static const struct platform_suspend_ops s2r_ops = {
	.valid = suspend_valid_only_mem,
	.prepare = s2r_prepare,
	.prepare_late = s2r_prepare_late,
	.enter = s2r_enter,
};

static int __init s2r_init(void)
{
	struct device_node *chosen = of_find_node_by_path("/chosen");
	u64 rec_addr = 0;

	if (!of_machine_is_compatible("apple,t6000"))
		return -ENODEV;

	if (preflight) {
		struct apple_smc *smc = find_smc();
		int ret = -ENODEV;

		pr_info("s2r-test: preflight: AP sleep then AP on, suspend not armed\n");
		iops_ap_power(RTKIT_AP_SLEEP);
		iops_ap_power(RTKIT_AP_ON);
		if (smc) {
			ret = apple_rtkit_set_ap_power(smc->rtk, RTKIT_AP_SLEEP);
			pr_info("s2r-test: SMC: AP power %#x: %d\n", RTKIT_AP_SLEEP, ret);
			ret = apple_rtkit_set_ap_power(smc->rtk, RTKIT_AP_ON);
			pr_info("s2r-test: SMC: AP power %#x: %d\n", RTKIT_AP_ON, ret);
		}
		return -EAGAIN; /* do not stay loaded */
	}

	if (chosen && !of_property_read_u64(chosen, "asahi,s2r-record", &rec_addr))
		rec = memremap(rec_addr, 0x100, MEMREMAP_WB);
	of_node_put(chosen);
	if (!rec)
		pr_warn("s2r-test: no m1n1 resume record; a wake will restart m1n1\n");

	cpu_start = ioremap(CPU_START, 4);
	cluster_ctl = ioremap(CLUSTER_CTL, 0x10);
	pmgr0 = ioremap(PMGR0, 0x80000);
	soc_east = ioremap(SOC_EAST, 0x1000);
	clkgen = ioremap(CLKGEN, 0x1000);
	pll = ioremap(PLL_OFF_MODE, 4);
	minipmgr = ioremap(MINIPMGR_S2R, 4);
	aic_mask_set = ioremap(AIC_MASK_SET, 0x200);
	wdt = ioremap(WDT, 0x20);
	fpwm = ioremap(FPWM0, 0x20);
	dc = ioremap(DOCKCHANNEL, 0x4030);
	if (!fpwm || !dc || !cpu_start || !cluster_ctl || !pmgr0 || !soc_east || !clkgen || !pll || !minipmgr ||
	    !aic_mask_set || !wdt)
		return -ENOMEM;

	dc_printf("\ns2r-test: loaded (stop=%u aop=%d extra=%d)\n", stop, aop, extra);

	if (beacon_test) {
		beacon_dump("before");
		beacon();
		beacon_dump("after");
		return -EAGAIN;
	}

	stage(99);
	suspend_set_ops(&s2r_ops);
	pr_warn("s2r-test: ARMED: the next suspend runs the S2R experiment and does not resume into Linux (stop=%u)\n",
		stop);
	return 0;
}
module_init(s2r_init);

MODULE_DESCRIPTION("Apple T6000 S2R experiment (testing only)");
MODULE_LICENSE("Dual MIT/GPL");
