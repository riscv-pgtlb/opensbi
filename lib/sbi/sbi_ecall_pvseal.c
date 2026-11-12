/* Experimental single-hart QEMU virt sealing policy. Not a standard SBI ABI. */
#include <sbi/riscv_asm.h>
#include <sbi/riscv_encoding.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_domain.h>
#include <sbi/sbi_ecall.h>
#include <sbi/sbi_error.h>
#include <sbi/sbi_hart.h>
#include <sbi/sbi_hfence.h>
#include <sbi/sbi_platform.h>
#include <sbi/sbi_scratch.h>
#include <sbi/sbi_trap.h>
#include <sbi/pmp_virt_layout.h>

#define SEAL_EXT 0x0a000056UL
static bool sealed;

static void fatal(void)
{
	sbi_printf("PMP.Virt seal FATAL: remaining in M-mode\n");
	for (;;)
		__asm__ volatile("wfi");
}

static unsigned long cfg_read(unsigned int n)
{
	return (csr_read_num(CSR_PMPCFG0 + (n / 8) * 2) >>
		((n % 8) * 8)) & 0xff;
}

static void cfg_write(unsigned int n, unsigned long cfg)
{
	unsigned int csr = CSR_PMPCFG0 + (n / 8) * 2;
	unsigned int shift = (n % 8) * 8;
	unsigned long value = csr_read_num(csr);
	value = (value & ~(0xffUL << shift)) | (cfg << shift);
	csr_write_num(csr, value);
}

static bool entry_matches(unsigned int n, unsigned long cfg,
			  unsigned long addr)
{
	return cfg_read(n) == cfg &&
	       csr_read_num(CSR_PMPADDR0 + n) == addr;
}

static void apply_policy(void)
{
	unsigned int i;
	/* M-mode runs with MPRV cleared by the trap entry. Keep entries 0..6. */
	for (i = 7; i < 16; i++)
		cfg_write(i, 0);
	csr_write_num(CSR_PMPADDR0 + 7, PV_TEXT_START >> 2);
	csr_write_num(CSR_PMPADDR0 + 8, PV_TEXT_LIMIT >> 2);
	csr_write_num(CSR_PMPADDR0 + 9, PV_RO_START >> 2);
	csr_write_num(CSR_PMPADDR0 + 10, PV_RO_LIMIT >> 2);
	csr_write_num(CSR_PMPADDR0 + 11, PV_RAM_NAPOT);
	csr_write_num(CSR_PMPADDR0 + 12, ~0UL);
	cfg_write(8, PMP_A_TOR | PMP_R | PMP_X);
	cfg_write(10, PMP_A_TOR | PMP_R);
	cfg_write(11, PMP_A_NAPOT | PMP_R | PMP_W | PMP_VIRT);
	/* Unknown/MMIO space remains RW, never executable or delegated. */
	cfg_write(12, PMP_A_NAPOT | PMP_R | PMP_W);
	if (!entry_matches(7, 0, PV_TEXT_START >> 2) ||
	    !entry_matches(8, 0x0d, PV_TEXT_LIMIT >> 2) ||
	    !entry_matches(9, 0, PV_RO_START >> 2) ||
	    !entry_matches(10, 0x09, PV_RO_LIMIT >> 2) ||
	    !entry_matches(11, 0x5b, PV_RAM_NAPOT) ||
	    !entry_matches(12, 0x1b, ~0UL))
		fatal();
	for (i = 13; i < 16; i++) {
		if (cfg_read(i))
			fatal();
	}
	__asm__ volatile("sfence.vma zero, zero" ::: "memory");
	if (misa_extension('H'))
		__sbi_hfence_gvma_all();
	__asm__ volatile("fence.i" ::: "memory");
}

/* Called after normal PMP setup on warm paths, so they cannot undo sealing. */
void pmp_virt_seal_reapply(void)
{
	if (sealed)
		apply_policy();
}

static int preflight(void)
{
	struct sbi_scratch *s = sbi_scratch_thishart_ptr();
	unsigned long prot, base, order, limit;
	unsigned int i;
	if (sbi_platform_hart_count(sbi_platform_ptr(s)) != 1 ||
	    sbi_hart_pmp_count(s) != 16 ||
	    sbi_hart_pmp_log2gran(s) > 12 ||
	    sbi_hart_has_extension(s, SBI_HART_EXT_SMEPMP) ||
	    sbi_domain_thishart_ptr()->next_addr != 0x80200000UL)
		return SBI_ENOTSUPP;
	/* Match the measured generic-virt domain, never overwrite firmware rules. */
	for (i = 0; i < 7; i++) {
		if (pmp_get(i, &prot, &base, &order) || !(prot & PMP_A) ||
		    (prot & (PMP_L | PMP_VIRT)) || order >= 63)
			return SBI_EFAIL;
		limit = base + (1UL << order);
		if (base < PV_RAM_LIMIT && limit > 0x80200000UL)
			return SBI_EFAIL;
		/* Any region covering firmware must be inaccessible to S/U. */
		if (base < 0x80200000UL && limit > 0x80000000UL &&
		    (prot & (PMP_R | PMP_W | PMP_X)))
			return SBI_EFAIL;
	}
	if (pmp_get(7, &prot, &base, &order) || base || order != 64 ||
	    prot != (PMP_A_NAPOT | PMP_R | PMP_W | PMP_X))
		return SBI_EFAIL;
	for (i = 8; i < 16; i++) {
		if (cfg_read(i))
			return SBI_EFAIL;
	}
	return 0;
}

static int handle(unsigned long extid, unsigned long funcid,
		  struct sbi_trap_regs *regs, struct sbi_ecall_return *out)
{
	int rc;
	(void)extid;
	out->value = 0;
	/* Only host S-mode, and no address/permission arguments accepted. */
	if (((regs->mstatus & MSTATUS_MPP) >> MSTATUS_MPP_SHIFT) != PRV_S ||
	    (regs->mstatus & MSTATUS_MPV))
		return SBI_EDENIED;
	if (funcid != 0)
		return SBI_ENOTSUPP;
	if (regs->a0 || regs->a1 || regs->a2 || regs->a3 || regs->a4 || regs->a5)
		return SBI_EINVAL;
	if (sealed) {
		out->value = 1;
		return 0;
	}
	rc = preflight();
	if (rc) {
		sbi_printf("PMP.Virt seal preflight FAIL: %d\n", rc);
		return rc;
	}
	apply_policy();
	sealed = true;
	out->value = 1;
	sbi_printf("PMP.Virt SEALED: text=[0x%lx,0x%lx) rodata=[0x%lx,0x%lx) "
		   "RAM=RWVirt image=" PV_IMAGE_SHA "\n",
		   PV_TEXT_START, PV_TEXT_LIMIT, PV_RO_START, PV_RO_LIMIT);
	return 0;
}

struct sbi_ecall_extension ecall_pvseal;
static int register_extension(void)
{
	return sbi_ecall_register_extension(&ecall_pvseal);
}

struct sbi_ecall_extension ecall_pvseal = {
	.name = "pvseal",
	.extid_start = SEAL_EXT,
	.extid_end = SEAL_EXT,
	.experimental = true,
	.register_extensions = register_extension,
	.handle = handle,
};
