// SPDX-License-Identifier: GPL-2.0-or-later

/***************************************************************************
 *   Copyright (C) 2013 Synapse Product Development                        *
 *   Andrey Smirnov <andrew.smironv@gmail.com>                             *
 *   Angus Gratton <gus@projectgus.com>                                    *
 *   Erdem U. Altunyurt <spamjunkeater@gmail.com>                          *
 *   Ben Wolsieffer <benwolsieffer@gmail.com>                              *
 ***************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "imp.h"
#include <helper/binarybuffer.h>
#include <helper/time_support.h>
#include <helper/types.h>
#include <target/algorithm.h>
#include <target/arm_adi_v5.h>
#include <target/armv7m.h>
#include <target/target_type.h>

#define NRF53_SECURE_REGS_OFFSET	0x10000000

enum nrf53_domain {
	NRF53_DOMAIN_APP,
	NRF53_DOMAIN_NET,
};

enum nrf53_periph_index {
	NRF53_PERIPH_FLASH,
	NRF53_PERIPH_FICR,
	NRF53_PERIPH_UICR,
	NRF53_PERIPH_SPU,
	NRF53_PERIPH_WDT,
	NRF53_PERIPH_NVMC,
	NRF53_PERIPH_INDEX_NUM,
};

enum nrf53_periph_mapping {
	/* Peripheral is unavailable */
	NRF53_PERIPH_MAPPING_UNAVAILABLE,
	/* No re-mapping */
	NRF53_PERIPH_MAPPING_NONE,
	/* Query security mapping from SPU */
	NRF53_PERIPH_MAPPING_QUERY_SPU,
};

struct nrf53_periph {
	enum nrf53_periph_mapping mapping;
	/* Base address, required if mapping != NRF53_PERIPH_MAPPING_UNAVAILABLE */
	target_addr_t base;
};

static const struct nrf53_periph nrf53_app_periphs[NRF53_PERIPH_INDEX_NUM] = {
	[NRF53_PERIPH_FLASH] = {
		.mapping = NRF53_PERIPH_MAPPING_NONE,
		.base = 0x00000000,
	},
	[NRF53_PERIPH_FICR] = {
		.mapping = NRF53_PERIPH_MAPPING_NONE,
		.base = 0x00FF0000,
	},
	[NRF53_PERIPH_UICR] = {
		.mapping = NRF53_PERIPH_MAPPING_NONE,
		.base = 0x00FF8000,
	},
	[NRF53_PERIPH_SPU] = {
		.mapping = NRF53_PERIPH_MAPPING_NONE,
		.base = 0x50003000,
	},
	[NRF53_PERIPH_WDT] = {
		.mapping = NRF53_PERIPH_MAPPING_QUERY_SPU,
		.base = 0x40018000,
	},
	[NRF53_PERIPH_NVMC] = {
		.mapping = NRF53_PERIPH_MAPPING_QUERY_SPU,
		.base = 0x40039000,
	},
};

static const struct nrf53_periph nrf53_net_periphs[NRF53_PERIPH_INDEX_NUM] = {
	[NRF53_PERIPH_FLASH] = {
		.mapping = NRF53_PERIPH_MAPPING_NONE,
		.base = 0x01000000,
	},
	[NRF53_PERIPH_FICR] = {
		.mapping = NRF53_PERIPH_MAPPING_NONE,
		.base = 0x01FF0000,
	},
	[NRF53_PERIPH_UICR] = {
		.mapping = NRF53_PERIPH_MAPPING_NONE,
		.base = 0x01FF8000,
	},
	[NRF53_PERIPH_WDT] = {
		.mapping = NRF53_PERIPH_MAPPING_NONE,
		.base = 0x4100B000,
	},
	[NRF53_PERIPH_NVMC] = {
		.mapping = NRF53_PERIPH_MAPPING_NONE,
		.base = 0x41080000,
	},
};

/* System Protection Unit Registers */
enum nrf53_spu_registers {
	NRF53_SPU_FLASHREGION0_PERM	= 0x600,
	NRF53_SPU_RAMREGION0_PERM	= 0x700,
	NRF53_SPU_PERIPHID0_PERM	= 0x800,
};

enum nrf53_spu_flashregion_perm_bits {
	NRF53_SPU_FLASHREGION_PERM_EXECUTE	= 1 << 0,
	NRF53_SPU_FLASHREGION_PERM_WRITE	= 1 << 1,
	NRF53_SPU_FLASHREGION_PERM_READ		= 1 << 2,
	NRF53_SPU_FLASHREGION_PERM_SECATTR	= 1 << 4,
	NRF53_SPU_FLASHREGION_PERM_LOCK		= 1 << 8,
};

enum nrf53_spu_periphid_perm_bits {
	NRF53_SPU_PERIPHID_PERM_SECUREMAPPING_MASK	= 0x3 << 0,
	NRF53_SPU_PERIPHID_PERM_SECUREMAPPING_NS	= 0x0 << 0,
	NRF53_SPU_PERIPHID_PERM_SECUREMAPPING_S		= 0x1 << 0,
	NRF53_SPU_PERIPHID_PERM_SECUREMAPPING_US	= 0x2 << 0,
	NRF53_SPU_PERIPHID_PERM_SECUREMAPPING_SPLIT	= 0x3 << 0,
	NRF53_SPU_PERIPHID_PERM_SECATTR				=   1 << 4,
};

/* Factory Information Configuration Registers */
enum nrf53_ficr_registers {
	NRF53_FICR_INFO_CONFIGID		= 0x200,
	NRF53_FICR_INFO_DEVICEID0		= 0x204,
	NRF53_FICR_INFO_DEVICEID1		= 0x208,
	NRF53_FICR_INFO_PART			= 0x20C,
	NRF53_FICR_INFO_VARIANT			= 0x210,
	NRF53_FICR_INFO_PACKAGE			= 0x214,
	NRF53_FICR_INFO_RAM				= 0x218,
	NRF53_FICR_INFO_FLASH			= 0x21C,
	NRF53_FICR_INFO_CODEPAGESIZE	= 0x220,
	NRF53_FICR_INFO_CODESIZE		= 0x224,
	NRF53_FICR_INFO_DEVICETYPE		= 0x228,

	NRF53_NET_FICR_ER0				= 0x280,
	NRF53_NET_FICR_ER1				= 0x284,
	NRF53_NET_FICR_ER2				= 0x288,
	NRF53_NET_FICR_ER3				= 0x28C,
	NRF53_NET_FICR_IR0				= 0x290,
	NRF53_NET_FICR_IR1				= 0x294,
	NRF53_NET_FICR_IR2				= 0x298,
	NRF53_NET_FICR_IR3				= 0x29C,
	NRF53_NET_FICR_DEVICEADDRTYPE	= 0x2A0,
	NRF53_NET_FICR_DEVICEADDR0		= 0x2A4,
	NRF53_NET_FICR_DEVICEADDR1		= 0x2A8,

	NRF53_APP_FICR_NFC_TAGHEADER0	= 0x450,
	NRF53_APP_FICR_NFC_TAGHEADER1	= 0x454,
	NRF53_APP_FICR_NFC_TAGHEADER2	= 0x458,
	NRF53_APP_FICR_NFC_TAGHEADER3	= 0x45C,
};

/* User Information Configuration Registers */
enum nrf53_uicr_registers {
	NRF53_UICR_APPROTECT			= 0x000,

	NRF53_NET_UICR_ERASEPROTECT		= 0x004,

	NRF53_APP_UICR_SECUREAPPROTECT	= 0x01C,
	NRF53_APP_UICR_ERASEPROTECT		= 0x020,
	NRF32_APP_UICR_TINSTANCE		= 0x028,
	NRF32_APP_UICR_NFCPINS			= 0x028,
};

#define NRF53_WDT_REFRESH_VALUE	0x6E524635

enum nrf53_wdt_registers {
	NRF53_WDT_RR0	= 0x600
};

enum nrf53_nvmc_registers {
	NRF53_NVMC_READY	= 0x400,
	NRF53_NVMC_CONFIG	= 0x504,
	NRF53_NVMC_ERASEALL	= 0x50C,
	NRF53_NVMC_CONFIGNS	= 0x584,
};

enum nrf53_nvmc_config_bits {
	NRF53_NVMC_CONFIG_REN	= 0x00,
	NRF53_NVMC_CONFIG_WEN	= 0x01,
	NRF53_NVMC_CONFIG_EEN	= 0x02,
	NRF53_NVMC_CONFIG_PEEN	= 0x02,
};

enum nrf53_ctrl_ap_registers {
	NRF53_CTRL_AP_RESET						= 0x000,
	NRF53_CTRL_AP_ERASEALL					= 0x004,
	NRF53_CTRL_AP_ERASEALLSTATUS			= 0x008,
	NRF53_CTRL_AP_APPROTECT_DISABLE			= 0x010,
	NRF53_CTRL_AP_SECUREAPPROTECT_DISABLE	= 0x014,
	NRF53_CTRL_AP_ERASEPROTECT_STATUS		= 0x018,
	NRF53_CTRL_AP_ERASEPROTECT_DISABLE		= 0x01C,
};

enum nrf53_approtect {
	/* Debug access allowed for all code */
	NRF53_APPROTECT_DISABLED,
	/* Debug access allowed for non-secure code */
	NRF53_APPROTECT_SECURE,
	/* Debug access disabled */
	NRF53_APPROTECT_FULL,
};

struct nrf53_ficr_info {
	uint32_t part;
	uint32_t variant;
	uint32_t package;
	uint32_t ram;
	uint32_t flash;
	uint32_t code_page_size;
	/* Number of pages in flash memory (not bytes) */
	uint32_t code_size;
};

struct nrf53_info {
	unsigned int refcount;

	struct nrf53_bank {
		struct nrf53_info *chip;
		bool probed;
	} bank[2];
	struct target *target;

	struct nrf53_base_addrs *addrs;
	struct nrf53_ficr_info ficr_info;
};

struct nrf53_device_package {
	uint32_t package;
	const char *code;
};

/* This table converts FICR INFO.PACKAGE to a two character code */
static const struct nrf53_device_package nrf53_packages_table[] = {
	{ 0x2000, "QK" },
	{ 0x2005, "CL" },
};

const struct flash_driver nrf53_flash;

static int nrf53_get_domain(struct target *target, enum nrf53_domain *domain)
{
	switch (target->coreid) {
	case 0:
		*domain = NRF53_DOMAIN_APP;
		return ERROR_OK;
	case 1:
		*domain = NRF53_DOMAIN_NET;
		return ERROR_OK;
	default:
		return ERROR_TARGET_INVALID;
	}
}

static int nrf53_periph_get_base(struct target *target, enum nrf53_periph_index index, target_addr_t *base);

static int nrf53_perif_is_secure(struct target *target, uint8_t periph_id, bool *secure)
{
	int res;
	enum nrf53_domain domain;
	uint32_t perm;

	res = nrf53_get_domain(target, &domain);
	if (res != ERROR_OK)
		return res;

	target_addr_t spu_base;
	res = nrf53_periph_get_base(target, NRF53_PERIPH_SPU, &spu_base);
	if (res != ERROR_OK)
		return res;

	switch (domain) {
	case NRF53_DOMAIN_APP:
		res = target_read_u32(target,
						spu_base + NRF53_SPU_PERIPHID0_PERM + periph_id * sizeof(uint32_t),
						&perm);
		if (res != ERROR_OK)
			return res;

		switch (perm & NRF53_SPU_PERIPHID_PERM_SECUREMAPPING_MASK) {
		case NRF53_SPU_PERIPHID_PERM_SECUREMAPPING_S:
			*secure = true;
			break;
		case NRF53_SPU_PERIPHID_PERM_SECUREMAPPING_NS:
			*secure = false;
			break;
		case NRF53_SPU_PERIPHID_PERM_SECUREMAPPING_US:
		case NRF53_SPU_PERIPHID_PERM_SECUREMAPPING_SPLIT:
			*secure = perm & NRF53_SPU_PERIPHID_PERM_SECATTR;
			break;
		}
		return ERROR_OK;
	case NRF53_DOMAIN_NET:
		*secure = false;
		return ERROR_OK;
	}

	assert(false);
}

static int nrf53_periph_get_base(struct target *target, enum nrf53_periph_index index, target_addr_t *base)
{
	assert(index < NRF53_PERIPH_INDEX_NUM);

	enum nrf53_domain domain;
	int res = nrf53_get_domain(target, &domain);
	if (res != ERROR_OK)
		return res;

	const struct nrf53_periph *periphs = NULL;
	switch (domain) {
	case NRF53_DOMAIN_APP:
		periphs = nrf53_app_periphs;
		break;
	case NRF53_DOMAIN_NET:
		periphs = nrf53_net_periphs;
		break;
	}
	assert(periphs);

	const struct nrf53_periph *periph = &periphs[index];

	switch (periph->mapping) {
	case NRF53_PERIPH_MAPPING_UNAVAILABLE:
		return ERROR_TARGET_RESOURCE_NOT_AVAILABLE;
	case NRF53_PERIPH_MAPPING_NONE:
		*base = periph->base;
		return ERROR_OK;
	case NRF53_PERIPH_MAPPING_QUERY_SPU: {
			uint8_t periph_id = (periph->base >> 12) & 0xFF;
			LOG_DEBUG("Base address: " TARGET_ADDR_FMT " -> periph ID: %u", periph->base, periph_id);
			bool secure;
			res = nrf53_perif_is_secure(target, periph_id, &secure);
			if (res != ERROR_OK)
				return res;

			if (secure)
				*base = periph->base | NRF53_SECURE_REGS_OFFSET;
			else
				*base = periph->base;

			return ERROR_OK;
		}
	}
	assert(false);
}

static bool nrf53_bank_is_probed(const struct flash_bank *bank)
{
	struct nrf53_bank *nbank = bank->driver_priv;

	assert(nbank);

	return nbank->probed;
}
static int nrf53_probe(struct flash_bank *bank);

static int nrf53_get_probed_chip_if_halted(struct flash_bank *bank, struct nrf53_info **chip)
{
	if (bank->target->state != TARGET_HALTED) {
		LOG_ERROR("Target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	struct nrf53_bank *nbank = bank->driver_priv;
	*chip = nbank->chip;

	if (nrf53_bank_is_probed(bank))
		return ERROR_OK;

	return nrf53_probe(bank);
}

static int nrf53_spu_get_flash_perm(struct nrf53_info *chip, target_addr_t addr, uint32_t *perm)
{
	int res;
	uint32_t region = addr / (16 * 1024);

	target_addr_t spu_base;
	res = nrf53_periph_get_base(chip->target, NRF53_PERIPH_SPU, &spu_base);
	if (res != ERROR_OK)
		return res;

	return target_read_u32(chip->target,
						spu_base + NRF53_SPU_FLASHREGION0_PERM + region * sizeof(uint32_t),
						perm);
}

static int nrf53_nvmc_get_config_register(struct nrf53_info *chip,
										target_addr_t addr,
										target_addr_t *config)
{
	int res;

	enum nrf53_domain domain;
	res = nrf53_get_domain(chip->target, &domain);
	if (res != ERROR_OK)
		return res;

	target_addr_t nvmc_base;
	res = nrf53_periph_get_base(chip->target, NRF53_PERIPH_NVMC, &nvmc_base);
	if (res != ERROR_OK)
		return res;

	/* Network core doesn't support CONFIGNS register */
	if (domain == NRF53_DOMAIN_NET) {
		*config = nvmc_base + NRF53_NVMC_CONFIG;
		return ERROR_OK;
	}

	uint32_t perm;
	res = nrf53_spu_get_flash_perm(chip, addr, &perm);
	if (res != ERROR_OK)
		return res;

	if (perm & NRF53_SPU_FLASHREGION_PERM_SECATTR)
		*config = (nvmc_base | NRF53_SECURE_REGS_OFFSET) + NRF53_NVMC_CONFIG;
	else
		*config = nvmc_base + NRF53_NVMC_CONFIGNS;

	return ERROR_OK;
}

static int nrf53_wait_for_nvmc(struct nrf53_info *chip)
{
	uint32_t ready;
	int res;
	int timeout_ms = 340;
	int64_t ts_start = timeval_ms();

	target_addr_t nvmc_base;
	res = nrf53_periph_get_base(chip->target, NRF53_PERIPH_NVMC, &nvmc_base);
	if (res != ERROR_OK)
		return res;

	do {
		res = target_read_u32(chip->target,
					nvmc_base + NRF53_NVMC_READY,
					&ready);
		if (res != ERROR_OK) {
			LOG_ERROR("Error waiting NVMC_READY: generic flash write/erase error (check protection etc...)");
			return res;
		}

		if (ready == 0x00000001)
			return ERROR_OK;

		keep_alive();

	} while ((timeval_ms()-ts_start) < timeout_ms);

	LOG_DEBUG("Timed out waiting for NVMC_READY");
	return ERROR_FLASH_BUSY;
}

static int nrf53_nvmc_erase_enable(struct nrf53_info *chip, target_addr_t config_register)
{
	int res;
	res = target_write_u32(chip->target,
					config_register,
					NRF53_NVMC_CONFIG_EEN);

	if (res != ERROR_OK) {
		LOG_ERROR("Failed to enable erase operation");
		return res;
	}

	/*
	  According to NVMC examples in Nordic SDK busy status must be
	  checked after writing to NVMC_CONFIG
	 */
	res = nrf53_wait_for_nvmc(chip);
	if (res != ERROR_OK)
		LOG_ERROR("Erase enable did not complete");

	return res;
}

static int nrf53_nvmc_write_enable(struct nrf53_info *chip, target_addr_t config_register)
{
	int res;
	res = target_write_u32(chip->target,
			       config_register,
			       NRF53_NVMC_CONFIG_WEN);

	if (res != ERROR_OK) {
		LOG_ERROR("Failed to enable write operation");
		return res;
	}

	/*
	  According to NVMC examples in Nordic SDK busy status must be
	  checked after writing to NVMC_CONFIG
	 */
	res = nrf53_wait_for_nvmc(chip);
	if (res != ERROR_OK)
		LOG_ERROR("Write enable did not complete");

	return res;
}

static int nrf53_nvmc_read_only(struct nrf53_info *chip, target_addr_t config_register)
{
	int res;
	res = target_write_u32(chip->target,
			       config_register,
			       NRF53_NVMC_CONFIG_REN);

	if (res != ERROR_OK) {
		LOG_ERROR("Failed to enable read-only operation");
		return res;
	}
	/*
	  According to NVMC examples in Nordic SDK busy status must be
	  checked after writing to NVMC_CONFIG
	 */
	res = nrf53_wait_for_nvmc(chip);
	if (res != ERROR_OK)
		LOG_ERROR("Read only enable did not complete");

	return res;
}

static int nrf53_nvmc_generic_erase(struct nrf53_info *chip,
			       target_addr_t erase_register, uint32_t erase_value)
{
	int res;

	target_addr_t config_register;
	res = nrf53_nvmc_get_config_register(chip, 0x0, &config_register);
	if (res != ERROR_OK)
		goto error;

	res = nrf53_nvmc_erase_enable(chip, config_register);
	if (res != ERROR_OK)
		goto error;

	res = target_write_u32(chip->target,
			       erase_register,
			       erase_value);
	if (res != ERROR_OK)
		goto set_read_only;

	res = nrf53_wait_for_nvmc(chip);
	if (res != ERROR_OK)
		goto set_read_only;

	return nrf53_nvmc_read_only(chip, config_register);

set_read_only:
	nrf53_nvmc_read_only(chip, config_register);
error:
	LOG_ERROR("Failed to erase reg: " TARGET_ADDR_FMT " val: 0x%08"PRIx32,
		  erase_register, erase_value);
	return ERROR_FAIL;
}

static bool nrf53_info_variant_to_str(uint32_t variant, char *bf)
{
	uint8_t b[4];

	h_u32_to_be(b, variant);
	if (isalnum(b[0]) && isalnum(b[1]) && isalnum(b[2]) && isalnum(b[3])) {
		memcpy(bf, b, 4);
		bf[4] = 0;
		return true;
	}

	strcpy(bf, "xxxx");
	return false;
}

static const char *nrf53_decode_info_package(uint32_t package)
{
	for (size_t i = 0; i < ARRAY_SIZE(nrf53_packages_table); i++) {
		if (nrf53_packages_table[i].package == package)
			return nrf53_packages_table[i].code;
	}
	return "xx";
}

static int get_nrf53_chip_type_str(const struct nrf53_info *chip, char *buf, unsigned int buf_size)
{
	int res;
	char variant[5];
	nrf53_info_variant_to_str(chip->ficr_info.variant, variant);
	res = snprintf(buf, buf_size, "nRF%" PRIx32 "-%s%.2s(build code: %s)",
			chip->ficr_info.part,
			nrf53_decode_info_package(chip->ficr_info.package),
			variant, &variant[2]);

	/* safety: */
	if (res <= 0 || (unsigned int)res >= buf_size) {
		LOG_ERROR("BUG: buffer problem in %s", __func__);
		return ERROR_FAIL;
	}
	return ERROR_OK;
}

static int nrf53_info(struct flash_bank *bank, struct command_invocation *cmd)
{
	struct nrf53_bank *nbank = bank->driver_priv;
	struct nrf53_info *chip = nbank->chip;

	char chip_type_str[256];
	if (get_nrf53_chip_type_str(chip, chip_type_str, sizeof(chip_type_str)) != ERROR_OK)
		return ERROR_FAIL;

	command_print_sameline(cmd, "%s %ukB Flash, %ukB RAM",
			chip_type_str, chip->ficr_info.flash, chip->ficr_info.ram);
	return ERROR_OK;
}

static int nrf53_read_ficr_info(struct nrf53_info *chip)
{
	int res;
	struct target *target = chip->target;

	target_addr_t ficr_base;
	res = nrf53_periph_get_base(target, NRF53_PERIPH_FICR, &ficr_base);
	if (res != ERROR_OK)
		return res;

	res = target_read_u32(target, ficr_base + NRF53_FICR_INFO_PART, &chip->ficr_info.part);
	if (res != ERROR_OK) {
		LOG_DEBUG("Couldn't read FICR INFO.PART register");
		return res;
	}

	switch (chip->ficr_info.part) {
	case 0x5340:
		break;
	default:
		LOG_DEBUG("FICR INFO likely not implemented. Invalid PART value 0x%08"
				PRIx32, chip->ficr_info.part);
		return ERROR_TARGET_RESOURCE_NOT_AVAILABLE;
	}

	res = target_read_u32(target, ficr_base + NRF53_FICR_INFO_VARIANT, &chip->ficr_info.variant);
	if (res != ERROR_OK)
		return res;

	res = target_read_u32(target, ficr_base + NRF53_FICR_INFO_PACKAGE, &chip->ficr_info.package);
	if (res != ERROR_OK)
		return res;

	res = target_read_u32(target, ficr_base + NRF53_FICR_INFO_RAM, &chip->ficr_info.ram);
	if (res != ERROR_OK)
		return res;

	res = target_read_u32(target, ficr_base + NRF53_FICR_INFO_FLASH, &chip->ficr_info.flash);
	if (res != ERROR_OK)
		return res;

	res = target_read_u32(target, ficr_base + NRF53_FICR_INFO_CODEPAGESIZE, &chip->ficr_info.code_page_size);
	if (res != ERROR_OK)
		return res;

	res = target_read_u32(target, ficr_base + NRF53_FICR_INFO_CODESIZE, &chip->ficr_info.code_size);
	if (res != ERROR_OK)
		return res;

	return ERROR_OK;
}

static int nrf53_probe(struct flash_bank *bank)
{
	int res;
	struct nrf53_bank *nbank = bank->driver_priv;
	struct nrf53_info *chip = nbank->chip;

	res = nrf53_read_ficr_info(chip);
	if (res != ERROR_OK)
		return res;

	if (!chip->bank[0].probed && !chip->bank[1].probed) {
		char chip_type_str[256];
		if (get_nrf53_chip_type_str(chip, chip_type_str, sizeof(chip_type_str)) != ERROR_OK)
			return ERROR_FAIL;
		LOG_INFO("%s %ukB Flash, %ukB RAM",
				chip_type_str,
				chip->ficr_info.flash,
				chip->ficr_info.ram);
	}

	free(bank->sectors);

	target_addr_t flash_base;
	res = nrf53_periph_get_base(chip->target, NRF53_PERIPH_FLASH, &flash_base);
	if (res != ERROR_OK)
		return res;

	if (bank->base == flash_base) {
		bank->num_sectors = chip->ficr_info.code_size;
		bank->size = chip->ficr_info.code_size * chip->ficr_info.code_page_size;

		bank->sectors = alloc_block_array(0, chip->ficr_info.code_page_size, chip->ficr_info.code_size);
		if (!bank->sectors)
			return ERROR_FAIL;

		chip->bank[0].probed = true;

	} else {
		bank->num_sectors = 1;
		bank->size = chip->ficr_info.code_page_size;

		bank->sectors = alloc_block_array(0, chip->ficr_info.code_page_size, chip->ficr_info.code_size);
		if (!bank->sectors)
			return ERROR_FAIL;

		bank->sectors[0].is_protected = 0;

		chip->bank[1].probed = true;
	}

	return ERROR_OK;
}

static int nrf53_auto_probe(struct flash_bank *bank)
{
	if (nrf53_bank_is_probed(bank))
		return ERROR_OK;

	return nrf53_probe(bank);
}

static int nrf53_erase_all(struct nrf53_info *chip)
{
	LOG_DEBUG("Erasing all non-volatile memory");
	return nrf53_nvmc_generic_erase(chip,
					NRF53_NVMC_ERASEALL,
					0x00000001);
}

static int nrf53_erase_page(struct flash_bank *bank,
							struct nrf53_info *chip,
							struct flash_sector *sector)
{
	LOG_DEBUG("Erasing page at 0x%"PRIx32, sector->offset);

	target_addr_t uicr_base;
	int res = nrf53_periph_get_base(chip->target, NRF53_PERIPH_UICR, &uicr_base);
	if (res != ERROR_OK)
		return res;

	if (bank->base == uicr_base) {
		LOG_WARNING("UICR may only be erased with mass erase");
		return ERROR_FLASH_OPER_UNSUPPORTED;
	}

	return nrf53_nvmc_generic_erase(chip, bank->base + sector->offset, 0xFFFFFFFF);
}

/* Start a low level flash write for the specified region */
static int nrf53_ll_flash_write(struct nrf53_info *chip, uint32_t address, const uint8_t *buffer, uint32_t bytes)
{
	struct target *target = chip->target;
	uint32_t buffer_size = 8192;
	struct working_area *write_algorithm;
	struct working_area *source;
	struct reg_param reg_params[6];
	struct armv7m_algorithm armv7m_info;
	int retval = ERROR_OK;

	static const uint8_t nrf53_flash_write_code[] = {
#include "../../../contrib/loaders/flash/nrf5/nrf5.inc"
	};

	LOG_DEBUG("Writing buffer to flash address=0x%"PRIx32" bytes=0x%"PRIx32, address, bytes);
	assert(bytes % 4 == 0);

	target_addr_t wdt_base;
	int res = nrf53_periph_get_base(target, NRF53_PERIPH_WDT, &wdt_base);
	if (res != ERROR_OK)
		return res;

	/* allocate working area with flash programming code */
	if (target_alloc_working_area(target, sizeof(nrf53_flash_write_code),
			&write_algorithm) != ERROR_OK) {
		LOG_WARNING("no working area available, falling back to slow memory writes");

		for (; bytes > 0; bytes -= 4) {
			retval = target_write_memory(target, address, 4, 1, buffer);
			if (retval != ERROR_OK)
				return retval;

			retval = nrf53_wait_for_nvmc(chip);
			if (retval != ERROR_OK)
				return retval;

			address += 4;
			buffer += 4;
		}

		return ERROR_OK;
	}

	retval = target_write_buffer(target, write_algorithm->address,
				sizeof(nrf53_flash_write_code),
				nrf53_flash_write_code);
	if (retval != ERROR_OK)
		return retval;

	/* memory buffer */
	while (target_alloc_working_area(target, buffer_size, &source) != ERROR_OK) {
		buffer_size /= 2;
		buffer_size &= ~3UL; /* Make sure it's 4 byte aligned */
		if (buffer_size <= 256) {
			/* free working area, write algorithm already allocated */
			target_free_working_area(target, write_algorithm);

			LOG_WARNING("No large enough working area available, can't do block memory writes");
			return ERROR_TARGET_RESOURCE_NOT_AVAILABLE;
		}
	}

	armv7m_info.common_magic = ARMV7M_COMMON_MAGIC;
	armv7m_info.core_mode = ARM_MODE_THREAD;

	init_reg_param(&reg_params[0], "r0", 32, PARAM_IN_OUT);	/* byte count */
	init_reg_param(&reg_params[1], "r1", 32, PARAM_OUT);	/* buffer start */
	init_reg_param(&reg_params[2], "r2", 32, PARAM_OUT);	/* buffer end */
	init_reg_param(&reg_params[3], "r3", 32, PARAM_IN_OUT);	/* target address */
	init_reg_param(&reg_params[4], "r6", 32, PARAM_OUT);	/* watchdog refresh value */
	init_reg_param(&reg_params[5], "r7", 32, PARAM_OUT);	/* watchdog refresh register address */

	buf_set_u32(reg_params[0].value, 0, 32, bytes);
	buf_set_u32(reg_params[1].value, 0, 32, source->address);
	buf_set_u32(reg_params[2].value, 0, 32, source->address + source->size);
	buf_set_u32(reg_params[3].value, 0, 32, address);
	buf_set_u32(reg_params[4].value, 0, 32, NRF53_WDT_REFRESH_VALUE);
	buf_set_u32(reg_params[5].value, 0, 32, wdt_base + NRF53_WDT_RR0);

	retval = target_run_flash_async_algorithm(target, buffer, bytes/4, 4,
			0, NULL,
			ARRAY_SIZE(reg_params), reg_params,
			source->address, source->size,
			write_algorithm->address, write_algorithm->address + sizeof(nrf53_flash_write_code) - 2,
			&armv7m_info);

	target_free_working_area(target, source);
	target_free_working_area(target, write_algorithm);

	destroy_reg_param(&reg_params[0]);
	destroy_reg_param(&reg_params[1]);
	destroy_reg_param(&reg_params[2]);
	destroy_reg_param(&reg_params[3]);
	destroy_reg_param(&reg_params[4]);
	destroy_reg_param(&reg_params[5]);

	return retval;
}

static int nrf53_write(struct flash_bank *bank, const uint8_t *buffer,
					uint32_t offset, uint32_t count)
{
	struct nrf53_info *chip;

	int res = nrf53_get_probed_chip_if_halted(bank, &chip);
	if (res != ERROR_OK)
		return res;

	assert(offset % 4 == 0);
	assert(count % 4 == 0);

	target_addr_t config_register;
	res = nrf53_nvmc_get_config_register(chip, 0x0, &config_register);
	if (res != ERROR_OK)
		return res;

	res = nrf53_nvmc_write_enable(chip, config_register);
	if (res != ERROR_OK)
		goto error;

	res = nrf53_ll_flash_write(chip, bank->base + offset, buffer, count);
	if (res != ERROR_OK)
		goto error;

	return nrf53_nvmc_read_only(chip, config_register);

error:
	nrf53_nvmc_read_only(chip, config_register);
	LOG_ERROR("Failed to write to nrf53 flash");
	return res;
}

static int nrf53_erase(struct flash_bank *bank, unsigned int first,
		unsigned int last)
{
	int res;
	struct nrf53_info *chip;

	res = nrf53_get_probed_chip_if_halted(bank, &chip);
	if (res != ERROR_OK)
		return res;

	/* For each sector to be erased */
	for (unsigned int s = first; s <= last && res == ERROR_OK; s++) {
		res = nrf53_erase_page(bank, chip, &bank->sectors[s]);
		if (res != ERROR_OK) {
			LOG_ERROR("Error erasing sector %d", s);
			return res;
		}
	}

	return ERROR_OK;
}

static void nrf53_free_driver_priv(struct flash_bank *bank)
{
	struct nrf53_bank *nbank = bank->driver_priv;
	struct nrf53_info *chip = nbank->chip;
	if (!chip)
		return;

	chip->refcount--;
	if (chip->refcount == 0) {
		free(chip);
		bank->driver_priv = NULL;
	}
}

static struct nrf53_info *nrf53_get_chip(struct target *target)
{
	struct flash_bank *bank_iter;

	/* iterate over nrf53 banks of same target */
	for (bank_iter = flash_bank_list(); bank_iter; bank_iter = bank_iter->next) {
		if (bank_iter->driver != &nrf53_flash)
			continue;

		if (bank_iter->target != target)
			continue;

		struct nrf53_bank *nbank = bank_iter->driver_priv;
		if (!nbank)
			continue;

		if (nbank->chip)
			return nbank->chip;
	}
	return NULL;
}

FLASH_BANK_COMMAND_HANDLER(nrf53_flash_bank_command)
{
	int res;
	struct nrf53_info *chip;
	struct nrf53_bank *nbank = NULL;

	target_addr_t flash_base;
	res = nrf53_periph_get_base(bank->target, NRF53_PERIPH_FLASH, &flash_base);
	if (res != ERROR_OK)
		return res;

	target_addr_t uicr_base;
	res = nrf53_periph_get_base(bank->target, NRF53_PERIPH_UICR, &uicr_base);
	if (res != ERROR_OK)
		return res;

	if (bank->base != flash_base && bank->base != uicr_base) {
		LOG_ERROR("Invalid bank address " TARGET_ADDR_FMT, bank->base);
		return ERROR_FAIL;
	}

	chip = nrf53_get_chip(bank->target);
	if (!chip) {
		/* Create a new chip */
		chip = calloc(1, sizeof(*chip));
		if (!chip)
			return ERROR_FAIL;

		chip->target = bank->target;
	}

	if (bank->base == flash_base) {
		nbank = &chip->bank[0];
	} else if (bank->base == uicr_base) {
		nbank = &chip->bank[1];
	}
	assert(nbank);

	chip->refcount++;
	nbank->chip = chip;
	nbank->probed = false;
	bank->driver_priv = nbank;
	bank->write_start_alignment = bank->write_end_alignment = 4;

	return ERROR_OK;
}

COMMAND_HANDLER(nrf53_handle_mass_erase_command)
{
	int res;
	struct flash_bank *bank = NULL;
	struct target *target = get_current_target(CMD_CTX);

	target_addr_t flash_base;
	res = nrf53_periph_get_base(target, NRF53_PERIPH_FLASH, &flash_base);
	if (res != ERROR_OK)
		return res;

	res = get_flash_bank_by_addr(target, flash_base, true, &bank);
	if (res != ERROR_OK)
		return res;

	assert(bank);

	struct nrf53_info *chip;

	res = nrf53_get_probed_chip_if_halted(bank, &chip);
	if (res != ERROR_OK)
		return res;

	res = nrf53_erase_all(chip);
	if (res == ERROR_OK) {
		LOG_INFO("Mass erase completed.");
	} else {
		LOG_ERROR("Failed to erase the chip");
	}

	return res;
}

COMMAND_HANDLER(nrf53_handle_info_command)
{
	int res;
	struct flash_bank *bank = NULL;
	struct target *target = get_current_target(CMD_CTX);

	target_addr_t flash_base;
	res = nrf53_periph_get_base(target, NRF53_PERIPH_FLASH, &flash_base);
	if (res != ERROR_OK)
		return res;

	res = get_flash_bank_by_addr(target, flash_base, true, &bank);
	if (res != ERROR_OK)
		return res;

	assert(bank);

	struct nrf53_info *chip;

	res = nrf53_get_probed_chip_if_halted(bank, &chip);
	if (res != ERROR_OK)
		return res;

	static struct {
		const uint32_t offset;
		uint32_t value;
	} ficr_common[] = {
		{ .offset = NRF53_FICR_INFO_CONFIGID		},
		{ .offset = NRF53_FICR_INFO_DEVICEID0		},
		{ .offset = NRF53_FICR_INFO_DEVICEID1		},
		{ .offset = NRF53_FICR_INFO_CODEPAGESIZE	},
		{ .offset = NRF53_FICR_INFO_CODESIZE		},
		{ .offset = NRF53_FICR_INFO_DEVICETYPE		},
	}, ficr_net[] = {
		{ .offset = NRF53_NET_FICR_ER0				},
		{ .offset = NRF53_NET_FICR_ER1				},
		{ .offset = NRF53_NET_FICR_ER2				},
		{ .offset = NRF53_NET_FICR_ER3				},
		{ .offset = NRF53_NET_FICR_IR0				},
		{ .offset = NRF53_NET_FICR_IR1				},
		{ .offset = NRF53_NET_FICR_IR2				},
		{ .offset = NRF53_NET_FICR_IR3				},
		{ .offset = NRF53_NET_FICR_DEVICEADDRTYPE	},
		{ .offset = NRF53_NET_FICR_DEVICEADDR0		},
		{ .offset = NRF53_NET_FICR_DEVICEADDR1		},
	}, uicr_common[] = {
		{ .offset = NRF53_UICR_APPROTECT			},
	}, uicr_app[] = {
		{ .offset = NRF53_APP_UICR_SECUREAPPROTECT	},
		{ .offset = NRF53_APP_UICR_ERASEPROTECT		},
		{ .offset = NRF32_APP_UICR_NFCPINS, 		},
	}, uicr_net[] = {
		{ .offset = NRF53_NET_UICR_ERASEPROTECT		},
	};

	enum nrf53_domain domain;

	res = nrf53_get_domain(target, &domain);
	if (res != ERROR_OK)
		return res;

	target_addr_t ficr_base;
	res = nrf53_periph_get_base(target, NRF53_PERIPH_FICR, &ficr_base);
	if (res != ERROR_OK)
		return res;

	for (size_t i = 0; i < ARRAY_SIZE(ficr_common); i++) {
		target_addr_t addr = ficr_base + ficr_common[i].offset;
		res = target_read_u32(chip->target, addr, &ficr_common[i].value);
		if (res != ERROR_OK) {
			LOG_ERROR("Couldn't read " TARGET_ADDR_FMT, addr);
			return res;
		}
	}

	if (domain == NRF53_DOMAIN_NET) {
		for (size_t i = 0; i < ARRAY_SIZE(ficr_net); i++) {
			target_addr_t addr = ficr_base + ficr_net[i].offset;
			res = target_read_u32(chip->target, addr, &ficr_net[i].value);
			if (res != ERROR_OK) {
				LOG_ERROR("Couldn't read " TARGET_ADDR_FMT, addr);
				return res;
			}
		}
	}

	target_addr_t uicr_base;
	res = nrf53_periph_get_base(target, NRF53_PERIPH_UICR, &uicr_base);
	if (res != ERROR_OK)
		return res;

	for (size_t i = 0; i < ARRAY_SIZE(uicr_common); i++) {
		target_addr_t addr = uicr_base + uicr_common[i].offset;
		res = target_read_u32(chip->target, addr, &uicr_common[i].value);
		if (res != ERROR_OK) {
			LOG_ERROR("Couldn't read " TARGET_ADDR_FMT, addr);
			return res;
		}
	}

	if (domain == NRF53_DOMAIN_APP) {
		for (size_t i = 0; i < ARRAY_SIZE(uicr_app); i++) {
			target_addr_t addr = uicr_base + uicr_app[i].offset;
			res = target_read_u32(chip->target, addr, &uicr_app[i].value);
			if (res != ERROR_OK) {
				LOG_ERROR("Couldn't read " TARGET_ADDR_FMT, addr);
				return res;
			}
		}
	}

	if (domain == NRF53_DOMAIN_NET) {
		for (size_t i = 0; i < ARRAY_SIZE(uicr_net); i++) {
			target_addr_t addr = uicr_base + uicr_net[i].offset;
			res = target_read_u32(chip->target, addr, &uicr_net[i].value);
			if (res != ERROR_OK) {
				LOG_ERROR("Couldn't read " TARGET_ADDR_FMT, addr);
				return res;
			}
		}
	}

	command_print(CMD,
		 "\n[factory information control block]\n\n"
		 "config id: %" PRIx32 "\n"
		 "device id: 0x%"PRIx32"%08"PRIx32"\n"
		 "code page size: %"PRIu32"B\n"
		 "code memory size: %"PRIu32"kB\n"
		 "device type: %s (0x%"PRIx32")",
		 ficr_common[0].value,
		 ficr_common[1].value, ficr_common[2].value,
		 ficr_common[3].value,
		 (ficr_common[4].value * ficr_common[3].value) / 1024,
		 ficr_common[5].value == 0xFFFFFFFF ? "FPGA" : "physical die", ficr_common[5].value);

	if (domain == NRF53_DOMAIN_NET) {
		command_print(CMD,
			"encryption root: 0x%08"PRIx32"%08"PRIx32"%08"PRIx32"%08"PRIx32"\n"
			"identity root: 0x%08"PRIx32"%08"PRIx32"%08"PRIx32"%08"PRIx32"\n"
			"device address type: %s (0x%"PRIx32")\n"
			"device address: 0x%"PRIx32"%08"PRIx32,
			ficr_net[0].value, ficr_net[1].value, ficr_net[2].value, ficr_net[3].value,
			ficr_net[4].value, ficr_net[5].value, ficr_net[6].value, ficr_net[7].value,
			ficr_net[8].value & 0x1 ? "random" : "public", ficr_net[8].value,
			ficr_net[9].value, ficr_net[10].value);
	}

	command_print(CMD,
		 "\n[user information control block]\n\n"
		 "debug access port: %s (0x%"PRIx32")",
		 uicr_common[0].value == 0x50FA50FA ? "unprotected" : "protected", uicr_common[0].value);

	if (domain == NRF53_DOMAIN_APP) {
		command_print(CMD,
			"secure debug access port: %s (0x%"PRIx32")\n"
			"flash erase: %s (0x%"PRIx32")\n"
			"NFC pins: %s (0x%"PRIx32")",
			uicr_app[0].value == 0x50FA50FA ? "unprotected" : "protected", uicr_app[0].value,
			uicr_app[1].value == 0xFFFFFFFF ? "unprotected" : "protected", uicr_app[1].value,
			uicr_app[2].value & 0x1 ? "enabled" : "disabled", uicr_app[2].value);
	}

	if (domain == NRF53_DOMAIN_NET) {
		command_print(CMD,
			"flash erase: %s (0x%"PRIx32")",
			uicr_net[0].value == 0xFFFFFFFF ? "unprotected" : "protected", uicr_net[0].value);
	}

	return ERROR_OK;
}

static const struct command_registration nrf53_exec_command_handlers[] = {
	{
		.name		= "mass_erase",
		.handler	= nrf53_handle_mass_erase_command,
		.mode		= COMMAND_EXEC,
		.help		= "Erase all flash contents of the chip.",
		.usage		= "",
	},
	{
		.name		= "info",
		.handler	= nrf53_handle_info_command,
		.mode		= COMMAND_EXEC,
		.help		= "Show FICR and UICR info.",
		.usage		= "",
	},
	COMMAND_REGISTRATION_DONE
};

static const struct command_registration nrf53_command_handlers[] = {
	{
		.name	= "nrf53",
		.mode	= COMMAND_ANY,
		.help	= "nrf53 flash command group",
		.usage	= "",
		.chain	= nrf53_exec_command_handlers,
	},
	COMMAND_REGISTRATION_DONE
};

const struct flash_driver nrf53_flash = {
	.name				= "nrf53",
	.commands			= nrf53_command_handlers,
	.flash_bank_command	= nrf53_flash_bank_command,
	.info				= nrf53_info,
	.erase				= nrf53_erase,
	.write				= nrf53_write,
	.read				= default_flash_read,
	.probe				= nrf53_probe,
	.auto_probe			= nrf53_auto_probe,
	.erase_check		= default_flash_blank_check,
	.free_driver_priv	= nrf53_free_driver_priv,
};