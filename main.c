/*
 * Copyright (C) Foundries Ltd. 2022 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/wait.h>
#include <getopt.h>

#include "se_tee.h"

/* Device detection not implemented */
#define SE050_MAX_BUF_SIZE_CMD (892)
#define SE050_MAX_BUF_SIZE_RSP (892)
#define SE051_MAX_BUF_SIZE_CMD (1024)
#define SE051_MAX_BUF_SIZE_RSP (1024)

static int SE05X_MAX_BUF_SIZE_CMD = SE051_MAX_BUF_SIZE_CMD;
static int SE05X_MAX_BUF_SIZE_RSP = SE051_MAX_BUF_SIZE_RSP;
static int SE05X_TLV_BUF_SIZE_CMD = SE051_MAX_BUF_SIZE_CMD;

#define BINARY_WRITE_MAX_LEN 500

enum se05x_tag {
	SE05x_TAG_NA = 0,
	SE05x_TAG_SESSION_ID = 0x10,
	SE05x_TAG_POLICY = 0x11,
	SE05x_TAG_MAX_ATTEMPTS = 0x12,
	SE05x_TAG_IMPORT_AUTH_DATA = 0x13,
	SE05x_TAG_IMPORT_AUTH_KEY_ID = 0x14,
	SE05x_TAG_POLICY_CHECK = 0x15,
	SE05x_TAG_1 = 0x41,
	SE05x_TAG_2 = 0x42,
	SE05x_TAG_3 = 0x43,
	SE05x_TAG_4 = 0x44,
	SE05x_TAG_5 = 0x45,
	SE05x_TAG_6 = 0x46,
	SE05x_TAG_7 = 0x47,
	SE05x_TAG_8 = 0x48,
	SE05x_TAG_9 = 0x49,
	SE05x_TAG_10 = 0x4A,
	SE05x_TAG_11 = 0x4B,
	SE05x_GP_TAG_CONTRL_REF_PARM = 0xA6,
	SE05x_GP_TAG_AID = 0x4F,
	SE05x_GP_TAG_KEY_TYPE = 0x80,
	SE05x_GP_TAG_KEY_LEN = 0x81,
	SE05x_GP_TAG_GET_DATA = 0x83,
	SE05x_GP_TAG_DR_SE = 0x85,
	SE05x_GP_TAG_RECEIPT = 0x86,
	SE05x_GP_TAG_SCP_PARMS = 0x90,
};

enum se05x_status {
	SE05x_NOT_OK = 0xFFFF,
	SE05x_OK = 0x9000,
};

enum se05x_result {
	kSE05x_Result_NA = 0,
	kSE05x_Result_SUCCESS = 0x01,
	kSE05x_Result_FAILURE = 0x02,
};

#define DER_CERT "/tmp/cert.der"

static const struct {
	const char *import_cert;
	const char *show_cert;
	const char *rm_der;
} cmd = {
	.rm_der = "rm "DER_CERT,
	.show_cert = "openssl x509 -inform der -in " DER_CERT " -text ",
	.import_cert = "pkcs11-tool --module /usr/lib/libckteec.so.0.1.0 -l "
	"--type cert --pin %s --id %s --write-object " DER_CERT,
};

static int tlvGet_u8buf(enum se05x_tag tag, size_t *index,
			uint8_t *buf, size_t len,
			uint8_t *rsp, size_t *olen)
{
	size_t extended_len = 0;
	size_t rsp_len = 0;
	uint8_t *p = NULL;
	int ret = 1;

	if (!rsp || !olen || !index || *index > len)
		return -EINVAL;

	p = buf + *index;

	if (*p++ != tag)
		return -EINVAL;

	rsp_len = *p++;

	switch (rsp_len) {
	case 0x00 ... 0x7F:
		extended_len = rsp_len;
		*index += 2;
		break;
	case 0x81:
		extended_len = *p++;
		*index += 3;
		break;
	case 0x82:
		extended_len = *p++;
		extended_len = (extended_len << 8) | *p++;
		*index += 4;
		break;
	default:
		return -EINVAL;
	}

	if (extended_len > *olen)
		return -EINVAL;

	if (extended_len > len)
		return -EINVAL;

	*olen = extended_len;
	*index += extended_len;

	while (extended_len-- > 0)
		*rsp++ = *p++;

	return 0;
}

static int tlvGet_u8(enum se05x_tag tag, size_t *index,
		     uint8_t *buf, size_t buf_len, uint8_t *rsp)
{
	uint8_t *p = buf + *index;
	uint8_t got_tag = *p++;
	size_t rsp_len = 0;

	if (*index > buf_len)
		return -EINVAL;

	if (got_tag != tag)
		return -EINVAL;

	rsp_len = *p++;
	if (rsp_len > 1)
		return -EINVAL;

	*rsp = *p;
	*index += (1 + 1 + (rsp_len));

	return 0;
}

static int tlvGet_u16(enum se05x_tag tag, size_t *index,
		      uint8_t *buf, size_t buf_len,
		      uint16_t *rsp)
{
	uint8_t *p = buf + *index;
	uint8_t got_tag = *p++;
	size_t rsp_len = 0;

	if (*index > buf_len)
		return -EINVAL;

	if (got_tag != tag)
		return -EINVAL;

	rsp_len = *p++;
	if (rsp_len > 2)
		return -EINVAL;

	*rsp = (*p++) << 8;
	*rsp |= *p++;
	*index += (1 + 1 + rsp_len);

	return 0;
}

static int tlvSet_u16(enum se05x_tag tag, uint8_t **buf, size_t *len,
		      uint16_t value)
{
	const size_t size_of_tlv = 1 + 1 + 2;
	uint8_t *p = *buf;

	if (size_of_tlv + *len > SE05X_TLV_BUF_SIZE_CMD)
		return -EINVAL;

	*p++ = (uint8_t)tag;
	*p++ = 2;
	*p++ = (uint8_t)((value >> 1 * 8) & 0xFF);
	*p++ = (uint8_t)((value >> 0 * 8) & 0xFF);
	*buf = p;
	*len += size_of_tlv;

	return 0;
}

static int tlvSet_u32(enum se05x_tag tag, uint8_t **buf, size_t *len,
		      uint32_t value)
{
	const size_t tlv_len = 1 + 1 + 4;
	uint8_t *p = *buf;

	if (tlv_len + *len > SE05X_TLV_BUF_SIZE_CMD)
		return -EINVAL;

	*p++ = (uint8_t)tag;
	*p++ = 4;
	*p++ = (uint8_t)((value >> 3 * 8) & 0xFF);
	*p++ = (uint8_t)((value >> 2 * 8) & 0xFF);
	*p++ = (uint8_t)((value >> 1 * 8) & 0xFF);
	*p++ = (uint8_t)((value >> 0 * 8) & 0xFF);

	*buf = p;
	*len += tlv_len;

	return 0;
}

static int object_exist(uint32_t oid, bool *exist)
{
	uint8_t CMD_OBJ_EXIST_HEADER[4] = {
		0x80, 0x04, 0x00, 0x27,
	};
	uint8_t *cmd = malloc(SE05X_MAX_BUF_SIZE_CMD);
	uint8_t *rsp = malloc(SE05X_MAX_BUF_SIZE_RSP);
	uint8_t *p = cmd;
	uint8_t *q = rsp;
	size_t rsp_len = SE05X_MAX_BUF_SIZE_RSP;
	size_t rsp_idx = 0;
	size_t cmd_len = 0;
	uint8_t result;
	size_t result_len = 1;

	if (!cmd || !rsp)
		return -ENOMEM;

	if (tlvSet_u32(SE05x_TAG_1, &p, &cmd_len, oid)) {
		printf("error, cant form command\n");
		goto error;
	}

	if (se_apdu_request(SE_APDU_CASE_4,
			    CMD_OBJ_EXIST_HEADER, sizeof(CMD_OBJ_EXIST_HEADER),
			    cmd, cmd_len,
			    rsp, &rsp_len)) {
		printf("error, cant communicate with TEE core\n");
		goto error;
	}

	if (tlvGet_u8buf(SE05x_TAG_1, &rsp_idx, rsp, rsp_len,
			 &result, &result_len)) {
		goto error;
	}

	*exist = result == kSE05x_Result_SUCCESS ? true : false;

	free(cmd);
	free(rsp);

	return 0;
error:
	free(cmd);
	free(rsp);

	return -EINVAL;
}

static int object_size(uint32_t oid, uint16_t *len)
{
	uint8_t CMD_OBJ_SIZE_HEADER[4] = {
		0x80, 0x02, 0x00, 0x07,
	};
	uint8_t *cmd = malloc(SE05X_MAX_BUF_SIZE_CMD);
	uint8_t *rsp = malloc(SE05X_MAX_BUF_SIZE_RSP);
	uint8_t *p = cmd;
	uint8_t *q = rsp;
	size_t rsp_len = SE05X_MAX_BUF_SIZE_RSP;
	size_t rsp_idx = 0;
	size_t cmd_len = 0;

	if (!cmd || !rsp)
		return -ENOMEM;

	if (tlvSet_u32(SE05x_TAG_1, &p, &cmd_len, oid)) {
		printf("error, cant form command\n");
		goto error;
	}

	if (se_apdu_request(SE_APDU_CASE_4,
			    CMD_OBJ_SIZE_HEADER, sizeof(CMD_OBJ_SIZE_HEADER),
			    cmd, cmd_len,
			    rsp, &rsp_len)) {
		printf("error, cant communicate with TEE core\n");
		goto error;
	}

	if (tlvGet_u16(SE05x_TAG_1, &rsp_idx, rsp, rsp_len, len)) {
		printf("error, cant get response\n");
		goto error;
	}
	free(cmd);
	free(rsp);

	return 0;
error:
	free(cmd);
	free(rsp);

	return -EINVAL;
}

static int object_type(uint32_t oid, bool *is_binary)
{
	uint8_t CMD_OBJ_TYPE_HEADER[4] = {
		0x80, 0x02, 0x00, 0x26,
	};
	uint8_t *cmd = malloc(SE05X_MAX_BUF_SIZE_CMD);
	uint8_t *rsp = malloc(SE05X_MAX_BUF_SIZE_RSP);
	uint8_t *p = cmd;
	uint8_t *q = rsp;
	size_t rsp_len = SE05X_MAX_BUF_SIZE_RSP;
	size_t cmd_len = 0;
	size_t rsp_idx = 0;
	uint8_t type = 0;

	if (!cmd || !rsp)
		return -ENOMEM;

	if (tlvSet_u32(SE05x_TAG_1, &p, &cmd_len, oid)) {
		printf("error, cant form command\n");
		goto error;
	}

	if (se_apdu_request(SE_APDU_CASE_4,
			    CMD_OBJ_TYPE_HEADER, sizeof(CMD_OBJ_TYPE_HEADER),
			    cmd, cmd_len,
			    rsp, &rsp_len)) {
		printf("error, cant communicate with TEE core\n");
		goto error;
	}

	if (tlvGet_u8(SE05x_TAG_1, &rsp_idx, rsp,  rsp_len, &type)) {
		printf("error, cant read type\n");
		goto error;
	}

	*is_binary = type == 0x0B ? true : false;

	free(cmd);
	free(rsp);

	return 0;
error:
	free(cmd);
	free(rsp);

	return -EINVAL;
}

static int object_get(uint32_t oid, uint16_t offset, uint16_t len,
		      char *buf, size_t *buf_len)
{
	uint8_t CMD_OBJ_GET_HEADER[4] = {
		0x80, 0x02, 0x00, 0x00
	};
	uint8_t *cmd = malloc(SE05X_MAX_BUF_SIZE_CMD);
	uint8_t *rsp = malloc(SE05X_MAX_BUF_SIZE_RSP);
	uint8_t *p = cmd;
	uint8_t *q = rsp;
	size_t rsp_len = SE05X_MAX_BUF_SIZE_RSP;
	size_t rsp_idx = 0;
	size_t cmd_len = 0;
	size_t index = 0;

	if (!cmd || !rsp)
		return -ENOMEM;

	if (tlvSet_u32(SE05x_TAG_1, &p, &cmd_len, oid))
		goto error;

	if (offset && tlvSet_u16(SE05x_TAG_2, &p, &cmd_len, offset))
		goto error;

	if (len && tlvSet_u16(SE05x_TAG_3, &p, &cmd_len, len))
		goto error;

	if (se_apdu_request(SE_APDU_CASE_4E,
			    CMD_OBJ_GET_HEADER, sizeof(CMD_OBJ_GET_HEADER),
			    cmd, cmd_len,
			    rsp, &rsp_len)) {
		printf("error, cant communicate with TEE core\n");
		goto error;
	}

	if (tlvGet_u8buf(SE05x_TAG_1, &rsp_idx, rsp, rsp_len, buf, buf_len)){
		printf(("error, cant get the binary data\n"));
		goto error;
	}

	free(cmd);
	free(rsp);

	return 0;
error:
	free(cmd);
	free(rsp);

	return -EINVAL;
}

static int get_certificate(uint32_t oid, char *fname)
{
	bool is_binary = false;
	size_t file_len = 0;
	uint8_t *bin = NULL;
	bool found = false;
	size_t offset = 0;
	uint16_t len = 0;

	if (object_exist(oid, &found) || !found) {
		printf("Error, no object found!\n");
		return -EINVAL;
	}

	if (object_type(oid, &is_binary) || !is_binary) {
		printf("Error, not binary type!\n");
		return -EINVAL;
	}

	if (object_size(oid, &len) || !len) {
		printf("Error, invalid size!\n");
		return -EINVAL;
	}

	bin = calloc(1, len);
	if (!bin) {
		printf("Error, not enough memory\n");
		return -EINVAL;
	}

	file_len = len;
	offset = 0;
	do {
		size_t rcv = len > BINARY_WRITE_MAX_LEN ?
			     BINARY_WRITE_MAX_LEN : len;

		if (object_get(oid, offset, rcv, bin + offset, &rcv)) {
			printf("Object 0x%x cant be retrieved!\n", oid);
			return -EINVAL;
		}
		offset += rcv;
		len -= rcv;
	} while (len);

	FILE *file = fopen(fname, "w+");
	if (!file) {
		printf("Cant open the file for writing!\n");
		return -EINVAL;
	}

	fwrite(bin, file_len, 1, file);
	fclose(file);
	free(bin);

	return 0;
}

static int do_certificate(bool import, uint32_t nxp, char *id, char *pin)
{
	char cmd_buf[512] = { '\0' };
	int ret;

	if (get_certificate(nxp, DER_CERT))
		errx(1, "APDU import certificate failed");

	if (import) {
		sprintf(cmd_buf, cmd.import_cert, pin, id);

		ret = system(cmd_buf);
		if (ret)
			fprintf(stderr,
				"pkcs11-tool import cert error %d\n", ret);
		goto out;
	}

	ret =  system(cmd.show_cert);
	if (ret)
		fprintf(stderr, "pkcs11-tool show cert error %d\n", ret);
out:
	return (system(cmd.rm_der) | ret);
}

static const struct option options[] = {
	{
#define help_opt 0
		.name = "help",
		.has_arg = 0,
		.flag = NULL,
	},
	{
#define import_opt 1
		.name = "import",
		.has_arg = 1,
		.flag = NULL,
	},
	{
#define show_opt 2
		.name = "show",
		.has_arg = 1,
		.flag = NULL,
	},
	{
#define sks_id_opt 3
		.name = "id",
		.has_arg = 1,
		.flag = NULL,
	},
	{
#define sks_pin_opt 4
		.name = "pin",
		.has_arg = 1,
		.flag = NULL,
	},
	{
#define se050_opt 5
		.name = "se050",
		.has_arg = 0,
		.flag = NULL,
	},
	{
		.name = NULL,
	},
};

static void usage(void)
{
	fprintf(stderr, "This tool imports certficates from the NXP SE051 into the cryptoki\n");
	fprintf(stderr, "Use the --se050 optional flag if the device is not an SE051\n");

	fprintf(stderr, "Usage: with:\n");
	fprintf(stderr, "--help             Display this menu\n");
	fprintf(stderr, "--import <se05x oid> "
			"--pin <pkcs11 pin> "
			"--id <pkcs11 object> "
			"[--se050] \t"
			"Import a Certificate to pkcs11\n");
	fprintf(stderr, "--show   <se05x oid> [--se050]\t\t\t\t\t\t"
			"Output the Certificate to the console\n");
	fprintf(stderr, "\n");
}

int main(int argc, char *argv[])
{
	char *sks_pin = NULL, *sks_id = NULL, *nxp_id = NULL;
	bool do_import = false;
	bool do_show = false;
	int lindex, opt;

	for (;;) {
		lindex = -EINVAL;
		opt = getopt_long_only(argc, argv, "", options, &lindex);
		if (opt == EOF)
			break;

		switch (lindex) {
		case help_opt:
			usage();
			exit(0);
		case import_opt:
			do_import = true;
			nxp_id = optarg;
			break;
		case show_opt:
			do_show = true;
			nxp_id = optarg;
			break;
		case sks_id_opt:
			sks_id = optarg;
			break;
		case sks_pin_opt:
			sks_pin = optarg;
			break;
		case se050_opt:
			SE05X_MAX_BUF_SIZE_CMD = SE050_MAX_BUF_SIZE_CMD;
			SE05X_MAX_BUF_SIZE_RSP = SE050_MAX_BUF_SIZE_RSP;
			SE05X_TLV_BUF_SIZE_CMD = SE050_MAX_BUF_SIZE_CMD;
			break;
		default:
			usage();
			exit(1);
		}
	}

	if (do_import && do_show)
		goto error;

	if ((do_import && sks_id && sks_pin && nxp_id) ||
	    (do_show && nxp_id))
		return do_certificate(do_import, strtoul(nxp_id, NULL, 16),
				      sks_id, sks_pin);
error:
	usage();
	exit(1);
}

