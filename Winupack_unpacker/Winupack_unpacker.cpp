// Winupack_unpacker.cpp : Defines the entry point for the console application.

#include "stdafx.h"
#include <windows.h>
#include <unicorn/unicorn.h>
#include <capstone.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <cstdint>

#define UNICORN_PAGESZ 0x1000
#define ALIGN_PAGE_DOWN(x) (x & ~(UNICORN_PAGESZ - 1))
#define ALIGN_PAGE_UP(x)  ((x + UNICORN_PAGESZ - 1) & ~(UNICORN_PAGESZ - 1))

typedef struct __unpacker {
	uint8_t *pe_data;
	uint32_t  entry_point;
	uint32_t  image_base;
	uint32_t  size_of_image;
	uint32_t  oep;
	uint32_t  code_section;
	uint32_t  code_section_size;
	uint32_t  load_library_call;
	uint32_t  getProcAddress_call;
	uint32_t pivot;
	csh hcs;
	uc_engine *huc;
}Unpacker;

static Unpacker *upk;

static void check_is_valid_exe(uint8_t *pFilename) {
	FILE *pF;
	uint32_t  nbytes;
	uint8_t *pMagic;

	if ((pF = fopen((char*)pFilename, "rb")) == NULL) {
		perror("fopen");
		exit(1);
	}
	if ((pMagic = (uint8_t*)calloc(sizeof(uint8_t), 2)) == NULL) {
		perror("calloc");
		exit(1);
	}
	if ((nbytes = fread(pMagic, sizeof(uint8_t), 2, pF)) < 2) {
		perror("fread");
		exit(1);
	}
	if (memcmp(pMagic, "MZ", 2)) {
		printf("[-] Not a valid executable\n");
	}
	fclose(pF);
	free(pMagic);
}

static void map_mem(uint32_t  address, uint32_t  size) {
	uint32_t  memStart = address;
	uint32_t  memEnd = address + size;
	uint32_t  memStartAligned = ALIGN_PAGE_DOWN(memStart);
	uint32_t  memEndAligned = ALIGN_PAGE_UP(memEnd);
	uc_mem_map(upk->huc, memStartAligned, memEndAligned - memStartAligned, UC_PROT_ALL);
}

static uint32_t  map_sections() {
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNTheaders;
	PIMAGE_SECTION_HEADER pSectionHeader;
	WORD nSections, i;

	pDosHeader = (PIMAGE_DOS_HEADER)upk->pe_data;
	pNTheaders = (PIMAGE_NT_HEADERS)((uint8_t*)pDosHeader + pDosHeader->e_lfanew);
	nSections = pNTheaders->FileHeader.NumberOfSections;
	pSectionHeader = (PIMAGE_SECTION_HEADER)((uint8_t*)(&pNTheaders->OptionalHeader) + pNTheaders->FileHeader.SizeOfOptionalHeader);

	for (i = 0; i < nSections; i++) {
		uint32_t  section_start = pSectionHeader[i].VirtualAddress + upk->image_base;
		uint32_t  section_end = section_start + pSectionHeader[i].Misc.VirtualSize;
		uint32_t  endAligned = ALIGN_PAGE_UP(section_end);

		map_mem(section_start,  endAligned - section_start);
		if (i == 0) {
			upk->code_section = section_start;
			upk->code_section_size = pSectionHeader[i].Misc.VirtualSize;
			map_mem( upk->image_base, pSectionHeader->VirtualAddress);
			if (uc_mem_write(upk->huc, section_start, (uint8_t*)upk->pe_data, pSectionHeader[i].SizeOfRawData)) {
				perror("uc_mem_write");
				return -1;
			}
		} else if (i == 1) {
			if (uc_mem_write(upk->huc, section_start, (uint8_t*)&upk->pe_data[pSectionHeader[i].PointerToRawData], pSectionHeader[i].SizeOfRawData)) {
				perror("uc_mem_write");
				return -1;
			}
		} else  if (i == 2) {
			if (uc_mem_write(upk->huc, section_start, (uint8_t*)upk->pe_data, pSectionHeader[i].SizeOfRawData)) {
				perror("uc_mem_write");
				return -1;
			}
		}
	}
	return 0;
}

static uint32_t  map_stack() {
	uint32_t  stack_size = UNICORN_PAGESZ;
	uint32_t  stack_top = 0x7f0000;
	uint32_t  stack_bottom = stack_top - stack_size;

	map_mem(stack_bottom, stack_size + 1 );
	if (uc_reg_write(upk->huc, UC_X86_REG_ESP, &stack_top) != UC_ERR_OK) {
		return -1;
	}
	return 0;
}

static  uint8_t *disasm(uint32_t  address, uint32_t  size) {
	uint8_t *data;
	WORD count;
	cs_insn *insn;

	data = (uint8_t*)calloc(sizeof(uint8_t), size);
	uc_mem_read(upk->huc, address, (uint8_t*)data, 100);

	if ((count = cs_disasm(upk->hcs, data, 100, address, 0, &insn)) > 0) {
		for (uint32_t  j = 0; j < 5/*count*/; j++) {
			printf("0x%lx:\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
		}
	}
	return data;
}

static bool hook_code(uc_engine *uc, uint32_t  address,  uint32_t  size, void *user_data) {
	uint32_t r_esp;
	const char nops[] = "\x90\x90";
	uint32_t entry;
	cs_insn *insn;

	if (!upk->oep && address == upk->image_base + upk->entry_point + 7) {
		uc_reg_read(upk->huc, UC_X86_REG_ESP, &r_esp);
		uc_mem_read(upk->huc, r_esp, &entry, 4);
		upk->oep = entry;
		upk->load_library_call = 0;
		upk->getProcAddress_call = 0;
		upk->pivot = 0;
		printf("[+] OEP found @ %lx\n", entry);
		printf("[*] Decompressing ...\n");

	} else if (upk->oep != 0 && upk->load_library_call == 0) {
		uc_reg_read(upk->huc, UC_X86_REG_ESP, &r_esp);
		uc_mem_read(upk->huc, r_esp, &entry, 4);

		if (entry == upk->oep) {
			upk->load_library_call = address + 0x9;
			upk->pivot = upk->load_library_call + 0x1c;
			upk->getProcAddress_call = upk->load_library_call + 0x17;

			uc_mem_write(upk->huc, upk->load_library_call, &nops, 2);
			uc_mem_write(upk->huc, upk->getProcAddress_call, &nops, 2);
			printf("[+] Decompression was sucessful,at @ 0x%lx\n[*] Resolving Imports\n", address);
		}

	} else if (upk->load_library_call == address && upk->oep != 0) {
		uc_reg_read(upk->huc, UC_X86_REG_ESP, &r_esp);
		uc_mem_read(upk->huc, r_esp, &entry, 4);
		uint8_t * shit = (uint8_t*)calloc(1, 100);
		uc_mem_read(upk->huc, entry, shit, 100);
		printf("[+] Module: %s\n", shit);
	
	} else if (upk->getProcAddress_call == address && upk->oep != 0) {
		uc_reg_read(upk->huc, UC_X86_REG_ESP, &r_esp);
		uc_mem_read(upk->huc, r_esp+4, &entry, 4);

		if (entry) {
			uint8_t * shit = (uint8_t*)calloc(1, 100);
			uc_mem_read(upk->huc, entry, shit, 100);
			printf("\t[+] Import : %s\n", shit);
		}

	} else if(upk->pivot == address && upk->oep != 0){
		printf("[+] Imports resolved\n");
		uc_emu_stop(upk->huc);
		return false;
		}
	}

static void export_file(const char *filename,  uint32_t address, uint32_t size) {
	uint8_t *stub;
	FILE *pFile;

	stub = (uint8_t*)calloc(sizeof(uint8_t), size);
	uc_mem_read(upk->huc, address, (uint8_t*)stub, size);
	pFile = fopen((char*)filename, "wb");
	fwrite(stub, sizeof(char), upk->code_section_size, pFile);
	
	free(stub);
	fclose(pFile);
}

int main(int argc, char **argv, char **envp) {
	uint8_t *pFilename;
	HANDLE hExe, hExeMap;
	LPVOID pBase;
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS32 pNTheaders;
	uint32_t entry_VA;
	uc_hook trace1;
	uc_err err;

	if (argc != 2) {
		printf("[*] Usage: %s <file to unpack>\n", argv[0]);
		exit(0);
	}
	pFilename = (uint8_t*)argv[1];
	check_is_valid_exe(pFilename);
	printf("[*] Unpacking %s\n", pFilename);

	if ((hExe = CreateFileA((LPCSTR)pFilename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
		perror("CreateFileA");
		exit(1);
	}
	if ((hExeMap = CreateFileMapping(hExe, NULL, PAGE_READONLY, 0, 0, NULL)) == INVALID_HANDLE_VALUE) {
		CloseHandle(hExe);
		perror("CreateFileMapping");
		exit(1);
	}
	if ((pBase = MapViewOfFile(hExeMap, FILE_MAP_READ, 0, 0, 0)) == 0) {
		CloseHandle(hExe);
		CloseHandle(hExeMap);
		perror("MapViewOfFile");
		exit(1);
	}
	upk = (Unpacker*)calloc(1, sizeof(Unpacker));
	pDosHeader = (PIMAGE_DOS_HEADER)pBase;
	pNTheaders = (PIMAGE_NT_HEADERS32)((uint32_t)pDosHeader + pDosHeader->e_lfanew);

	upk->image_base = (uint32_t )pNTheaders->OptionalHeader.ImageBase;
	upk->entry_point = (uint32_t)pNTheaders->OptionalHeader.AddressOfEntryPoint;
	upk->size_of_image = (uint32_t)pNTheaders->OptionalHeader.SizeOfImage;
	upk->pe_data = (uint8_t*)pBase;
	
	upk->code_section = 0;
	upk->code_section_size = 0;
	upk->oep = 0;

	if(cs_open(CS_ARCH_X86, CS_MODE_32, &upk->hcs) != CS_ERR_OK) {
		perror("cs_open");
		goto quit;
	}

	err = uc_open(UC_ARCH_X86, UC_MODE_32, &upk->huc);
	if(err != UC_ERR_OK) {
		printf("Failed on uc_open() with error returned: %u\n", err);
		cs_close(&upk->hcs);
		goto quit;
	}

	if (map_sections()) {
		printf("[-] Could not map sections\n");
		uc_close(upk->huc);
		cs_close(&upk->hcs);
		goto quit;
	}
	
	if (map_stack()) {
		printf("[-] Could not map stack\n");
		uc_close(upk->huc);
		cs_close(&upk->hcs);
		goto quit;
	}
	uc_hook_add(upk->huc, &trace1, UC_HOOK_CODE, hook_code, NULL, 1, 0);
	 entry_VA = upk->entry_point + upk->image_base;

	printf("[*] Searching for OEP\n");
	err = uc_emu_start(upk->huc, entry_VA, entry_VA + upk->size_of_image, 0, 0);
	if (err != UC_ERR_OK) {
		 printf("Failed on uc_start() with error returned: %u\n", err);
		 goto quit;
	}
	printf("[*] Emlation done\n");
	//export_file("dumped_file", upk->code_section, upk->code_section_size);

	quit:
	CloseHandle(hExe);
	CloseHandle(hExeMap);
	free(upk);
	return 0;
}
