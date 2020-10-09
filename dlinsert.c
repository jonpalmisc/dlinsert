#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <copyfile.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>

#define IS_64_BIT(x) ((x) == MH_MAGIC_64 || (x) == MH_CIGAM_64)
#define IS_LITTLE_ENDIAN(x) ((x) == FAT_CIGAM || (x) == MH_CIGAM_64 || (x) == MH_CIGAM)
#define SWAP32(x, magic) (IS_LITTLE_ENDIAN(magic)? OSSwapInt32(x): (x))
#define SWAP64(x, magic) (IS_LITTLE_ENDIAN(magic)? OSSwapInt64(x): (x))

#define ROUND_UP(x, y) (((x) + (y) - 1) & -(y))

#define ABSDIFF(x, y) ((x) > (y)? (uintmax_t)(x) - (uintmax_t)(y): (uintmax_t)(y) - (uintmax_t)(x))

#define BUFSIZE 512

void fbzero(FILE *f, off_t offset, size_t len) {
	static unsigned char zeros[BUFSIZE] = {0};
	fseeko(f, offset, SEEK_SET);
	while(len != 0) {
		size_t size = MIN(len, sizeof(zeros));
		fwrite(zeros, size, 1, f);
		len -= size;
	}
}

void fmemmove(FILE *f, off_t dst, off_t src, size_t len) {
	static unsigned char buf[BUFSIZE];
	while(len != 0) {
		size_t size = MIN(len, sizeof(buf));
		fseeko(f, src, SEEK_SET);
		fread(&buf, size, 1, f);
		fseeko(f, dst, SEEK_SET);
		fwrite(buf, size, 1, f);

		len -= size;
		src += size;
		dst += size;
	}
}

int flag_inplace = false;
int flag_weak = false;
int flag_overwrite = false;
int flag_unsign = 0;
int flag_auto_agree = false;

static struct option opts[] = {
	{"inplace",          no_argument, &flag_inplace,   true},
	{"weak",             no_argument, &flag_weak,      true},
	{"overwrite",        no_argument, &flag_overwrite, true},
	{"unsign",           no_argument, &flag_unsign,   1},
	{"yes",              no_argument, &flag_auto_agree,       true},
	{NULL,               0,           NULL,            0}
};

void print_usage(void) {
	printf("Insert LC_LOAD_DYLIB commands into existing binaries.\n\n");

	printf("Usage: dlinsert [flags] path binary [output]\n\n");

	printf("Required arguments:\n");
	printf("  path      The path to the dylib to load ^1\n");
	printf("  binary    The binary to modify\n\n");

	printf("Optional arguments:\n");
	printf("  output    Where to write the output binary ^2\n\n");

	printf("Flags:\n");
	printf("  --inplace      Modify the input binary in place\n");
	printf("  --weak         Insert LC_LOAD_WEAK_DYLIB instead of LC_LOAD_DYLIB\n");
	printf("  --overwrite    Approve overwriting the input binary\n");
	printf("  --unsign       Remove the code signature if present\n");
	printf("  --yes          Automatically agree to all prompts\n\n");

	printf("^1: The path argument MUST be either an absolute path or a relative path\n");
	printf("utilizing @executable_path, @loader_path, or @rpath. Failing to provide a valid\n");
	printf("path will cause the produced binary to crash upon startup.\n\n");

	printf("^2: By default, the output is adjacent to the input, with a \"_patched\" suffix.\n");
}

__attribute__((format(printf, 1, 2)))
bool prompt_user(const char *format, ...) {
	char *question;
	asprintf(&question, "%s [Y/N] ", format);

	va_list args;
	va_start(args, format);
	vprintf(question, args);
	va_end(args);

	free(question);

	// Continuously prompt the user until we get a valid answer.
	while(true) {
		char *line = NULL;
		size_t size;

		// Automatically agree if the flag is set.
		if(flag_auto_agree) {
			puts("y");
			line = "y";
		} else {
			getline(&line, &size, stdin);
		}

		switch(line[0]) {
			case 'y':
			case 'Y':
				return true;
				break;
			case 'n':
			case 'N':
				return false;
				break;
			default:
				printf("Enter Y or N: ");
		}
	}
}

size_t fpeek(void *restrict ptr, size_t size, size_t nitems, FILE *restrict stream) {
	off_t pos = ftello(stream);
	size_t result = fread(ptr, size, nitems, stream);
	fseeko(stream, pos, SEEK_SET);
	return result;
}

void *read_load_command(FILE *f, uint32_t cmdsize) {
	void *lc = malloc(cmdsize);

	fpeek(lc, cmdsize, 1, f);

	return lc;
}

bool check_load_commands(FILE *f, struct mach_header *mh, size_t header_offset, size_t commands_offset, const char *dylib_path, off_t *slice_size) {
	fseeko(f, commands_offset, SEEK_SET);

	uint32_t ncmds = SWAP32(mh->ncmds, mh->magic);

	off_t linkedit_32_pos = -1;
	off_t linkedit_64_pos = -1;
	struct segment_command linkedit_32;
	struct segment_command_64 linkedit_64;

	off_t symtab_pos = -1;
	uint32_t symtab_size = 0;

	for(int i = 0; i < ncmds; i++) {
		struct load_command lc;
		fpeek(&lc, sizeof(lc), 1, f);

		uint32_t cmdsize = SWAP32(lc.cmdsize, mh->magic);
		uint32_t cmd = SWAP32(lc.cmd, mh->magic);

		switch(cmd) {
			case LC_CODE_SIGNATURE:
				if(i == ncmds - 1) {
					if(flag_unsign == 2) {
						return true;
					}

					if(flag_unsign == 0 && !prompt_user("A LC_CODE_SIGNATURE command was found. Would you like remove it?")) {
						return true;
					}

					struct linkedit_data_command *cmd = read_load_command(f, cmdsize);

					fbzero(f, ftello(f), cmdsize);

					uint32_t dataoff = SWAP32(cmd->dataoff, mh->magic);
					uint32_t datasize = SWAP32(cmd->datasize, mh->magic);

					free(cmd);

					uint64_t linkedit_fileoff = 0;
					uint64_t linkedit_filesize = 0;

					if(linkedit_32_pos != -1) {
						linkedit_fileoff = SWAP32(linkedit_32.fileoff, mh->magic);
						linkedit_filesize = SWAP32(linkedit_32.filesize, mh->magic);
					} else if(linkedit_64_pos != -1) {
						linkedit_fileoff = SWAP64(linkedit_64.fileoff, mh->magic);
						linkedit_filesize = SWAP64(linkedit_64.filesize, mh->magic);
					} else {
						fprintf(stderr, "Warning: __LINKEDIT segment not found.\n");
					}

					if(linkedit_32_pos != -1 || linkedit_64_pos != -1) {
						if(linkedit_fileoff + linkedit_filesize != *slice_size) {
							fprintf(stderr, "Warning: __LINKEDIT not at end of file; output will be unsignable.\n");
						} else {
							if(dataoff + datasize != *slice_size) {
								fprintf(stderr, "Warning: Code signature not at end of __LINKEDIT; output will be unsignable.\n");
							} else {
								*slice_size -= datasize;
								//int64_t diff_size = 0;
								if(symtab_pos == -1) {
									fprintf(stderr, "Warning: Missing LC_SYMTAB command; output might not be signable.\n");
								} else {
									fseeko(f, symtab_pos, SEEK_SET);
									struct symtab_command *symtab = read_load_command(f, symtab_size);

									uint32_t strsize = SWAP32(symtab->strsize, mh->magic);
									int64_t diff_size = SWAP32(symtab->stroff, mh->magic) + strsize - (int64_t)*slice_size;
									if(-0x10 <= diff_size && diff_size <= 0) {
										symtab->strsize = SWAP32((uint32_t)(strsize - diff_size), mh->magic);
										fwrite(symtab, symtab_size, 1, f);
									} else {
										fprintf(stderr, "Warning: String table not immediately before signature; output might not be signable.\n");
									}

									free(symtab);
								}

								linkedit_filesize -= datasize;
								uint64_t linkedit_vmsize = ROUND_UP(linkedit_filesize, 0x1000);

								if(linkedit_32_pos != -1) {
									linkedit_32.filesize = SWAP32((uint32_t)linkedit_filesize, mh->magic);
									linkedit_32.vmsize = SWAP32((uint32_t)linkedit_vmsize, mh->magic);

									fseeko(f, linkedit_32_pos, SEEK_SET);
									fwrite(&linkedit_32, sizeof(linkedit_32), 1, f);
								} else {
									linkedit_64.filesize = SWAP64(linkedit_filesize, mh->magic);
									linkedit_64.vmsize = SWAP64(linkedit_vmsize, mh->magic);

									fseeko(f, linkedit_64_pos, SEEK_SET);
									fwrite(&linkedit_64, sizeof(linkedit_64), 1, f);
								}

								goto fix_header;
							}
						}
					}

					// If we haven't truncated the file, zero out the code signature
					fbzero(f, header_offset + dataoff, datasize);

				fix_header:
					mh->ncmds = SWAP32(ncmds - 1, mh->magic);
					mh->sizeofcmds = SWAP32(SWAP32(mh->sizeofcmds, mh->magic) - cmdsize, mh->magic);

					return true;
				} else {
					printf("Error: Code signature was not last command; removal failed.\n");
				}
				break;
			case LC_LOAD_DYLIB:
			case LC_LOAD_WEAK_DYLIB: {
				struct dylib_command *dylib_command = read_load_command(f, cmdsize);

				union lc_str offset = dylib_command->dylib.name;
				char *name = &((char *)dylib_command)[SWAP32(offset.offset, mh->magic)];

				int cmp = strcmp(name, dylib_path);

				free(dylib_command);

				if(cmp == 0) {
					if(!prompt_user("A load command for the specified path already exists. Continue anyway?")) {
						return false;
					}
				}

				break;
			}
			case LC_SEGMENT:
			case LC_SEGMENT_64:
				if(cmd == LC_SEGMENT) {
					struct segment_command *cmd = read_load_command(f, cmdsize);
					if(strcmp(cmd->segname, "__LINKEDIT") == 0) {
						linkedit_32_pos = ftello(f);
						linkedit_32 = *cmd;
					}
					free(cmd);
				} else {
					struct segment_command_64 *cmd = read_load_command(f, cmdsize);
					if(strcmp(cmd->segname, "__LINKEDIT") == 0) {
						linkedit_64_pos = ftello(f);
						linkedit_64 = *cmd;
					}
					free(cmd);
				}
			case LC_SYMTAB:
				symtab_pos = ftello(f);
				symtab_size = cmdsize;
		}

		fseeko(f, SWAP32(lc.cmdsize, mh->magic), SEEK_CUR);
	}

	return true;
}

bool insert_dylib(FILE *f, size_t header_offset, const char *dylib_path, off_t *slice_size) {
	fseeko(f, header_offset, SEEK_SET);

	struct mach_header mh;
	fread(&mh, sizeof(struct mach_header), 1, f);

	if(mh.magic != MH_MAGIC_64 && mh.magic != MH_CIGAM_64 && mh.magic != MH_MAGIC && mh.magic != MH_CIGAM) {
		printf("Error: Unknown Mach-O header magic. (0x%x)\n", mh.magic);
		return false;
	}

	size_t commands_offset = header_offset + (IS_64_BIT(mh.magic)? sizeof(struct mach_header_64): sizeof(struct mach_header));

	bool cont = check_load_commands(f, &mh, header_offset, commands_offset, dylib_path, slice_size);

	if(!cont) {
		return true;
	}

	// Even though a padding of 4 works for x86_64, codesign doesn't like it
	size_t path_padding = 8;

	size_t dylib_path_len = strlen(dylib_path);
	size_t dylib_path_size = (dylib_path_len & ~(path_padding - 1)) + path_padding;
	uint32_t cmdsize = (uint32_t)(sizeof(struct dylib_command) + dylib_path_size);

	struct dylib_command dylib_command = {
		.cmd = SWAP32(flag_weak? LC_LOAD_WEAK_DYLIB: LC_LOAD_DYLIB, mh.magic),
		.cmdsize = SWAP32(cmdsize, mh.magic),
		.dylib = {
			.name = SWAP32(sizeof(struct dylib_command), mh.magic),
			.timestamp = 0,
			.current_version = 0,
			.compatibility_version = 0
		}
	};

	uint32_t sizeofcmds = SWAP32(mh.sizeofcmds, mh.magic);

	fseeko(f, commands_offset + sizeofcmds, SEEK_SET);
	char space[cmdsize];

	fread(&space, cmdsize, 1, f);

	bool empty = true;
	for(int i = 0; i < cmdsize; i++) {
		if(space[i] != 0) {
			empty = false;
			break;
		}
	}

	if(!empty) {
		if(!prompt_user("Insufficient empty space detected. Continue anyway?")) {
			return false;
		}
	}

	fseeko(f, -((off_t)cmdsize), SEEK_CUR);

	char *dylib_path_padded = calloc(dylib_path_size, 1);
	memcpy(dylib_path_padded, dylib_path, dylib_path_len);

	fwrite(&dylib_command, sizeof(dylib_command), 1, f);
	fwrite(dylib_path_padded, dylib_path_size, 1, f);

	free(dylib_path_padded);

	mh.ncmds = SWAP32(SWAP32(mh.ncmds, mh.magic) + 1, mh.magic);
	sizeofcmds += cmdsize;
	mh.sizeofcmds = SWAP32(sizeofcmds, mh.magic);

	fseeko(f, header_offset, SEEK_SET);
	fwrite(&mh, sizeof(mh), 1, f);

	return true;
}

// Checks if a file exists.
bool file_exists(const char *p) {
	struct stat s;
	return stat(p, &s) != 0;
}

int main(int argc, const char *argv[]) {
	while(true) {
		int option_index = 0;

		int c = getopt_long(argc, (char *const *)argv, "", opts, &option_index);

		if(c == -1) {
			break;
		}

		switch(c) {
			case 0:
				break;
			case '?':
				print_usage();
				exit(1);
				break;
			default:
				abort();
				break;
		}
	}

	argv = &argv[optind - 1];
	argc -= optind - 1;

	// Show the usage and quit if we received invalid arguments.
	if(argc < 3 || argc > 4) {
		print_usage();
		exit(1);
	}

	const char *lc_name = flag_weak ? "LC_LOAD_WEAK_DYLIB": "LC_LOAD_DYLIB";

	const char *dylib_path = argv[1];
	const char *binary_path = argv[2];

	// Verify the input file exists.
	if (!file_exists(binary_path)) {
		printf("Error: Could not find input binary. (%s)\n", binary_path);
		exit(1);
	}

	// Verify the dylib path exists. (Currently only checks absolute paths.)
	// TODO: Add verification for relative paths.
	if(dylib_path[0] != '@' && !file_exists(dylib_path)) {
		if(!prompt_user("The provided path doesn't exist. Continue anyway?")) {
			exit(1);
		}
	}

	bool binary_path_was_malloced = false;
	if(!flag_inplace) {
		char *new_binary_path;
		if(argc == 4) {
			new_binary_path = (char *)argv[3];
		} else {
			asprintf(&new_binary_path, "%s_patched", binary_path);
			binary_path_was_malloced = true;
		}

		if(!flag_overwrite && file_exists(binary_path)) {
			if(!prompt_user("%s already exists. Overwrite it?", new_binary_path)) {
				exit(1);
			}
		}

		if(copyfile(binary_path, new_binary_path, NULL, COPYFILE_DATA | COPYFILE_UNLINK)) {
			printf("Error: Failed to create output binary. (%s)\n", new_binary_path);
			exit(1);
		}

		binary_path = new_binary_path;
	}

	FILE *f = fopen(binary_path, "r+");

	if(!f) {
		printf("Error: Failed to open file input binary. (%s)\n", binary_path);
		exit(1);
	}

	bool success = true;

	fseeko(f, 0, SEEK_END);
	off_t file_size = ftello(f);
	rewind(f);

	uint32_t magic;
	fread(&magic, sizeof(uint32_t), 1, f);

	switch(magic) {
		case FAT_MAGIC:
		case FAT_CIGAM: {
			fseeko(f, 0, SEEK_SET);

			struct fat_header fh;
			fread(&fh, sizeof(fh), 1, f);

			uint32_t nfat_arch = SWAP32(fh.nfat_arch, magic);

			// printf("Binary is a fat binary with %d archs.\n", nfat_arch);

			struct fat_arch archs[nfat_arch];
			fread(archs, sizeof(archs), 1, f);

			int fails = 0;

			uint32_t offset = 0;
			if(nfat_arch > 0) {
				offset = SWAP32(archs[0].offset, magic);
			}

			for(int i = 0; i < nfat_arch; i++) {
				off_t orig_offset = SWAP32(archs[i].offset, magic);
				off_t orig_slice_size = SWAP32(archs[i].size, magic);
				offset = ROUND_UP(offset, 1 << SWAP32(archs[i].align, magic));
				if(orig_offset != offset) {
					fmemmove(f, offset, orig_offset, orig_slice_size);
					fbzero(f, MIN(offset, orig_offset) + orig_slice_size, ABSDIFF(offset, orig_offset));

					archs[i].offset = SWAP32(offset, magic);
				}

				off_t slice_size = orig_slice_size;
				bool r = insert_dylib(f, offset, dylib_path, &slice_size);
				if(!r) {
					printf("Error: Failed to add %s to architecture #%d.\n", lc_name, i + 1);
					fails++;
				}

				if(slice_size < orig_slice_size && i < nfat_arch - 1) {
					fbzero(f, offset + slice_size, orig_slice_size - slice_size);
				}

				file_size = offset + slice_size;
				offset += slice_size;
				archs[i].size = SWAP32((uint32_t)slice_size, magic);
			}

			rewind(f);
			fwrite(&fh, sizeof(fh), 1, f);
			fwrite(archs, sizeof(archs), 1, f);

			// We need to flush before truncating
			fflush(f);
			ftruncate(fileno(f), file_size);

			if(fails == 0) {
				// printf("Added %s to all archs in %s\n", lc_name, binary_path);
			} else if(fails == nfat_arch) {
				printf("Error: Failed to add %s to any architectures.\n", lc_name);
				success = false;
			} else {
				printf("Warning: Only added %s to %d of %d architectures.\n", lc_name, nfat_arch - fails, nfat_arch);
			}

			break;
		}
		case MH_MAGIC_64:
		case MH_CIGAM_64:
		case MH_MAGIC:
		case MH_CIGAM:
			if(insert_dylib(f, 0, dylib_path, &file_size)) {
				ftruncate(fileno(f), file_size);
				// printf("Added %s to %s\n", lc_name, binary_path);
			} else {
				printf("Error: Failed to add %s.\n", lc_name);
				success = false;
			}
			break;
		default:
			printf("Error: Unknown Mach-O header magic. (0x%x)\n", magic);
			exit(1);
	}

	fclose(f);

	if(!success) {
		if(!flag_inplace) {
			unlink(binary_path);
		}
		exit(1);
	}

	if(binary_path_was_malloced) {
		free((void *)binary_path);
	}

    return 0;
}
