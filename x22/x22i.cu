/**
 * X22I algorithm
 */

extern "C" {
#include "sph/sph_blake.h"
#include "sph/sph_bmw.h"
#include "sph/sph_groestl.h"
#include "sph/sph_skein.h"
#include "sph/sph_jh.h"
#include "sph/sph_keccak.h"

#include "sph/sph_luffa.h"
#include "sph/sph_cubehash.h"
#include "sph/sph_shavite.h"
#include "sph/sph_simd.h"
#include "sph/sph_echo.h"

#include "sph/sph_hamsi.h"
#include "sph/sph_fugue.h"

#include "sph/sph_shabal.h"
#include "sph/sph_whirlpool.h"

#include "sph/sph_sha2.h"
#include "sph/sph_haval.h"

#include "sph/sph_tiger.h"
#include "lyra2/Lyra2.h"
}
#include "sph/sph_streebog.h"
#include "SWIFFTX/SWIFFTX.h"

#include "miner.h"
#include "cuda_helper.h"
#include "x11/cuda_x11.h"

static uint32_t *d_hash[MAX_GPUS], *d_hash1[MAX_GPUS], *d_hash2[MAX_GPUS], *d_hash3[MAX_GPUS];
static uint64_t* d_matrix[MAX_GPUS];

//extern void x16_echo512_cpu_hash_64(int thr_id, uint32_t threads, uint32_t *d_hash);

extern void x13_hamsi512_cpu_init(int thr_id, uint32_t threads);
extern void x13_hamsi512_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *d_nonceVector, uint32_t *d_hash, int order);

extern void x13_fugue512_cpu_init(int thr_id, uint32_t threads);
extern void x13_fugue512_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *d_nonceVector, uint32_t *d_hash, int order);
extern void x13_fugue512_cpu_free(int thr_id);

extern void x14_shabal512_cpu_init(int thr_id, uint32_t threads);
extern void x14_shabal512_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *d_nonceVector, uint32_t *d_hash, int order);

extern void x15_whirlpool_cpu_init(int thr_id, uint32_t threads, int flag);
extern void x15_whirlpool_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *d_nonceVector, uint32_t *d_hash, int order);
extern void x15_whirlpool_cpu_free(int thr_id);

extern void x17_sha512_cpu_init(int thr_id, uint32_t threads);
extern void x17_sha512_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *d_hash);

extern void x17_haval256_cpu_init(int thr_id, uint32_t threads);
extern void x17_haval256_cpu_hash_64(int thr_id, uint32_t threads, uint32_t startNounce, uint32_t *d_hash, const int outlen);

extern void streebog_cpu_hash_64(int thr_id, uint32_t threads, uint32_t *d_hash);

extern void lyra2v2_cpu_init(int thr_id, uint32_t threads, uint64_t *d_matrix);
extern void lyra2v2_cpu_hash_32(int thr_id, uint32_t threads, uint32_t startNounce, uint64_t *g_hash, int order);

extern void tiger192_cpu_hash_64(int thr_id, int threads, uint32_t *d_hash);
extern void sha256_cpu_hash_64(int thr_id, int threads, uint32_t *d_hash);

extern void h_InitializeSWIFFTX();
extern void swifftx512_cpu_hash_64(int thr_id, int threads, uint32_t *d_hash, uint32_t *d_hash1, uint32_t *d_hash2, uint32_t *d_hash3);


// X22I CPU Hash (Validation)
extern "C" void x22ihash(void *output, const void *input)
{
	//unsigned char _ALIGN(64) hash[128];
	unsigned char hash[64 * 4] = {0}, hash2[64] = {0};

	// x11 + hamsi12-fugue13-shabal14-whirlpool15-sha512-haval256

	sph_blake512_context ctx_blake;
	sph_bmw512_context ctx_bmw;
	sph_groestl512_context ctx_groestl;
	sph_jh512_context ctx_jh;
	sph_keccak512_context ctx_keccak;
	sph_skein512_context ctx_skein;
	sph_luffa512_context ctx_luffa;
	sph_cubehash512_context ctx_cubehash;
	sph_shavite512_context ctx_shavite;
	sph_simd512_context ctx_simd;
	sph_echo512_context ctx_echo;
	sph_hamsi512_context ctx_hamsi;
	sph_fugue512_context ctx_fugue;
	sph_shabal512_context ctx_shabal;
	sph_whirlpool_context ctx_whirlpool;
	sph_sha512_context ctx_sha512;
	sph_haval256_5_context ctx_haval;
	sph_tiger_context         ctx_tiger;
	sph_gost512_context       ctx_gost;
	sph_sha256_context        ctx_sha;

	sph_blake512_init(&ctx_blake);
	sph_blake512(&ctx_blake, input, 80);
	sph_blake512_close(&ctx_blake, hash);

	sph_bmw512_init(&ctx_bmw);
	/*
	// ZERO hash test, leads to "624381675728598999"
	unsigned char test[64] = {0};
	sph_bmw512(&ctx_bmw, (const void*) test, 64);
	*/
	sph_bmw512(&ctx_bmw, (const void*) hash, 64);
	sph_bmw512_close(&ctx_bmw, hash);

	sph_groestl512_init(&ctx_groestl);
	sph_groestl512(&ctx_groestl, (const void*) hash, 64);
	sph_groestl512_close(&ctx_groestl, hash);

	sph_skein512_init(&ctx_skein);
	sph_skein512(&ctx_skein, (const void*) hash, 64);
	sph_skein512_close(&ctx_skein, hash);

	sph_jh512_init(&ctx_jh);
	sph_jh512(&ctx_jh, (const void*) hash, 64);
	sph_jh512_close(&ctx_jh, hash);

	sph_keccak512_init(&ctx_keccak);
	sph_keccak512(&ctx_keccak, (const void*) hash, 64);
	sph_keccak512_close(&ctx_keccak, hash);

	sph_luffa512_init(&ctx_luffa);
	sph_luffa512(&ctx_luffa, (const void*) hash, 64);
	sph_luffa512_close (&ctx_luffa, hash);

	sph_cubehash512_init(&ctx_cubehash);
	sph_cubehash512(&ctx_cubehash, (const void*) hash, 64);
	sph_cubehash512_close(&ctx_cubehash, hash);

	sph_shavite512_init(&ctx_shavite);
	sph_shavite512(&ctx_shavite, (const void*) hash, 64);
	sph_shavite512_close(&ctx_shavite, hash);

	sph_simd512_init(&ctx_simd);
	sph_simd512(&ctx_simd, (const void*) hash, 64);
	sph_simd512_close(&ctx_simd, hash);

	sph_echo512_init(&ctx_echo);
	sph_echo512(&ctx_echo, (const void*) hash, 64);
	sph_echo512_close(&ctx_echo, hash);

	sph_hamsi512_init(&ctx_hamsi);
	sph_hamsi512(&ctx_hamsi, (const void*) hash, 64);
	sph_hamsi512_close(&ctx_hamsi, hash);

	sph_fugue512_init(&ctx_fugue);
	sph_fugue512(&ctx_fugue, (const void*) hash, 64);
	sph_fugue512_close(&ctx_fugue, hash);

	sph_shabal512_init(&ctx_shabal);
	sph_shabal512(&ctx_shabal, (const void*) hash, 64);
	sph_shabal512_close(&ctx_shabal, &hash[64]);

	sph_whirlpool_init(&ctx_whirlpool);
	sph_whirlpool (&ctx_whirlpool, (const void*) &hash[64], 64);
	sph_whirlpool_close(&ctx_whirlpool, &hash[128]);

	sph_sha512_init(&ctx_sha512);
	sph_sha512(&ctx_sha512,(const void*) &hash[128], 64);
	sph_sha512_close(&ctx_sha512,(void*) &hash[192]);

	InitializeSWIFFTX();
	ComputeSingleSWIFFTX((unsigned char*)hash, (unsigned char*)hash2, false);

	memset(hash, 0, 64);
	sph_haval256_5_init(&ctx_haval);
	sph_haval256_5(&ctx_haval,(const void*) hash2, 64);
	sph_haval256_5_close(&ctx_haval,hash);

	memset(hash2, 0, 64);
	sph_tiger_init(&ctx_tiger);
	sph_tiger (&ctx_tiger, (const void*) hash, 64);
	sph_tiger_close(&ctx_tiger, (void*) hash2);

	memset(hash, 0, 64);
	LYRA2((void*) hash, 32, (const void*) hash2, 32, (const void*) hash2, 32, 1, 4, 4);

	sph_gost512_init(&ctx_gost);
	sph_gost512 (&ctx_gost, (const void*) hash, 64);
	sph_gost512_close(&ctx_gost, (void*) hash);

	sph_sha256_init(&ctx_sha);
	sph_sha256 (&ctx_sha, (const void*) hash, 64);
	sph_sha256_close(&ctx_sha, (void*) hash);

	/*
  // zero hash test print
  printf("%lu\n", ((uint64_t*)(hash))[0]);
  */

	memcpy(output, hash, 32);
}

static bool init[MAX_GPUS] = { 0 };

extern "C" int scanhash_x22i(int thr_id, struct work* work, uint32_t max_nonce, unsigned long *hashes_done)
{
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;
	const uint32_t first_nonce = pdata[19];
	const int dev_id = device_map[thr_id];

	uint32_t throughput =  cuda_default_throughput(thr_id, 1U << 19); // 19=256*256*8;
	//if (init[thr_id]) throughput = min(throughput, max_nonce - first_nonce);

	uint64_t gpu_ram_size = 16 * sizeof(uint32_t) * throughput;

	if (opt_benchmark)
		((uint32_t*)ptarget)[7] = 0x08ff;

	if (!init[thr_id])
	{
		cudaSetDevice(dev_id);
		if (opt_cudaschedule == -1 && gpu_threads == 1) {
			cudaDeviceReset();
			// reduce cpu usage
			cudaSetDeviceFlags(cudaDeviceScheduleBlockingSync);
		}
		gpulog(LOG_INFO, thr_id, "Intensity set to %g, %u cuda threads", throughput2intensity(throughput), throughput);

		size_t matrix_sz = 16 * sizeof(uint64_t) * 4 * 3;
		// SM 3 implentation requires a bit more memory
		if (device_sm[dev_id] < 500 || cuda_arch[dev_id] < 500) matrix_sz = 16 * sizeof(uint64_t) * 4 * 4;
		CUDA_CALL_OR_RET_X(cudaMalloc(&d_matrix[thr_id], matrix_sz * throughput), -1);

		cuda_get_arch(thr_id);
		x11_echo512_cpu_init(thr_id, throughput);

		quark_blake512_cpu_init(thr_id, throughput);
		quark_groestl512_cpu_init(thr_id, throughput);
		quark_skein512_cpu_init(thr_id, throughput);
		quark_bmw512_cpu_init(thr_id, throughput);
		quark_keccak512_cpu_init(thr_id, throughput);
		quark_jh512_cpu_init(thr_id, throughput);
		x11_luffaCubehash512_cpu_init(thr_id, throughput);
		x11_shavite512_cpu_init(thr_id, throughput);
		x11_simd512_cpu_init(thr_id, throughput);
		x13_hamsi512_cpu_init(thr_id, throughput);
		x13_fugue512_cpu_init(thr_id, throughput);
		x14_shabal512_cpu_init(thr_id, throughput);
		x15_whirlpool_cpu_init(thr_id, throughput, 0);
		x17_sha512_cpu_init(thr_id, throughput);
		h_InitializeSWIFFTX();
		x17_haval256_cpu_init(thr_id, throughput);
		lyra2v2_cpu_init(thr_id, throughput, d_matrix[thr_id]);

		CUDA_CALL_OR_RET_X(cudaMalloc(&d_hash [thr_id], gpu_ram_size), 0);
		CUDA_CALL_OR_RET_X(cudaMalloc(&d_hash1[thr_id], gpu_ram_size), 0);
		CUDA_CALL_OR_RET_X(cudaMalloc(&d_hash2[thr_id], gpu_ram_size), 0);
		CUDA_CALL_OR_RET_X(cudaMalloc(&d_hash3[thr_id], gpu_ram_size), 0);

		cuda_check_cpu_init(thr_id, throughput);

		api_set_throughput(thr_id, throughput);
		init[thr_id] = true;
	}

	uint32_t _ALIGN(64) endiandata[20];
	for (int k=0; k < 20; k++)
		be32enc(&endiandata[k], pdata[k]);

	quark_blake512_cpu_setBlock_80(thr_id, endiandata);
	cuda_check_cpu_setTarget(ptarget);

	int warn = 0;

	do {
		int order = 0;

		// Hash with CUDA
		quark_blake512_cpu_hash_80(thr_id, throughput, pdata[19], d_hash[thr_id]); order++;

		/*
		// zero hash test
		cudaMemset(d_hash[thr_id], 0, gpu_ram_size);
		*/

		quark_bmw512_cpu_hash_64(thr_id, throughput, pdata[19], NULL, d_hash[thr_id], order++);
		quark_groestl512_cpu_hash_64(thr_id, throughput, pdata[19], NULL, d_hash[thr_id], order++);
		quark_skein512_cpu_hash_64(thr_id, throughput, pdata[19], NULL, d_hash[thr_id], order++);
		quark_jh512_cpu_hash_64(thr_id, throughput, pdata[19], NULL, d_hash[thr_id], order++);
		quark_keccak512_cpu_hash_64(thr_id, throughput, pdata[19], NULL, d_hash[thr_id], order++);
		x11_luffaCubehash512_cpu_hash_64(thr_id, throughput, d_hash[thr_id], order++);
		x11_shavite512_cpu_hash_64(thr_id, throughput, pdata[19], NULL, d_hash[thr_id], order++);
		x11_simd512_cpu_hash_64(thr_id, throughput, pdata[19], NULL, d_hash[thr_id], order++);
		x11_echo512_cpu_hash_64(thr_id, throughput, pdata[19], NULL, d_hash[thr_id], order++);
		x13_hamsi512_cpu_hash_64(thr_id, throughput, pdata[19], NULL, d_hash[thr_id], order++);

		x13_fugue512_cpu_hash_64(thr_id, throughput, pdata[19], NULL, d_hash[thr_id], order++);

		cudaMemcpy(d_hash1[thr_id], d_hash[thr_id], gpu_ram_size, cudaMemcpyDeviceToDevice);
		x14_shabal512_cpu_hash_64(thr_id, throughput, pdata[19], NULL, d_hash1[thr_id], order++);

		cudaMemcpy(d_hash2[thr_id], d_hash1[thr_id], gpu_ram_size, cudaMemcpyDeviceToDevice);
		x15_whirlpool_cpu_hash_64(thr_id, throughput, pdata[19], NULL, d_hash2[thr_id], order++);

		cudaMemcpy(d_hash3[thr_id], d_hash2[thr_id], gpu_ram_size, cudaMemcpyDeviceToDevice);
		x17_sha512_cpu_hash_64(thr_id, throughput, pdata[19], d_hash3[thr_id]); order++;

		swifftx512_cpu_hash_64(thr_id, throughput, d_hash[thr_id], d_hash1[thr_id], d_hash2[thr_id], d_hash3[thr_id]);

		x17_haval256_cpu_hash_64(thr_id, throughput, pdata[19], d_hash[thr_id], 512); order++;
		tiger192_cpu_hash_64(thr_id, throughput, d_hash[thr_id]);

		lyra2v2_cpu_hash_32(thr_id, throughput, pdata[19], (uint64_t*) d_hash[thr_id], order++);		// add 0 padding????

		streebog_cpu_hash_64(thr_id, throughput, d_hash[thr_id]);
		sha256_cpu_hash_64(thr_id, throughput, d_hash[thr_id]);

		/*
		// zero hash test print
		uint64_t tmp;
		cudaMemcpy(&tmp, d_hash[thr_id], 8, cudaMemcpyDeviceToHost);
		printf("D: %lu\n", tmp);
		*/

		*hashes_done = pdata[19] - first_nonce + throughput;

		work->nonces[0] = cuda_check_hash(thr_id, throughput, pdata[19], d_hash[thr_id]);
		if (work->nonces[0] != UINT32_MAX)
		{
			const uint32_t Htarg = ptarget[7];
			uint32_t _ALIGN(64) vhash[8];
			be32enc(&endiandata[19], work->nonces[0]);
			x22ihash(vhash, endiandata);

			if (vhash[7] <= Htarg && fulltest(vhash, ptarget)) {
				work->valid_nonces = 1;
				work->nonces[1] = cuda_check_hash_suppl(thr_id, throughput, pdata[19], d_hash[thr_id], 1);
				work_set_target_ratio(work, vhash);
				if (work->nonces[1] != 0) {
					be32enc(&endiandata[19], work->nonces[1]);
					x22ihash(vhash, endiandata);
					bn_set_target_ratio(work, vhash, 1);
					work->valid_nonces++;
					pdata[19] = max(work->nonces[0], work->nonces[1]) + 1;
				} else {
					pdata[19] = work->nonces[0] + 1; // cursor
				}
				return work->valid_nonces;
			}
			else if (vhash[7] > Htarg) {
				// x11+ coins could do some random error, but not on retry
				gpu_increment_reject(thr_id);
				if (!warn) {
					warn++;
					pdata[19] = work->nonces[0] + 1;
					continue;
				} else {
					if (!opt_quiet)
					gpulog(LOG_WARNING, thr_id, "result for %08x does not validate on CPU!", work->nonces[0]);
					warn = 0;
				}
			}
		}

		if ((uint64_t)throughput + pdata[19] >= max_nonce) {
			pdata[19] = max_nonce;
			break;
		}

		pdata[19] += throughput;

	} while (pdata[19] < max_nonce && !work_restart[thr_id].restart);

	*hashes_done = pdata[19] - first_nonce;
	return 0;
}

// cleanup
extern "C" void free_x22i(int thr_id)
{
	if (!init[thr_id])
		return;

	cudaThreadSynchronize();

	cudaFree(d_matrix[thr_id]);
	cudaFree(d_hash [thr_id]);
	cudaFree(d_hash1[thr_id]);
	cudaFree(d_hash2[thr_id]);
	cudaFree(d_hash3[thr_id]);

	quark_blake512_cpu_free(thr_id);
	quark_groestl512_cpu_free(thr_id);
	x11_simd512_cpu_free(thr_id);
	x13_fugue512_cpu_free(thr_id);
	x15_whirlpool_cpu_free(thr_id);

	cuda_check_cpu_free(thr_id);

	cudaDeviceSynchronize();
	init[thr_id] = false;
}
