#include"global.h"

#define MAX_MOMENTUM_NONCE		(1<<26)	// 67.108.864
#define SEARCH_SPACE_BITS		50
#define BIRTHDAYS_PER_HASH		8

__declspec(thread) uint32* __collisionMap = NULL;

volatile uint32 totalCollisionCount = 0;
volatile uint32 totalShareCount = 0;

bool protoshares_revalidateCollision(minerProtosharesBlock_t* block, uint8* midHash, uint32 indexA, uint32 indexB)
{
	//if( indexA > MAX_MOMENTUM_NONCE )
	//	printf("indexA out of range\n");
	//if( indexB > MAX_MOMENTUM_NONCE )
	//	printf("indexB out of range\n");
	//if( indexA == indexB )
	//	printf("indexA == indexB");
	uint8 tempHash[32+4];
	uint64 resultHash[8];
	memcpy(tempHash+4, midHash, 32);
	// get birthday A
	*(uint32*)tempHash = indexA&~7;
	sph_sha512_context c512;
	sph_sha512_init(&c512);
	sph_sha512(&c512, tempHash, 32+4);
	sph_sha512_close(&c512, (unsigned char*)resultHash);
	uint64 birthdayA = resultHash[indexA&7] >> (64ULL-SEARCH_SPACE_BITS);
	// get birthday B
	*(uint32*)tempHash = indexB&~7;
	sph_sha512_init(&c512);
	sph_sha512(&c512, tempHash, 32+4);
	sph_sha512_close(&c512, (unsigned char*)resultHash);
	uint64 birthdayB = resultHash[indexB&7] >> (64ULL-SEARCH_SPACE_BITS);
	if( birthdayA != birthdayB )
	{
		return false; // invalid collision
	}
	// birthday collision found
	totalCollisionCount += 2; // we can use every collision twice -> A B and B A
	//printf("Collision found %8d = %8d | num: %d\n", indexA, indexB, totalCollisionCount);
	// get full block hash (for A B)
	block->birthdayA = indexA;
	block->birthdayB = indexB;
	uint8 proofOfWorkHash[32];
	sph_sha256_context c256;
	sph_sha256_init(&c256);
	sph_sha256(&c256, (unsigned char*)block, 80+8);
	sph_sha256_close(&c256, proofOfWorkHash);
	sph_sha256_init(&c256);
	sph_sha256(&c256, (unsigned char*)proofOfWorkHash, 32);
	sph_sha256_close(&c256, proofOfWorkHash);
	bool hashMeetsTarget = true;
	uint32* generatedHash32 = (uint32*)proofOfWorkHash;
	uint32* targetHash32 = (uint32*)block->targetShare;
	for(sint32 hc=7; hc>=0; hc--)
	{
		if( generatedHash32[hc] < targetHash32[hc] )
		{
			hashMeetsTarget = true;
			break;
		}
		else if( generatedHash32[hc] > targetHash32[hc] )
		{
			hashMeetsTarget = false;
			break;
		}
	}
	if( hashMeetsTarget )
	{
		totalShareCount++;
		jhProtominer_submitShare(block);
	}
	// get full block hash (for B A)
	block->birthdayA = indexB;
	block->birthdayB = indexA;
	sph_sha256_init(&c256);
	sph_sha256(&c256, (unsigned char*)block, 80+8);
	sph_sha256_close(&c256, proofOfWorkHash);
	sph_sha256_init(&c256);
	sph_sha256(&c256, (unsigned char*)proofOfWorkHash, 32);
	sph_sha256_close(&c256, proofOfWorkHash);
	hashMeetsTarget = true;
	generatedHash32 = (uint32*)proofOfWorkHash;
	targetHash32 = (uint32*)block->targetShare;
	for(sint32 hc=7; hc>=0; hc--)
	{
		if( generatedHash32[hc] < targetHash32[hc] )
		{
			hashMeetsTarget = true;
			break;
		}
		else if( generatedHash32[hc] > targetHash32[hc] )
		{
			hashMeetsTarget = false;
			break;
		}
	}
	if( hashMeetsTarget )
	{
		totalShareCount++;
		jhProtominer_submitShare(block);
	}
	return true;
}

#define PROCESS_METHOD(x) void protoshares_process_##x (minerProtosharesBlock_t* block)

#undef CACHED_HASHES 
#undef COLLISION_TABLE_BITS
#undef COLLISION_TABLE_SIZE
#undef COLLISION_KEY_WIDTH
#undef COLLISION_KEY_MASK
#define CACHED_HASHES			(32)
#define COLLISION_TABLE_BITS	(30)
#define COLLISION_TABLE_SIZE	(1<<COLLISION_TABLE_BITS)
#define COLLISION_KEY_WIDTH		(32-COLLISION_TABLE_BITS)
#define COLLISION_KEY_MASK		(0xFFFFFFFF<<(32-(COLLISION_KEY_WIDTH)))

PROCESS_METHOD(4096)
#include "protosharesMinerWorker.cpp"

#undef CACHED_HASHES 
#undef COLLISION_TABLE_BITS
#undef COLLISION_TABLE_SIZE
#undef COLLISION_KEY_WIDTH
#undef COLLISION_KEY_MASK
#define CACHED_HASHES			(32)
#define COLLISION_TABLE_BITS	(29)
#define COLLISION_TABLE_SIZE	(1<<COLLISION_TABLE_BITS)
#define COLLISION_KEY_WIDTH		(32-COLLISION_TABLE_BITS)
#define COLLISION_KEY_MASK		(0xFFFFFFFF<<(32-(COLLISION_KEY_WIDTH)))

PROCESS_METHOD(2048)
#include "protosharesMinerWorker.cpp"

#undef CACHED_HASHES 
#undef COLLISION_TABLE_BITS
#undef COLLISION_TABLE_SIZE
#undef COLLISION_KEY_WIDTH
#undef COLLISION_KEY_MASK
#define CACHED_HASHES			(32)
#define COLLISION_TABLE_BITS	(28)
#define COLLISION_TABLE_SIZE	(1<<COLLISION_TABLE_BITS)
#define COLLISION_KEY_WIDTH		(32-COLLISION_TABLE_BITS)
#define COLLISION_KEY_MASK		(0xFFFFFFFF<<(32-(COLLISION_KEY_WIDTH)))

PROCESS_METHOD(1024)
#include "protosharesMinerWorker.cpp"

#undef CACHED_HASHES 
#undef COLLISION_TABLE_BITS
#undef COLLISION_TABLE_SIZE
#undef COLLISION_KEY_WIDTH
#undef COLLISION_KEY_MASK
#define CACHED_HASHES			(32)
#define COLLISION_TABLE_BITS	(27)
#define COLLISION_TABLE_SIZE	(1<<COLLISION_TABLE_BITS)
#define COLLISION_KEY_WIDTH		(32-COLLISION_TABLE_BITS)
#define COLLISION_KEY_MASK		(0xFFFFFFFF<<(32-(COLLISION_KEY_WIDTH)))

PROCESS_METHOD(512)
#include "protosharesMinerWorker.cpp"

#undef CACHED_HASHES 
#undef COLLISION_TABLE_BITS
#undef COLLISION_TABLE_SIZE
#undef COLLISION_KEY_WIDTH
#undef COLLISION_KEY_MASK
#define CACHED_HASHES			(32)
#define COLLISION_TABLE_BITS	(26)
#define COLLISION_TABLE_SIZE	(1<<COLLISION_TABLE_BITS)
#define COLLISION_KEY_WIDTH		(32-COLLISION_TABLE_BITS)
#define COLLISION_KEY_MASK		(0xFFFFFFFF<<(32-(COLLISION_KEY_WIDTH)))

PROCESS_METHOD(256)
#include "protosharesMinerWorker.cpp"

#undef CACHED_HASHES 
#undef COLLISION_TABLE_BITS
#undef COLLISION_TABLE_SIZE
#undef COLLISION_KEY_WIDTH
#undef COLLISION_KEY_MASK
#define CACHED_HASHES			(32)
#define COLLISION_TABLE_BITS	(25)
#define COLLISION_TABLE_SIZE	(1<<COLLISION_TABLE_BITS)
#define COLLISION_KEY_WIDTH		(32-COLLISION_TABLE_BITS)
#define COLLISION_KEY_MASK		(0xFFFFFFFF<<(32-(COLLISION_KEY_WIDTH)))

PROCESS_METHOD(128)
#include "protosharesMinerWorker.cpp"

#undef CACHED_HASHES 
#undef COLLISION_TABLE_BITS
#undef COLLISION_TABLE_SIZE
#undef COLLISION_KEY_WIDTH
#undef COLLISION_KEY_MASK
#define CACHED_HASHES			(32)
#define COLLISION_TABLE_BITS	(23)
#define COLLISION_TABLE_SIZE	(1<<COLLISION_TABLE_BITS)
#define COLLISION_KEY_WIDTH		(32-COLLISION_TABLE_BITS)
#define COLLISION_KEY_MASK		(0xFFFFFFFF<<(32-(COLLISION_KEY_WIDTH)))

PROCESS_METHOD(32)
#include "protosharesMinerWorker.cpp"

#undef CACHED_HASHES 
#undef COLLISION_TABLE_BITS
#undef COLLISION_TABLE_SIZE
#undef COLLISION_KEY_WIDTH
#undef COLLISION_KEY_MASK
#define CACHED_HASHES			(32)
#define COLLISION_TABLE_BITS	(21)
#define COLLISION_TABLE_SIZE	(1<<COLLISION_TABLE_BITS)
#define COLLISION_KEY_WIDTH		(32-COLLISION_TABLE_BITS)
#define COLLISION_KEY_MASK		(0xFFFFFFFF<<(32-(COLLISION_KEY_WIDTH)))

PROCESS_METHOD(8)
#include "protosharesMinerWorker.cpp"