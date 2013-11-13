{
	// generate mid hash using sha256 (header hash)
	uint8 midHash[32];
	sph_sha256_context c256;
	sph_sha256_init(&c256);
	sph_sha256(&c256, (unsigned char*)block, 80);
	sph_sha256_close(&c256, midHash);
	sph_sha256_init(&c256);
	sph_sha256(&c256, (unsigned char*)midHash, 32);
	sph_sha256_close(&c256, midHash);
	// init collision map
	if( __collisionMap == NULL )
		__collisionMap = (uint32*)malloc(sizeof(uint32)*COLLISION_TABLE_SIZE);
	uint32* collisionIndices = __collisionMap;
	memset(collisionIndices, 0x00, sizeof(uint32)*COLLISION_TABLE_SIZE);
	// start search
	// uint8 midHash[64];
	uint8 tempHash[32+4];
	sph_sha512_context c512;
	uint64 resultHashStorage[8*CACHED_HASHES];
	memcpy(tempHash+4, midHash, 32);
	for(uint32 n=0; n<MAX_MOMENTUM_NONCE; n += BIRTHDAYS_PER_HASH * CACHED_HASHES)
	{
		// generate hash (birthdayA)
		//sph_sha512_init(&c512);
		//sha512_update(&c512, tempHash, 32+4);
		//sph_sha512_close(&c512, (unsigned char*)resultHash);
		//sha512(tempHash, 32+4, (unsigned char*)resultHash);
		for(uint32 m=0; m<CACHED_HASHES; m++)
		{
			sph_sha512_init(&c512);
			*(uint32*)tempHash = n+m*8;
			sph_sha512(&c512, tempHash, 32+4);
			sph_sha512_close(&c512, (unsigned char*)(resultHashStorage+8*m));
			//sha512_update_final(&c512, tempHash, 32+4, (unsigned char*)(resultHashStorage+8*m));
		}
		for(uint32 m=0; m<CACHED_HASHES; m++)
		{
			uint64* resultHash = resultHashStorage + 8*m;
			uint32 i = n + m*8;
			//uint64 resultHash2[8];
			//sph_sha512_init(&c512);
			//sha512_update(&c512, tempHash, 32+4);
			//sph_sha512_close(&c512, (unsigned char*)resultHash);
			//sha512(tempHash, 32+4, (unsigned char*)resultHash2);
			//if( memcmp(resultHash, resultHash2, sizeof(resultHash2)) )
			//	__debugbreak();


			for(uint32 f=0; f<8; f++)
			{
				uint64 birthday = resultHash[f] >> (64ULL-SEARCH_SPACE_BITS);
				uint32 collisionKey = (uint32)((birthday>>18) & COLLISION_KEY_MASK);
				birthday %= COLLISION_TABLE_SIZE;
				if( collisionIndices[birthday] )
				{
					if( ((collisionIndices[birthday]&COLLISION_KEY_MASK) != collisionKey) || protoshares_revalidateCollision(block, midHash, collisionIndices[birthday]&~COLLISION_KEY_MASK, i+f) == false )
					{
						// invalid collision -> ignore
						// todo: Maybe mark this entry as invalid?
					}
				}
				collisionIndices[birthday] = i+f | collisionKey; // we have 6 bits available for validation
			}
		}
	}
}