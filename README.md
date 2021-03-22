# PES_5_PBKDF2
Run Time of the program:

The runtime of the programs after making below mentioned changes is  7161 ms.

Size of .text segment:

The size of the .text segment after optimization is 20964 bytes


Changes made in the code:

1.	In file isha.c, the equations for value of W[t] in the function ISHAProcessMessageBlock() was reduced from 4 to 1, performing OR operation as given below:


  W[t] =   (((uint32_t) ctx->MBlock[t * 4]) << 24)            | 
              (((uint32_t) ctx->MBlock[t * 4 + 1]) << 16)     | 
              (((uint32_t) ctx->MBlock[t * 4 + 2]) << 8)      | 
              (((uint32_t) ctx->MBlock[t * 4 + 3]));


2.	In file isha.c, one iteration of the for loop dealing with values of A, B, C, D, and E was taken out of the loop as shown below:



temp = (ISHACircularShift(5,A) + ((B & C) | ((~B) & D)) + E + W[0]) & 0xFFFFFFFF;
  	E = D;
  	D = C;
  	C = ISHACircularShift(30,B);
  	B = A;
  	A = temp;
  	for(t = 1; t < 16; t++) {
temp = (ISHACircularShift(5,A) + ((B & C) | ((~B) & D)) + E + W[t]) & 0xFFFFFFFF;
    	E = D;
    	D = C;
    	C = ISHACircularShift(30,B);
    	B = A;
    	A = temp;
      }

3.	In the file isha.c’s ISHAResult() function, the bytes of MD[0] to MD[4] were swapped to make them little endian and an 8 bit pointer pointing at MD was created. Then in the following for loop, pointer was used to assign values to digest_out[].



   ctx->MD[0] = __builtin_bswap32(ctx->MD[0]);
   ctx->MD[1] = __builtin_bswap32(ctx->MD[1]);
   ctx->MD[2] = __builtin_bswap32(ctx->MD[2]);
   ctx->MD[3] = __builtin_bswap32(ctx->MD[3]);
   ctx->MD[4] = __builtin_bswap32(ctx->MD[4]);
   uint8_t *MD_ptr = (uint8_t *) &ctx->MD;

  	for (int i=0; i<20; i+=4) {

	  digest_out[i] = *(MD_ptr + i);
	  digest_out[i+1] = *(MD_ptr + i + 1);
	  digest_out[i+2] = *(MD_ptr + i + 2);
	  digest_out[i+3] = *(MD_ptr + i + 3);

  } 


4.	There was a part in the function ISHAInput isha.c (containing if else statements) which was redundant and did not make any changes to test results as well as production output. This part (mentioned below) of the function was removed.


	if (!length)
  {
    return;
  }

  if (ctx->Computed || ctx->Corrupted)
  {
    ctx->Corrupted = 1;
    return;
  }
______________________________________


    ctx->Length_Low &= 0xFFFFFFFF;
    if (ctx->Length_Low == 0)
    {
      ctx->Length_High++;
      /* Force it to 32 bits */
     // ctx->Length_High &= 0xFFFFFFFF;
      if (ctx->Length_High == 0)
      {
        /* Message is too long */
        ctx->Corrupted = 1;
      }
    }



5.	In the function F() of pbkdf2.c, the blkidx bytes are swapped to make it little endian and an 8 bit pointer pointing at blkidx was created. Then in the following for loop, pointer was used to assign values to saltplus[].



      blkidx = __builtin_bswap32(blkidx);
      int8_t *ptr_bid = (uint8_t *) &blkidx;

  	  saltplus[i] = *ptr_bid;
    	saltplus[i+1] = *(ptr_bid + 1);
    	saltplus[i+2] = *(ptr_bid + 2);
      saltplus[i+3] = *(ptr_bid + 3);


6.	Declared functions ISHAProcessMessageBlock(), and ISHAPadMessage() as static inline.

7.	Replaced the 3 for loops inside the “else” of function hmac_isha() with following code:


for (i=0; i<ISHA_BLOCKLEN; i++)
	{
		  if(i<key_len)
			keypad[i] = key[i];
		  else
			keypad[i] = 0x00;
		  ipad[i] = keypad[i] ^ 0x36;
		  opad[i] = keypad[i] ^ 0x5c;
}


8.	Apart from these changes, appropriate header files were included in required files.
