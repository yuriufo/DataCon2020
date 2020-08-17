rule _match_8 {
   meta:
      description = "black - from files 0f9eddc5e740edcd96e2f32d6acc3bb3, 8a490aa2517646411b6ea1383f17bbd1, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 5f52a27f400818807d2693e1a52260ad, e28e3404155556ecafff204356fcc5f0, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, af408f884178b56843b9f7324bcdefb4, a3b4afa503657e7a327934ddd231887e, b9280790ed58987ab2af68537ad18d6d, b1b0580af0e8fa730486561255426f38, 26fc98d7481f9b494ecbfebacdcbeab3, ae33c5c9544d63463cca74c42a556983, ee3f5f355249823f286f389ce0567002, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 86d7666073561a5d0ca494d80eae3e5e, 9b3518901fb21e67bfd3986cdcded31c, 99fe45ec1a50c0413a6dcb1d23b754f9, e97524afde7b751f6b024fa4798bdf51, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash2 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash3 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash4 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash5 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash6 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash7 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash8 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash9 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash10 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash11 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash12 = "c92d9638c8fb2b0556802ea87082be829f50dd7d29579a1a893ade35bd7a9256"
      hash13 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash14 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash15 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash16 = "b95f40cce47499183ef95d6d56b8b5deed0d99a413a8bd7067200c5b1ae752a9"
      hash17 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash18 = "ade656b212a4bef11d70720679ec7fd91586a9507448634cd716178ed908e509"
      hash19 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash20 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash21 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash22 = "ee7ab7d8bd4643e2f2d63bc0329b21c6d3437beea13fc379ee7fbfc0e326d0f5"
      hash23 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash24 = "b81e7c41d4c6cec4c6f99f9e577c8335c685bf09351af664d82c2a97bc12b89c"
      hash25 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash26 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = "__kernel void find_shares(__global const uint64_t* hashes,uint64_t target,uint32_t start_nonce,__global uint32_t* shares)" fullword ascii
      $s2 = "void blake2b_512_process_single_block(ulong *h,const ulong* m,uint blockTemplateSize)" fullword ascii
      $s3 = "blake2b_512_process_single_block(hash,m,blockTemplateSize);" fullword ascii
      $s4 = "__kernel void blake2b_initial_hash(__global void *out,__global const void* blockTemplate,uint blockTemplateSize,uint start_nonce" ascii
      $s5 = "__kernel void blake2b_initial_hash(__global void *out,__global const void* blockTemplate,uint blockTemplateSize,uint start_nonce" ascii
      $s6 = "__kernel void execute_vm(__global void* vm_states,__global void* rounding,__global void* scratchpads,__global const void* datase" ascii
      $s7 = "__local exec_t* execution_plan=(__local exec_t*)(execution_plan_buf+(get_local_id(0)/8)*RANDOMX_PROGRAM_SIZE*WORKERS_PER_HASH*si" ascii
      $s8 = "__kernel void execute_vm(__global void* vm_states,__global void* rounding,__global void* scratchpads,__global const void* datase" ascii
      $s9 = "__local exec_t* execution_plan=(__local exec_t*)(execution_plan_buf+(get_local_id(0)/8)*RANDOMX_PROGRAM_SIZE*WORKERS_PER_HASH*si" ascii
      $s10 = "__kernel void JH(__global ulong *states,__global uint *BranchBuf,__global uint *output,ulong Target,uint Threads)" fullword ascii
      $s11 = "__kernel void Skein(__global ulong *states,__global uint *BranchBuf,__global uint *output,ulong Target,uint Threads)" fullword ascii
      $s12 = "__kernel void Groestl(__global ulong *states,__global uint *BranchBuf,__global uint *output,ulong Target,uint Threads)" fullword ascii
      $s13 = "__kernel void Blake(__global ulong *states,__global uint *BranchBuf,__global uint *output,ulong Target,uint Threads)" fullword ascii
      $s14 = "void blake2b_512_process_double_block_name(ulong *out,ulong* m,__global const ulong* in)" fullword ascii
      $s15 = "__global uint* jit_emit_instruction(__global uint* p,__global uint* last_branch_target,const uint2 inst,int prefetch_vgpr_index," ascii
      $s16 = "int registerLastChangedAtBranchTarget[8]={ -1,-1,-1,-1,-1,-1,-1,-1 };" fullword ascii
      $s17 = "blake2b_512_process_double_block_name(hash,m,p);" fullword ascii
      $s18 = "__global uint* last_branch_target=p;" fullword ascii
      $s19 = "__global uint* jit_emit_instruction(__global uint* p,__global uint* last_branch_target,const uint2 inst,int prefetch_vgpr_index," ascii
      $s20 = "SKEIN_INJECT_KEY(p,s);" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 19000KB and ( 8 of them )
      ) or ( all of them )
}

rule _match_24 {
   meta:
      description = "black - from files 905eeda0ddf717b45bb294b227e6d8ae, 0f9eddc5e740edcd96e2f32d6acc3bb3, 8a490aa2517646411b6ea1383f17bbd1, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 5f52a27f400818807d2693e1a52260ad, e28e3404155556ecafff204356fcc5f0, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, af408f884178b56843b9f7324bcdefb4, a3b4afa503657e7a327934ddd231887e, b9280790ed58987ab2af68537ad18d6d, b1b0580af0e8fa730486561255426f38, 26fc98d7481f9b494ecbfebacdcbeab3, ae33c5c9544d63463cca74c42a556983, ee3f5f355249823f286f389ce0567002, 9a07ca40de9c85495231302023c6a74a, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 86d7666073561a5d0ca494d80eae3e5e, 9b3518901fb21e67bfd3986cdcded31c, 5e68b441f8c061285f596c5e0731514d, 99fe45ec1a50c0413a6dcb1d23b754f9, e97524afde7b751f6b024fa4798bdf51, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "a28878f5880b8a1c506258dd39b459cec616f79100afe006b4779525b8a937a3"
      hash2 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash3 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash4 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash5 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash6 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash7 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash8 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash9 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash10 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash11 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash12 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash13 = "c92d9638c8fb2b0556802ea87082be829f50dd7d29579a1a893ade35bd7a9256"
      hash14 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash15 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash16 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash17 = "b95f40cce47499183ef95d6d56b8b5deed0d99a413a8bd7067200c5b1ae752a9"
      hash18 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash19 = "ade656b212a4bef11d70720679ec7fd91586a9507448634cd716178ed908e509"
      hash20 = "ea9d91772dd86455d5bf25c080ed859faae39c7085abb5de0b3142a397e7f131"
      hash21 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash22 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash23 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash24 = "ee7ab7d8bd4643e2f2d63bc0329b21c6d3437beea13fc379ee7fbfc0e326d0f5"
      hash25 = "f56df2b39807ac070aa06c977177aff8c79c48f399fc5b8c904df6c898bf431a"
      hash26 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash27 = "b81e7c41d4c6cec4c6f99f9e577c8335c685bf09351af664d82c2a97bc12b89c"
      hash28 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash29 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = "2e395c4b394b652e" ascii /* hex encoded string '.9\K9Ke.' */
      $s2 = "2B7D4F32322B647D" ascii /* hex encoded string '+}O22+d}' */
      $s3 = "2769533A3A277469" ascii /* hex encoded string ''iS::'ti' */
      $s4 = "246C54383824706C" ascii /* hex encoded string '$lT88$pl' */
      $s5 = "2030405030507020" ascii /* hex encoded string ' 0@P0Pp ' */
      $s6 = "3A4E622C2C3A584E" ascii /* hex encoded string ':Nb,,:XN' */
      $s7 = "362d6c772d774136" ascii /* hex encoded string '6-lw-wA6' */
      $s8 = "2878483030286078" ascii /* hex encoded string '(xH00(`x' */
      $s9 = "26354c5f355f7926" ascii /* hex encoded string '&5L_5_y&' */
      $s10 = "22665A3C3C227866" ascii /* hex encoded string '"fZ<<"xf' */
      $s11 = "322b647d2b7d4f32" ascii /* hex encoded string '2+d}+}O2' */
      $s12 = "3e217c6321635d3e" ascii /* hex encoded string '>!|c!c]>' */
      $s13 = "3a2774692769533a" ascii /* hex encoded string ':'ti'iS:' */
      $s14 = "3824706c246c5438" ascii /* hex encoded string '8$pl$lT8' */
      $s15 = "365A7E242436485A" ascii /* hex encoded string '6Z~$$6HZ' */
      $s16 = "3028607828784830" ascii /* hex encoded string '0(`x(xH0' */
      $s17 = "21635D3E3E217C63" ascii /* hex encoded string '!c]>>!|c' */
      $s18 = "2c3a584e3a4e622c" ascii /* hex encoded string ',:XN:Nb,' */
      $s19 = "283c50443c446c28" ascii /* hex encoded string '(<PD<Dl(' */
      $s20 = "3c22786622665a3c" ascii /* hex encoded string '<"xf"fZ<' */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 19000KB and ( 8 of them )
      ) or ( all of them )
}

rule _match_56 {
   
   strings:
      $s1 = "m64j___hw.dll" fullword ascii
      $s2 = "K0U0b0l0p" fullword ascii /* base64 encoded string '+E4oIt' */
      $s3 = "4 4$4(4,4044484<4@" fullword ascii /* hex encoded string 'DD@DHD' */
      $s4 = "\"=5=<=B=" fullword ascii /* hex encoded string '[' */
      $s5 = ">#>)>/>5>0" fullword ascii /* hex encoded string 'P' */
      $s6 = ": :(:,:0:4:8:<:@:D:L:P:T:X:\\:`:d:h:t:|:" fullword ascii
      $s7 = "Q\"DZ:\"?" fullword ascii
      $s8 = "D:L:T:\\:" fullword ascii
      $s9 = "9-9B9N9" fullword ascii /* Goodware String - occured 1 times */
      $s10 = "9~iFiW%m " fullword ascii
      $s11 = "HlGD|Bh" fullword ascii
      $s12 = "2.2V2j2" fullword ascii /* Goodware String - occured 1 times */
      $s13 = "?#?i?{?" fullword ascii /* Goodware String - occured 1 times */
      $s14 = "80<0@0D0H0X0\\0" fullword ascii /* Goodware String - occured 1 times */
      $s15 = "`=h=p=x=" fullword ascii /* Goodware String - occured 1 times */
      $s16 = "2Q3W3a3" fullword ascii /* Goodware String - occured 1 times */
      $s17 = "4'4E4S4" fullword ascii /* Goodware String - occured 1 times */
      $s18 = "D4H4L4P4" fullword ascii /* Goodware String - occured 1 times */
      $s19 = "7.8:8[8" fullword ascii /* Goodware String - occured 1 times */
      $s20 = "4 9$9(9,9094989<9@9D9H9L9P9T9X9\\9`9d9h9l9p9t9x9|9" fullword ascii /* Goodware String - occured 1 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule _match_58 {
   meta:
      description = "black - from files 568c6b1b3531ebd169c2a0ed65e62ef2, 945c640a20136010a058c9b4585ee47d, 4cc2fe8853b10d5f0b3149197d6663e4, ddcb5a9db519905658d881fa4103aa9a, 8a0d9d21af0356ddb2c82938f44e76d6, bed6e71336cb5309922a8cc3703ae7bd, 28281dec5a549c89ed55cc716069880c, 2ec73fee140c557a280e903dca386d4c, 45666ebea0ee088eb73616ad7eb16bb8, 0cc9fc7f24baf15588f438668d1eb27b, 3563aa2973ecef6681fb05e8b8d3eb13, ebef3b340f36cadf104a4a4630c15e2a, 6ac3b36f512b8f24cf6b52968d1243db, 06bc107a1237a49172bcc05fa64b3c72, 664d97ce12fe1690a5577ff601450a2f, 974c78abe08937557dd3f76ddda86c6e, c6f26ae8372c6b5550268ea143f6a6b2, 866a36906d5a0bf307e5424e67d55855, 00e69728719213a306c42e2abc8960ab, 032f9521303b5f0290d454ace3b74092, 31977b7f611099363326b3b5f10cdc16, 138650bdcf49b37f28ba9442aee758e1, 001e98ad444991d549d32ccda6d0f163, 578701d99783505703e6c79edf03de38, caab1031e15330c70aae8eb59e9e990c, c5d0fb9299c61e0e4c4811a7d3adec0e, b3a7cac730bc9c86f93be1b9e19e8ef2, c2e6e8c7c69afc5dc3bfdf4584df0e26, d669cf0445190e3b99678f6117c10f44, 495e6dae9afeb153886008d2c2f8e904, 86fe125eb293f34f113ac369dd82ad8e, b64fc678f1ffee948e1467bea12b5151, b821ac143b1ef6255ec26927b513721f, 8089bfe80c3950ab2c3aa9cea4da897c, 438dfb539ffb2275e5cde2557c9fafc4, f77112868bc3c7548136fe3ba98173bb, 26f5653be871bbf96ae6b14a9d90e16a, 6ceec8b6bc987c3944f85d585298fcb4, c4beabd1eed6215f933417c6c71a8c38, bf5c98c53c232481dea1c844adb260c2, 6d5f2f5b87b36569402723eff364fb3b, fd15788b6f10fd2b40b490de031036e8, 63ec990cf6b2d2dd9993f534b72f363e, 68006d734fa1ff1112cdcb1980c2045f, c75488f8a3f9c68cb4595c93aa198ba6, 05a33d00fbe7015caa1dec3a032db941, bf6a20945af16f099345b8996e4c3105, cf02f19e6e3db88f5165808cef0ff18f, 0553b99673cec4aae84126595799d04b, 61f0f4ec78a00d0b0f90c9ddec70c882, 0a4ea2bc69d0f743172a94d9c5d44d10, cc068a79d76a8fd587ccbdf0457500a4, d5ad9957fda245d5b443ac0ef29fac36, ca6fdcfa15dfd53fd86e106f02954b2e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "d8bb9838164d5239c7865fb0d647fd7690aa88e20afc6e64f3571501f8cdaeed"
      hash2 = "94f14fd7f48959be578b0a8eb1665ad7bca238dcbaa5dde93166cd812d30117a"
      hash3 = "e3889d79eb9b2eb5cfe48bf7890c131f5f78bdfa07f9b6b1c1be68b0f34f5469"
      hash4 = "5f3f2312d38f6661ab6a2cbfa62aa69aa1c654560baee42aeb11acd7975c5404"
      hash5 = "13318a5072747bbea5274cbeffa70a4b54a846227b522b2305fa9084e50eedfe"
      hash6 = "7e94c91042d2bb54fa4799916995531f5e8e60a4006b454b7efc3b41114e9997"
      hash7 = "027193e7e65434cc2cb02ccb9630adef451836ff749ac53567425df89d554dbd"
      hash8 = "9d9577f969b681660485deaa86d98a3eac91c40183274e441a1430ea9df3704a"
      hash9 = "3f7f4d46bc6a80eefd05ae0a68790a91cd9793f9c9610fa35f52334cae7588ed"
      hash10 = "a56b3fd3adb9b82aeb6fbe87d6f3c3abab99b2ed66e39dc919caf1f3a41ec39a"
      hash11 = "80cdeb8403a52b68b2111fa82eeccebc348ade40d3c310c885558ae239f9191b"
      hash12 = "d14a8879d6f5494fcde844418ae12942d10d68cf1251e53b8bf32a7e32c1c3ca"
      hash13 = "328b16103c3e45530336c8f8fed73270f3978825856186dd8b762a25cd2d66f2"
      hash14 = "ad2761ceae4efbdf61fa1e3b14eb63e9e7be18aa653fe81b48ae47f3720f5e77"
      hash15 = "2782d85b803ddd1e2f6f669bdc63e04be83df42aada87f95642c102f3634fc98"
      hash16 = "0251908b98972dfc0f4be031a52d727b3a2ec61dec11b714c69e9dc43859c227"
      hash17 = "393d1196202090c0fa7b91d9cba1e0813c10cc5b9a9ddc95f94f73f24d42bf85"
      hash18 = "0c7cae8a6dfda31f1301117cfcb35718c8dc339d3ecc8b59bfd6d352462be306"
      hash19 = "d8ebd67551e9b8e484716a3db342de47b755ce14787ad64e1be2a3c35f866449"
      hash20 = "42c5e48280453ae905f0225a26bb46696fe6137edad53a71292572dd0e29d453"
      hash21 = "ada2cdb11b677dc930aa8efaddd64b76fcc13237be75678fc22d3ee07a1b01c6"
      hash22 = "c1ac650fc52b93f29917b3f8e31ae5fbc454e4db5393a43a80289e6e73b1cef6"
      hash23 = "fffb60f3530e2d8ead6ba2e7af33e1d4ccf7374f6cfedf29b31be200f3d35d85"
      hash24 = "5fb55c1ea3228126438d5adf84bda429f7b34c6f2fd1ba13bf28998b0290a984"
      hash25 = "4f4ccc67dfd75b5b6381ca103fb59db0993074fdf47c6207ffcf3445b157705d"
      hash26 = "14ea784bb6f0eb3d4d02671333c6ce6017313af3ae6b7bf34a9014be601ce811"
      hash27 = "1a806c8ce5d8739af51ae29f6bd0ebfa81bc2902defe839c180e580d529d76cf"
      hash28 = "8e3ebdd236e5d5f86901e622a44722a337bcae4c407b6788180e6ba9d45da1b4"
      hash29 = "ec0c435c5b028ec2a5032b55093b2d58eaa4d1b6c3393fb3c86bc4d62e98ed4f"
      hash30 = "75716bdc15998b47f345c329f67dcdba69cbb3307185223a5b3aadf6a7a111d3"
      hash31 = "0ceff53c08811cd2beb63a05540983ac66990e73035d6def77e45746c54c64b1"
      hash32 = "9d56b44a7d661f4f19407e3a1cbd3894b676084dd13f04bddcf705aacc4a25c8"
      hash33 = "97dfbe369a4443f6fdb3cc5baf94297a9390bc9477a8bb40a593fc34bda8dd99"
      hash34 = "c849aaf6ffc518407bc3fdbe6a799717cd8b7ab9c311a157dc9c6fa0b92b731e"
      hash35 = "ad441eb91d8c1a9e3ab9236ad5aa21f6921b9d17bcd53f8f6ba7f71f142fe371"
      hash36 = "d164adbcc75129eac9e51801634f8c24659e8f19a3d8dfb5ee09bfe57b802d6c"
      hash37 = "59cf778386c70416b41727d8b3350f65e9a2161959d6a3bbf67ec3257988cd61"
      hash38 = "70b4b95db10476f42efe0bd9ca6f330adebd3c781f9d3085523023c4656a1f8d"
      hash39 = "f915e58bac90e89a2a9c5809363131d881be6b09f0a1ad8602a8075246b22898"
      hash40 = "93d60abf15b2c5ef5847c70af31bad188db2eaa7cc6f1eb46bb851de71a3b9b7"
      hash41 = "5928d3cbe2c423aa672423b72608d2b609f4a24758d42c782ba3e25c85bca595"
      hash42 = "e9ea35b72b2b66680bc0ca9cd0f93c4934bbb0263fda63c19202d698976aaf54"
      hash43 = "3f31b4d2ca54b90c109f9a4444d080d40351769ea6354e817cf43ba5e44eb190"
      hash44 = "ea7b50030a83f64a9acbf6732567de2f155a762db8dacca4ad00e5e971403f04"
      hash45 = "ce386e19019fbd1edb3ebd5379a74e7c3dd1b18525cb7f8a8c8883b6663c218f"
      hash46 = "f6ba827dbf74c8cc8614f10298f7ee2ffd39d24367dad0cf09ef515c14785da4"
      hash47 = "5547725b534420b1a6ea435f756f4c6d35588b1cd811f14ae091721f2594e856"
      hash48 = "07c6661d8d1b4bdc3da5074e6e9739db100be2037c75f9c390df3174f4ae38c8"
      hash49 = "29899e0ead4381d8b560799d595b38d12520f07512639aeca7ee636d469ba3ab"
      hash50 = "2c17365876f6ad394b63f2b08115bc967f24ff304cf4ea6d5697e557ebd1716c"
      hash51 = "c82140ef3c150e830843707005802e2f201935e4cf315949b9f2410c6ed4446e"
      hash52 = "74b87ab37c24f819570e8c418535d3c03235661c764ecbb968571b7a49323bec"
      hash53 = "05db9268b60613003145246001646d12396a9becea41a15bb88dc2a283cf081c"
      hash54 = "97c689f7732beb1180b70bf6536a4037990459600175d49ab14734239c77b4d6"
   strings:
      $s1 = "mkjfedmod.dll" fullword ascii
      $s2 = "Mozilla/5.0 (compatible; MSIE 7.0; Windows NT %d.%d)" fullword ascii
      $s3 = ";+;3;\\;c;" fullword ascii /* hex encoded string '<' */
      $s4 = "4'4.4@4^4)5" fullword ascii /* hex encoded string 'DDE' */
      $s5 = "<\"=,=2=8=" fullword ascii /* hex encoded string '(' */
      $s6 = "ip address currently banned" fullword ascii
      $s7 = "7 7$7(7,707470" fullword ascii /* hex encoded string 'wwptp' */
      $s8 = "X:\\:`:d:h:l:p:" fullword ascii
      $s9 = "%s (%d) %sx64 %sAES-NI" fullword ascii
      $s10 = "SUVWh06" fullword ascii
      $s11 = "9@:c:}:" fullword ascii /* Goodware String - occured 1 times */
      $s12 = "register_dsrc" fullword ascii
      $s13 = ":5:W:{:" fullword ascii /* Goodware String - occured 1 times */
      $s14 = "4F5N5t5" fullword ascii /* Goodware String - occured 1 times */
      $s15 = "66)6:6" fullword ascii /* Goodware String - occured 1 times */
      $s16 = ";T$,uS" fullword ascii /* Goodware String - occured 1 times */
      $s17 = "405Z5b5" fullword ascii /* Goodware String - occured 1 times */
      $s18 = ";D$0s" fullword ascii /* Goodware String - occured 1 times */
      $s19 = "5f6n6v6~6" fullword ascii /* Goodware String - occured 1 times */
      $s20 = "7bad array new length" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule _match_60 {
   meta:
      description = "black - from files c0c47b20d4a0acf33130efd241dcecb7, 9f4d9aaa17f43e35b68909cae6e2963e, 6638373439ec194078e3e6867a68e936, 0aa72cf7f23aeb9a055d869b1352ab05, b8c541161474bdb653f90b25c266bf32, 5d7241a98f223e091f32498665b4b205, 2ca8a43dc76db43db4d7af35859a770f, 5d07e7441e45078f8cbcf62fcd6dae0a, 96d989641197f46942207b72fa661820, 416610b942ffaaf0b83b20b1591a1623, e90d08f6690a46b566c3381bebdc38af, 52f16c77af20982d5a0897b7e81beff8, 66532a0adab204c8239633eb49d07ce1, b74d586186adaa3cc2fe40d495263c84, cd0bbad6af58ff1e1a6dd4406c7b7ec0, 8b171722624178254ba65819889b41f2, 15630701c421ca2fcfecfd91622a30b3, 07b636a8bf645b7c512be756a8b69fe2, 05ee0d9bb5b1789da51fb0c022b33268, 0e9a01b4b3cc55564426f0d296d62846, bcdf3c943e6aa549e8753c32ded15360, 573bb9ebe60a259c6e0a890a74fa5a9e, 1297fa863626ddc4c5f5d9f6c5e5cb2f"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "5f4a3d3b5b21106dc72cca87921dc2788b3c4b70935eeca58eadb63a3518063f"
      hash2 = "bb53f0db836794aaedc9bccdd044105dbaa19ccb3a8e4583b11a29d26b56ca7c"
      hash3 = "c2e3029089ee805aadddf739c0c3018e7a833760b98d26b25f45e88f15cb11b6"
      hash4 = "503a30682bed0e07f14dbaedbfa0ad56398923d31aeca6efbda85f649b2f4ecc"
      hash5 = "3a800217027270f563a4721ba7df9ec5e101aeca3f27997ebd634e71abfd634f"
      hash6 = "b2dabbc952e916996f8ab3e3b868be538e00cdd2095450a296338d37da1afbb2"
      hash7 = "53cc5abba6e39f54eecb9c0e4f80bf0a3df71982b3614dbaac48325c223c24ca"
      hash8 = "2044f43871ea0b24f228f0a30760b9bdbef26056726dc918e0bc31d130a4fd28"
      hash9 = "1048876df466fc480e46db03dacf774a0df61df51d3efb2876426321c60fe8b8"
      hash10 = "d5001e36a8c10501ebc0b03d1ec750e7657e0e7f3524a11c18cfbd3b06b7d634"
      hash11 = "e85181b8b3ba26ff40b9258fefc5fb6e974cfb99474ad29f445d6275ca6f74cc"
      hash12 = "a0f204d460f124f0f59b78ac6cc5dfcb6b1ced2e142185ff194435ff4016a788"
      hash13 = "cda8030bbabb0f8780de77912c63088d10c78b99bd5d4caadc27a3f8b8ec0a53"
      hash14 = "69de46a3d1262baa013ffd1f68c7eb5da4c988841335cf53278bd9a1087639cf"
      hash15 = "cf98b7c3daf69163ba7b2dd76538a0d9e19f63cb0d5d359ad529119d4f448d67"
      hash16 = "b9727e82fb6c723b18fb7a3906b5db97c0a0fc33e4808d10cb7329875973ea1a"
      hash17 = "a79e724b8b19334d676ac488569ca70f2737065495736b322c85f5edc8867f03"
      hash18 = "d8b1007592166e012ef7f1c709d35384481ded2c670add63edbb25f8d39c1a9f"
      hash19 = "62a098d7034672832209bc3495cf8a0a461542d816058dcc690009b2d2a44e85"
      hash20 = "6e2fd44944b0b6adf608d298aa78781bfc7bf9ab29c0644132eea183ff5e58d9"
      hash21 = "06e263554cbc8aad32eeedf2ca5374f5cde628312d5b61d61bdaaddc62c2e252"
      hash22 = "06c4fd2b55e3691fca7ceee681fb4858a7afcca05d9a2da86e9d9d4315294d9c"
      hash23 = "7b183d3b61275360f6715097e51be6bd47723899ae7d6d48085b766f01f2dee4"
   strings:
      $s1 = "6&6.686=6" fullword ascii /* hex encoded string 'fhf' */
      $s2 = ".>4>:>?>E>" fullword ascii /* hex encoded string 'N' */
      $s3 = "=\"=-=2=7=[=" fullword ascii /* hex encoded string ''' */
      $s4 = "KckX\\v\\W" fullword ascii
      $s5 = "0$0D0P0p0" fullword ascii /* Goodware String - occured 1 times */
      $s6 = "iNsYmwF" fullword ascii
      $s7 = ">>&>,>" fullword ascii /* Goodware String - occured 1 times */
      $s8 = "3$4H4T4\\4t4" fullword ascii /* Goodware String - occured 1 times */
      $s9 = "nhEc3~<" fullword ascii
      $s10 = "034383<3" fullword ascii /* Goodware String - occured 1 times */
      $s11 = "|EgRf44$~r" fullword ascii
      $s12 = "4'4C4`4n4" fullword ascii /* Goodware String - occured 1 times */
      $s13 = "L2P2T2X2\\2" fullword ascii /* Goodware String - occured 2 times */
      $s14 = "@<`<|<" fullword ascii /* Goodware String - occured 2 times */
      $s15 = "7!7+7;7" fullword ascii /* Goodware String - occured 2 times */
      $s16 = "><>E>P>" fullword ascii /* Goodware String - occured 2 times */
      $s17 = "545<5H5" fullword ascii /* Goodware String - occured 2 times */
      $s18 = "T:\\:d:l:t:|:" fullword ascii /* Goodware String - occured 3 times */
      $s19 = "\\.B|/7*" fullword ascii
      $s20 = "\\;l;t;" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _match_82 {
   meta:
      description = "black - from files 19176a32e4bd18544c4ab624755737b5, 48935d567681844f7ea1b722365169f6, df58eb906800cd90ec6c28396036150a, db04155d60feb5141e9da63f0d41b835, 9e353fd5f82d5c25c5cfc7b0e8ba430b, c7b986b67364b7ef50d9aedd54f2e48d, ca7a9c16f205c9b2dbb06791dc70da8a, ec57d8cc725c307f29c32134dfa94557, ea320e82b0458a2a4b830a66c5451df8, 0492f2a2f0192956d126fb3d357fea7d, 613ec5127caf1e796ae587358fcbb515, baac2d6f7648809675f0ab5984e326a0, f09f18e7f15dbe8319922b158f60ec19, e60077c1abbf72bbc80f4d05abcf39b4, 8094fc03cccd28280842d70618125e29, 0a28f126a2c8481cb0bb76c7365c35a7, 64550e15998af388224e75dbd5948f38, 32d8b79a2213c0b0116afb8c4f8d9ab7, 5bf18e52357bdf8376e2caf14e72c55a, 117ca68d168e0f8a83232845f062bcd5, dce7d6c25f4939df011b45d720a5c14a, 8db77740e4775ef51224b0fb8975b601, 9d9ca1ba4bc52d6a29c5ff51acb9cfc6, 4c5101211ed17a2970f431254d4f433b"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "146a037f821cf561133b2459bd1b1cf9c65689abe8d62ed0c1a9625efef65835"
      hash2 = "051bf363e26c9a9d9d3d9f2ea6eceb93fc7113499db4193de7796ad783b3ba83"
      hash3 = "30beb66eeb378f866d21439dcf4f8e69fa66b752b385848517c91739a5370c2a"
      hash4 = "c4552ad6496f0e20cfd3137ad2a0e66d961b99fbc6d19b3316062d01f8f02f7d"
      hash5 = "c36f205dbd4c376c7e93c06488c76ab4d3286a275d1a46785d045d98ee725903"
      hash6 = "b24fb139f9fcd5c31a547128236de3d5f9ab0e1a99ce439c9eabacd1b893eeae"
      hash7 = "9041d5cf64135d66fe439777d1f68d6e39116af32e7de18f1734628bc5a81069"
      hash8 = "3df65c798ab8b3866df5f0b620fe41b66790e6e69ede8c32229b3caf48590ae6"
      hash9 = "3c989131f6b5539dd8643023bfa9f486cd467ef7dadc71fea4c5acc952ddc959"
      hash10 = "4f4c6191510eafc7102064e0d505fa948b1e187eeb0342927b39450837b2a2f9"
      hash11 = "3424150aceaa2517390277db3b683d099e302c068b697a89e70655b9d93694df"
      hash12 = "32e8de0f91143f67e9b7ca61a15bd9fb2b79d3c589965fa6d06e0db9962f8912"
      hash13 = "bb63a6314631fa01c7b29823fe0c58d452ef96d0eb6db2a89fb48f8c4da8124f"
      hash14 = "efa516d078f5512b04e05ffb2f25bdcf1cfa7fce05640a304369f883901082ce"
      hash15 = "4d78b1d04170aea677908b52c92288d95399e7b79a8b15fc8db90bd83892dd4a"
      hash16 = "4d0f858311902ad6c8de4a01b0c98bbeab51375cc51b669a373c138acd0b9608"
      hash17 = "9e309abd9ffae40f90fd920bac66992db6b6fb9070599413c1063287549d6c61"
      hash18 = "54de1957593ef530f8ff1304e8d519db061703cb646a681316c1c62f982d7487"
      hash19 = "77d88e561947a0650c3f5b148937e39b541f7cf364c39f94194e39f31656dbf0"
      hash20 = "c4069c8a07e84cf34ec23484b70487c6a24671ea56551f5ffcb4d2fe7d50c99a"
      hash21 = "947048fc0aaa241f825a3d1a52ccfa006d5425d31e308586b489b7251a9b9759"
      hash22 = "ad8ba4a2c3cd5e2c1ac73a41b6055f10463794d0d5c4408bd537518abb300608"
      hash23 = "5b55dfa9b7779f4780ba3d0a2db463e1bcf2270f8e4b9bff690d2ebedbe52e42"
      hash24 = "b2538b160b45dc717ce906aa2066d2c14d230035d6f76428d73ed238426f5da0"
   strings:
      $s1 = "cjmodme_c.dll" fullword ascii
      $s2 = "-<3<:<A<@" fullword ascii /* hex encoded string ':' */
      $s3 = ",282@2\\2|2" fullword ascii /* hex encoded string '(""' */
      $s4 = "4:<:D:L:T:\\:d:`" fullword ascii
      $s5 = "QVWht429" fullword ascii
      $s6 = "uSVhxL39" fullword ascii
      $s7 = "3$3(3@3" fullword ascii /* Goodware String - occured 1 times */
      $s8 = ">1>L>W>" fullword ascii /* Goodware String - occured 1 times */
      $s9 = "p?v?|?" fullword ascii /* Goodware String - occured 1 times */
      $s10 = "6.6W6e6" fullword ascii /* Goodware String - occured 1 times */
      $s11 = "d8h8l8p8" fullword ascii /* Goodware String - occured 1 times */
      $s12 = ".?xqrfhiArwChCpmue" fullword ascii
      $s13 = "0G0Y0_0" fullword ascii /* Goodware String - occured 1 times */
      $s14 = "3$>,>4><>D>L>T>\\>d>l>t>|>" fullword ascii /* Goodware String - occured 1 times */
      $s15 = "!9bad array new length" fullword ascii
      $s16 = "949<9H9" fullword ascii /* Goodware String - occured 1 times */
      $s17 = "X1\\1`1" fullword ascii /* Goodware String - occured 1 times */
      $s18 = "<9@9D9H9L9P9" fullword ascii /* Goodware String - occured 2 times */
      $s19 = "l5t5|5" fullword ascii /* Goodware String - occured 2 times */
      $s20 = "Z0^0b0f0" fullword ascii /* Goodware String - occured 2 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule _match_96 {
   meta:
      description = "black - from files 0f9eddc5e740edcd96e2f32d6acc3bb3, 8a490aa2517646411b6ea1383f17bbd1, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 5f52a27f400818807d2693e1a52260ad, e28e3404155556ecafff204356fcc5f0, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, a3b4afa503657e7a327934ddd231887e, b1b0580af0e8fa730486561255426f38, 26fc98d7481f9b494ecbfebacdcbeab3, ae33c5c9544d63463cca74c42a556983, ee3f5f355249823f286f389ce0567002, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 86d7666073561a5d0ca494d80eae3e5e, 9b3518901fb21e67bfd3986cdcded31c, 99fe45ec1a50c0413a6dcb1d23b754f9, e97524afde7b751f6b024fa4798bdf51, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash2 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash3 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash4 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash5 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash6 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash7 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash8 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash9 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash10 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash11 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash12 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash13 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash14 = "b95f40cce47499183ef95d6d56b8b5deed0d99a413a8bd7067200c5b1ae752a9"
      hash15 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash16 = "ade656b212a4bef11d70720679ec7fd91586a9507448634cd716178ed908e509"
      hash17 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash18 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash19 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash20 = "ee7ab7d8bd4643e2f2d63bc0329b21c6d3437beea13fc379ee7fbfc0e326d0f5"
      hash21 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash22 = "b81e7c41d4c6cec4c6f99f9e577c8335c685bf09351af664d82c2a97bc12b89c"
      hash23 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash24 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = "__kernel void cn2(__global uint4 *Scratchpad,__global ulong *states,__global uint *output,ulong Target,uint Threads)" fullword ascii
      $s2 = "if(State[3]<=Target)" fullword ascii
      $s3 = "__kernel void cn1(__global int *lpad_in,__global int *spad,uint numThreads)" fullword ascii
      $s4 = "__kernel void cn0(__global ulong *input,__global int *Scratchpad,__global ulong *states,uint Threads)" fullword ascii
      $s5 = "inline void round_compute(float4 n0,float4 n1,float4 n2,float4 n3,float4 rnd_c,float4* c,float4* r)" fullword ascii
      $s6 = "float va_tmp2=((__local float*)smem->va)[block+ 8]+((__local float*)smem->va)[block+12];" fullword ascii
      $s7 = "inline int4 single_comupte(float4 n0,float4 n1,float4 n2,float4 n3,float cnt,float4 rnd_c,__local float4* sum)" fullword ascii
      $s8 = "inline void single_comupte_wrap(const uint rot,int4 v0,int4 v1,int4 v2,int4 v3,float cnt,float4 rnd_c,__local float4* sum,__loca" ascii
      $s9 = "inline void single_comupte_wrap(const uint rot,int4 v0,int4 v1,int4 v2,int4 v3,float cnt,float4 rnd_c,__local float4* sum,__loca" ascii
      $s10 = "__local struct SharedMemChunk* smem=smem_in+chunk;" fullword ascii
      $s11 = "const uint gIdx=getIdx()/64;" fullword ascii
      $s12 = "output[outIdx]=get_global_id(0);" fullword ascii
      $s13 = "{3,1,2,0}," fullword ascii /* hex encoded string '1 ' */
      $s14 = "{3,0,2,1}" fullword ascii /* hex encoded string '0!' */
      $s15 = "inline uint getIdx()" fullword ascii
      $s16 = "{2,0,3,1}," fullword ascii /* hex encoded string ' 1' */
      $s17 = "__kernel void cn00(__global int *Scratchpad,__global ulong *states)" fullword ascii
      $s18 = "uint chunk=get_local_id(0)/16;" fullword ascii
      $s19 = "for (int i=0,i1=get_local_id(1); i<(MEMORY>>7); ++i,i1=(i1+16) % (MEMORY>>4)) {" fullword ascii
      $s20 = "for (int i=get_local_id(0); i<25; i+=get_local_size(0)) {" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 19000KB and ( 8 of them )
      ) or ( all of them )
}

rule _match_99 {
   meta:
      description = "black - from files 0f9eddc5e740edcd96e2f32d6acc3bb3, 6cfc530100079ac1f1ed0cf61bed2ca8, acd5942fee24e5bc6769bb2fb529b695, 8a490aa2517646411b6ea1383f17bbd1, 50b754688ea8b1994abc99ea58263ebb, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 5f52a27f400818807d2693e1a52260ad, 0086748f3a7854b3a35f69b5285c534f, e28e3404155556ecafff204356fcc5f0, 4d6dff8b2def91e85a09faa27899d9d5, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, af408f884178b56843b9f7324bcdefb4, 51f0f95501d456804707bd997c56b416, fc481ae3e90d67283ce944cefb433d25, a3b4afa503657e7a327934ddd231887e, b3c0545d8bdbd5cd9c4c5cbd4d070d2a, cd9d53902ae60c8a9330b6b145cbe3bb, b9280790ed58987ab2af68537ad18d6d, b1b0580af0e8fa730486561255426f38, 26fc98d7481f9b494ecbfebacdcbeab3, ae33c5c9544d63463cca74c42a556983, ee3f5f355249823f286f389ce0567002, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 86d7666073561a5d0ca494d80eae3e5e, 233cb487009705a47f32a694558deca5, 9b3518901fb21e67bfd3986cdcded31c, 5e68b441f8c061285f596c5e0731514d, 99fe45ec1a50c0413a6dcb1d23b754f9, e97524afde7b751f6b024fa4798bdf51, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash2 = "438784b7594602da1a92d67890953b527ef6cb045e0c64ccaa4e78448576fff5"
      hash3 = "0083066406394696a0e6f26928d71785bf9fcdecdd6dcf52731a93b78f2cca0c"
      hash4 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash5 = "2efbcf082019f2fe3b7b065842a6e99e0441e7166265d2021695fce00f0d4373"
      hash6 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash7 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash8 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash9 = "0693cfd2a09f5358cdec077df4cf049c88fe5fcdc606a228e389c9b2e517f965"
      hash10 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash11 = "dbc26374af31e9c81b8bc3a6c3063387f587a2596510e2a3be24aea6e025294f"
      hash12 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash13 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash14 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash15 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash16 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash17 = "c92d9638c8fb2b0556802ea87082be829f50dd7d29579a1a893ade35bd7a9256"
      hash18 = "a8efd58c2f819b96742b10bad9aa76494731295f32ccc9897d3694944017b2a4"
      hash19 = "201b177ab0fe48289ac660b899b7813ed6f276a9ea1246574c28ebacb943905d"
      hash20 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash21 = "7bf303baebaec1c10be08273dd3d1ce503c4a7e1edaefc6092778b2926ebb278"
      hash22 = "9c62abcac2762be0e5abbb7f06ffb65c0b8fbea84d015944b6593453354303eb"
      hash23 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash24 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash25 = "b95f40cce47499183ef95d6d56b8b5deed0d99a413a8bd7067200c5b1ae752a9"
      hash26 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash27 = "ade656b212a4bef11d70720679ec7fd91586a9507448634cd716178ed908e509"
      hash28 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash29 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash30 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash31 = "1c6eeaf450250baad8b4bbdcb4539a5ec8ad9878d1ea4c96c493e01cca02f1d2"
      hash32 = "ee7ab7d8bd4643e2f2d63bc0329b21c6d3437beea13fc379ee7fbfc0e326d0f5"
      hash33 = "f56df2b39807ac070aa06c977177aff8c79c48f399fc5b8c904df6c898bf431a"
      hash34 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash35 = "b81e7c41d4c6cec4c6f99f9e577c8335c685bf09351af664d82c2a97bc12b89c"
      hash36 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash37 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = "* The error occured in hwloc %s inside process `%s', while" fullword ascii
      $s2 = "* the input XML was generated by hwloc %s inside process `%s'." fullword ascii
      $s3 = "* Otherwise please report this error message to the hwloc user's mailing list," fullword ascii
      $s4 = "* Error occurred in topology.c line %d" fullword ascii
      $s5 = "* Object %s cpuset %s complete %s" fullword ascii
      $s6 = "*   What should I do when hwloc reports \"operating system\" warnings?" fullword ascii
      $s7 = "* along with any relevant topology information from your platform." fullword ascii
      $s8 = "* hwloc has encountered an out-of-order XML topology load." fullword ascii
      $s9 = "* Please check that your input topology XML file is valid." fullword ascii
      $s10 = "* was inserted after object %s with %s and %s." fullword ascii
      $s11 = "Dropping previously registered discovery component `%s', priority %u lower than new one %u" fullword ascii
      $s12 = "HWLOC_XML_USERDATA_NOT_DECODED" fullword ascii
      $s13 = "topologydiff" fullword ascii
      $s14 = "Failed to read synthetic index interleaving loop '%s' without number between '*' and ':'" fullword ascii
      $s15 = "Failed to read synthetic index #%lu at '%s'" fullword ascii
      $s16 = "Failed to read synthetic index interleaving loop type '%s'" fullword ascii
      $s17 = "Failed to read synthetic index interleaving loop '%s' without number before '*'" fullword ascii
      $s18 = "hostbridge" fullword ascii
      $s19 = "Failed to instantiate discovery component `%s'" fullword ascii
      $s20 = "%s: XML component discovery failed." fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 25000KB and ( 8 of them )
      ) or ( all of them )
}

rule _match_101 {
   meta:
      description = "black - from files 0f9eddc5e740edcd96e2f32d6acc3bb3, 8a490aa2517646411b6ea1383f17bbd1, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 5f52a27f400818807d2693e1a52260ad, e28e3404155556ecafff204356fcc5f0, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, a3b4afa503657e7a327934ddd231887e, b9280790ed58987ab2af68537ad18d6d, b1b0580af0e8fa730486561255426f38, ae33c5c9544d63463cca74c42a556983, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 86d7666073561a5d0ca494d80eae3e5e, 99fe45ec1a50c0413a6dcb1d23b754f9, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash2 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash3 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash4 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash5 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash6 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash7 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash8 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash9 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash10 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash11 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash12 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash13 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash14 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash15 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash16 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash17 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash18 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash19 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash20 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash21 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = "invalid vector subscript" fullword ascii
      $s2 = "invalid bitset position" fullword ascii
      $s3 = "list too long" fullword ascii
      $s4 = ".?AV?$_ExceptionPtr_static@Vbad_exception@std@@@?A0xc16bda6b@@" fullword ascii
      $s5 = "tVHcB0H9B8~" fullword ascii
      $s6 = "L$HH;L$P" fullword ascii /* Goodware String - occured 1 times */
      $s7 = ")t$pD;" fullword ascii /* Goodware String - occured 1 times */
      $s8 = ".?AV_ExceptionPtr_normal@?A0xc16bda6b@@" fullword ascii
      $s9 = "\\$HLc@" fullword ascii /* Goodware String - occured 1 times */
      $s10 = "GenuineIH;" fullword ascii
      $s11 = ".?AV?$_ExceptionPtr_static@Vbad_alloc@std@@@?A0xc16bda6b@@" fullword ascii
      $s12 = "pA^_^H" fullword ascii /* Goodware String - occured 1 times */
      $s13 = "d$$D;g" fullword ascii /* Goodware String - occured 2 times */
      $s14 = "H+L$8L" fullword ascii /* Goodware String - occured 3 times */
      $s15 = "\\$xwCH" fullword ascii
      $s16 = "\\$`McJ" fullword ascii
      $s17 = "D$@H+D$0H" fullword ascii /* Goodware String - occured 3 times */
      $s18 = "\\$0H+L$HH" fullword ascii
      $s19 = "f F+l\"(;A," fullword ascii
      $s20 = "L$(McQ" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 13000KB and ( 8 of them )
      ) or ( all of them )
}

rule _match_109 {
   meta:
      description = "black - from files 97ee5c92d5c865ef6db67c35bc8a427a, d220d7b9023e6bd3717edc17765fbb25, eafa15f8a4e79523f4f6288519e2d60a, 0f4acbb2acfaa97b146f4949729d0ec6, 09b0bb70c4456e39cb26cdf2667b2be7, 5846aed02e23db1af696661606cf5bfd, cd7e6a6f2e3fc3cb1049efbbf235577f, 3934d1adff337a3741fc308eb83daaba, 99bd2332ea3179db7a70a6e66d11e096, af408f884178b56843b9f7324bcdefb4, 0cf00d65acee7181d4679d2ad3da5301, 51f0f95501d456804707bd997c56b416, f8a8bd5eb3b9328c007438070e0c3ca8, 2458b8fb100cb0d0c80a3f62aea0e080, 0742b7c20e14fc0b9390fd5aafef6442, 6a80142ac8cf4d5534d2eb9cb0e3e08d, ddafbf9406cc26df63a32702126e3fc9, b1a919e6fb009361b64d51b351a25e4c, 3ba79ba35b4b388fe9699e51d4c43fea, 26fc98d7481f9b494ecbfebacdcbeab3, e74a8e9fbf1969888d78bfe6bf757759, 9f8125060a075a7c7b3e8b13d630bcf9, e97524afde7b751f6b024fa4798bdf51"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "e91e3d9138b2961bf0807b39ab1c0647e78ccf6985890246db1d698af498e43b"
      hash2 = "8d887ba624e0e8f55be8deb805ec25c1a2a34e6fa137b6bc30025cfbc124dfb8"
      hash3 = "7d2a58520ab1dea0d33c5866fdfbb8ccfb5a446f200c6d4c064d14ff90cdf76c"
      hash4 = "4c9bf0426483d1f8f7943cb291345134964d237f1b8270f88f51cbdd1557a41e"
      hash5 = "bc2a8aa09df1303d24917145a3b41acf1b9df09c72e65273883c63b288623e2b"
      hash6 = "5d1ef3f5bc06e457945af001cad5e392eea47ae4486522ad3342f42b6e2b7436"
      hash7 = "08e6eb5d64f01d4a982bf75e4ffbec7d0f61d7ece7b7fbfe2fade7ae39ad8884"
      hash8 = "2fefce5634c8b6f9e334fd6b1c34b86f6cb8278dc07558034d1ead43d1467cbb"
      hash9 = "2e999f22d7fa0d018342d235067b5bb879b4505bb0e42156f816d38ae61cd3fe"
      hash10 = "c92d9638c8fb2b0556802ea87082be829f50dd7d29579a1a893ade35bd7a9256"
      hash11 = "a0e6799ed9cb59ac3aeab73f2c10015fbabbacc850b56148778f69cc38835d27"
      hash12 = "a8efd58c2f819b96742b10bad9aa76494731295f32ccc9897d3694944017b2a4"
      hash13 = "2df4f0927f0f73ff7ca38a4edfe9406be229985fd5ae468d9b5aa19b9b0cd0ac"
      hash14 = "ba3e5e8af6d21e5fa3a78b69a87ca1cd39afd4342795f514bd651af81e9b8e47"
      hash15 = "3b38ac70eac888ba76ae3c5812179863a78b4e63ce92f5108f019bb00f96b35c"
      hash16 = "c8eb9182adc12b591cbdafe27759495487a53c0cd38f83f77f575edf21e5d4b3"
      hash17 = "a35d47fde5d36de866ba7fbe638c7ea9f5860962b326484936a992cbba6fa22f"
      hash18 = "72356978da0b156bae25c84189c01a47b7c8e8daf22e2be533f1e2733f8372f2"
      hash19 = "d274427049b5e28fdd153a0bdbcb08445ffebd9031ed666dba23b62e44b3191a"
      hash20 = "b95f40cce47499183ef95d6d56b8b5deed0d99a413a8bd7067200c5b1ae752a9"
      hash21 = "4c486b48b0524a9e3059f5dab86bffa9a0fa82787363c7784c624453344dc1d1"
      hash22 = "a2cce624ed3e428075dedc5b4243c065baafe0a121de26d686756e487e4d7232"
      hash23 = "b81e7c41d4c6cec4c6f99f9e577c8335c685bf09351af664d82c2a97bc12b89c"
   strings:
      $s1 = "fdopt.data.stream->type == UV_NAMED_PIPE" fullword ascii
      $s2 = "process_title" fullword ascii
      $s3 = "src/win/process.c" fullword ascii
      $s4 = "!process->exit_cb_pending" fullword ascii
      $s5 = "src/win/process-stdio.c" fullword ascii
      $s6 = "!(options->flags & ~(UV_PROCESS_DETACHED | UV_PROCESS_SETGID | UV_PROCESS_SETUID | UV_PROCESS_WINDOWS_HIDE | UV_PROCESS_WINDOWS_" ascii
      $s7 = "!(fdopt.data.stream->flags & UV_HANDLE_PIPESERVER)" fullword ascii
      $s8 = "r == target_len" fullword ascii
      $s9 = "pipe->u.fd == -1 || pipe->u.fd > 2" fullword ascii
      $s10 = "mode == (PIPE_READMODE_BYTE | PIPE_WAIT)" fullword ascii
      $s11 = "pipe->flags & UV_HANDLE_READ_PENDING" fullword ascii
      $s12 = "Error cleaning up spin_keys for thread " fullword ascii
      $s13 = "path_len == buf_sz - (pos - buf)" fullword ascii
      $s14 = "!(fdopt.data.stream->flags & UV_HANDLE_CONNECTION)" fullword ascii
      $s15 = "handle->pipe.serv.accept_reqs" fullword ascii
      $s16 = "req->pipeHandle != INVALID_HANDLE_VALUE" fullword ascii
      $s17 = "0 && \"unexpected address family\"" fullword ascii
      $s18 = "!(handle->flags & UV_HANDLE_PIPESERVER)" fullword ascii
      $s19 = "len > 0 && len < ARRAY_SIZE(key_name)" fullword ascii
      $s20 = "((uv_shutdown_t*) req)->handle->type == UV_NAMED_PIPE" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 27000KB and ( 8 of them )
      ) or ( all of them )
}

rule _match_122 {
   meta:
      description = "black - from files 0f9eddc5e740edcd96e2f32d6acc3bb3, 8a490aa2517646411b6ea1383f17bbd1, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 5f52a27f400818807d2693e1a52260ad, e28e3404155556ecafff204356fcc5f0, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, a3b4afa503657e7a327934ddd231887e, b9280790ed58987ab2af68537ad18d6d, b1b0580af0e8fa730486561255426f38, ae33c5c9544d63463cca74c42a556983, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 86d7666073561a5d0ca494d80eae3e5e, 9b3518901fb21e67bfd3986cdcded31c, 99fe45ec1a50c0413a6dcb1d23b754f9, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash2 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash3 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash4 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash5 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash6 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash7 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash8 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash9 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash10 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash11 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash12 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash13 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash14 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash15 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash16 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash17 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash18 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash19 = "ee7ab7d8bd4643e2f2d63bc0329b21c6d3437beea13fc379ee7fbfc0e326d0f5"
      hash20 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash21 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash22 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = "WinRing0x64.sys" fullword wide
      $s2 = "co-processor" fullword ascii
      $s3 = "[0;31mfailed to get path to driver, error %u" fullword ascii
      $s4 = "%s: %s child needs content of length %d" fullword ascii
      $s5 = "Registered discovery component `%s' phases 0x%x with priority %u (%s%s)" fullword ascii
      $s6 = "Excluding discovery component `%s' phases 0x%x, conflicts with excludes 0x%x" fullword ascii
      $s7 = "xml/export/v1: failed to allocated logical_to_v2array" fullword ascii
      $s8 = "[1;33mto write MSR registers Administrator privileges required." fullword ascii
      $s9 = "[0;31mfailed to remove WinRing0 driver, error %u" fullword ascii
      $s10 = "[0;31mfailed to start WinRing0 driver, error %u" fullword ascii
      $s11 = "[0;31mfailed to connect to WinRing0 driver, error %u" fullword ascii
      $s12 = "Excluding blacklisted discovery component `%s' phases 0x%x" fullword ascii
      $s13 = "[0;31mfailed to open service control manager, error %u" fullword ascii
      $s14 = "Blacklisting component `%s` phases 0x%x" fullword ascii
      $s15 = "[0;31mfailed to install WinRing0 driver, error %u" fullword ascii
      $s16 = "[%s] already connected" fullword ascii
      $s17 = "Enabling discovery component `%s' with phases 0x%x (among 0x%x)" fullword ascii
      $s18 = "Trying discovery component `%s' with phases 0x%x instead of 0x%x" fullword ascii
      $s19 = "Disabling discovery component `%s'" fullword ascii
      $s20 = "\\\\.\\WinRing0_1_2_0" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 13000KB and ( 8 of them )
      ) or ( all of them )
}

rule _match_132 {
   meta:
      description = "black - from files 0f9eddc5e740edcd96e2f32d6acc3bb3, 8a490aa2517646411b6ea1383f17bbd1, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 5f52a27f400818807d2693e1a52260ad, e28e3404155556ecafff204356fcc5f0, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, af408f884178b56843b9f7324bcdefb4, a3b4afa503657e7a327934ddd231887e, b9280790ed58987ab2af68537ad18d6d, b1b0580af0e8fa730486561255426f38, 26fc98d7481f9b494ecbfebacdcbeab3, ae33c5c9544d63463cca74c42a556983, ee3f5f355249823f286f389ce0567002, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 86d7666073561a5d0ca494d80eae3e5e, 9b3518901fb21e67bfd3986cdcded31c, 99fe45ec1a50c0413a6dcb1d23b754f9, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash2 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash3 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash4 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash5 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash6 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash7 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash8 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash9 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash10 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash11 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash12 = "c92d9638c8fb2b0556802ea87082be829f50dd7d29579a1a893ade35bd7a9256"
      hash13 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash14 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash15 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash16 = "b95f40cce47499183ef95d6d56b8b5deed0d99a413a8bd7067200c5b1ae752a9"
      hash17 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash18 = "ade656b212a4bef11d70720679ec7fd91586a9507448634cd716178ed908e509"
      hash19 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash20 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash21 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash22 = "ee7ab7d8bd4643e2f2d63bc0329b21c6d3437beea13fc379ee7fbfc0e326d0f5"
      hash23 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash24 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash25 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = "xmrig-cuda.dll" fullword ascii
      $s2 = "nvmlSystemGetDriverVersion" fullword ascii
      $s3 = "cuda-loader" fullword ascii
      $s4 = "#define LOC_L3 (32 - 18)" fullword ascii
      $s5 = "block_template" fullword ascii
      $s6 = "[0m huge pages %s%3.0f%% %u/%u" fullword ascii
      $s7 = "[0m huge pages %s%3.0f%%" fullword ascii
      $s8 = "[0m huge pages %s%1.0f%% %zu/%zu" fullword ascii
      $s9 = "[0m huge pages %s%1.0f%% %u/%u" fullword ascii
      $s10 = "[%s] incompatible/disabled algorithm \"%s\" detected, reconnect" fullword ascii
      $s11 = "[%s] unsupported algorithm \"%s\" detected, reconnect" fullword ascii
      $s12 = "nvmlDeviceGetFanSpeed_v2" fullword ascii
      $s13 = "[%s] unknown algorithm, make sure you set \"algo\" or \"coin\" option" fullword ascii
      $s14 = "[1;37m thread%s)" fullword ascii
      $s15 = "max-threads-hint" fullword ascii
      $s16 = "[1;32mdataset ready" fullword ascii
      $s17 = "[%s] required field " fullword ascii
      $s18 = "cpu-max-threads-hint" fullword ascii
      $s19 = "[0m for health report" fullword ascii
      $s20 = "[0;31m (failed to load CUDA plugin)" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 19000KB and ( 8 of them )
      ) or ( all of them )
}

rule _match_134 {
   meta:
      description = "black - from files 0f9eddc5e740edcd96e2f32d6acc3bb3, 6cfc530100079ac1f1ed0cf61bed2ca8, acd5942fee24e5bc6769bb2fb529b695, 8a490aa2517646411b6ea1383f17bbd1, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 5f52a27f400818807d2693e1a52260ad, 0086748f3a7854b3a35f69b5285c534f, e28e3404155556ecafff204356fcc5f0, 4d6dff8b2def91e85a09faa27899d9d5, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, af408f884178b56843b9f7324bcdefb4, 51f0f95501d456804707bd997c56b416, fc481ae3e90d67283ce944cefb433d25, a3b4afa503657e7a327934ddd231887e, b3c0545d8bdbd5cd9c4c5cbd4d070d2a, b9280790ed58987ab2af68537ad18d6d, b1b0580af0e8fa730486561255426f38, 26fc98d7481f9b494ecbfebacdcbeab3, ae33c5c9544d63463cca74c42a556983, ee3f5f355249823f286f389ce0567002, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 86d7666073561a5d0ca494d80eae3e5e, 9b3518901fb21e67bfd3986cdcded31c, 99fe45ec1a50c0413a6dcb1d23b754f9, e97524afde7b751f6b024fa4798bdf51, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash2 = "438784b7594602da1a92d67890953b527ef6cb045e0c64ccaa4e78448576fff5"
      hash3 = "0083066406394696a0e6f26928d71785bf9fcdecdd6dcf52731a93b78f2cca0c"
      hash4 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash5 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash6 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash7 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash8 = "0693cfd2a09f5358cdec077df4cf049c88fe5fcdc606a228e389c9b2e517f965"
      hash9 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash10 = "dbc26374af31e9c81b8bc3a6c3063387f587a2596510e2a3be24aea6e025294f"
      hash11 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash12 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash13 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash14 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash15 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash16 = "c92d9638c8fb2b0556802ea87082be829f50dd7d29579a1a893ade35bd7a9256"
      hash17 = "a8efd58c2f819b96742b10bad9aa76494731295f32ccc9897d3694944017b2a4"
      hash18 = "201b177ab0fe48289ac660b899b7813ed6f276a9ea1246574c28ebacb943905d"
      hash19 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash20 = "7bf303baebaec1c10be08273dd3d1ce503c4a7e1edaefc6092778b2926ebb278"
      hash21 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash22 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash23 = "b95f40cce47499183ef95d6d56b8b5deed0d99a413a8bd7067200c5b1ae752a9"
      hash24 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash25 = "ade656b212a4bef11d70720679ec7fd91586a9507448634cd716178ed908e509"
      hash26 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash27 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash28 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash29 = "ee7ab7d8bd4643e2f2d63bc0329b21c6d3437beea13fc379ee7fbfc0e326d0f5"
      hash30 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash31 = "b81e7c41d4c6cec4c6f99f9e577c8335c685bf09351af664d82c2a97bc12b89c"
      hash32 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash33 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = "Could not read dumped cpuid file %s, ignoring cpuiddump." fullword ascii
      $s2 = "* hwloc %s received invalid information from the operating system." fullword ascii
      $s3 = "Couldn't find %x,%x,%x,%x in dumped cpuid, returning 0s." fullword ascii
      $s4 = "Ignoring dumped cpuid directory." fullword ascii
      $s5 = "* hwloc %s was given invalid distances by the user." fullword ascii
      $s6 = "* hwloc will now ignore this invalid topology information and continue." fullword ascii
      $s7 = "* do not contradict any other topology information." fullword ascii
      $s8 = "Failed to allocate %u cpuiddump entries for PU #%u, ignoring cpuiddump." fullword ascii
      $s9 = "failed to export hwloc topology." fullword ascii
      $s10 = "topology.xml" fullword ascii
      $s11 = "<!DOCTYPE topologydiff SYSTEM \"hwloc2-diff.dtd\">" fullword ascii
      $s12 = "Co-Processor" fullword ascii
      $s13 = "hwloc topology successfully exported to \"%s\"" fullword ascii
      $s14 = "<!DOCTYPE topology SYSTEM \"%s\">" fullword ascii
      $s15 = "%s: ignoring unknown tag `%s' after root object, expected `distances2'" fullword ascii
      $s16 = "%s: %s object not-supported, will be ignored" fullword ascii
      $s17 = "* Set HWLOC_DEBUG_CHECK=1 in the environment to detect further issues." fullword ascii
      $s18 = "* Please make sure that distances given through the programming API" fullword ascii
      $s19 = "--export-topology" fullword ascii
      $s20 = "<topology version=\"%u.%u\">" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 25000KB and ( 8 of them )
      ) or ( all of them )
}

rule _match_142 {
   meta:
      description = "black - from files 905eeda0ddf717b45bb294b227e6d8ae, 6b97eabf2e7eef8ccfc36593771ebe12, 4396f6981923a6e702a9d18a3d76e482, 20addcaa91c6bc5c7cc665ddb2e8c52c, 97ee5c92d5c865ef6db67c35bc8a427a, 50b754688ea8b1994abc99ea58263ebb, d220d7b9023e6bd3717edc17765fbb25, 0f4acbb2acfaa97b146f4949729d0ec6, 5846aed02e23db1af696661606cf5bfd, cd7e6a6f2e3fc3cb1049efbbf235577f, a7e372d0982334302446756bf112d881, 3934d1adff337a3741fc308eb83daaba, 99bd2332ea3179db7a70a6e66d11e096, 0cf00d65acee7181d4679d2ad3da5301, f8a8bd5eb3b9328c007438070e0c3ca8, 2458b8fb100cb0d0c80a3f62aea0e080, 0742b7c20e14fc0b9390fd5aafef6442, cd9d53902ae60c8a9330b6b145cbe3bb, 80ba21786b71bb0dba959194fa1d3f63, a746e73da04945445e385850616990c9, 6a80142ac8cf4d5534d2eb9cb0e3e08d, ddafbf9406cc26df63a32702126e3fc9, b1a919e6fb009361b64d51b351a25e4c, 3ba79ba35b4b388fe9699e51d4c43fea, e74a8e9fbf1969888d78bfe6bf757759, 9a07ca40de9c85495231302023c6a74a, 2ae5db210e8c7c0c96e6bed93bce1da6, 6bd4123b8dc8281bfee4c09350545c7e, 233cb487009705a47f32a694558deca5, 0cccafcbc4d1a6d50ccd8fa1df89bc0f, 3a69511ef880ea841a6740357901ca61, 74f394c609338509e94d61091a70b6f5"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "a28878f5880b8a1c506258dd39b459cec616f79100afe006b4779525b8a937a3"
      hash2 = "d2b4b16be498e2fbe782b6f0e73515f6fc74c7a661c44891a9860cbf2b690d02"
      hash3 = "4fd49a0d1574549b4f8b64c9d474417600d6ede505c3997b3b07eb9e92bd440a"
      hash4 = "c2389593cb340e9b682e457e6bf926abf1eee594d129c237f3f87852731dba7d"
      hash5 = "e91e3d9138b2961bf0807b39ab1c0647e78ccf6985890246db1d698af498e43b"
      hash6 = "2efbcf082019f2fe3b7b065842a6e99e0441e7166265d2021695fce00f0d4373"
      hash7 = "8d887ba624e0e8f55be8deb805ec25c1a2a34e6fa137b6bc30025cfbc124dfb8"
      hash8 = "4c9bf0426483d1f8f7943cb291345134964d237f1b8270f88f51cbdd1557a41e"
      hash9 = "5d1ef3f5bc06e457945af001cad5e392eea47ae4486522ad3342f42b6e2b7436"
      hash10 = "08e6eb5d64f01d4a982bf75e4ffbec7d0f61d7ece7b7fbfe2fade7ae39ad8884"
      hash11 = "d204dc52cd7c86013aa224f66e5631efec50edff579c78d21310c49b05910018"
      hash12 = "2fefce5634c8b6f9e334fd6b1c34b86f6cb8278dc07558034d1ead43d1467cbb"
      hash13 = "2e999f22d7fa0d018342d235067b5bb879b4505bb0e42156f816d38ae61cd3fe"
      hash14 = "a0e6799ed9cb59ac3aeab73f2c10015fbabbacc850b56148778f69cc38835d27"
      hash15 = "2df4f0927f0f73ff7ca38a4edfe9406be229985fd5ae468d9b5aa19b9b0cd0ac"
      hash16 = "ba3e5e8af6d21e5fa3a78b69a87ca1cd39afd4342795f514bd651af81e9b8e47"
      hash17 = "3b38ac70eac888ba76ae3c5812179863a78b4e63ce92f5108f019bb00f96b35c"
      hash18 = "9c62abcac2762be0e5abbb7f06ffb65c0b8fbea84d015944b6593453354303eb"
      hash19 = "2e4b386aa820c4a1b294274d89652098e4a78921df83b1ed101213f558f704ea"
      hash20 = "beae2bc4274deb42c452e6ad910853cfa1a60e05f0180ed43829e2a4f5281e04"
      hash21 = "c8eb9182adc12b591cbdafe27759495487a53c0cd38f83f77f575edf21e5d4b3"
      hash22 = "a35d47fde5d36de866ba7fbe638c7ea9f5860962b326484936a992cbba6fa22f"
      hash23 = "72356978da0b156bae25c84189c01a47b7c8e8daf22e2be533f1e2733f8372f2"
      hash24 = "d274427049b5e28fdd153a0bdbcb08445ffebd9031ed666dba23b62e44b3191a"
      hash25 = "4c486b48b0524a9e3059f5dab86bffa9a0fa82787363c7784c624453344dc1d1"
      hash26 = "ea9d91772dd86455d5bf25c080ed859faae39c7085abb5de0b3142a397e7f131"
      hash27 = "3b1a32116390ef2a821cbeb15e214f937293ee39cfde2a2e97f2eb128474bce3"
      hash28 = "12a37426a995ef84e905c85a531c2754d10926dfdec03125074f83b738fe40af"
      hash29 = "1c6eeaf450250baad8b4bbdcb4539a5ec8ad9878d1ea4c96c493e01cca02f1d2"
      hash30 = "4a49d867bbb4e4e36b55c77f0f514fdf18a78b18b701ae853075092ac2893e2e"
      hash31 = "477ff70035e7438bbb414dcaf805d93a61dc39f75acf882134097fe3be105e48"
      hash32 = "02bd77bfd0a50ae5ea7e8a6587187e84b5c4d0d5638c7559abe609fbebbacd38"
   strings:
      $s1 = "Hit process or system resource limit at %u connections, temporarily suspending accept(). Consider setting a lower MHD_OPTION_CON" ascii
      $s2 = "Hit process or system resource limit at %u connections, temporarily suspending accept(). Consider setting a lower MHD_OPTION_CON" ascii
      $s3 = "MHD HTTPS option %d passed to MHD compiled without HTTPS support" fullword ascii
      $s4 = "MHD failed to initialize IP connection limit mutex" fullword ascii
      $s5 = "<html><head><title>&quot;Host:&quot; header required</title></head><body>In HTTP 1.1, requests must include a &quot;Host:&quot; " ascii
      $s6 = "<html><head><title>&quot;Host:&quot; header required</title></head><body>In HTTP 1.1, requests must include a &quot;Host:&quot; " ascii
      $s7 = "Failed to bind to port %u: %s" fullword ascii
      $s8 = "Hit process or system resource limit at FIRST connection. This is really bad as there is no sane way to proceed. Will try busy w" ascii
      $s9 = "Closing connection (failed to create response header)" fullword ascii
      $s10 = "Hit process or system resource limit at FIRST connection. This is really bad as there is no sane way to proceed. Will try busy w" ascii
      $s11 = "Failed to create listen thread: %s" fullword ascii
      $s12 = "Fatal error in GNU libmicrohttpd %s:%u: %s" fullword ascii
      $s13 = "<html><head><title>Request too big</title></head><body>Your HTTP header was too big for the memory constraints of this webserver" ascii
      $s14 = "header, and your HTTP 1.1 request lacked such a header.</body></html>" fullword ascii
      $s15 = "<html><head><title>Request too big</title></head><body>Your HTTP header was too big for the memory constraints of this webserver" ascii
      $s16 = "Failed to listen for connections: %s" fullword ascii
      $s17 = "Failed to create a thread: %s" fullword ascii
      $s18 = "Invalid QoS flow descriptor" fullword ascii
      $s19 = "Error during select (%d): `%s'" fullword ascii
      $s20 = "Failed to find previously-added IP address" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 27000KB and ( 8 of them )
      ) or ( all of them )
}

rule _match_161 {
   meta:
      description = "black - from files 0f9eddc5e740edcd96e2f32d6acc3bb3, 8a490aa2517646411b6ea1383f17bbd1, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 5f52a27f400818807d2693e1a52260ad, e28e3404155556ecafff204356fcc5f0, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, af408f884178b56843b9f7324bcdefb4, a3b4afa503657e7a327934ddd231887e, b9280790ed58987ab2af68537ad18d6d, b1b0580af0e8fa730486561255426f38, 26fc98d7481f9b494ecbfebacdcbeab3, ae33c5c9544d63463cca74c42a556983, ee3f5f355249823f286f389ce0567002, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 86d7666073561a5d0ca494d80eae3e5e, 9b3518901fb21e67bfd3986cdcded31c, 5e68b441f8c061285f596c5e0731514d, 99fe45ec1a50c0413a6dcb1d23b754f9, e97524afde7b751f6b024fa4798bdf51, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash2 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash3 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash4 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash5 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash6 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash7 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash8 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash9 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash10 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash11 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash12 = "c92d9638c8fb2b0556802ea87082be829f50dd7d29579a1a893ade35bd7a9256"
      hash13 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash14 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash15 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash16 = "b95f40cce47499183ef95d6d56b8b5deed0d99a413a8bd7067200c5b1ae752a9"
      hash17 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash18 = "ade656b212a4bef11d70720679ec7fd91586a9507448634cd716178ed908e509"
      hash19 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash20 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash21 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash22 = "ee7ab7d8bd4643e2f2d63bc0329b21c6d3437beea13fc379ee7fbfc0e326d0f5"
      hash23 = "f56df2b39807ac070aa06c977177aff8c79c48f399fc5b8c904df6c898bf431a"
      hash24 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash25 = "b81e7c41d4c6cec4c6f99f9e577c8335c685bf09351af664d82c2a97bc12b89c"
      hash26 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash27 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = "if(!get_local_id(1))" fullword ascii
      $s2 = "AESExpandKey256(ExpandedKey1);" fullword ascii
      $s3 = "((uint4 *)a)[0] ^= tmp;" fullword ascii
      $s4 = "ulong tmp[5];" fullword ascii
      $s5 = "uint4 tmp;" fullword ascii
      $s6 = "ulong tmp[8];" fullword ascii
      $s7 = "AESExpandKey256(ExpandedKey2);" fullword ascii
      $s8 = "#pragma unroll 1" fullword ascii
      $s9 = "h7h ^= input[6]; \\" fullword ascii
      $s10 = "barrier(CLK_GLOBAL_MEM_FENCE);" fullword ascii
      $s11 = "h3h ^= input[6]; \\" fullword ascii
      $s12 = "h5l ^= input[3]; \\" fullword ascii
      $s13 = "ulong input[8];" fullword ascii
      $s14 = "unsigned int m[16];" fullword ascii
      $s15 = "PERM_SMALL_P(State);" fullword ascii
      $s16 = "h1l ^= input[3]; \\" fullword ascii
      $s17 = "uint4 b_x;" fullword ascii
      $s18 = "#pragma unroll 2" fullword ascii
      $s19 = "h4l ^= input[1]; \\" fullword ascii
      $s20 = "ulong c[2];" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 19000KB and ( 8 of them )
      ) or ( all of them )
}

rule _match_179 {
   meta:
      description = "black - from files 0f9eddc5e740edcd96e2f32d6acc3bb3, 8a490aa2517646411b6ea1383f17bbd1, 162a7b063003403841e98dc02aaa6b76, e28e3404155556ecafff204356fcc5f0, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, af408f884178b56843b9f7324bcdefb4, a3b4afa503657e7a327934ddd231887e, b1b0580af0e8fa730486561255426f38, 26fc98d7481f9b494ecbfebacdcbeab3, ae33c5c9544d63463cca74c42a556983, ee3f5f355249823f286f389ce0567002, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 86d7666073561a5d0ca494d80eae3e5e, 9b3518901fb21e67bfd3986cdcded31c, 99fe45ec1a50c0413a6dcb1d23b754f9, e97524afde7b751f6b024fa4798bdf51, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash2 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash3 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash4 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash5 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash6 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash7 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash8 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash9 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash10 = "c92d9638c8fb2b0556802ea87082be829f50dd7d29579a1a893ade35bd7a9256"
      hash11 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash12 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash13 = "b95f40cce47499183ef95d6d56b8b5deed0d99a413a8bd7067200c5b1ae752a9"
      hash14 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash15 = "ade656b212a4bef11d70720679ec7fd91586a9507448634cd716178ed908e509"
      hash16 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash17 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash18 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash19 = "ee7ab7d8bd4643e2f2d63bc0329b21c6d3437beea13fc379ee7fbfc0e326d0f5"
      hash20 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash21 = "b81e7c41d4c6cec4c6f99f9e577c8335c685bf09351af664d82c2a97bc12b89c"
      hash22 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash23 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = "for (int pass=0; pass<2; ++pass)" fullword ascii
      $s2 = "*(p++)=0x860e0010u|(dst<<1)|(conditionMaskReg<<8);" fullword ascii
      $s3 = "const uint64_t mantissa_mask=(1UL<<mantissa_size)-1;" fullword ascii
      $s4 = "*(p++)=0xbf8c0f70u|(vmcnt&15)|((vmcnt>>4)<<14);" fullword ascii
      $s5 = "*(p++)=0xbea000ffu;" fullword ascii
      $s6 = "const uint32_t sign_b=as_uint2(b).y>>31;" fullword ascii
      $s7 = "const uint64_t mantissa_high_bit=1UL<<mantissa_size;" fullword ascii
      $s8 = "const uint64_t mantissa_b=(as_ulong(b)&mantissa_mask)|mantissa_high_bit;" fullword ascii
      $s9 = "const uint32_t sign_a=as_uint2(a).y>>31;" fullword ascii
      $s10 = "const uint32_t exponent_b=(as_uint2(b).y>>20)&exponent_mask;" fullword ascii
      $s11 = "if(fma_result[1]==mantissa_high_bit)" fullword ascii
      $s12 = "*(p++)=0xbebe00ffu;" fullword ascii
      $s13 = "const uint32_t exponent_c=(as_uint2(c).y>>20)&exponent_mask;" fullword ascii
      $s14 = "*(p++)=0x8ea28010u|(dst<<1)|((64-shift)<<8);" fullword ascii
      $s15 = "const uint64_t mantissa_a=(as_ulong(a)&mantissa_mask)|mantissa_high_bit;" fullword ascii
      $s16 = "const uint64_t mantissa_c=(as_ulong(c)&mantissa_mask)|mantissa_high_bit;" fullword ascii
      $s17 = "*(p++)=0x8e8e8010u|(src<<1)|(shift<<8);" fullword ascii
      $s18 = "*(p++)=0x8fa08010u|(dst<<1)|(shift<<8);" fullword ascii
      $s19 = "const uint32_t exponent_a=(as_uint2(a).y>>20)&exponent_mask;" fullword ascii
      $s20 = "uint32_t ScratchpadLatency=0;" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 19000KB and ( 8 of them )
      ) or ( all of them )
}

rule _match_183 {
   meta:
      description = "black - from files 0f9eddc5e740edcd96e2f32d6acc3bb3, 8a490aa2517646411b6ea1383f17bbd1, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 5f52a27f400818807d2693e1a52260ad, e28e3404155556ecafff204356fcc5f0, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, a3b4afa503657e7a327934ddd231887e, b9280790ed58987ab2af68537ad18d6d, b1b0580af0e8fa730486561255426f38, ae33c5c9544d63463cca74c42a556983, ee3f5f355249823f286f389ce0567002, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 86d7666073561a5d0ca494d80eae3e5e, 9b3518901fb21e67bfd3986cdcded31c, 99fe45ec1a50c0413a6dcb1d23b754f9, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash2 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash3 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash4 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash5 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash6 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash7 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash8 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash9 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash10 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash11 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash12 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash13 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash14 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash15 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash16 = "ade656b212a4bef11d70720679ec7fd91586a9507448634cd716178ed908e509"
      hash17 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash18 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash19 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash20 = "ee7ab7d8bd4643e2f2d63bc0329b21c6d3437beea13fc379ee7fbfc0e326d0f5"
      hash21 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash22 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash23 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = ".?AVExecuteVmKernel@xmrig@@" fullword ascii
      $s2 = ".?AVBlake2bInitialHashKernel@xmrig@@" fullword ascii
      $s3 = ".?AVRxRunKernel@xmrig@@" fullword ascii
      $s4 = ".?AVHashAesKernel@xmrig@@" fullword ascii
      $s5 = ".?AVBlake2bHashRegistersKernel@xmrig@@" fullword ascii
      $s6 = ".?AVFindSharesKernel@xmrig@@" fullword ascii
      $s7 = ".?AVCn0Kernel@xmrig@@" fullword ascii
      $s8 = ".?AVFillAesKernel@xmrig@@" fullword ascii
      $s9 = ".?AVOclKernel@xmrig@@" fullword ascii
      $s10 = ".?AVCn1Kernel@xmrig@@" fullword ascii
      $s11 = ".?AVRxJitKernel@xmrig@@" fullword ascii
      $s12 = ".?AVInitVmKernel@xmrig@@" fullword ascii
      $s13 = ".?AVCn2Kernel@xmrig@@" fullword ascii
      $s14 = ".?AVCnBranchKernel@xmrig@@" fullword ascii
      $s15 = ".?AVCudaCnRunner@xmrig@@" fullword ascii
      $s16 = ".?AVOclBaseRunner@xmrig@@" fullword ascii
      $s17 = ".?AVOclRxJitRunner@xmrig@@" fullword ascii
      $s18 = ".?AVCudaBaseRunner@xmrig@@" fullword ascii
      $s19 = ".?AVOclRxVmRunner@xmrig@@" fullword ascii
      $s20 = ".?AVIRxListener@xmrig@@" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 13000KB and ( 8 of them )
      ) or ( all of them )
}

rule _match_197 {
   meta:
      description = "black - from files 0f9eddc5e740edcd96e2f32d6acc3bb3, 8a490aa2517646411b6ea1383f17bbd1, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 5f52a27f400818807d2693e1a52260ad, 0086748f3a7854b3a35f69b5285c534f, e28e3404155556ecafff204356fcc5f0, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, af408f884178b56843b9f7324bcdefb4, 51f0f95501d456804707bd997c56b416, a3b4afa503657e7a327934ddd231887e, b9280790ed58987ab2af68537ad18d6d, b1b0580af0e8fa730486561255426f38, 26fc98d7481f9b494ecbfebacdcbeab3, ae33c5c9544d63463cca74c42a556983, ee3f5f355249823f286f389ce0567002, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 86d7666073561a5d0ca494d80eae3e5e, 9b3518901fb21e67bfd3986cdcded31c, 99fe45ec1a50c0413a6dcb1d23b754f9, e97524afde7b751f6b024fa4798bdf51, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash2 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash3 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash4 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash5 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash6 = "0693cfd2a09f5358cdec077df4cf049c88fe5fcdc606a228e389c9b2e517f965"
      hash7 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash8 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash9 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash10 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash11 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash12 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash13 = "c92d9638c8fb2b0556802ea87082be829f50dd7d29579a1a893ade35bd7a9256"
      hash14 = "a8efd58c2f819b96742b10bad9aa76494731295f32ccc9897d3694944017b2a4"
      hash15 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash16 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash17 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash18 = "b95f40cce47499183ef95d6d56b8b5deed0d99a413a8bd7067200c5b1ae752a9"
      hash19 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash20 = "ade656b212a4bef11d70720679ec7fd91586a9507448634cd716178ed908e509"
      hash21 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash22 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash23 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash24 = "ee7ab7d8bd4643e2f2d63bc0329b21c6d3437beea13fc379ee7fbfc0e326d0f5"
      hash25 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash26 = "b81e7c41d4c6cec4c6f99f9e577c8335c685bf09351af664d82c2a97bc12b89c"
      hash27 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash28 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = "Failed to allocate executable memory" fullword ascii
      $s2 = "randomx" fullword ascii
      $s3 = "setcc cl" fullword ascii
      $s4 = "imul r,r" fullword ascii
      $s5 = "/2/summary" fullword ascii
      $s6 = "IADD_RS" fullword ascii
      $s7 = "/2/backends" fullword ascii
      $s8 = "IMULH_R" fullword ascii
      $s9 = "RandomXL" fullword ascii
      $s10 = "IXOR_C8" fullword ascii
      $s11 = "IMUL_RCP" fullword ascii
      $s12 = "IXOR_C7" fullword ascii
      $s13 = "/2/config" fullword ascii
      $s14 = "randomx/loki" fullword ascii
      $s15 = "IADD_C8" fullword ascii
      $s16 = "IXOR_C9" fullword ascii
      $s17 = "IADD_C7" fullword ascii
      $s18 = "RandomWOW" fullword ascii
      $s19 = "randomx/0" fullword ascii
      $s20 = "testjz r,i" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 25000KB and ( 8 of them )
      ) or ( all of them )
}



rule _match_216 {
   meta:
      description = "black - from files 905eeda0ddf717b45bb294b227e6d8ae, 6b97eabf2e7eef8ccfc36593771ebe12, 4396f6981923a6e702a9d18a3d76e482, 20addcaa91c6bc5c7cc665ddb2e8c52c, 97ee5c92d5c865ef6db67c35bc8a427a, 50b754688ea8b1994abc99ea58263ebb, d220d7b9023e6bd3717edc17765fbb25, 0f4acbb2acfaa97b146f4949729d0ec6, 5846aed02e23db1af696661606cf5bfd, cd7e6a6f2e3fc3cb1049efbbf235577f, 3934d1adff337a3741fc308eb83daaba, 99bd2332ea3179db7a70a6e66d11e096, 0cf00d65acee7181d4679d2ad3da5301, f8a8bd5eb3b9328c007438070e0c3ca8, 2458b8fb100cb0d0c80a3f62aea0e080, 0742b7c20e14fc0b9390fd5aafef6442, cd9d53902ae60c8a9330b6b145cbe3bb, 80ba21786b71bb0dba959194fa1d3f63, a746e73da04945445e385850616990c9, 6a80142ac8cf4d5534d2eb9cb0e3e08d, ddafbf9406cc26df63a32702126e3fc9, b1a919e6fb009361b64d51b351a25e4c, 3ba79ba35b4b388fe9699e51d4c43fea, e74a8e9fbf1969888d78bfe6bf757759, 9a07ca40de9c85495231302023c6a74a, 2ae5db210e8c7c0c96e6bed93bce1da6, 233cb487009705a47f32a694558deca5, 0cccafcbc4d1a6d50ccd8fa1df89bc0f, 3a69511ef880ea841a6740357901ca61, 74f394c609338509e94d61091a70b6f5"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "a28878f5880b8a1c506258dd39b459cec616f79100afe006b4779525b8a937a3"
      hash2 = "d2b4b16be498e2fbe782b6f0e73515f6fc74c7a661c44891a9860cbf2b690d02"
      hash3 = "4fd49a0d1574549b4f8b64c9d474417600d6ede505c3997b3b07eb9e92bd440a"
      hash4 = "c2389593cb340e9b682e457e6bf926abf1eee594d129c237f3f87852731dba7d"
      hash5 = "e91e3d9138b2961bf0807b39ab1c0647e78ccf6985890246db1d698af498e43b"
      hash6 = "2efbcf082019f2fe3b7b065842a6e99e0441e7166265d2021695fce00f0d4373"
      hash7 = "8d887ba624e0e8f55be8deb805ec25c1a2a34e6fa137b6bc30025cfbc124dfb8"
      hash8 = "4c9bf0426483d1f8f7943cb291345134964d237f1b8270f88f51cbdd1557a41e"
      hash9 = "5d1ef3f5bc06e457945af001cad5e392eea47ae4486522ad3342f42b6e2b7436"
      hash10 = "08e6eb5d64f01d4a982bf75e4ffbec7d0f61d7ece7b7fbfe2fade7ae39ad8884"
      hash11 = "2fefce5634c8b6f9e334fd6b1c34b86f6cb8278dc07558034d1ead43d1467cbb"
      hash12 = "2e999f22d7fa0d018342d235067b5bb879b4505bb0e42156f816d38ae61cd3fe"
      hash13 = "a0e6799ed9cb59ac3aeab73f2c10015fbabbacc850b56148778f69cc38835d27"
      hash14 = "2df4f0927f0f73ff7ca38a4edfe9406be229985fd5ae468d9b5aa19b9b0cd0ac"
      hash15 = "ba3e5e8af6d21e5fa3a78b69a87ca1cd39afd4342795f514bd651af81e9b8e47"
      hash16 = "3b38ac70eac888ba76ae3c5812179863a78b4e63ce92f5108f019bb00f96b35c"
      hash17 = "9c62abcac2762be0e5abbb7f06ffb65c0b8fbea84d015944b6593453354303eb"
      hash18 = "2e4b386aa820c4a1b294274d89652098e4a78921df83b1ed101213f558f704ea"
      hash19 = "beae2bc4274deb42c452e6ad910853cfa1a60e05f0180ed43829e2a4f5281e04"
      hash20 = "c8eb9182adc12b591cbdafe27759495487a53c0cd38f83f77f575edf21e5d4b3"
      hash21 = "a35d47fde5d36de866ba7fbe638c7ea9f5860962b326484936a992cbba6fa22f"
      hash22 = "72356978da0b156bae25c84189c01a47b7c8e8daf22e2be533f1e2733f8372f2"
      hash23 = "d274427049b5e28fdd153a0bdbcb08445ffebd9031ed666dba23b62e44b3191a"
      hash24 = "4c486b48b0524a9e3059f5dab86bffa9a0fa82787363c7784c624453344dc1d1"
      hash25 = "ea9d91772dd86455d5bf25c080ed859faae39c7085abb5de0b3142a397e7f131"
      hash26 = "3b1a32116390ef2a821cbeb15e214f937293ee39cfde2a2e97f2eb128474bce3"
      hash27 = "1c6eeaf450250baad8b4bbdcb4539a5ec8ad9878d1ea4c96c493e01cca02f1d2"
      hash28 = "4a49d867bbb4e4e36b55c77f0f514fdf18a78b18b701ae853075092ac2893e2e"
      hash29 = "477ff70035e7438bbb414dcaf805d93a61dc39f75acf882134097fe3be105e48"
      hash30 = "02bd77bfd0a50ae5ea7e8a6587187e84b5c4d0d5638c7559abe609fbebbacd38"
   strings:
      $s1 = "Error processing request (HTTP response code is %u (`%s')). Closing connection." fullword ascii
      $s2 = "WARNING: incomplete upload processing and connection not suspended may result in hung connection." fullword ascii
      $s3 = "Failed to parse `Content-Length' header. Closing connection." fullword ascii
      $s4 = "MHD failed to initialize cleanup connection mutex" fullword ascii
      $s5 = "Received HTTP 1.1 request without `Host' header." fullword ascii
      $s6 = "<html><head><title>Internal server error</title></head><body>Please ask the developer of this Web server to carefully read the G" ascii
      $s7 = "Failed to signal end of connection via inter-thread communication channel" fullword ascii
      $s8 = "Failed to signal resume of connection via inter-thread communication channel." fullword ascii
      $s9 = "Failed to signal new connection via inter-thread communication channel." fullword ascii
      $s10 = "Warning: MHD_USE_THREAD_PER_CONNECTION must be used only with MHD_USE_INTERNAL_POLLING_THREAD. Flag MHD_USE_INTERNAL_POLLING_THR" ascii
      $s11 = "<html><head><title>Internal server error</title></head><body>Please ask the developer of this Web server to carefully read the G" ascii
      $s12 = "NU libmicrohttpd documentation about connection management and blocking.</body></html>" fullword ascii
      $s13 = "Both MHD_OPTION_THREAD_POOL_SIZE option and MHD_USE_THREAD_PER_CONNECTION flag are specified." fullword ascii
      $s14 = "Received malformed HTTP request (bad chunked encoding). Closing connection." fullword ascii
      $s15 = "Warning: MHD_USE_THREAD_PER_CONNECTION must be used only with MHD_USE_INTERNAL_POLLING_THREAD. Flag MHD_USE_INTERNAL_POLLING_THR" ascii
      $s16 = "Failed to create worker inter-thread communication channel: %s" fullword ascii
      $s17 = "Failed to signal shutdown via inter-thread communication channel" fullword ascii
      $s18 = "Failed to signal shutdown via inter-thread communication channel." fullword ascii
      $s19 = "Failed to signal resume via inter-thread communication channel." fullword ascii
      $s20 = "EAD was added. Consider setting MHD_USE_INTERNAL_POLLING_THREAD explicitly." fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 27000KB and ( 8 of them )
      ) or ( all of them )
}

rule _match_220 {
   meta:
      description = "black - from files 0f9eddc5e740edcd96e2f32d6acc3bb3, 8a490aa2517646411b6ea1383f17bbd1, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 5f52a27f400818807d2693e1a52260ad, e28e3404155556ecafff204356fcc5f0, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, a3b4afa503657e7a327934ddd231887e, b9280790ed58987ab2af68537ad18d6d, b1b0580af0e8fa730486561255426f38, 26fc98d7481f9b494ecbfebacdcbeab3, ae33c5c9544d63463cca74c42a556983, ee3f5f355249823f286f389ce0567002, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 86d7666073561a5d0ca494d80eae3e5e, 9b3518901fb21e67bfd3986cdcded31c, 99fe45ec1a50c0413a6dcb1d23b754f9, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash2 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash3 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash4 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash5 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash6 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash7 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash8 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash9 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash10 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash11 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash12 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash13 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash14 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash15 = "b95f40cce47499183ef95d6d56b8b5deed0d99a413a8bd7067200c5b1ae752a9"
      hash16 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash17 = "ade656b212a4bef11d70720679ec7fd91586a9507448634cd716178ed908e509"
      hash18 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash19 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash20 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash21 = "ee7ab7d8bd4643e2f2d63bc0329b21c6d3437beea13fc379ee7fbfc0e326d0f5"
      hash22 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash23 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash24 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = "      --opencl-loader=PATH      path to OpenCL-ICD-Loader (OpenCL.dll or libOpenCL.so)" fullword ascii
      $s2 = "      --cuda-loader=PATH        path to CUDA plugin (xmrig-cuda.dll or libxmrig-cuda.so)" fullword ascii
      $s3 = "  -a, --algo=ALGO               mining algorithm https://xmrig.com/docs/algorithms" fullword ascii
      $s4 = "      --self-select=URL         self-select block templates from URL" fullword ascii
      $s5 = "      --cpu-max-threads-hint=N  maximum CPU threads count (in percentage) hint for autoconfig" fullword ascii
      $s6 = "Logging:" fullword ascii
      $s7 = "[1;31mfast RandomX mode disabled by config" fullword ascii
      $s8 = "      --donate-over-proxy=N     control donate over xmrig-proxy feature" fullword ascii
      $s9 = "      --cuda-bfactor-hint=N     bfactor hint for autoconfig (0-12)" fullword ascii
      $s10 = "      --opencl-devices=N        comma separated list of OpenCL devices to use" fullword ascii
      $s11 = "      --cuda-devices=N          comma separated list of CUDA devices to use" fullword ascii
      $s12 = "      --health-print-time=N     print health report every N seconds" fullword ascii
      $s13 = "      --cuda-bsleep-hint=N      bsleep hint for autoconfig" fullword ascii
      $s14 = "      --no-nvml                 disable NVML (NVIDIA Management Library) support" fullword ascii
      $s15 = "  -t, --threads=N               number of CPU threads" fullword ascii
      $s16 = "hardware_concurrency" fullword ascii
      $s17 = "resident_set_memory" fullword ascii
      $s18 = "load_average" fullword ascii
      $s19 = "CPU backend:" fullword ascii
      $s20 = "CUDA backend:" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 19000KB and ( 8 of them )
      ) or ( all of them )
}

rule _match_225 {
   meta:
      description = "black - from files 0f9eddc5e740edcd96e2f32d6acc3bb3, 6cfc530100079ac1f1ed0cf61bed2ca8, acd5942fee24e5bc6769bb2fb529b695, 8a490aa2517646411b6ea1383f17bbd1, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 5f52a27f400818807d2693e1a52260ad, 0086748f3a7854b3a35f69b5285c534f, e28e3404155556ecafff204356fcc5f0, 4d6dff8b2def91e85a09faa27899d9d5, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, a3b4afa503657e7a327934ddd231887e, b3c0545d8bdbd5cd9c4c5cbd4d070d2a, b9280790ed58987ab2af68537ad18d6d, b1b0580af0e8fa730486561255426f38, ae33c5c9544d63463cca74c42a556983, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 86d7666073561a5d0ca494d80eae3e5e, 99fe45ec1a50c0413a6dcb1d23b754f9, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash2 = "438784b7594602da1a92d67890953b527ef6cb045e0c64ccaa4e78448576fff5"
      hash3 = "0083066406394696a0e6f26928d71785bf9fcdecdd6dcf52731a93b78f2cca0c"
      hash4 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash5 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash6 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash7 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash8 = "0693cfd2a09f5358cdec077df4cf049c88fe5fcdc606a228e389c9b2e517f965"
      hash9 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash10 = "dbc26374af31e9c81b8bc3a6c3063387f587a2596510e2a3be24aea6e025294f"
      hash11 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash12 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash13 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash14 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash15 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash16 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash17 = "7bf303baebaec1c10be08273dd3d1ce503c4a7e1edaefc6092778b2926ebb278"
      hash18 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash19 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash20 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash21 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash22 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash23 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash24 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash25 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash26 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = "A$;A,tZ3" fullword ascii
      $s2 = "`_RDATA" fullword ascii
      $s3 = "8HcFTL" fullword ascii
      $s4 = "L$PH3G#H" fullword ascii
      $s5 = "MXH3MHfH" fullword ascii
      $s6 = "2</uSH" fullword ascii
      $s7 = "EPH3E@f" fullword ascii
      $s8 = "U`H;Uht," fullword ascii
      $s9 = "E97u}E3" fullword ascii
      $s10 = "u=I;P r7H" fullword ascii
      $s11 = "D$@H9P s" fullword ascii
      $s12 = "d$`u`A" fullword ascii
      $s13 = "tj<jtV" fullword ascii
      $s14 = ":u(f9Q" fullword ascii
      $s15 = "D$ f;VPu" fullword ascii
      $s16 = "bD8d$8t" fullword ascii
      $s17 = " D8d$8t" fullword ascii
      $s18 = "c(H3>L33L3~" fullword ascii
      $s19 = "A:8ucI" fullword ascii
      $s20 = "f9|$ tyf" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and ( 8 of them )
      ) or ( all of them )
}

rule _match_247 {
   meta:
      description = "black - from files 97ee5c92d5c865ef6db67c35bc8a427a, d220d7b9023e6bd3717edc17765fbb25, 0f4acbb2acfaa97b146f4949729d0ec6, 5846aed02e23db1af696661606cf5bfd, cd7e6a6f2e3fc3cb1049efbbf235577f, 3934d1adff337a3741fc308eb83daaba, 99bd2332ea3179db7a70a6e66d11e096, 0cf00d65acee7181d4679d2ad3da5301, f8a8bd5eb3b9328c007438070e0c3ca8, 2458b8fb100cb0d0c80a3f62aea0e080, 0742b7c20e14fc0b9390fd5aafef6442, 6a80142ac8cf4d5534d2eb9cb0e3e08d, ddafbf9406cc26df63a32702126e3fc9, b1a919e6fb009361b64d51b351a25e4c, 3ba79ba35b4b388fe9699e51d4c43fea, c2f7a2599c9dea0e04d9d20a4eb2c0f0, e88d37df942ac9ab1432c686ef346a6c, fa52279e88d5510ea6c4eaec3b100c00, e74a8e9fbf1969888d78bfe6bf757759, 7c2a9696e8feae3fdd4d2a71a2359019, 47a32262fbe86e120fd5d69e295b9fc3"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "e91e3d9138b2961bf0807b39ab1c0647e78ccf6985890246db1d698af498e43b"
      hash2 = "8d887ba624e0e8f55be8deb805ec25c1a2a34e6fa137b6bc30025cfbc124dfb8"
      hash3 = "4c9bf0426483d1f8f7943cb291345134964d237f1b8270f88f51cbdd1557a41e"
      hash4 = "5d1ef3f5bc06e457945af001cad5e392eea47ae4486522ad3342f42b6e2b7436"
      hash5 = "08e6eb5d64f01d4a982bf75e4ffbec7d0f61d7ece7b7fbfe2fade7ae39ad8884"
      hash6 = "2fefce5634c8b6f9e334fd6b1c34b86f6cb8278dc07558034d1ead43d1467cbb"
      hash7 = "2e999f22d7fa0d018342d235067b5bb879b4505bb0e42156f816d38ae61cd3fe"
      hash8 = "a0e6799ed9cb59ac3aeab73f2c10015fbabbacc850b56148778f69cc38835d27"
      hash9 = "2df4f0927f0f73ff7ca38a4edfe9406be229985fd5ae468d9b5aa19b9b0cd0ac"
      hash10 = "ba3e5e8af6d21e5fa3a78b69a87ca1cd39afd4342795f514bd651af81e9b8e47"
      hash11 = "3b38ac70eac888ba76ae3c5812179863a78b4e63ce92f5108f019bb00f96b35c"
      hash12 = "c8eb9182adc12b591cbdafe27759495487a53c0cd38f83f77f575edf21e5d4b3"
      hash13 = "a35d47fde5d36de866ba7fbe638c7ea9f5860962b326484936a992cbba6fa22f"
      hash14 = "72356978da0b156bae25c84189c01a47b7c8e8daf22e2be533f1e2733f8372f2"
      hash15 = "d274427049b5e28fdd153a0bdbcb08445ffebd9031ed666dba23b62e44b3191a"
      hash16 = "6c9ad0cbcb8156f327526451c3452837d5256283239a77f931b1a3f542e61b82"
      hash17 = "9741357a1d61e8777cbb9234b46369df7752b9950f069fef7154a8ce748619e3"
      hash18 = "be1c04b7dc32a549668dc96f6f14c1e70f552f119864a0e467418455ec6f62a5"
      hash19 = "4c486b48b0524a9e3059f5dab86bffa9a0fa82787363c7784c624453344dc1d1"
      hash20 = "6057eeaa384d6cefe9c0917ff848da11508bc0754714446465d508a3a232fbdb"
      hash21 = "1b435cd0e002358d4ca191463d0fb54ea1136b53b74de8db93d61f935203392e"
   strings:
      $s1 = "MHD_get_version" fullword ascii
      $s2 = "MHD_get_connection_values" fullword ascii
      $s3 = "MHD_get_connection_info" fullword ascii
      $s4 = "MHD_get_reason_phrase_for" fullword ascii
      $s5 = "MHD_get_timeout" fullword ascii
      $s6 = "MHD_get_response_header" fullword ascii
      $s7 = "MHD_add_response_header" fullword ascii
      $s8 = "MHD_del_response_header" fullword ascii
      $s9 = "MHD_get_daemon_info" fullword ascii
      $s10 = "MHD_get_response_headers" fullword ascii
      $s11 = "MHD_lookup_connection_value" fullword ascii
      $s12 = "MHD_run_from_select" fullword ascii
      $s13 = "MHD_set_connection_value" fullword ascii
      $s14 = "MHD_add_connection" fullword ascii
      $s15 = "MHD_set_connection_option" fullword ascii
      $s16 = "MHD_get_fdset" fullword ascii
      $s17 = "MHD_destroy_response" fullword ascii
      $s18 = "MHD_start_daemon" fullword ascii
      $s19 = "MHD_set_panic_func" fullword ascii
      $s20 = "MHD_run" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 27000KB and ( 8 of them )
      ) or ( all of them )
}

rule _match_251 {
   meta:
      description = "black - from files 0f9eddc5e740edcd96e2f32d6acc3bb3, 8a490aa2517646411b6ea1383f17bbd1, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 5f52a27f400818807d2693e1a52260ad, 0086748f3a7854b3a35f69b5285c534f, e28e3404155556ecafff204356fcc5f0, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, af408f884178b56843b9f7324bcdefb4, 51f0f95501d456804707bd997c56b416, a3b4afa503657e7a327934ddd231887e, b9280790ed58987ab2af68537ad18d6d, b1b0580af0e8fa730486561255426f38, 13ce83c5c7ea01852b0ae2e35b74949b, 26fc98d7481f9b494ecbfebacdcbeab3, ae33c5c9544d63463cca74c42a556983, ee3f5f355249823f286f389ce0567002, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 15c4fc341d735f9ea8427f918d3f5422, 86d7666073561a5d0ca494d80eae3e5e, 9b3518901fb21e67bfd3986cdcded31c, 99fe45ec1a50c0413a6dcb1d23b754f9, e97524afde7b751f6b024fa4798bdf51, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash2 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash3 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash4 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash5 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash6 = "0693cfd2a09f5358cdec077df4cf049c88fe5fcdc606a228e389c9b2e517f965"
      hash7 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash8 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash9 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash10 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash11 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash12 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash13 = "c92d9638c8fb2b0556802ea87082be829f50dd7d29579a1a893ade35bd7a9256"
      hash14 = "a8efd58c2f819b96742b10bad9aa76494731295f32ccc9897d3694944017b2a4"
      hash15 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash16 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash17 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash18 = "10fe50b5f6fbaad5498bdc524145e5e05719fccc308da6de5a7c30ce9c3cbba3"
      hash19 = "b95f40cce47499183ef95d6d56b8b5deed0d99a413a8bd7067200c5b1ae752a9"
      hash20 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash21 = "ade656b212a4bef11d70720679ec7fd91586a9507448634cd716178ed908e509"
      hash22 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash23 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash24 = "242b2e8bf86f40047ed0c60607f61f81fb144a641a394ab51f4b21f1511ddca8"
      hash25 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash26 = "ee7ab7d8bd4643e2f2d63bc0329b21c6d3437beea13fc379ee7fbfc0e326d0f5"
      hash27 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash28 = "b81e7c41d4c6cec4c6f99f9e577c8335c685bf09351af664d82c2a97bc12b89c"
      hash29 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash30 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = "blocktemplate_blob" fullword ascii
      $s2 = "/getheight" fullword ascii
      $s3 = "/getinfo" fullword ascii
      $s4 = "daemon+http://" fullword ascii
      $s5 = "top_block_hash" fullword ascii
      $s6 = "blockhashing_blob" fullword ascii
      $s7 = "HTTP API" fullword ascii
      $s8 = "daemon+https://" fullword ascii
      $s9 = "REBIND" fullword ascii
      $s10 = "[1;%dm%d " fullword ascii
      $s11 = "SOURCE" fullword ascii /* Goodware String - occured 38 times */
      $s12 = "SUBSCRIBE" fullword ascii /* Goodware String - occured 39 times */
      $s13 = "[1;30m\"%s\"" fullword ascii
      $s14 = "/json_rpc" fullword ascii
      $s15 = "/favicon.ico" fullword ascii /* Goodware String - occured 1 times */
      $s16 = "MKCALENDAR" fullword ascii
      $s17 = "[0;36m%s " fullword ascii
      $s18 = "[1;37m%zu " fullword ascii
      $s19 = "[1;31m%s" fullword ascii
      $s20 = "[1;35m%s" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 25000KB and ( 8 of them )
      ) or ( all of them )
}

rule _match_258 {
   meta:
      description = "black - from files 905eeda0ddf717b45bb294b227e6d8ae, 6b97eabf2e7eef8ccfc36593771ebe12, 4396f6981923a6e702a9d18a3d76e482, 0f9eddc5e740edcd96e2f32d6acc3bb3, 20addcaa91c6bc5c7cc665ddb2e8c52c, 8a490aa2517646411b6ea1383f17bbd1, 97ee5c92d5c865ef6db67c35bc8a427a, 50b754688ea8b1994abc99ea58263ebb, d220d7b9023e6bd3717edc17765fbb25, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 0f4acbb2acfaa97b146f4949729d0ec6, 5f52a27f400818807d2693e1a52260ad, 5846aed02e23db1af696661606cf5bfd, cd7e6a6f2e3fc3cb1049efbbf235577f, 0086748f3a7854b3a35f69b5285c534f, e28e3404155556ecafff204356fcc5f0, a7e372d0982334302446756bf112d881, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, 3934d1adff337a3741fc308eb83daaba, 99bd2332ea3179db7a70a6e66d11e096, af408f884178b56843b9f7324bcdefb4, 0cf00d65acee7181d4679d2ad3da5301, 51f0f95501d456804707bd997c56b416, f8a8bd5eb3b9328c007438070e0c3ca8, 2458b8fb100cb0d0c80a3f62aea0e080, 0742b7c20e14fc0b9390fd5aafef6442, a3b4afa503657e7a327934ddd231887e, cd9d53902ae60c8a9330b6b145cbe3bb, b9280790ed58987ab2af68537ad18d6d, 80ba21786b71bb0dba959194fa1d3f63, a746e73da04945445e385850616990c9, 6a80142ac8cf4d5534d2eb9cb0e3e08d, ddafbf9406cc26df63a32702126e3fc9, b1b0580af0e8fa730486561255426f38, 13ce83c5c7ea01852b0ae2e35b74949b, b1a919e6fb009361b64d51b351a25e4c, 3ba79ba35b4b388fe9699e51d4c43fea, 26fc98d7481f9b494ecbfebacdcbeab3, ae33c5c9544d63463cca74c42a556983, ee3f5f355249823f286f389ce0567002, e74a8e9fbf1969888d78bfe6bf757759, 9a07ca40de9c85495231302023c6a74a, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 15c4fc341d735f9ea8427f918d3f5422, 2ae5db210e8c7c0c96e6bed93bce1da6, 86d7666073561a5d0ca494d80eae3e5e, 6bd4123b8dc8281bfee4c09350545c7e, 7c2a9696e8feae3fdd4d2a71a2359019, 233cb487009705a47f32a694558deca5, 0cccafcbc4d1a6d50ccd8fa1df89bc0f, 9b3518901fb21e67bfd3986cdcded31c, 99fe45ec1a50c0413a6dcb1d23b754f9, 3a69511ef880ea841a6740357901ca61, 74f394c609338509e94d61091a70b6f5, e97524afde7b751f6b024fa4798bdf51, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "a28878f5880b8a1c506258dd39b459cec616f79100afe006b4779525b8a937a3"
      hash2 = "d2b4b16be498e2fbe782b6f0e73515f6fc74c7a661c44891a9860cbf2b690d02"
      hash3 = "4fd49a0d1574549b4f8b64c9d474417600d6ede505c3997b3b07eb9e92bd440a"
      hash4 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash5 = "c2389593cb340e9b682e457e6bf926abf1eee594d129c237f3f87852731dba7d"
      hash6 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash7 = "e91e3d9138b2961bf0807b39ab1c0647e78ccf6985890246db1d698af498e43b"
      hash8 = "2efbcf082019f2fe3b7b065842a6e99e0441e7166265d2021695fce00f0d4373"
      hash9 = "8d887ba624e0e8f55be8deb805ec25c1a2a34e6fa137b6bc30025cfbc124dfb8"
      hash10 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash11 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash12 = "4c9bf0426483d1f8f7943cb291345134964d237f1b8270f88f51cbdd1557a41e"
      hash13 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash14 = "5d1ef3f5bc06e457945af001cad5e392eea47ae4486522ad3342f42b6e2b7436"
      hash15 = "08e6eb5d64f01d4a982bf75e4ffbec7d0f61d7ece7b7fbfe2fade7ae39ad8884"
      hash16 = "0693cfd2a09f5358cdec077df4cf049c88fe5fcdc606a228e389c9b2e517f965"
      hash17 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash18 = "d204dc52cd7c86013aa224f66e5631efec50edff579c78d21310c49b05910018"
      hash19 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash20 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash21 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash22 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash23 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash24 = "2fefce5634c8b6f9e334fd6b1c34b86f6cb8278dc07558034d1ead43d1467cbb"
      hash25 = "2e999f22d7fa0d018342d235067b5bb879b4505bb0e42156f816d38ae61cd3fe"
      hash26 = "c92d9638c8fb2b0556802ea87082be829f50dd7d29579a1a893ade35bd7a9256"
      hash27 = "a0e6799ed9cb59ac3aeab73f2c10015fbabbacc850b56148778f69cc38835d27"
      hash28 = "a8efd58c2f819b96742b10bad9aa76494731295f32ccc9897d3694944017b2a4"
      hash29 = "2df4f0927f0f73ff7ca38a4edfe9406be229985fd5ae468d9b5aa19b9b0cd0ac"
      hash30 = "ba3e5e8af6d21e5fa3a78b69a87ca1cd39afd4342795f514bd651af81e9b8e47"
      hash31 = "3b38ac70eac888ba76ae3c5812179863a78b4e63ce92f5108f019bb00f96b35c"
      hash32 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash33 = "9c62abcac2762be0e5abbb7f06ffb65c0b8fbea84d015944b6593453354303eb"
      hash34 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash35 = "2e4b386aa820c4a1b294274d89652098e4a78921df83b1ed101213f558f704ea"
      hash36 = "beae2bc4274deb42c452e6ad910853cfa1a60e05f0180ed43829e2a4f5281e04"
      hash37 = "c8eb9182adc12b591cbdafe27759495487a53c0cd38f83f77f575edf21e5d4b3"
      hash38 = "a35d47fde5d36de866ba7fbe638c7ea9f5860962b326484936a992cbba6fa22f"
      hash39 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash40 = "10fe50b5f6fbaad5498bdc524145e5e05719fccc308da6de5a7c30ce9c3cbba3"
      hash41 = "72356978da0b156bae25c84189c01a47b7c8e8daf22e2be533f1e2733f8372f2"
      hash42 = "d274427049b5e28fdd153a0bdbcb08445ffebd9031ed666dba23b62e44b3191a"
      hash43 = "b95f40cce47499183ef95d6d56b8b5deed0d99a413a8bd7067200c5b1ae752a9"
      hash44 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash45 = "ade656b212a4bef11d70720679ec7fd91586a9507448634cd716178ed908e509"
      hash46 = "4c486b48b0524a9e3059f5dab86bffa9a0fa82787363c7784c624453344dc1d1"
      hash47 = "ea9d91772dd86455d5bf25c080ed859faae39c7085abb5de0b3142a397e7f131"
      hash48 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash49 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash50 = "242b2e8bf86f40047ed0c60607f61f81fb144a641a394ab51f4b21f1511ddca8"
      hash51 = "3b1a32116390ef2a821cbeb15e214f937293ee39cfde2a2e97f2eb128474bce3"
      hash52 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash53 = "12a37426a995ef84e905c85a531c2754d10926dfdec03125074f83b738fe40af"
      hash54 = "6057eeaa384d6cefe9c0917ff848da11508bc0754714446465d508a3a232fbdb"
      hash55 = "1c6eeaf450250baad8b4bbdcb4539a5ec8ad9878d1ea4c96c493e01cca02f1d2"
      hash56 = "4a49d867bbb4e4e36b55c77f0f514fdf18a78b18b701ae853075092ac2893e2e"
      hash57 = "ee7ab7d8bd4643e2f2d63bc0329b21c6d3437beea13fc379ee7fbfc0e326d0f5"
      hash58 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash59 = "477ff70035e7438bbb414dcaf805d93a61dc39f75acf882134097fe3be105e48"
      hash60 = "02bd77bfd0a50ae5ea7e8a6587187e84b5c4d0d5638c7559abe609fbebbacd38"
      hash61 = "b81e7c41d4c6cec4c6f99f9e577c8335c685bf09351af664d82c2a97bc12b89c"
      hash62 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash63 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = "Variant Also Negotiates" fullword ascii
      $s2 = "Not Extended" fullword ascii /* Goodware String - occured 1 times */
      $s3 = "Unavailable For Legal Reasons" fullword ascii
      $s4 = "Insufficient Storage" fullword ascii /* Goodware String - occured 2 times */
      $s5 = "Unprocessable Entity" fullword ascii /* Goodware String - occured 2 times */
      $s6 = "Failed Dependency" fullword ascii /* Goodware String - occured 2 times */
      $s7 = "Upgrade Required" fullword ascii /* Goodware String - occured 4 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 27000KB and ( all of them )
      ) or ( all of them )
}

rule _match_259 {
   meta:
      description = "black - from files f6ae12377ac77bd2b27c5977a7a01f6e, 86e319d1829ff562e623f18753e2e93f, b04996ef7a113bf1f00888c4549afa93, 478e84180c19dc6e3f8aa6e6ebb2c7d0, 4ef7a01ccf898a2a139112fc82dc6daa, f46e9d4d3a936d3b85f5bd7b57dc2a3f, d64b3c6bcfa051b4725f4e991dc69b2c, 2578ba1d40ae41f63401af64cfc96803, 04c93df4e64d5b8421c28e103b7cba43, 3f915707b453bd1cb84172b243dfc4e9, a2bde96e2d58cbb462b119380229d7f1, bed4c27f271c12d2b95f72ebb46a9c78, f65c66a0018c3026eacc92dafde90a0c, d38ac75f463b0517666bc171a3857b02, 30eb70ff293c54191675850d488c8edf, 75d0d94f087a9e8db3c88cbb5a6a8581, 184a71bd3054df5debb180933daf2dc8, 2489fcdbc397f255d261314d0e8f6cec, 5f1cc00a759fbaf72f02e9a37e6facb3, 90ab577f39b0ac8507e040117936efc1, 7fcfc4a9bbf477fe3e60b3dc2973f2bd, 5bf5e758581dbe00659d7e33065b7995, 2da8b883993ad19ccc8d4037ba904146, 38dc5cda072ae24cbbc42951da82ca9e, daa493a267811288fa42e31a2bee5c03, fa7fe9e295f9f6c4fe68572077790c62, 9e7afd009e1fc67700825548ccfd5db6, 5e88545848b639cbcd20f0b91a6a9d6a, 9a03e726e17750485746d9b4221c3c43"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "d03177393a733bc582065ea4331b6f5143c30c8c080502990158022f5670656b"
      hash2 = "6d3962c8bb8b5cd8aa7c2ffb746ea7300f26ce413ef2e51c623ae264e6aa53b6"
      hash3 = "1c6878417802864542aaecf710f8d150bf86fc3c1e3efe125465ae7097e2a841"
      hash4 = "f5387d3900b664d91bb64e2fbd4cba6798ae4453110230cff8574235a4da2d57"
      hash5 = "d2546fc94b5e707620311d42ffb5d357cb0f4bb9232844d1443ce6bdca48695e"
      hash6 = "22b7e4063b65d0ff6d1123afab92486a63c4001ad20f46912098a2b8dd2765fd"
      hash7 = "0ba38581fffb9dc1e839698215a3d0cecec70617401eff3ff137f1a2c993555d"
      hash8 = "28faaf21893e7050f72f2ebc625c9b277838af082f8802334ac644ba2a7e3817"
      hash9 = "2f39eda2aac8f011cd62c859ca1ed11bee46176f9e960560e9bfdd72decf6e47"
      hash10 = "07ce5434b4351184ecfbceb07656bef9b9fd86ad24944383c11849936c86ef15"
      hash11 = "603772dc820d896156cfb6b5f3a063dcf5679f8498159da333eac75619811abc"
      hash12 = "8a07303b7102324fa1a6258e1ff6e5680b2c2e0020e103f656e3a72ef3c6019e"
      hash13 = "3115857f4f3637f4caeff807bf060a875d75c67b551420f99e6800569ea1e375"
      hash14 = "76a579b7137df1875b1bcf0fe76842648d47b02c6355f6ad2bbeebe3b2874ba3"
      hash15 = "b4272b4c37af4ca5cdd6cd88d130cfbe543046ad18e03d6e17ab65db04da2325"
      hash16 = "0010dd78b832f3c63555286846ceec9f45218766ada59f366f08abcf6284549a"
      hash17 = "5b2d32a75fa7212d10ea6cbfc02a623ca4b3b824444fdf07220d468b00e50aeb"
      hash18 = "a980557bc3319653eb8a58ccfa9084a630a3c8c2db5cd65fb41d97689ea916ba"
      hash19 = "43c2f983cfdcae1f5f808b84c985bacbf5ed2eabed0ee3d91e61d86658f27909"
      hash20 = "0fb9d466e83cbab992088b5ee79db56f9c87bb2362abfe0568f5fc6388371ac3"
      hash21 = "7bccfe4068a5a9d531b262a48755485c2586932fa448f2b23098b21b92bb1252"
      hash22 = "ccf07834ff02e45f76ad2c0fc953ffd22c5064c717f32ff7343948ae14855c97"
      hash23 = "de6a1b84e4b0b00e322cb031c68209e3b2769b656dec8dd6d07c8848e6ae1552"
      hash24 = "cda1657bf6eee7c53253ea6d5391515a61058d8ba8076a31ef7dba33bf70db4c"
      hash25 = "6a9e5cbe50e96087d5b5fa480f3182911a5f1b549e27d3c3c3ec8406d2518d6b"
      hash26 = "e8a522970e58eb47433067c6a0f2044135a9248a614aea2ccfe148821fa7f024"
      hash27 = "9fe39e3c738da59a6fa83bf0998fe0419d0da51cb0796fe28f13bb73905fc582"
      hash28 = "3ff4ed2042ba6b6e5b949a88766e57033636873c8bd4d704ebec61a209528f86"
      hash29 = "6783fa21bdd16b94156b3855f3104f4d9e534ac806f7afa0b681b0e68127126d"
   strings:
      $s1 = "t$D3\\$" fullword ascii /* Goodware String - occured 1 times */
      $s2 = "t$D3T$" fullword ascii /* Goodware String - occured 1 times */
      $s3 = "l$43l$" fullword ascii /* Goodware String - occured 2 times */
      $s4 = "t$43t$(" fullword ascii /* Goodware String - occured 2 times */
      $s5 = "L$83L$$" fullword ascii /* Goodware String - occured 3 times */
      $s6 = "\\$,3D$(" fullword ascii
      $s7 = "\\$x3D$ " fullword ascii
      $s8 = "L$ 3t$" fullword ascii /* Goodware String - occured 3 times */
      $s9 = "\\$03t$" fullword ascii
      $s10 = "D$83T$ 3D$" fullword ascii
      $s11 = "l$83l$" fullword ascii
      $s12 = "D$43T$(" fullword ascii
      $s13 = "l$P3|$" fullword ascii
      $s14 = "T$83l$" fullword ascii
      $s15 = "L$,3l$" fullword ascii
      $s16 = "D$43T$ 3D$" fullword ascii
      $s17 = "1\\$,3L$$" fullword ascii
      $s18 = "D$,3t$(" fullword ascii
      $s19 = "L$,3L$$" fullword ascii
      $s20 = "D$43t$(" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and ( 8 of them )
      ) or ( all of them )
}

rule _match_262 {
   meta:
      description = "black - from files 0f9eddc5e740edcd96e2f32d6acc3bb3, 8a490aa2517646411b6ea1383f17bbd1, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 5f52a27f400818807d2693e1a52260ad, 0086748f3a7854b3a35f69b5285c534f, e28e3404155556ecafff204356fcc5f0, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, a3b4afa503657e7a327934ddd231887e, b9280790ed58987ab2af68537ad18d6d, b1b0580af0e8fa730486561255426f38, ae33c5c9544d63463cca74c42a556983, ee3f5f355249823f286f389ce0567002, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 86d7666073561a5d0ca494d80eae3e5e, 9b3518901fb21e67bfd3986cdcded31c, 99fe45ec1a50c0413a6dcb1d23b754f9, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash2 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash3 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash4 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash5 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash6 = "0693cfd2a09f5358cdec077df4cf049c88fe5fcdc606a228e389c9b2e517f965"
      hash7 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash8 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash9 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash10 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash11 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash12 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash13 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash14 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash15 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash16 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash17 = "ade656b212a4bef11d70720679ec7fd91586a9507448634cd716178ed908e509"
      hash18 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash19 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash20 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash21 = "ee7ab7d8bd4643e2f2d63bc0329b21c6d3437beea13fc379ee7fbfc0e326d0f5"
      hash22 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash23 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash24 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = ".?AV?$CompiledVm@$00@randomx@@" fullword ascii
      $s2 = ".?AV?$CompiledLightVm@$00@randomx@@" fullword ascii
      $s3 = ".?AV?$CompiledVm@$0A@@randomx@@" fullword ascii
      $s4 = ".?AV?$CompiledLightVm@$0A@@randomx@@" fullword ascii
      $s5 = ".?AV?$InterpretedVm@$0A@@randomx@@" fullword ascii
      $s6 = ".?AV?$InterpretedLightVm@$00@randomx@@" fullword ascii
      $s7 = ".?AV?$InterpretedLightVm@$0A@@randomx@@" fullword ascii
      $s8 = ".?AV?$VmBase@$0A@@randomx@@" fullword ascii
      $s9 = ".?AV?$InterpretedVm@$00@randomx@@" fullword ascii
      $s10 = "_RANDOMX_JITX86_STATIC" fullword ascii
      $s11 = ".?AV?$VmBase@$00@randomx@@" fullword ascii
      $s12 = ".?AVrandomx_vm@@" fullword ascii
      $s13 = ".?AVBytecodeMachine@randomx@@" fullword ascii
      $s14 = "USATAUI" fullword ascii /* Goodware String - occured 3 times */
      $s15 = "G8f9C8t" fullword ascii
      $s16 = "@ L;B u^H" fullword ascii
      $s17 = "C0L;G0u/H" fullword ascii
      $s18 = "D$HH1C(H" fullword ascii
      $s19 = "ltV*/H" fullword ascii
      $s20 = "A(I1@(H" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 13000KB and ( 8 of them )
      ) or ( all of them )
}

rule _match_279 {
   meta:
      description = "black - from files 97ee5c92d5c865ef6db67c35bc8a427a, d220d7b9023e6bd3717edc17765fbb25, 0f4acbb2acfaa97b146f4949729d0ec6, 09b0bb70c4456e39cb26cdf2667b2be7, 5846aed02e23db1af696661606cf5bfd, cd7e6a6f2e3fc3cb1049efbbf235577f, 3934d1adff337a3741fc308eb83daaba, 99bd2332ea3179db7a70a6e66d11e096, af408f884178b56843b9f7324bcdefb4, 0cf00d65acee7181d4679d2ad3da5301, 51f0f95501d456804707bd997c56b416, f8a8bd5eb3b9328c007438070e0c3ca8, 2458b8fb100cb0d0c80a3f62aea0e080, 0742b7c20e14fc0b9390fd5aafef6442, 6a80142ac8cf4d5534d2eb9cb0e3e08d, ddafbf9406cc26df63a32702126e3fc9, b1a919e6fb009361b64d51b351a25e4c, 3ba79ba35b4b388fe9699e51d4c43fea, 26fc98d7481f9b494ecbfebacdcbeab3, e74a8e9fbf1969888d78bfe6bf757759, e97524afde7b751f6b024fa4798bdf51"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "e91e3d9138b2961bf0807b39ab1c0647e78ccf6985890246db1d698af498e43b"
      hash2 = "8d887ba624e0e8f55be8deb805ec25c1a2a34e6fa137b6bc30025cfbc124dfb8"
      hash3 = "4c9bf0426483d1f8f7943cb291345134964d237f1b8270f88f51cbdd1557a41e"
      hash4 = "bc2a8aa09df1303d24917145a3b41acf1b9df09c72e65273883c63b288623e2b"
      hash5 = "5d1ef3f5bc06e457945af001cad5e392eea47ae4486522ad3342f42b6e2b7436"
      hash6 = "08e6eb5d64f01d4a982bf75e4ffbec7d0f61d7ece7b7fbfe2fade7ae39ad8884"
      hash7 = "2fefce5634c8b6f9e334fd6b1c34b86f6cb8278dc07558034d1ead43d1467cbb"
      hash8 = "2e999f22d7fa0d018342d235067b5bb879b4505bb0e42156f816d38ae61cd3fe"
      hash9 = "c92d9638c8fb2b0556802ea87082be829f50dd7d29579a1a893ade35bd7a9256"
      hash10 = "a0e6799ed9cb59ac3aeab73f2c10015fbabbacc850b56148778f69cc38835d27"
      hash11 = "a8efd58c2f819b96742b10bad9aa76494731295f32ccc9897d3694944017b2a4"
      hash12 = "2df4f0927f0f73ff7ca38a4edfe9406be229985fd5ae468d9b5aa19b9b0cd0ac"
      hash13 = "ba3e5e8af6d21e5fa3a78b69a87ca1cd39afd4342795f514bd651af81e9b8e47"
      hash14 = "3b38ac70eac888ba76ae3c5812179863a78b4e63ce92f5108f019bb00f96b35c"
      hash15 = "c8eb9182adc12b591cbdafe27759495487a53c0cd38f83f77f575edf21e5d4b3"
      hash16 = "a35d47fde5d36de866ba7fbe638c7ea9f5860962b326484936a992cbba6fa22f"
      hash17 = "72356978da0b156bae25c84189c01a47b7c8e8daf22e2be533f1e2733f8372f2"
      hash18 = "d274427049b5e28fdd153a0bdbcb08445ffebd9031ed666dba23b62e44b3191a"
      hash19 = "b95f40cce47499183ef95d6d56b8b5deed0d99a413a8bd7067200c5b1ae752a9"
      hash20 = "4c486b48b0524a9e3059f5dab86bffa9a0fa82787363c7784c624453344dc1d1"
      hash21 = "b81e7c41d4c6cec4c6f99f9e577c8335c685bf09351af664d82c2a97bc12b89c"
   strings:
      $s1 = "%s: __pos (which is %zu) > this->size() (which is %zu)" fullword ascii
      $s2 = "string::string" fullword ascii
      $s3 = "basic_string::at: __n (which is %zu) >= this->size() (which is %zu)" fullword ascii
      $s4 = "basic_string::_M_construct null not valid" fullword ascii
      $s5 = "basic_string::_M_replace" fullword ascii
      $s6 = "basic_string::_M_create" fullword ascii
      $s7 = "random_device::random_device(const std::string&)" fullword ascii /* Goodware String - occured 2 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 27000KB and ( all of them )
      ) or ( all of them )
}

rule _match_294 {
   meta:
      description = "black - from files 905eeda0ddf717b45bb294b227e6d8ae, 0f9eddc5e740edcd96e2f32d6acc3bb3, 8a490aa2517646411b6ea1383f17bbd1, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 5f52a27f400818807d2693e1a52260ad, e28e3404155556ecafff204356fcc5f0, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, af408f884178b56843b9f7324bcdefb4, a3b4afa503657e7a327934ddd231887e, b9280790ed58987ab2af68537ad18d6d, b1b0580af0e8fa730486561255426f38, 26fc98d7481f9b494ecbfebacdcbeab3, ae33c5c9544d63463cca74c42a556983, ee3f5f355249823f286f389ce0567002, 9a07ca40de9c85495231302023c6a74a, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 86d7666073561a5d0ca494d80eae3e5e, 9b3518901fb21e67bfd3986cdcded31c, 99fe45ec1a50c0413a6dcb1d23b754f9, e97524afde7b751f6b024fa4798bdf51, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "a28878f5880b8a1c506258dd39b459cec616f79100afe006b4779525b8a937a3"
      hash2 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash3 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash4 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash5 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash6 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash7 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash8 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash9 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash10 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash11 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash12 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash13 = "c92d9638c8fb2b0556802ea87082be829f50dd7d29579a1a893ade35bd7a9256"
      hash14 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash15 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash16 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash17 = "b95f40cce47499183ef95d6d56b8b5deed0d99a413a8bd7067200c5b1ae752a9"
      hash18 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash19 = "ade656b212a4bef11d70720679ec7fd91586a9507448634cd716178ed908e509"
      hash20 = "ea9d91772dd86455d5bf25c080ed859faae39c7085abb5de0b3142a397e7f131"
      hash21 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash22 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash23 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash24 = "ee7ab7d8bd4643e2f2d63bc0329b21c6d3437beea13fc379ee7fbfc0e326d0f5"
      hash25 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash26 = "b81e7c41d4c6cec4c6f99f9e577c8335c685bf09351af664d82c2a97bc12b89c"
      hash27 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash28 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = "clCreateCommandQueueWithProperties" fullword ascii
      $s2 = "#define mix_and_propagate(xin) (xin)[(get_local_id(1)) % 8][get_local_id(0)] ^ (xin)[(get_local_id(1) + 1) % 8][get_local_id(0)]" ascii
      $s3 = "#if defined(__NV_CL_C_VERSION) && STRIDED_INDEX != 0" fullword ascii
      $s4 = "inline ulong getIdx()" fullword ascii
      $s5 = "Error %s when calling %s, param 0x%04x" fullword ascii
      $s6 = "[1;32mcompilation completed" fullword ascii
      $s7 = "#if (STRIDED_INDEX == 0)" fullword ascii
      $s8 = "static const __constant uchar sbox[256] =" fullword ascii
      $s9 = "#define MEM_CHUNK (1 << MEM_CHUNK_EXPONENT)" fullword ascii
      $s10 = "inline uint fast_sqrt_v2(const ulong n1)" fullword ascii
      $s11 = "#elif (STRIDED_INDEX == 1)" fullword ascii
      $s12 = "#define VARIANT1_1(p) \\" fullword ascii
      $s13 = "#define VARIANT1_2(p) ((uint2 *)&(p))[0] ^= tweak1_2_0" fullword ascii
      $s14 = "#elif (STRIDED_INDEX == 2)" fullword ascii
      $s15 = "No OpenCL platform found." fullword ascii
      $s16 = "#define VARIANT1_INIT() \\" fullword ascii
      $s17 = "[1;33mcompiling..." fullword ascii
      $s18 = "[1;37m#%zu" fullword ascii
      $s19 = "static const __constant uint keccakf_rotc[24] =" fullword ascii
      $s20 = "#ifdef cl_clang_storage_class_specifiers" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 19000KB and ( 8 of them )
      ) or ( all of them )
}

rule _match_302 {
   meta:
      description = "black - from files 0f9eddc5e740edcd96e2f32d6acc3bb3, 6cfc530100079ac1f1ed0cf61bed2ca8, acd5942fee24e5bc6769bb2fb529b695, 8a490aa2517646411b6ea1383f17bbd1, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 5f52a27f400818807d2693e1a52260ad, 0086748f3a7854b3a35f69b5285c534f, e28e3404155556ecafff204356fcc5f0, 4d6dff8b2def91e85a09faa27899d9d5, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, 4451163751d9841553744a6f80ca0aed, fc481ae3e90d67283ce944cefb433d25, a3b4afa503657e7a327934ddd231887e, b3c0545d8bdbd5cd9c4c5cbd4d070d2a, b9280790ed58987ab2af68537ad18d6d, b1b0580af0e8fa730486561255426f38, 13ce83c5c7ea01852b0ae2e35b74949b, 63d152e378907ea71551baff27a82d7d, ae33c5c9544d63463cca74c42a556983, ee3f5f355249823f286f389ce0567002, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 15c4fc341d735f9ea8427f918d3f5422, 86d7666073561a5d0ca494d80eae3e5e, e4c92dd63239428f0b33c7f424293687, 9b3518901fb21e67bfd3986cdcded31c, 99fe45ec1a50c0413a6dcb1d23b754f9, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash2 = "438784b7594602da1a92d67890953b527ef6cb045e0c64ccaa4e78448576fff5"
      hash3 = "0083066406394696a0e6f26928d71785bf9fcdecdd6dcf52731a93b78f2cca0c"
      hash4 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash5 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash6 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash7 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash8 = "0693cfd2a09f5358cdec077df4cf049c88fe5fcdc606a228e389c9b2e517f965"
      hash9 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash10 = "dbc26374af31e9c81b8bc3a6c3063387f587a2596510e2a3be24aea6e025294f"
      hash11 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash12 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash13 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash14 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash15 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash16 = "e90a53ae1c6318e25816e74530a4c3607e55cbadf3b7eb0d0ff97fb78d6a8d96"
      hash17 = "201b177ab0fe48289ac660b899b7813ed6f276a9ea1246574c28ebacb943905d"
      hash18 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash19 = "7bf303baebaec1c10be08273dd3d1ce503c4a7e1edaefc6092778b2926ebb278"
      hash20 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash21 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash22 = "10fe50b5f6fbaad5498bdc524145e5e05719fccc308da6de5a7c30ce9c3cbba3"
      hash23 = "f275d2589f252cfd2a131a89429837de58c04322c5ced8986dfc968d37bb1d4f"
      hash24 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash25 = "ade656b212a4bef11d70720679ec7fd91586a9507448634cd716178ed908e509"
      hash26 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash27 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash28 = "242b2e8bf86f40047ed0c60607f61f81fb144a641a394ab51f4b21f1511ddca8"
      hash29 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash30 = "c9d6e3fa0bf1bae569a87f1526093204b2b6bbc227e8ddcd2af450c4fb5c71c3"
      hash31 = "ee7ab7d8bd4643e2f2d63bc0329b21c6d3437beea13fc379ee7fbfc0e326d0f5"
      hash32 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash33 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash34 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = ".?AVILogBackend@xmrig@@" fullword ascii
      $s2 = ".?AVConsoleLog@xmrig@@" fullword ascii
      $s3 = ".?AVIConfigTransform@xmrig@@" fullword ascii
      $s4 = ".?AVIJsonReader@xmrig@@" fullword ascii
      $s5 = ".?AVIDnsListener@xmrig@@" fullword ascii
      $s6 = ".?AVIBaseListener@xmrig@@" fullword ascii
      $s7 = ".?AVILineListener@xmrig@@" fullword ascii
      $s8 = ".?AVBaseConfig@xmrig@@" fullword ascii
      $s9 = ".?AVIConsoleListener@xmrig@@" fullword ascii
      $s10 = ".?AVITimerListener@xmrig@@" fullword ascii
      $s11 = ".?AVConfigTransform@xmrig@@" fullword ascii
      $s12 = ".?AVBase@xmrig@@" fullword ascii
      $s13 = ".?AVJsonChain@xmrig@@" fullword ascii
      $s14 = ".?AVIClient@xmrig@@" fullword ascii
      $s15 = ".?AVBaseClient@xmrig@@" fullword ascii
      $s16 = ".?AVBaseTransform@xmrig@@" fullword ascii
      $s17 = ".?AVClient@xmrig@@" fullword ascii
      $s18 = "H3D$XI3" fullword ascii
      $s19 = "GPI3G@f" fullword ascii
      $s20 = "MXH3MHfL" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and ( 8 of them )
      ) or ( all of them )
}

rule _match_303 {
   meta:
      description = "black - from files 0f9eddc5e740edcd96e2f32d6acc3bb3, 8a490aa2517646411b6ea1383f17bbd1, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 5f52a27f400818807d2693e1a52260ad, e28e3404155556ecafff204356fcc5f0, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, 51f0f95501d456804707bd997c56b416, 4451163751d9841553744a6f80ca0aed, a3b4afa503657e7a327934ddd231887e, b9280790ed58987ab2af68537ad18d6d, b1b0580af0e8fa730486561255426f38, 13ce83c5c7ea01852b0ae2e35b74949b, 26fc98d7481f9b494ecbfebacdcbeab3, 63d152e378907ea71551baff27a82d7d, ae33c5c9544d63463cca74c42a556983, ee3f5f355249823f286f389ce0567002, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 15c4fc341d735f9ea8427f918d3f5422, 86d7666073561a5d0ca494d80eae3e5e, e4c92dd63239428f0b33c7f424293687, 9b3518901fb21e67bfd3986cdcded31c, 99fe45ec1a50c0413a6dcb1d23b754f9, e97524afde7b751f6b024fa4798bdf51, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash2 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash3 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash4 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash5 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash6 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash7 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash8 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash9 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash10 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash11 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash12 = "a8efd58c2f819b96742b10bad9aa76494731295f32ccc9897d3694944017b2a4"
      hash13 = "e90a53ae1c6318e25816e74530a4c3607e55cbadf3b7eb0d0ff97fb78d6a8d96"
      hash14 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash15 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash16 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash17 = "10fe50b5f6fbaad5498bdc524145e5e05719fccc308da6de5a7c30ce9c3cbba3"
      hash18 = "b95f40cce47499183ef95d6d56b8b5deed0d99a413a8bd7067200c5b1ae752a9"
      hash19 = "f275d2589f252cfd2a131a89429837de58c04322c5ced8986dfc968d37bb1d4f"
      hash20 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash21 = "ade656b212a4bef11d70720679ec7fd91586a9507448634cd716178ed908e509"
      hash22 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash23 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash24 = "242b2e8bf86f40047ed0c60607f61f81fb144a641a394ab51f4b21f1511ddca8"
      hash25 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash26 = "c9d6e3fa0bf1bae569a87f1526093204b2b6bbc227e8ddcd2af450c4fb5c71c3"
      hash27 = "ee7ab7d8bd4643e2f2d63bc0329b21c6d3437beea13fc379ee7fbfc0e326d0f5"
      hash28 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash29 = "b81e7c41d4c6cec4c6f99f9e577c8335c685bf09351af664d82c2a97bc12b89c"
      hash30 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash31 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = "      --nicehash                enable nicehash.com support" fullword ascii
      $s2 = "      --user-agent              set custom user-agent string for pool" fullword ascii
      $s3 = "      --cpu-affinity            set process affinity to CPU core(s), mask 0x3 for cores 0 and 1" fullword ascii
      $s4 = "      --cpu-priority            set process priority (0 idle, 2 normal to 5 highest)" fullword ascii
      $s5 = "  -p, --pass=PASSWORD           password for mining server" fullword ascii
      $s6 = "  -O, --userpass=U:P            username:password pair for mining server" fullword ascii
      $s7 = "      --rig-id=ID               rig identifier for pool-side statistics (needs pool support)" fullword ascii
      $s8 = "      --dry-run                 test configuration and exit" fullword ascii
      $s9 = "      --print-time=N            print hashrate report every N seconds" fullword ascii
      $s10 = "  -l, --log-file=FILE           log all output to a file" fullword ascii
      $s11 = "      --no-huge-pages           disable huge pages support" fullword ascii
      $s12 = "  -V, --version                 output version information and exit" fullword ascii
      $s13 = "  -B, --background              run the miner in the background" fullword ascii
      $s14 = "  -k, --keepalive               send keepalived packet for prevent timeout (needs pool support)" fullword ascii
      $s15 = "  -u, --user=USERNAME           username for mining server" fullword ascii
      $s16 = "  -o, --url=URL                 URL of mining server" fullword ascii
      $s17 = "  -v, --av=N                    algorithm variation, 0 auto select" fullword ascii
      $s18 = "  -R, --retry-pause=N           time to pause between retries (default: 5)" fullword ascii
      $s19 = "  -r, --retries=N               number of times to retry before switch to backup server (default: 5)" fullword ascii
      $s20 = "      --donate-level=N          donate level, default 5%% (5 minutes in 100 minutes)" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 25000KB and ( 8 of them )
      ) or ( all of them )
}

rule _match_313 {
   meta:
      description = "black - from files 4396f6981923a6e702a9d18a3d76e482, 20addcaa91c6bc5c7cc665ddb2e8c52c, f957d3e479a07339edad73308c36e092, 97ee5c92d5c865ef6db67c35bc8a427a, d220d7b9023e6bd3717edc17765fbb25, 0f4acbb2acfaa97b146f4949729d0ec6, 5846aed02e23db1af696661606cf5bfd, cd7e6a6f2e3fc3cb1049efbbf235577f, 3934d1adff337a3741fc308eb83daaba, 99bd2332ea3179db7a70a6e66d11e096, 0cf00d65acee7181d4679d2ad3da5301, f8a8bd5eb3b9328c007438070e0c3ca8, 2458b8fb100cb0d0c80a3f62aea0e080, 2b3e56a15d75e4aa0327ac55733353ca, 0742b7c20e14fc0b9390fd5aafef6442, 80ba21786b71bb0dba959194fa1d3f63, a746e73da04945445e385850616990c9, 6a80142ac8cf4d5534d2eb9cb0e3e08d, ddafbf9406cc26df63a32702126e3fc9, b1a919e6fb009361b64d51b351a25e4c, be3781cfcf4d7b709449382184148803, 3ba79ba35b4b388fe9699e51d4c43fea, e74a8e9fbf1969888d78bfe6bf757759, 2ae5db210e8c7c0c96e6bed93bce1da6, a79c869cbd44bdfa9860a858facd982e, 9ad1d65187d0fb50941ff23676234c5d, a4d33f5f38e992c5e6d56865ff2ba1dc, 74f394c609338509e94d61091a70b6f5"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "4fd49a0d1574549b4f8b64c9d474417600d6ede505c3997b3b07eb9e92bd440a"
      hash2 = "c2389593cb340e9b682e457e6bf926abf1eee594d129c237f3f87852731dba7d"
      hash3 = "3a3fcb2a72c7e88bb0a5e31240f73f6b401ea9f22416a65519cd0c699d665e94"
      hash4 = "e91e3d9138b2961bf0807b39ab1c0647e78ccf6985890246db1d698af498e43b"
      hash5 = "8d887ba624e0e8f55be8deb805ec25c1a2a34e6fa137b6bc30025cfbc124dfb8"
      hash6 = "4c9bf0426483d1f8f7943cb291345134964d237f1b8270f88f51cbdd1557a41e"
      hash7 = "5d1ef3f5bc06e457945af001cad5e392eea47ae4486522ad3342f42b6e2b7436"
      hash8 = "08e6eb5d64f01d4a982bf75e4ffbec7d0f61d7ece7b7fbfe2fade7ae39ad8884"
      hash9 = "2fefce5634c8b6f9e334fd6b1c34b86f6cb8278dc07558034d1ead43d1467cbb"
      hash10 = "2e999f22d7fa0d018342d235067b5bb879b4505bb0e42156f816d38ae61cd3fe"
      hash11 = "a0e6799ed9cb59ac3aeab73f2c10015fbabbacc850b56148778f69cc38835d27"
      hash12 = "2df4f0927f0f73ff7ca38a4edfe9406be229985fd5ae468d9b5aa19b9b0cd0ac"
      hash13 = "ba3e5e8af6d21e5fa3a78b69a87ca1cd39afd4342795f514bd651af81e9b8e47"
      hash14 = "7bdb3093778ff709bac2a5e5e22960ab93fce19da7fc8e79aed29105c8d45f61"
      hash15 = "3b38ac70eac888ba76ae3c5812179863a78b4e63ce92f5108f019bb00f96b35c"
      hash16 = "2e4b386aa820c4a1b294274d89652098e4a78921df83b1ed101213f558f704ea"
      hash17 = "beae2bc4274deb42c452e6ad910853cfa1a60e05f0180ed43829e2a4f5281e04"
      hash18 = "c8eb9182adc12b591cbdafe27759495487a53c0cd38f83f77f575edf21e5d4b3"
      hash19 = "a35d47fde5d36de866ba7fbe638c7ea9f5860962b326484936a992cbba6fa22f"
      hash20 = "72356978da0b156bae25c84189c01a47b7c8e8daf22e2be533f1e2733f8372f2"
      hash21 = "714ae3c335d8dd42c2db8fe655c433887a5e0ef1c5f49a267d91f523427b2b61"
      hash22 = "d274427049b5e28fdd153a0bdbcb08445ffebd9031ed666dba23b62e44b3191a"
      hash23 = "4c486b48b0524a9e3059f5dab86bffa9a0fa82787363c7784c624453344dc1d1"
      hash24 = "3b1a32116390ef2a821cbeb15e214f937293ee39cfde2a2e97f2eb128474bce3"
      hash25 = "58fc973c2df43431d85dd6713461e818376109c4b8f681cf9775768d45e18bf1"
      hash26 = "6b5e1968ea97bcb10a53e2754d4f33c58bc1efed2ff1533d9bb3c346d8dfe318"
      hash27 = "0e1b04257292042084e66b6497e1a2411a81d497dabcee84e238da35e9472b50"
      hash28 = "02bd77bfd0a50ae5ea7e8a6587187e84b5c4d0d5638c7559abe609fbebbacd38"
   strings:
      $s1 = "      --cpu-affinity       set process affinity to CPU core(s), mask 0x3 for cores 0 and 1" fullword ascii
      $s2 = "      --cpu-priority       set process priority (0 idle, 2 normal to 5 highest)" fullword ascii
      $s3 = "  -p, --pass=PASSWORD      password for mining server" fullword ascii
      $s4 = "  -O, --userpass=U:P       username:password pair for mining server" fullword ascii
      $s5 = "      --max-cpu-usage=N    maximum CPU usage for automatic threads mode (default 75)" fullword ascii
      $s6 = "      --print-time=N       print hashrate report every N seconds" fullword ascii
      $s7 = "  -l, --log-file=FILE      log all output to a file" fullword ascii
      $s8 = "  -u, --user=USERNAME      username for mining server" fullword ascii
      $s9 = "  -c, --config=FILE        load a JSON-format configuration file" fullword ascii
      $s10 = "      --api-access-token=T access token for API" fullword ascii
      $s11 = "  -V, --version            output version information and exit" fullword ascii
      $s12 = "      --safe               safe adjust threads and av settings for current CPU" fullword ascii
      $s13 = "      --no-huge-pages      disable huge pages support" fullword ascii
      $s14 = "  -R, --retry-pause=N      time to pause between retries (default: 5)" fullword ascii
      $s15 = "      --donate-level=N     donate level, default 5%% (5 minutes in 100 minutes)" fullword ascii
      $s16 = "      --no-color           disable colored output" fullword ascii
      $s17 = "  -h, --help               display this help and exit" fullword ascii
      $s18 = "  -v, --av=N               algorithm variation, 0 auto select" fullword ascii
      $s19 = "  -o, --url=URL            URL of mining server" fullword ascii
      $s20 = "      --api-worker-id=ID   custom worker-id for API" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 27000KB and ( 8 of them )
      ) or ( all of them )
}



rule _match_325 {
   meta:
      description = "black - from files 4396f6981923a6e702a9d18a3d76e482, 0f9eddc5e740edcd96e2f32d6acc3bb3, 6cfc530100079ac1f1ed0cf61bed2ca8, acd5942fee24e5bc6769bb2fb529b695, 8a490aa2517646411b6ea1383f17bbd1, de5e6b20d9d57a8c34b9dccb2588dbf2, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 5f52a27f400818807d2693e1a52260ad, 0086748f3a7854b3a35f69b5285c534f, e28e3404155556ecafff204356fcc5f0, 4d6dff8b2def91e85a09faa27899d9d5, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, a3b4afa503657e7a327934ddd231887e, b3c0545d8bdbd5cd9c4c5cbd4d070d2a, b9280790ed58987ab2af68537ad18d6d, b1b0580af0e8fa730486561255426f38, ae33c5c9544d63463cca74c42a556983, ee3f5f355249823f286f389ce0567002, 9a07ca40de9c85495231302023c6a74a, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 86d7666073561a5d0ca494d80eae3e5e, 9b3518901fb21e67bfd3986cdcded31c, 99fe45ec1a50c0413a6dcb1d23b754f9, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "4fd49a0d1574549b4f8b64c9d474417600d6ede505c3997b3b07eb9e92bd440a"
      hash2 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash3 = "438784b7594602da1a92d67890953b527ef6cb045e0c64ccaa4e78448576fff5"
      hash4 = "0083066406394696a0e6f26928d71785bf9fcdecdd6dcf52731a93b78f2cca0c"
      hash5 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash6 = "a7a273fb3a56da7b4f75f958a02d4a7a7641e8ec3701d90b786fe9fad54b7eb3"
      hash7 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash8 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash9 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash10 = "0693cfd2a09f5358cdec077df4cf049c88fe5fcdc606a228e389c9b2e517f965"
      hash11 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash12 = "dbc26374af31e9c81b8bc3a6c3063387f587a2596510e2a3be24aea6e025294f"
      hash13 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash14 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash15 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash16 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash17 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash18 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash19 = "7bf303baebaec1c10be08273dd3d1ce503c4a7e1edaefc6092778b2926ebb278"
      hash20 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash21 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash22 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash23 = "ade656b212a4bef11d70720679ec7fd91586a9507448634cd716178ed908e509"
      hash24 = "ea9d91772dd86455d5bf25c080ed859faae39c7085abb5de0b3142a397e7f131"
      hash25 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash26 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash27 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash28 = "ee7ab7d8bd4643e2f2d63bc0329b21c6d3437beea13fc379ee7fbfc0e326d0f5"
      hash29 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash30 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash31 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = "D$XD9x" fullword ascii /* Goodware String - occured 2 times */
      $s2 = "8\\$8t(H" fullword ascii
      $s3 = "f9)u:H" fullword ascii
      $s4 = "vB8_(t" fullword ascii
      $s5 = "H97u+A" fullword ascii
      $s6 = "uF8Z(t" fullword ascii
      $s7 = "D8T8>t" fullword ascii
      $s8 = "@8t$HtsL" fullword ascii
      $s9 = "tU;\\$0tH" fullword ascii
      $s10 = "u\"8Z(t" fullword ascii
      $s11 = ";D$Xs;" fullword ascii
      $s12 = "vC8_(t" fullword ascii
      $s13 = "%D8d$8t" fullword ascii
      $s14 = "fD94iu" fullword ascii /* Goodware String - occured 4 times */
      $s15 = "?D8d$8t" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 21000KB and ( 8 of them )
      ) or ( all of them )
}


rule _match_346 {
   meta:
      description = "black - from files 905eeda0ddf717b45bb294b227e6d8ae, 6b97eabf2e7eef8ccfc36593771ebe12, 4396f6981923a6e702a9d18a3d76e482, 0f9eddc5e740edcd96e2f32d6acc3bb3, 20addcaa91c6bc5c7cc665ddb2e8c52c, 8a490aa2517646411b6ea1383f17bbd1, bab9ba3432d3255edc4f8e86f6ea6010, f957d3e479a07339edad73308c36e092, 97ee5c92d5c865ef6db67c35bc8a427a, 50b754688ea8b1994abc99ea58263ebb, 4faf8ab0a89ae8993085f64b0f0b0e25, d220d7b9023e6bd3717edc17765fbb25, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 6a6858a0087de5ff6493aa76d105d6df, 0f4acbb2acfaa97b146f4949729d0ec6, 5f52a27f400818807d2693e1a52260ad, 09b0bb70c4456e39cb26cdf2667b2be7, 5846aed02e23db1af696661606cf5bfd, cd7e6a6f2e3fc3cb1049efbbf235577f, 0086748f3a7854b3a35f69b5285c534f, e0095ff4e8222e5caafe0aedce42f9d4, e28e3404155556ecafff204356fcc5f0, a7e372d0982334302446756bf112d881, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, 3934d1adff337a3741fc308eb83daaba, 99bd2332ea3179db7a70a6e66d11e096, af408f884178b56843b9f7324bcdefb4, 0cf00d65acee7181d4679d2ad3da5301, 51f0f95501d456804707bd997c56b416, f8a8bd5eb3b9328c007438070e0c3ca8, 2458b8fb100cb0d0c80a3f62aea0e080, 2b3e56a15d75e4aa0327ac55733353ca, b260a9a94c0fa871bb59781447c7c6e9, 0742b7c20e14fc0b9390fd5aafef6442, 4451163751d9841553744a6f80ca0aed, a3b4afa503657e7a327934ddd231887e, cd9d53902ae60c8a9330b6b145cbe3bb, b9280790ed58987ab2af68537ad18d6d, 80ba21786b71bb0dba959194fa1d3f63, a746e73da04945445e385850616990c9, 604ce4d062c9c9f06a3231313e603ce8, 6a80142ac8cf4d5534d2eb9cb0e3e08d, ddafbf9406cc26df63a32702126e3fc9, b1b0580af0e8fa730486561255426f38, 720c0967b97baeaadefdfff2d265a183, 13ce83c5c7ea01852b0ae2e35b74949b, 0304ecd571a157fbcd4723d455bb554b, b1a919e6fb009361b64d51b351a25e4c, be3781cfcf4d7b709449382184148803, 3ba79ba35b4b388fe9699e51d4c43fea, 26fc98d7481f9b494ecbfebacdcbeab3, 63d152e378907ea71551baff27a82d7d, ae33c5c9544d63463cca74c42a556983, ee3f5f355249823f286f389ce0567002, e74a8e9fbf1969888d78bfe6bf757759, 9a07ca40de9c85495231302023c6a74a, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 15c4fc341d735f9ea8427f918d3f5422, 2ae5db210e8c7c0c96e6bed93bce1da6, a79c869cbd44bdfa9860a858facd982e, 9ad1d65187d0fb50941ff23676234c5d, 86d7666073561a5d0ca494d80eae3e5e, 6bd4123b8dc8281bfee4c09350545c7e, e4c92dd63239428f0b33c7f424293687, 233cb487009705a47f32a694558deca5, 0cccafcbc4d1a6d50ccd8fa1df89bc0f, 9b3518901fb21e67bfd3986cdcded31c, 5e68b441f8c061285f596c5e0731514d, a4d33f5f38e992c5e6d56865ff2ba1dc, 99fe45ec1a50c0413a6dcb1d23b754f9, 74f394c609338509e94d61091a70b6f5, e97524afde7b751f6b024fa4798bdf51, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "a28878f5880b8a1c506258dd39b459cec616f79100afe006b4779525b8a937a3"
      hash2 = "d2b4b16be498e2fbe782b6f0e73515f6fc74c7a661c44891a9860cbf2b690d02"
      hash3 = "4fd49a0d1574549b4f8b64c9d474417600d6ede505c3997b3b07eb9e92bd440a"
      hash4 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash5 = "c2389593cb340e9b682e457e6bf926abf1eee594d129c237f3f87852731dba7d"
      hash6 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash7 = "95319d0df797fdb6ceb91efe6883dbc0455c5cc1932d559b1db37454538801c7"
      hash8 = "3a3fcb2a72c7e88bb0a5e31240f73f6b401ea9f22416a65519cd0c699d665e94"
      hash9 = "e91e3d9138b2961bf0807b39ab1c0647e78ccf6985890246db1d698af498e43b"
      hash10 = "2efbcf082019f2fe3b7b065842a6e99e0441e7166265d2021695fce00f0d4373"
      hash11 = "653a01be62d87a19b3b5a982a98a0e625dde359ec6c8eb881683f2cbfe058f6f"
      hash12 = "8d887ba624e0e8f55be8deb805ec25c1a2a34e6fa137b6bc30025cfbc124dfb8"
      hash13 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash14 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash15 = "632f7efefd5383c0a53b18bb6cb327296b1b0bea50ea89ec493a4064e9df5973"
      hash16 = "4c9bf0426483d1f8f7943cb291345134964d237f1b8270f88f51cbdd1557a41e"
      hash17 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash18 = "bc2a8aa09df1303d24917145a3b41acf1b9df09c72e65273883c63b288623e2b"
      hash19 = "5d1ef3f5bc06e457945af001cad5e392eea47ae4486522ad3342f42b6e2b7436"
      hash20 = "08e6eb5d64f01d4a982bf75e4ffbec7d0f61d7ece7b7fbfe2fade7ae39ad8884"
      hash21 = "0693cfd2a09f5358cdec077df4cf049c88fe5fcdc606a228e389c9b2e517f965"
      hash22 = "ac51683da9fbe47c0d65f00d85a8b9705c4ab01a66f43c4a872b8f5407516f2b"
      hash23 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash24 = "d204dc52cd7c86013aa224f66e5631efec50edff579c78d21310c49b05910018"
      hash25 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash26 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash27 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash28 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash29 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash30 = "2fefce5634c8b6f9e334fd6b1c34b86f6cb8278dc07558034d1ead43d1467cbb"
      hash31 = "2e999f22d7fa0d018342d235067b5bb879b4505bb0e42156f816d38ae61cd3fe"
      hash32 = "c92d9638c8fb2b0556802ea87082be829f50dd7d29579a1a893ade35bd7a9256"
      hash33 = "a0e6799ed9cb59ac3aeab73f2c10015fbabbacc850b56148778f69cc38835d27"
      hash34 = "a8efd58c2f819b96742b10bad9aa76494731295f32ccc9897d3694944017b2a4"
      hash35 = "2df4f0927f0f73ff7ca38a4edfe9406be229985fd5ae468d9b5aa19b9b0cd0ac"
      hash36 = "ba3e5e8af6d21e5fa3a78b69a87ca1cd39afd4342795f514bd651af81e9b8e47"
      hash37 = "7bdb3093778ff709bac2a5e5e22960ab93fce19da7fc8e79aed29105c8d45f61"
      hash38 = "90d8f55bef684479fe2bb446475df73bb6fdd6ef91df216daae96a22fed08dc5"
      hash39 = "3b38ac70eac888ba76ae3c5812179863a78b4e63ce92f5108f019bb00f96b35c"
      hash40 = "e90a53ae1c6318e25816e74530a4c3607e55cbadf3b7eb0d0ff97fb78d6a8d96"
      hash41 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash42 = "9c62abcac2762be0e5abbb7f06ffb65c0b8fbea84d015944b6593453354303eb"
      hash43 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash44 = "2e4b386aa820c4a1b294274d89652098e4a78921df83b1ed101213f558f704ea"
      hash45 = "beae2bc4274deb42c452e6ad910853cfa1a60e05f0180ed43829e2a4f5281e04"
      hash46 = "85d6affc4c33cadc6d1d3d86b240cb1d8bd1c01c80780339e6bf0db53ec626c6"
      hash47 = "c8eb9182adc12b591cbdafe27759495487a53c0cd38f83f77f575edf21e5d4b3"
      hash48 = "a35d47fde5d36de866ba7fbe638c7ea9f5860962b326484936a992cbba6fa22f"
      hash49 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash50 = "a5da66d083a3a55342caab79f28aa97728682eebad7a9b8de88b0af92e9a7c28"
      hash51 = "10fe50b5f6fbaad5498bdc524145e5e05719fccc308da6de5a7c30ce9c3cbba3"
      hash52 = "02abeb1e769c65f180a39d46e4fb04f2282de9356b891f9734ce1ab86b5b183d"
      hash53 = "72356978da0b156bae25c84189c01a47b7c8e8daf22e2be533f1e2733f8372f2"
      hash54 = "714ae3c335d8dd42c2db8fe655c433887a5e0ef1c5f49a267d91f523427b2b61"
      hash55 = "d274427049b5e28fdd153a0bdbcb08445ffebd9031ed666dba23b62e44b3191a"
      hash56 = "b95f40cce47499183ef95d6d56b8b5deed0d99a413a8bd7067200c5b1ae752a9"
      hash57 = "f275d2589f252cfd2a131a89429837de58c04322c5ced8986dfc968d37bb1d4f"
      hash58 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash59 = "ade656b212a4bef11d70720679ec7fd91586a9507448634cd716178ed908e509"
      hash60 = "4c486b48b0524a9e3059f5dab86bffa9a0fa82787363c7784c624453344dc1d1"
      hash61 = "ea9d91772dd86455d5bf25c080ed859faae39c7085abb5de0b3142a397e7f131"
      hash62 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash63 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash64 = "242b2e8bf86f40047ed0c60607f61f81fb144a641a394ab51f4b21f1511ddca8"
      hash65 = "3b1a32116390ef2a821cbeb15e214f937293ee39cfde2a2e97f2eb128474bce3"
      hash66 = "58fc973c2df43431d85dd6713461e818376109c4b8f681cf9775768d45e18bf1"
      hash67 = "6b5e1968ea97bcb10a53e2754d4f33c58bc1efed2ff1533d9bb3c346d8dfe318"
      hash68 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash69 = "12a37426a995ef84e905c85a531c2754d10926dfdec03125074f83b738fe40af"
      hash70 = "c9d6e3fa0bf1bae569a87f1526093204b2b6bbc227e8ddcd2af450c4fb5c71c3"
      hash71 = "1c6eeaf450250baad8b4bbdcb4539a5ec8ad9878d1ea4c96c493e01cca02f1d2"
      hash72 = "4a49d867bbb4e4e36b55c77f0f514fdf18a78b18b701ae853075092ac2893e2e"
      hash73 = "ee7ab7d8bd4643e2f2d63bc0329b21c6d3437beea13fc379ee7fbfc0e326d0f5"
      hash74 = "f56df2b39807ac070aa06c977177aff8c79c48f399fc5b8c904df6c898bf431a"
      hash75 = "0e1b04257292042084e66b6497e1a2411a81d497dabcee84e238da35e9472b50"
      hash76 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash77 = "02bd77bfd0a50ae5ea7e8a6587187e84b5c4d0d5638c7559abe609fbebbacd38"
      hash78 = "b81e7c41d4c6cec4c6f99f9e577c8335c685bf09351af664d82c2a97bc12b89c"
      hash79 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash80 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = "Missing a comma or ']' after an array element." fullword ascii
      $s2 = "Unspecific syntax error." fullword ascii
      $s3 = "Missing a comma or '}' after an object member." fullword ascii
      $s4 = "The document root must not be followed by other values." fullword ascii
      $s5 = "Terminate parsing due to Handler error." fullword ascii
      $s6 = "Missing a closing quotation mark in string." fullword ascii
      $s7 = "Missing a name for object member." fullword ascii
      $s8 = "Miss fraction part in number." fullword ascii
      $s9 = "Invalid value." fullword ascii
      $s10 = "Miss exponent in number." fullword ascii
      $s11 = "Missing a colon after a name of object member." fullword ascii
      $s12 = "The surrogate pair in string is invalid." fullword ascii
      $s13 = "Number too big to be stored in double." fullword ascii
      $s14 = "The document is empty." fullword ascii
      $s15 = "Invalid encoding in string." fullword ascii
      $s16 = "Incorrect hex digit after \\u escape in string." fullword ascii
      $s17 = "Invalid escape character in string." fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 27000KB and ( 8 of them )
      ) or ( all of them )
}


rule _match_351 {
   meta:
      description = "black - from files 4396f6981923a6e702a9d18a3d76e482, 0f9eddc5e740edcd96e2f32d6acc3bb3, 6cfc530100079ac1f1ed0cf61bed2ca8, acd5942fee24e5bc6769bb2fb529b695, 8a490aa2517646411b6ea1383f17bbd1, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 5f52a27f400818807d2693e1a52260ad, 0086748f3a7854b3a35f69b5285c534f, e28e3404155556ecafff204356fcc5f0, 4d6dff8b2def91e85a09faa27899d9d5, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, a3b4afa503657e7a327934ddd231887e, b3c0545d8bdbd5cd9c4c5cbd4d070d2a, b9280790ed58987ab2af68537ad18d6d, b1b0580af0e8fa730486561255426f38, ae33c5c9544d63463cca74c42a556983, ee3f5f355249823f286f389ce0567002, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 86d7666073561a5d0ca494d80eae3e5e, 9b3518901fb21e67bfd3986cdcded31c, 99fe45ec1a50c0413a6dcb1d23b754f9, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "4fd49a0d1574549b4f8b64c9d474417600d6ede505c3997b3b07eb9e92bd440a"
      hash2 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash3 = "438784b7594602da1a92d67890953b527ef6cb045e0c64ccaa4e78448576fff5"
      hash4 = "0083066406394696a0e6f26928d71785bf9fcdecdd6dcf52731a93b78f2cca0c"
      hash5 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash6 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash7 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash8 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash9 = "0693cfd2a09f5358cdec077df4cf049c88fe5fcdc606a228e389c9b2e517f965"
      hash10 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash11 = "dbc26374af31e9c81b8bc3a6c3063387f587a2596510e2a3be24aea6e025294f"
      hash12 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash13 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash14 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash15 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash16 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash17 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash18 = "7bf303baebaec1c10be08273dd3d1ce503c4a7e1edaefc6092778b2926ebb278"
      hash19 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash20 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash21 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash22 = "ade656b212a4bef11d70720679ec7fd91586a9507448634cd716178ed908e509"
      hash23 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash24 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash25 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash26 = "ee7ab7d8bd4643e2f2d63bc0329b21c6d3437beea13fc379ee7fbfc0e326d0f5"
      hash27 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash28 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash29 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = "L$<;L$H" fullword ascii /* Goodware String - occured 1 times */
      $s2 = "<CtO<Dv" fullword ascii
      $s3 = "tQD8c:u0M" fullword ascii
      $s4 = "<[tO<a" fullword ascii
      $s5 = "8\\$PtD" fullword ascii
      $s6 = "@8)u#H" fullword ascii
      $s7 = "8\\$PtF" fullword ascii
      $s8 = "L$4+L$@" fullword ascii
      $s9 = "t?8_:t" fullword ascii
      $s10 = "tA8_:t" fullword ascii
      $s11 = "D8Y:u_H" fullword ascii
      $s12 = "utfD9A" fullword ascii
      $s13 = "ugfD9A" fullword ascii
      $s14 = "D8a:uVH" fullword ascii
      $s15 = "<itz<ntm<ot`<ptS<st" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and ( 8 of them )
      ) or ( all of them )
}

rule _match_353 {
   meta:
      description = "black - from files 0f9eddc5e740edcd96e2f32d6acc3bb3, 8a490aa2517646411b6ea1383f17bbd1, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 5f52a27f400818807d2693e1a52260ad, e28e3404155556ecafff204356fcc5f0, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, af408f884178b56843b9f7324bcdefb4, a3b4afa503657e7a327934ddd231887e, b9280790ed58987ab2af68537ad18d6d, b1b0580af0e8fa730486561255426f38, 26fc98d7481f9b494ecbfebacdcbeab3, ae33c5c9544d63463cca74c42a556983, ee3f5f355249823f286f389ce0567002, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 86d7666073561a5d0ca494d80eae3e5e, e4c92dd63239428f0b33c7f424293687, 9b3518901fb21e67bfd3986cdcded31c, 99fe45ec1a50c0413a6dcb1d23b754f9, e97524afde7b751f6b024fa4798bdf51, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash2 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash3 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash4 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash5 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash6 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash7 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash8 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash9 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash10 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash11 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash12 = "c92d9638c8fb2b0556802ea87082be829f50dd7d29579a1a893ade35bd7a9256"
      hash13 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash14 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash15 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash16 = "b95f40cce47499183ef95d6d56b8b5deed0d99a413a8bd7067200c5b1ae752a9"
      hash17 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash18 = "ade656b212a4bef11d70720679ec7fd91586a9507448634cd716178ed908e509"
      hash19 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash20 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash21 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash22 = "c9d6e3fa0bf1bae569a87f1526093204b2b6bbc227e8ddcd2af450c4fb5c71c3"
      hash23 = "ee7ab7d8bd4643e2f2d63bc0329b21c6d3437beea13fc379ee7fbfc0e326d0f5"
      hash24 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash25 = "b81e7c41d4c6cec4c6f99f9e577c8335c685bf09351af664d82c2a97bc12b89c"
      hash26 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash27 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = "Password[%u]: " fullword ascii
      $s2 = " After pass %u:" fullword ascii
      $s3 = "Secret[%u]: " fullword ascii
      $s4 = "Pre-hashing digest: " fullword ascii
      $s5 = "%s version number %d" fullword ascii
      $s6 = "Memory: %u KiB, Iterations: %u, Parallelism: %u lanes, Tag length: %u bytes" fullword ascii
      $s7 = "chukwa" fullword ascii
      $s8 = "argon2-impl" fullword ascii
      $s9 = "Associated data[%u]: " fullword ascii
      $s10 = "[0m implementation " fullword ascii
      $s11 = "argon2/chukwa" fullword ascii
      $s12 = "argon2/wrkz" fullword ascii
      $s13 = "[1;37margon2" fullword ascii
      $s14 = "Salt[%u]: " fullword ascii
      $s15 = "%s use " fullword ascii
      $s16 = "CLEARED" fullword ascii /* Goodware String - occured 4 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 19000KB and ( 8 of them )
      ) or ( all of them )
}

rule _match_362 {
   meta:
      description = "black - from files 905eeda0ddf717b45bb294b227e6d8ae, 6b97eabf2e7eef8ccfc36593771ebe12, 4396f6981923a6e702a9d18a3d76e482, 0f9eddc5e740edcd96e2f32d6acc3bb3, 8a490aa2517646411b6ea1383f17bbd1, bab9ba3432d3255edc4f8e86f6ea6010, f957d3e479a07339edad73308c36e092, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 6a6858a0087de5ff6493aa76d105d6df, 5f52a27f400818807d2693e1a52260ad, 5846aed02e23db1af696661606cf5bfd, e0095ff4e8222e5caafe0aedce42f9d4, e28e3404155556ecafff204356fcc5f0, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, 3934d1adff337a3741fc308eb83daaba, 99bd2332ea3179db7a70a6e66d11e096, af408f884178b56843b9f7324bcdefb4, 0cf00d65acee7181d4679d2ad3da5301, 51f0f95501d456804707bd997c56b416, 2458b8fb100cb0d0c80a3f62aea0e080, 2b3e56a15d75e4aa0327ac55733353ca, 4451163751d9841553744a6f80ca0aed, a3b4afa503657e7a327934ddd231887e, b9280790ed58987ab2af68537ad18d6d, 80ba21786b71bb0dba959194fa1d3f63, b1b0580af0e8fa730486561255426f38, 720c0967b97baeaadefdfff2d265a183, 13ce83c5c7ea01852b0ae2e35b74949b, 0304ecd571a157fbcd4723d455bb554b, be3781cfcf4d7b709449382184148803, 26fc98d7481f9b494ecbfebacdcbeab3, 63d152e378907ea71551baff27a82d7d, ae33c5c9544d63463cca74c42a556983, ee3f5f355249823f286f389ce0567002, 9a07ca40de9c85495231302023c6a74a, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 15c4fc341d735f9ea8427f918d3f5422, 9ad1d65187d0fb50941ff23676234c5d, 86d7666073561a5d0ca494d80eae3e5e, e4c92dd63239428f0b33c7f424293687, 9b3518901fb21e67bfd3986cdcded31c, 99fe45ec1a50c0413a6dcb1d23b754f9, e97524afde7b751f6b024fa4798bdf51, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "a28878f5880b8a1c506258dd39b459cec616f79100afe006b4779525b8a937a3"
      hash2 = "d2b4b16be498e2fbe782b6f0e73515f6fc74c7a661c44891a9860cbf2b690d02"
      hash3 = "4fd49a0d1574549b4f8b64c9d474417600d6ede505c3997b3b07eb9e92bd440a"
      hash4 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash5 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash6 = "95319d0df797fdb6ceb91efe6883dbc0455c5cc1932d559b1db37454538801c7"
      hash7 = "3a3fcb2a72c7e88bb0a5e31240f73f6b401ea9f22416a65519cd0c699d665e94"
      hash8 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash9 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash10 = "632f7efefd5383c0a53b18bb6cb327296b1b0bea50ea89ec493a4064e9df5973"
      hash11 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash12 = "5d1ef3f5bc06e457945af001cad5e392eea47ae4486522ad3342f42b6e2b7436"
      hash13 = "ac51683da9fbe47c0d65f00d85a8b9705c4ab01a66f43c4a872b8f5407516f2b"
      hash14 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash15 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash16 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash17 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash18 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash19 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash20 = "2fefce5634c8b6f9e334fd6b1c34b86f6cb8278dc07558034d1ead43d1467cbb"
      hash21 = "2e999f22d7fa0d018342d235067b5bb879b4505bb0e42156f816d38ae61cd3fe"
      hash22 = "c92d9638c8fb2b0556802ea87082be829f50dd7d29579a1a893ade35bd7a9256"
      hash23 = "a0e6799ed9cb59ac3aeab73f2c10015fbabbacc850b56148778f69cc38835d27"
      hash24 = "a8efd58c2f819b96742b10bad9aa76494731295f32ccc9897d3694944017b2a4"
      hash25 = "ba3e5e8af6d21e5fa3a78b69a87ca1cd39afd4342795f514bd651af81e9b8e47"
      hash26 = "7bdb3093778ff709bac2a5e5e22960ab93fce19da7fc8e79aed29105c8d45f61"
      hash27 = "e90a53ae1c6318e25816e74530a4c3607e55cbadf3b7eb0d0ff97fb78d6a8d96"
      hash28 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash29 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash30 = "2e4b386aa820c4a1b294274d89652098e4a78921df83b1ed101213f558f704ea"
      hash31 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash32 = "a5da66d083a3a55342caab79f28aa97728682eebad7a9b8de88b0af92e9a7c28"
      hash33 = "10fe50b5f6fbaad5498bdc524145e5e05719fccc308da6de5a7c30ce9c3cbba3"
      hash34 = "02abeb1e769c65f180a39d46e4fb04f2282de9356b891f9734ce1ab86b5b183d"
      hash35 = "714ae3c335d8dd42c2db8fe655c433887a5e0ef1c5f49a267d91f523427b2b61"
      hash36 = "b95f40cce47499183ef95d6d56b8b5deed0d99a413a8bd7067200c5b1ae752a9"
      hash37 = "f275d2589f252cfd2a131a89429837de58c04322c5ced8986dfc968d37bb1d4f"
      hash38 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash39 = "ade656b212a4bef11d70720679ec7fd91586a9507448634cd716178ed908e509"
      hash40 = "ea9d91772dd86455d5bf25c080ed859faae39c7085abb5de0b3142a397e7f131"
      hash41 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash42 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash43 = "242b2e8bf86f40047ed0c60607f61f81fb144a641a394ab51f4b21f1511ddca8"
      hash44 = "6b5e1968ea97bcb10a53e2754d4f33c58bc1efed2ff1533d9bb3c346d8dfe318"
      hash45 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash46 = "c9d6e3fa0bf1bae569a87f1526093204b2b6bbc227e8ddcd2af450c4fb5c71c3"
      hash47 = "ee7ab7d8bd4643e2f2d63bc0329b21c6d3437beea13fc379ee7fbfc0e326d0f5"
      hash48 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash49 = "b81e7c41d4c6cec4c6f99f9e577c8335c685bf09351af664d82c2a97bc12b89c"
      hash50 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash51 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = "[%s] login error code: %d" fullword ascii
      $s2 = "[%s] connect error: \"%s\"" fullword ascii
      $s3 = "[%s] read error: \"%s\"" fullword ascii
      $s4 = "[%s] JSON decode failed" fullword ascii
      $s5 = "[%s] JSON decode failed: \"%s\"" fullword ascii
      $s6 = "[%s] DNS error: \"%s\"" fullword ascii
      $s7 = "[%s] error: \"%s\", code: %d" fullword ascii
      $s8 = "[%s] unsupported method: \"%s\"" fullword ascii
      $s9 = "[0;36m %s %s " fullword ascii
      $s10 = "[1;37m%s:%d" fullword ascii
      $s11 = "[1;36m%s H/s" fullword ascii
      $s12 = "[1;36m%s" fullword ascii
      $s13 = "[0m max " fullword ascii
      $s14 = "[1;37mspeed" fullword ascii
      $s15 = "[1;36mH/s" fullword ascii
      $s16 = "[0m 10s/60s/15m " fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 25000KB and ( 8 of them )
      ) or ( all of them )
}



rule _match_365 {
   meta:
      description = "black - from files 0f9eddc5e740edcd96e2f32d6acc3bb3, 8a490aa2517646411b6ea1383f17bbd1, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 5f52a27f400818807d2693e1a52260ad, e28e3404155556ecafff204356fcc5f0, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, af408f884178b56843b9f7324bcdefb4, a3b4afa503657e7a327934ddd231887e, b9280790ed58987ab2af68537ad18d6d, b1b0580af0e8fa730486561255426f38, 26fc98d7481f9b494ecbfebacdcbeab3, ae33c5c9544d63463cca74c42a556983, ee3f5f355249823f286f389ce0567002, 9a07ca40de9c85495231302023c6a74a, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 86d7666073561a5d0ca494d80eae3e5e, 9b3518901fb21e67bfd3986cdcded31c, 99fe45ec1a50c0413a6dcb1d23b754f9, e97524afde7b751f6b024fa4798bdf51, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash2 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash3 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash4 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash5 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash6 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash7 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash8 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash9 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash10 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash11 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash12 = "c92d9638c8fb2b0556802ea87082be829f50dd7d29579a1a893ade35bd7a9256"
      hash13 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash14 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash15 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash16 = "b95f40cce47499183ef95d6d56b8b5deed0d99a413a8bd7067200c5b1ae752a9"
      hash17 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash18 = "ade656b212a4bef11d70720679ec7fd91586a9507448634cd716178ed908e509"
      hash19 = "ea9d91772dd86455d5bf25c080ed859faae39c7085abb5de0b3142a397e7f131"
      hash20 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash21 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash22 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash23 = "ee7ab7d8bd4643e2f2d63bc0329b21c6d3437beea13fc379ee7fbfc0e326d0f5"
      hash24 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash25 = "b81e7c41d4c6cec4c6f99f9e577c8335c685bf09351af664d82c2a97bc12b89c"
      hash26 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash27 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = "#ifdef __NV_CL_C_VERSION" fullword ascii
      $s2 = "inline uint get_reciprocal(uint a)" fullword ascii
      $s3 = "XMRIG_INCLUDE_RANDOM_MATH" fullword ascii
      $s4 = "#define SKEIN_KS_PARITY 0x1BD11BDAA9FC1A22" fullword ascii
      $s5 = "#define BYTE(x, y) (xmrig_amd_bfe((x), (y) << 3U, 8U))" fullword ascii
      $s6 = "#define ROT_BITS 32" fullword ascii
      $s7 = "#define FAST_DIV_HEAVY_CL" fullword ascii
      $s8 = "#ifndef FAST_DIV_HEAVY_CL" fullword ascii
      $s9 = "=rotate(r" fullword ascii
      $s10 = "Baffin" fullword ascii /* Goodware String - occured 1 times */
      $s11 = "#undef SWAP4" fullword ascii
      $s12 = "void keccakf1600_2(__local ulong *st)" fullword ascii
      $s13 = "gfx804" fullword ascii
      $s14 = "\\xmrig\\.cache\\" fullword ascii
      $s15 = ",ROT_BITS-r" fullword ascii
      $s16 = "/xmrig" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 19000KB and ( 8 of them )
      ) or ( all of them )
}

rule _match_366 {
   meta:
      description = "black - from files 0f9eddc5e740edcd96e2f32d6acc3bb3, 8a490aa2517646411b6ea1383f17bbd1, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 5f52a27f400818807d2693e1a52260ad, 0086748f3a7854b3a35f69b5285c534f, e28e3404155556ecafff204356fcc5f0, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, a3b4afa503657e7a327934ddd231887e, b9280790ed58987ab2af68537ad18d6d, b1b0580af0e8fa730486561255426f38, 13ce83c5c7ea01852b0ae2e35b74949b, ae33c5c9544d63463cca74c42a556983, ee3f5f355249823f286f389ce0567002, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 15c4fc341d735f9ea8427f918d3f5422, 86d7666073561a5d0ca494d80eae3e5e, 9b3518901fb21e67bfd3986cdcded31c, 99fe45ec1a50c0413a6dcb1d23b754f9, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash2 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash3 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash4 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash5 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash6 = "0693cfd2a09f5358cdec077df4cf049c88fe5fcdc606a228e389c9b2e517f965"
      hash7 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash8 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash9 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash10 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash11 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash12 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash13 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash14 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash15 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash16 = "10fe50b5f6fbaad5498bdc524145e5e05719fccc308da6de5a7c30ce9c3cbba3"
      hash17 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash18 = "ade656b212a4bef11d70720679ec7fd91586a9507448634cd716178ed908e509"
      hash19 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash20 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash21 = "242b2e8bf86f40047ed0c60607f61f81fb144a641a394ab51f4b21f1511ddca8"
      hash22 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash23 = "ee7ab7d8bd4643e2f2d63bc0329b21c6d3437beea13fc379ee7fbfc0e326d0f5"
      hash24 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash25 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash26 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = ".?AVIHttpListener@xmrig@@" fullword ascii
      $s2 = "GET, PUT, POST, DELETE" fullword ascii
      $s3 = ".?AVHttpApiRequest@xmrig@@" fullword ascii
      $s4 = ".?AVHttpData@xmrig@@" fullword ascii
      $s5 = ".?AVITcpServerListener@xmrig@@" fullword ascii
      $s6 = ".?AVHttpContext@xmrig@@" fullword ascii
      $s7 = ".?AVHttpd@xmrig@@" fullword ascii
      $s8 = ".?AVJsonReader@xmrig@@" fullword ascii
      $s9 = ".?AVHttpClient@xmrig@@" fullword ascii
      $s10 = ".?AVApiRequest@xmrig@@" fullword ascii
      $s11 = ".?AVApi@xmrig@@" fullword ascii
      $s12 = ".?AVDaemonClient@xmrig@@" fullword ascii
      $s13 = ".?AVIApiRequest@xmrig@@" fullword ascii
      $s14 = "rD9c@|'H" fullword ascii
      $s15 = "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 13000KB and ( 8 of them )
      ) or ( all of them )
}

rule _match_367 {
   meta:
      description = "black - from files 0f9eddc5e740edcd96e2f32d6acc3bb3, 6cfc530100079ac1f1ed0cf61bed2ca8, acd5942fee24e5bc6769bb2fb529b695, 8a490aa2517646411b6ea1383f17bbd1, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 5f52a27f400818807d2693e1a52260ad, 5846aed02e23db1af696661606cf5bfd, 0086748f3a7854b3a35f69b5285c534f, e28e3404155556ecafff204356fcc5f0, 4d6dff8b2def91e85a09faa27899d9d5, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, af408f884178b56843b9f7324bcdefb4, 51f0f95501d456804707bd997c56b416, 4451163751d9841553744a6f80ca0aed, fc481ae3e90d67283ce944cefb433d25, a3b4afa503657e7a327934ddd231887e, b3c0545d8bdbd5cd9c4c5cbd4d070d2a, b9280790ed58987ab2af68537ad18d6d, b1b0580af0e8fa730486561255426f38, 13ce83c5c7ea01852b0ae2e35b74949b, 26fc98d7481f9b494ecbfebacdcbeab3, 63d152e378907ea71551baff27a82d7d, ae33c5c9544d63463cca74c42a556983, ee3f5f355249823f286f389ce0567002, 9a07ca40de9c85495231302023c6a74a, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 15c4fc341d735f9ea8427f918d3f5422, 86d7666073561a5d0ca494d80eae3e5e, e4c92dd63239428f0b33c7f424293687, 9b3518901fb21e67bfd3986cdcded31c, 99fe45ec1a50c0413a6dcb1d23b754f9, e97524afde7b751f6b024fa4798bdf51, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash2 = "438784b7594602da1a92d67890953b527ef6cb045e0c64ccaa4e78448576fff5"
      hash3 = "0083066406394696a0e6f26928d71785bf9fcdecdd6dcf52731a93b78f2cca0c"
      hash4 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash5 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash6 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash7 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash8 = "5d1ef3f5bc06e457945af001cad5e392eea47ae4486522ad3342f42b6e2b7436"
      hash9 = "0693cfd2a09f5358cdec077df4cf049c88fe5fcdc606a228e389c9b2e517f965"
      hash10 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash11 = "dbc26374af31e9c81b8bc3a6c3063387f587a2596510e2a3be24aea6e025294f"
      hash12 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash13 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash14 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash15 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash16 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash17 = "c92d9638c8fb2b0556802ea87082be829f50dd7d29579a1a893ade35bd7a9256"
      hash18 = "a8efd58c2f819b96742b10bad9aa76494731295f32ccc9897d3694944017b2a4"
      hash19 = "e90a53ae1c6318e25816e74530a4c3607e55cbadf3b7eb0d0ff97fb78d6a8d96"
      hash20 = "201b177ab0fe48289ac660b899b7813ed6f276a9ea1246574c28ebacb943905d"
      hash21 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash22 = "7bf303baebaec1c10be08273dd3d1ce503c4a7e1edaefc6092778b2926ebb278"
      hash23 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash24 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash25 = "10fe50b5f6fbaad5498bdc524145e5e05719fccc308da6de5a7c30ce9c3cbba3"
      hash26 = "b95f40cce47499183ef95d6d56b8b5deed0d99a413a8bd7067200c5b1ae752a9"
      hash27 = "f275d2589f252cfd2a131a89429837de58c04322c5ced8986dfc968d37bb1d4f"
      hash28 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash29 = "ade656b212a4bef11d70720679ec7fd91586a9507448634cd716178ed908e509"
      hash30 = "ea9d91772dd86455d5bf25c080ed859faae39c7085abb5de0b3142a397e7f131"
      hash31 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash32 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash33 = "242b2e8bf86f40047ed0c60607f61f81fb144a641a394ab51f4b21f1511ddca8"
      hash34 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash35 = "c9d6e3fa0bf1bae569a87f1526093204b2b6bbc227e8ddcd2af450c4fb5c71c3"
      hash36 = "ee7ab7d8bd4643e2f2d63bc0329b21c6d3437beea13fc379ee7fbfc0e326d0f5"
      hash37 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash38 = "b81e7c41d4c6cec4c6f99f9e577c8335c685bf09351af664d82c2a97bc12b89c"
      hash39 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash40 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = "elit, sed do eiusmod tempor incididunt ut labore" fullword ascii
      $s2 = "sunt in culpa qui officia deserunt mollit anim id est laborum." fullword ascii
      $s3 = "ut aliquip ex ea commodo consequat. Duis aute" fullword ascii
      $s4 = "irure dolor in reprehenderit in voluptate velit" fullword ascii
      $s5 = "quis nostrud exercitation ullamco laboris nisi" fullword ascii
      $s6 = "cryptonight/rwz" fullword ascii
      $s7 = "This is a test This is a test This is a test" fullword ascii
      $s8 = "cryptonight/zls" fullword ascii
      $s9 = "cryptonight/double" fullword ascii
      $s10 = "et dolore magna aliqua. Ut enim ad minim veniam," fullword ascii
      $s11 = "Lorem ipsum dolor sit amet, consectetur adipiscing" fullword ascii
      $s12 = "esse cillum dolore eu fugiat nulla pariatur." fullword ascii
      $s13 = "cn/double" fullword ascii
      $s14 = "cn/zls" fullword ascii
      $s15 = "cn/rwz" fullword ascii
      $s16 = "Excepteur sint occaecat cupidatat non proident," fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 25000KB and ( 8 of them )
      ) or ( all of them )
}

rule _match_372 {
   meta:
      description = "black - from files 905eeda0ddf717b45bb294b227e6d8ae, 6b97eabf2e7eef8ccfc36593771ebe12, 4396f6981923a6e702a9d18a3d76e482, 0f9eddc5e740edcd96e2f32d6acc3bb3, 8a490aa2517646411b6ea1383f17bbd1, bab9ba3432d3255edc4f8e86f6ea6010, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 5f52a27f400818807d2693e1a52260ad, 5846aed02e23db1af696661606cf5bfd, e28e3404155556ecafff204356fcc5f0, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, 3934d1adff337a3741fc308eb83daaba, 99bd2332ea3179db7a70a6e66d11e096, af408f884178b56843b9f7324bcdefb4, 0cf00d65acee7181d4679d2ad3da5301, 51f0f95501d456804707bd997c56b416, 2458b8fb100cb0d0c80a3f62aea0e080, 4451163751d9841553744a6f80ca0aed, a3b4afa503657e7a327934ddd231887e, b9280790ed58987ab2af68537ad18d6d, 80ba21786b71bb0dba959194fa1d3f63, b1b0580af0e8fa730486561255426f38, 0304ecd571a157fbcd4723d455bb554b, 26fc98d7481f9b494ecbfebacdcbeab3, 63d152e378907ea71551baff27a82d7d, ae33c5c9544d63463cca74c42a556983, ee3f5f355249823f286f389ce0567002, 9a07ca40de9c85495231302023c6a74a, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 9ad1d65187d0fb50941ff23676234c5d, 86d7666073561a5d0ca494d80eae3e5e, e4c92dd63239428f0b33c7f424293687, 9b3518901fb21e67bfd3986cdcded31c, 99fe45ec1a50c0413a6dcb1d23b754f9, e97524afde7b751f6b024fa4798bdf51, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "a28878f5880b8a1c506258dd39b459cec616f79100afe006b4779525b8a937a3"
      hash2 = "d2b4b16be498e2fbe782b6f0e73515f6fc74c7a661c44891a9860cbf2b690d02"
      hash3 = "4fd49a0d1574549b4f8b64c9d474417600d6ede505c3997b3b07eb9e92bd440a"
      hash4 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash5 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash6 = "95319d0df797fdb6ceb91efe6883dbc0455c5cc1932d559b1db37454538801c7"
      hash7 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash8 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash9 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash10 = "5d1ef3f5bc06e457945af001cad5e392eea47ae4486522ad3342f42b6e2b7436"
      hash11 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash12 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash13 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash14 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash15 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash16 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash17 = "2fefce5634c8b6f9e334fd6b1c34b86f6cb8278dc07558034d1ead43d1467cbb"
      hash18 = "2e999f22d7fa0d018342d235067b5bb879b4505bb0e42156f816d38ae61cd3fe"
      hash19 = "c92d9638c8fb2b0556802ea87082be829f50dd7d29579a1a893ade35bd7a9256"
      hash20 = "a0e6799ed9cb59ac3aeab73f2c10015fbabbacc850b56148778f69cc38835d27"
      hash21 = "a8efd58c2f819b96742b10bad9aa76494731295f32ccc9897d3694944017b2a4"
      hash22 = "ba3e5e8af6d21e5fa3a78b69a87ca1cd39afd4342795f514bd651af81e9b8e47"
      hash23 = "e90a53ae1c6318e25816e74530a4c3607e55cbadf3b7eb0d0ff97fb78d6a8d96"
      hash24 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash25 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash26 = "2e4b386aa820c4a1b294274d89652098e4a78921df83b1ed101213f558f704ea"
      hash27 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash28 = "02abeb1e769c65f180a39d46e4fb04f2282de9356b891f9734ce1ab86b5b183d"
      hash29 = "b95f40cce47499183ef95d6d56b8b5deed0d99a413a8bd7067200c5b1ae752a9"
      hash30 = "f275d2589f252cfd2a131a89429837de58c04322c5ced8986dfc968d37bb1d4f"
      hash31 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash32 = "ade656b212a4bef11d70720679ec7fd91586a9507448634cd716178ed908e509"
      hash33 = "ea9d91772dd86455d5bf25c080ed859faae39c7085abb5de0b3142a397e7f131"
      hash34 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash35 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash36 = "6b5e1968ea97bcb10a53e2754d4f33c58bc1efed2ff1533d9bb3c346d8dfe318"
      hash37 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash38 = "c9d6e3fa0bf1bae569a87f1526093204b2b6bbc227e8ddcd2af450c4fb5c71c3"
      hash39 = "ee7ab7d8bd4643e2f2d63bc0329b21c6d3437beea13fc379ee7fbfc0e326d0f5"
      hash40 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash41 = "b81e7c41d4c6cec4c6f99f9e577c8335c685bf09351af664d82c2a97bc12b89c"
      hash42 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash43 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = "cn-heavy/0" fullword ascii
      $s2 = "cryptonight-heavy/tube" fullword ascii
      $s3 = "cryptonight-lite/1" fullword ascii
      $s4 = "cn-heavy/tube" fullword ascii
      $s5 = "cn-heavy/xhv" fullword ascii
      $s6 = "cryptonight-heavy" fullword ascii
      $s7 = "cryptonight-lite/0" fullword ascii
      $s8 = "cryptonight-heavy/0" fullword ascii
      $s9 = "cryptonight-heavy/xhv" fullword ascii
      $s10 = "cn-lite/1" fullword ascii
      $s11 = "cn-light" fullword ascii
      $s12 = "cn-heavy" fullword ascii
      $s13 = "recW~|" fullword ascii
      $s14 = "cn-lite/0" fullword ascii
      $s15 = "cn-lite" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 25000KB and ( 8 of them )
      ) or ( all of them )
}

rule _match_373 {
   meta:
      description = "black - from files 905eeda0ddf717b45bb294b227e6d8ae, 6b97eabf2e7eef8ccfc36593771ebe12, 4396f6981923a6e702a9d18a3d76e482, 0f9eddc5e740edcd96e2f32d6acc3bb3, 20addcaa91c6bc5c7cc665ddb2e8c52c, 8a490aa2517646411b6ea1383f17bbd1, 97ee5c92d5c865ef6db67c35bc8a427a, 50b754688ea8b1994abc99ea58263ebb, d220d7b9023e6bd3717edc17765fbb25, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 0f4acbb2acfaa97b146f4949729d0ec6, 5f52a27f400818807d2693e1a52260ad, 5846aed02e23db1af696661606cf5bfd, cd7e6a6f2e3fc3cb1049efbbf235577f, 0086748f3a7854b3a35f69b5285c534f, e28e3404155556ecafff204356fcc5f0, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, 3934d1adff337a3741fc308eb83daaba, 99bd2332ea3179db7a70a6e66d11e096, af408f884178b56843b9f7324bcdefb4, 0cf00d65acee7181d4679d2ad3da5301, 51f0f95501d456804707bd997c56b416, f8a8bd5eb3b9328c007438070e0c3ca8, 2458b8fb100cb0d0c80a3f62aea0e080, 0742b7c20e14fc0b9390fd5aafef6442, a3b4afa503657e7a327934ddd231887e, cd9d53902ae60c8a9330b6b145cbe3bb, b9280790ed58987ab2af68537ad18d6d, 80ba21786b71bb0dba959194fa1d3f63, a746e73da04945445e385850616990c9, 6a80142ac8cf4d5534d2eb9cb0e3e08d, ddafbf9406cc26df63a32702126e3fc9, b1b0580af0e8fa730486561255426f38, 13ce83c5c7ea01852b0ae2e35b74949b, b1a919e6fb009361b64d51b351a25e4c, 3ba79ba35b4b388fe9699e51d4c43fea, 26fc98d7481f9b494ecbfebacdcbeab3, ae33c5c9544d63463cca74c42a556983, ee3f5f355249823f286f389ce0567002, e74a8e9fbf1969888d78bfe6bf757759, 9a07ca40de9c85495231302023c6a74a, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 15c4fc341d735f9ea8427f918d3f5422, 2ae5db210e8c7c0c96e6bed93bce1da6, 86d7666073561a5d0ca494d80eae3e5e, 233cb487009705a47f32a694558deca5, 0cccafcbc4d1a6d50ccd8fa1df89bc0f, 9b3518901fb21e67bfd3986cdcded31c, 99fe45ec1a50c0413a6dcb1d23b754f9, 3a69511ef880ea841a6740357901ca61, 74f394c609338509e94d61091a70b6f5, e97524afde7b751f6b024fa4798bdf51, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "a28878f5880b8a1c506258dd39b459cec616f79100afe006b4779525b8a937a3"
      hash2 = "d2b4b16be498e2fbe782b6f0e73515f6fc74c7a661c44891a9860cbf2b690d02"
      hash3 = "4fd49a0d1574549b4f8b64c9d474417600d6ede505c3997b3b07eb9e92bd440a"
      hash4 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash5 = "c2389593cb340e9b682e457e6bf926abf1eee594d129c237f3f87852731dba7d"
      hash6 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash7 = "e91e3d9138b2961bf0807b39ab1c0647e78ccf6985890246db1d698af498e43b"
      hash8 = "2efbcf082019f2fe3b7b065842a6e99e0441e7166265d2021695fce00f0d4373"
      hash9 = "8d887ba624e0e8f55be8deb805ec25c1a2a34e6fa137b6bc30025cfbc124dfb8"
      hash10 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash11 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash12 = "4c9bf0426483d1f8f7943cb291345134964d237f1b8270f88f51cbdd1557a41e"
      hash13 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash14 = "5d1ef3f5bc06e457945af001cad5e392eea47ae4486522ad3342f42b6e2b7436"
      hash15 = "08e6eb5d64f01d4a982bf75e4ffbec7d0f61d7ece7b7fbfe2fade7ae39ad8884"
      hash16 = "0693cfd2a09f5358cdec077df4cf049c88fe5fcdc606a228e389c9b2e517f965"
      hash17 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash18 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash19 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash20 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash21 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash22 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash23 = "2fefce5634c8b6f9e334fd6b1c34b86f6cb8278dc07558034d1ead43d1467cbb"
      hash24 = "2e999f22d7fa0d018342d235067b5bb879b4505bb0e42156f816d38ae61cd3fe"
      hash25 = "c92d9638c8fb2b0556802ea87082be829f50dd7d29579a1a893ade35bd7a9256"
      hash26 = "a0e6799ed9cb59ac3aeab73f2c10015fbabbacc850b56148778f69cc38835d27"
      hash27 = "a8efd58c2f819b96742b10bad9aa76494731295f32ccc9897d3694944017b2a4"
      hash28 = "2df4f0927f0f73ff7ca38a4edfe9406be229985fd5ae468d9b5aa19b9b0cd0ac"
      hash29 = "ba3e5e8af6d21e5fa3a78b69a87ca1cd39afd4342795f514bd651af81e9b8e47"
      hash30 = "3b38ac70eac888ba76ae3c5812179863a78b4e63ce92f5108f019bb00f96b35c"
      hash31 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash32 = "9c62abcac2762be0e5abbb7f06ffb65c0b8fbea84d015944b6593453354303eb"
      hash33 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash34 = "2e4b386aa820c4a1b294274d89652098e4a78921df83b1ed101213f558f704ea"
      hash35 = "beae2bc4274deb42c452e6ad910853cfa1a60e05f0180ed43829e2a4f5281e04"
      hash36 = "c8eb9182adc12b591cbdafe27759495487a53c0cd38f83f77f575edf21e5d4b3"
      hash37 = "a35d47fde5d36de866ba7fbe638c7ea9f5860962b326484936a992cbba6fa22f"
      hash38 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash39 = "10fe50b5f6fbaad5498bdc524145e5e05719fccc308da6de5a7c30ce9c3cbba3"
      hash40 = "72356978da0b156bae25c84189c01a47b7c8e8daf22e2be533f1e2733f8372f2"
      hash41 = "d274427049b5e28fdd153a0bdbcb08445ffebd9031ed666dba23b62e44b3191a"
      hash42 = "b95f40cce47499183ef95d6d56b8b5deed0d99a413a8bd7067200c5b1ae752a9"
      hash43 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash44 = "ade656b212a4bef11d70720679ec7fd91586a9507448634cd716178ed908e509"
      hash45 = "4c486b48b0524a9e3059f5dab86bffa9a0fa82787363c7784c624453344dc1d1"
      hash46 = "ea9d91772dd86455d5bf25c080ed859faae39c7085abb5de0b3142a397e7f131"
      hash47 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash48 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash49 = "242b2e8bf86f40047ed0c60607f61f81fb144a641a394ab51f4b21f1511ddca8"
      hash50 = "3b1a32116390ef2a821cbeb15e214f937293ee39cfde2a2e97f2eb128474bce3"
      hash51 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash52 = "1c6eeaf450250baad8b4bbdcb4539a5ec8ad9878d1ea4c96c493e01cca02f1d2"
      hash53 = "4a49d867bbb4e4e36b55c77f0f514fdf18a78b18b701ae853075092ac2893e2e"
      hash54 = "ee7ab7d8bd4643e2f2d63bc0329b21c6d3437beea13fc379ee7fbfc0e326d0f5"
      hash55 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash56 = "477ff70035e7438bbb414dcaf805d93a61dc39f75acf882134097fe3be105e48"
      hash57 = "02bd77bfd0a50ae5ea7e8a6587187e84b5c4d0d5638c7559abe609fbebbacd38"
      hash58 = "b81e7c41d4c6cec4c6f99f9e577c8335c685bf09351af664d82c2a97bc12b89c"
      hash59 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash60 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = "Payload Too Large" fullword ascii
      $s2 = "Already Reported" fullword ascii
      $s3 = "Multi-Status" fullword ascii /* Goodware String - occured 1 times */
      $s4 = "Range Not Satisfiable" fullword ascii
      $s5 = "Misdirected Request" fullword ascii
      $s6 = "Loop Detected" fullword ascii /* Goodware String - occured 2 times */
      $s7 = "IM Used" fullword ascii
      $s8 = "URI Too Long" fullword ascii
      $s9 = "Too Many Requests" fullword ascii /* Goodware String - occured 5 times */
      $s10 = "Network Authentication Required" fullword ascii /* Goodware String - occured 5 times */
      $s11 = "Precondition Required" fullword ascii /* Goodware String - occured 5 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 27000KB and ( 8 of them )
      ) or ( all of them )
}

rule _match_374 {
   meta:
      description = "black - from files 4396f6981923a6e702a9d18a3d76e482, 8a490aa2517646411b6ea1383f17bbd1, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 5f52a27f400818807d2693e1a52260ad, e28e3404155556ecafff204356fcc5f0, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, 3934d1adff337a3741fc308eb83daaba, 51f0f95501d456804707bd997c56b416, 2458b8fb100cb0d0c80a3f62aea0e080, a3b4afa503657e7a327934ddd231887e, b9280790ed58987ab2af68537ad18d6d, 80ba21786b71bb0dba959194fa1d3f63, b1b0580af0e8fa730486561255426f38, 26fc98d7481f9b494ecbfebacdcbeab3, ae33c5c9544d63463cca74c42a556983, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 86d7666073561a5d0ca494d80eae3e5e, 47a32262fbe86e120fd5d69e295b9fc3, 99fe45ec1a50c0413a6dcb1d23b754f9, e97524afde7b751f6b024fa4798bdf51, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "4fd49a0d1574549b4f8b64c9d474417600d6ede505c3997b3b07eb9e92bd440a"
      hash2 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash3 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash4 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash5 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash6 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash7 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash8 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash9 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash10 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash11 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash12 = "2fefce5634c8b6f9e334fd6b1c34b86f6cb8278dc07558034d1ead43d1467cbb"
      hash13 = "a8efd58c2f819b96742b10bad9aa76494731295f32ccc9897d3694944017b2a4"
      hash14 = "ba3e5e8af6d21e5fa3a78b69a87ca1cd39afd4342795f514bd651af81e9b8e47"
      hash15 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash16 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash17 = "2e4b386aa820c4a1b294274d89652098e4a78921df83b1ed101213f558f704ea"
      hash18 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash19 = "b95f40cce47499183ef95d6d56b8b5deed0d99a413a8bd7067200c5b1ae752a9"
      hash20 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash21 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash22 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash23 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash24 = "1b435cd0e002358d4ca191463d0fb54ea1136b53b74de8db93d61f935203392e"
      hash25 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash26 = "b81e7c41d4c6cec4c6f99f9e577c8335c685bf09351af664d82c2a97bc12b89c"
      hash27 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash28 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = "vwwvqqq" fullword ascii
      $s2 = "tuuaVWW" fullword ascii
      $s3 = "qqqLxyy" fullword ascii
      $s4 = "qqqLqqq" fullword ascii
      $s5 = "qqqLvww" fullword ascii
      $s6 = "vwwvVWW" fullword ascii
      $s7 = "@Dh,>=q" fullword ascii
      $s8 = "eee#lmm" fullword ascii
      $s9 = "eee#qqq" fullword ascii
      $s10 = "eee#stt" fullword ascii
      $s11 = "z_~Tt3" fullword ascii
      $s12 = "\"vSk!=q" fullword ascii
      $s13 = "e&M<2B" fullword ascii
      $s14 = "eee#_``" fullword ascii
      $s15 = ">?W8u " fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 25000KB and ( 8 of them )
      ) or ( all of them )
}

rule _match_377 {
   meta:
      description = "black - from files 6489a3782bb5ad4b60a556f953b2a569, 25830165f6ad0b16d2a35d9291c9a172, faa4814f4844451358a5271d1430a95e, 256269eeb2a766a3ee3c6298331e0021, 3ae2d39e32767613ab97a1b050525c02, 7d98df10c15276bb856b370bd95910fc, f927913489a0981eb65151d52e82b5ee, 8545fd6f644a486da16f613dec559eb6, e50e309535ce0210e06b0eb259f975dd, 081fad571b447985a5a7c3ee6fde98de, b51b5e17a2233f0c04e6d1c9c740b6d7, f5242c43a3b5cd4dff32767fde5fdba3, 6cc60dca50ddb6ad192a1d26c49c3066, af7ad3bdf22a056a786dc432360f60ac, 97101c9199efe18fdb7b0a572228bc90, 7c2a9696e8feae3fdd4d2a71a2359019, 5c1ad28d5d5a3ba12e7d8341f7cdb0cb, 8371a38b5cb85a23d696ce62be10194d, fe515b2ef66db0d8805b0fbffc36e3e4, 4bf7db25ccd4a8ba8bd0275bf6c168f6"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "c009183705f5cc854e8fc9990e6c36ac90c06c10f5fd369bb822310b4c42c71c"
      hash2 = "4af8b31843cc28578ec771a4cbecb424b3a2fd416d82001e50eadad255c35417"
      hash3 = "60002c82d2b95930c628b245c63cefa4448886ab1740efa786656305ad7600c4"
      hash4 = "022d6ee1f40b739745767f36333d97d9e6968532cd1102ddcc8ed5249cae6fc0"
      hash5 = "34ddfd5a1c424e74a0dbf1199b906f96c5bde89a5af66e6425ba2adb0b5192e3"
      hash6 = "cc38d385ce50ead01e56b0039e31c044d65ffd683a031c2a9bf8031a2a77bf17"
      hash7 = "9b344a7a2c792836011402097b7b5633921de4a1c2cf412f2c2c18d41d2c4eb2"
      hash8 = "dd594260e168dfe9a83382dd420b8e4eadfe716c704cec962c505d7eb693c018"
      hash9 = "8ad16f245c2da1e7c2cbcd3ffef50f098441709967be27f9f198576dd9929ce0"
      hash10 = "27816b0b4766afbe29112748248bcd4aaa60e2e77c2fc8b33ec8cfaa07807d53"
      hash11 = "bb2db792bbd1197ad66f671c04ec5fdf5eb2c80b086032ad0722ae548b603903"
      hash12 = "b913e3246118a19394be026b03ef7655cf01064c1f56fc9a52dcb881bc8275de"
      hash13 = "0bdd0465a28822b133e42cb582569a5b6a21b48be3e364316bf64d8f787822d2"
      hash14 = "6866a43caa754fd9925b770f3cbccdd4c428ee36a0a990269350cab5da0c466e"
      hash15 = "ce0e1fb940820934da5cd2456a90c9ca9aec2de59efb4e1e65d67307d9e51eb0"
      hash16 = "6057eeaa384d6cefe9c0917ff848da11508bc0754714446465d508a3a232fbdb"
      hash17 = "003f4d718ef7a4fadd75796c9fea06eeb470920e9061d12553983eae5a6d8b7d"
      hash18 = "84956376aa32d236635d36de5a04c7fdaddf09ccdc66959bb1580072ad7ccfb8"
      hash19 = "9aa2a7bf59ced9b8388d2047a32684c197f8a17f3bf08cbec6e8217c91e8a492"
      hash20 = "40226c28ad8b3e9deff277f939402cb02c4339ec35eead96f443a020d4879cb3"
   strings:
      $s1 = "thread %d create failed" fullword ascii
      $s2 = "JSON decode failed(%d): %s" fullword ascii
      $s3 = "JSON key '%s' is not a string" fullword ascii
      $s4 = "JSON key '%s' not found" fullword ascii
      $s5 = "scantime" fullword ascii
      $s6 = "submitold" fullword ascii
      $s7 = "HTTP request failed: %s" fullword ascii
      $s8 = "JSON protocol response:" fullword ascii
      $s9 = "X-Reject-Reason" fullword ascii
      $s10 = "JSON protocol request:" fullword ascii
      $s11 = "reject-reason" fullword ascii
      $s12 = "JSON-RPC call failed: %s" fullword ascii
      $s13 = "(unknown reason)" fullword ascii /* Goodware String - occured 3 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 18000KB and ( 8 of them )
      ) or ( all of them )
}

rule _match_378 {
   meta:
      description = "black - from files 0f9eddc5e740edcd96e2f32d6acc3bb3, 6cfc530100079ac1f1ed0cf61bed2ca8, acd5942fee24e5bc6769bb2fb529b695, 8a490aa2517646411b6ea1383f17bbd1, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 5f52a27f400818807d2693e1a52260ad, 0086748f3a7854b3a35f69b5285c534f, e28e3404155556ecafff204356fcc5f0, 4d6dff8b2def91e85a09faa27899d9d5, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, a3b4afa503657e7a327934ddd231887e, b3c0545d8bdbd5cd9c4c5cbd4d070d2a, b9280790ed58987ab2af68537ad18d6d, b1b0580af0e8fa730486561255426f38, ae33c5c9544d63463cca74c42a556983, ee3f5f355249823f286f389ce0567002, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 86d7666073561a5d0ca494d80eae3e5e, 9b3518901fb21e67bfd3986cdcded31c, 99fe45ec1a50c0413a6dcb1d23b754f9, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash2 = "438784b7594602da1a92d67890953b527ef6cb045e0c64ccaa4e78448576fff5"
      hash3 = "0083066406394696a0e6f26928d71785bf9fcdecdd6dcf52731a93b78f2cca0c"
      hash4 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash5 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash6 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash7 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash8 = "0693cfd2a09f5358cdec077df4cf049c88fe5fcdc606a228e389c9b2e517f965"
      hash9 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash10 = "dbc26374af31e9c81b8bc3a6c3063387f587a2596510e2a3be24aea6e025294f"
      hash11 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash12 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash13 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash14 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash15 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash16 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash17 = "7bf303baebaec1c10be08273dd3d1ce503c4a7e1edaefc6092778b2926ebb278"
      hash18 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash19 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash20 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash21 = "ade656b212a4bef11d70720679ec7fd91586a9507448634cd716178ed908e509"
      hash22 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash23 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash24 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash25 = "ee7ab7d8bd4643e2f2d63bc0329b21c6d3437beea13fc379ee7fbfc0e326d0f5"
      hash26 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash27 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash28 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = "t#HcL$`H" fullword ascii /* Goodware String - occured 1 times */
      $s2 = "t\"HcM`H" fullword ascii /* Goodware String - occured 1 times */
      $s3 = "9{0u5H" fullword ascii /* Goodware String - occured 2 times */
      $s4 = "HcL$4;" fullword ascii /* Goodware String - occured 3 times */
      $s5 = "9t$pt'I" fullword ascii
      $s6 = "W(L9:u" fullword ascii
      $s7 = "t$@t@Hc" fullword ascii
      $s8 = "F0H)F@I" fullword ascii
      $s9 = "C HcU " fullword ascii
      $s10 = "yH;Whr" fullword ascii
      $s11 = "9s0uKH" fullword ascii
      $s12 = "9s0u@H" fullword ascii
      $s13 = "9yhv}fff" fullword ascii
      $s14 = "9iLu@H" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and ( 8 of them )
      ) or ( all of them )
}

rule _match_380 {
   meta:
      description = "black - from files 20addcaa91c6bc5c7cc665ddb2e8c52c, 97ee5c92d5c865ef6db67c35bc8a427a, d220d7b9023e6bd3717edc17765fbb25, eafa15f8a4e79523f4f6288519e2d60a, 0f4acbb2acfaa97b146f4949729d0ec6, 09b0bb70c4456e39cb26cdf2667b2be7, cd7e6a6f2e3fc3cb1049efbbf235577f, f8a8bd5eb3b9328c007438070e0c3ca8, 0742b7c20e14fc0b9390fd5aafef6442, a746e73da04945445e385850616990c9, 6a80142ac8cf4d5534d2eb9cb0e3e08d, ddafbf9406cc26df63a32702126e3fc9, b1a919e6fb009361b64d51b351a25e4c, 936c8489a348fbdb03c66bbf46c60d7e, 3ba79ba35b4b388fe9699e51d4c43fea, e74a8e9fbf1969888d78bfe6bf757759, 2ae5db210e8c7c0c96e6bed93bce1da6, a79c869cbd44bdfa9860a858facd982e, 9f8125060a075a7c7b3e8b13d630bcf9, 0cccafcbc4d1a6d50ccd8fa1df89bc0f, a4d33f5f38e992c5e6d56865ff2ba1dc, e2ab3fc59ad63fee82456d2e42b23d2c, 74f394c609338509e94d61091a70b6f5"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "c2389593cb340e9b682e457e6bf926abf1eee594d129c237f3f87852731dba7d"
      hash2 = "e91e3d9138b2961bf0807b39ab1c0647e78ccf6985890246db1d698af498e43b"
      hash3 = "8d887ba624e0e8f55be8deb805ec25c1a2a34e6fa137b6bc30025cfbc124dfb8"
      hash4 = "7d2a58520ab1dea0d33c5866fdfbb8ccfb5a446f200c6d4c064d14ff90cdf76c"
      hash5 = "4c9bf0426483d1f8f7943cb291345134964d237f1b8270f88f51cbdd1557a41e"
      hash6 = "bc2a8aa09df1303d24917145a3b41acf1b9df09c72e65273883c63b288623e2b"
      hash7 = "08e6eb5d64f01d4a982bf75e4ffbec7d0f61d7ece7b7fbfe2fade7ae39ad8884"
      hash8 = "2df4f0927f0f73ff7ca38a4edfe9406be229985fd5ae468d9b5aa19b9b0cd0ac"
      hash9 = "3b38ac70eac888ba76ae3c5812179863a78b4e63ce92f5108f019bb00f96b35c"
      hash10 = "beae2bc4274deb42c452e6ad910853cfa1a60e05f0180ed43829e2a4f5281e04"
      hash11 = "c8eb9182adc12b591cbdafe27759495487a53c0cd38f83f77f575edf21e5d4b3"
      hash12 = "a35d47fde5d36de866ba7fbe638c7ea9f5860962b326484936a992cbba6fa22f"
      hash13 = "72356978da0b156bae25c84189c01a47b7c8e8daf22e2be533f1e2733f8372f2"
      hash14 = "b29176abdf91577a1267f00ad74137289898c4edd08ec4e27556f439a3d406e8"
      hash15 = "d274427049b5e28fdd153a0bdbcb08445ffebd9031ed666dba23b62e44b3191a"
      hash16 = "4c486b48b0524a9e3059f5dab86bffa9a0fa82787363c7784c624453344dc1d1"
      hash17 = "3b1a32116390ef2a821cbeb15e214f937293ee39cfde2a2e97f2eb128474bce3"
      hash18 = "58fc973c2df43431d85dd6713461e818376109c4b8f681cf9775768d45e18bf1"
      hash19 = "a2cce624ed3e428075dedc5b4243c065baafe0a121de26d686756e487e4d7232"
      hash20 = "4a49d867bbb4e4e36b55c77f0f514fdf18a78b18b701ae853075092ac2893e2e"
      hash21 = "0e1b04257292042084e66b6497e1a2411a81d497dabcee84e238da35e9472b50"
      hash22 = "5fc5a50b6becf57bcc7e47f6dcbbe2efa2ce15f43739f230f889b69e642619a9"
      hash23 = "02bd77bfd0a50ae5ea7e8a6587187e84b5c4d0d5638c7559abe609fbebbacd38"
   strings:
      $s1 = " * HUGE PAGES:   %s, %s" fullword ascii
      $s2 = " * CPU:          %s (%d) %sx64 %sAES-NI" fullword ascii
      $s3 = "[01;32m * " fullword ascii
      $s4 = "[01;37mHUGE PAGES:   %s, %s" fullword ascii
      $s5 = "[01;31mdisabled" fullword ascii
      $s6 = "[01;32menabled" fullword ascii
      $s7 = "[01;32mavailable" fullword ascii
      $s8 = "[01;36m%s:%d" fullword ascii
      $s9 = "[01;37mCPU:          %s (%d) %sx64 %sAES-NI" fullword ascii
      $s10 = "[01;37mTHREADS:      " fullword ascii
      $s11 = "[01;37mVERSIONS:     " fullword ascii
      $s12 = "[01;31m-" fullword ascii
      $s13 = "[01;36m%d" fullword ascii
      $s14 = " * CPU L2/L3:    %.1f MB/%.1f MB" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 27000KB and ( 8 of them )
      ) or ( all of them )
}

rule _match_405 {
   meta:
      description = "black - from files 0f9eddc5e740edcd96e2f32d6acc3bb3, 8a490aa2517646411b6ea1383f17bbd1, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 5f52a27f400818807d2693e1a52260ad, e28e3404155556ecafff204356fcc5f0, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, af408f884178b56843b9f7324bcdefb4, a3b4afa503657e7a327934ddd231887e, b9280790ed58987ab2af68537ad18d6d, b1b0580af0e8fa730486561255426f38, 0304ecd571a157fbcd4723d455bb554b, 26fc98d7481f9b494ecbfebacdcbeab3, ae33c5c9544d63463cca74c42a556983, ee3f5f355249823f286f389ce0567002, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 86d7666073561a5d0ca494d80eae3e5e, 9b3518901fb21e67bfd3986cdcded31c, 99fe45ec1a50c0413a6dcb1d23b754f9, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash2 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash3 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash4 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash5 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash6 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash7 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash8 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash9 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash10 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash11 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash12 = "c92d9638c8fb2b0556802ea87082be829f50dd7d29579a1a893ade35bd7a9256"
      hash13 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash14 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash15 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash16 = "02abeb1e769c65f180a39d46e4fb04f2282de9356b891f9734ce1ab86b5b183d"
      hash17 = "b95f40cce47499183ef95d6d56b8b5deed0d99a413a8bd7067200c5b1ae752a9"
      hash18 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash19 = "ade656b212a4bef11d70720679ec7fd91586a9507448634cd716178ed908e509"
      hash20 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash21 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash22 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash23 = "ee7ab7d8bd4643e2f2d63bc0329b21c6d3437beea13fc379ee7fbfc0e326d0f5"
      hash24 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash25 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash26 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = "%PROGRAMFILES%\\NVIDIA Corporation\\NVSMI\\nvml.dll" fullword ascii
      $s2 = "nvml.dll" fullword ascii
      $s3 = "nvmlSystemGetNVMLVersion" fullword ascii
      $s4 = "nvmlDeviceGetFanSpeed" fullword ascii
      $s5 = "nvmlDeviceGetHandleByIndex_v2" fullword ascii
      $s6 = "nvmlDeviceGetCount_v2" fullword ascii
      $s7 = "nvmlDeviceGetPciInfo_v2" fullword ascii
      $s8 = "bsleep" fullword ascii
      $s9 = "cuda-devices" fullword ascii
      $s10 = "nvmlShutdown" fullword ascii
      $s11 = "nvmlInit_v2" fullword ascii
      $s12 = "health" fullword ascii /* Goodware String - occured 3 times */
      $s13 = "[1;37mh" fullword ascii
      $s14 = "mem_clock" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 19000KB and ( 8 of them )
      ) or ( all of them )
}

rule _match_446 {
   meta:
      description = "black - from files c0c47b20d4a0acf33130efd241dcecb7, 9f4d9aaa17f43e35b68909cae6e2963e, 6638373439ec194078e3e6867a68e936, 0aa72cf7f23aeb9a055d869b1352ab05, b8c541161474bdb653f90b25c266bf32, 5d7241a98f223e091f32498665b4b205, e58365a2c5cebc3ef06e3e32c7921572, 2ca8a43dc76db43db4d7af35859a770f, 5d07e7441e45078f8cbcf62fcd6dae0a, 96d989641197f46942207b72fa661820, 416610b942ffaaf0b83b20b1591a1623, e90d08f6690a46b566c3381bebdc38af, 52f16c77af20982d5a0897b7e81beff8, 66532a0adab204c8239633eb49d07ce1, b74d586186adaa3cc2fe40d495263c84, cd0bbad6af58ff1e1a6dd4406c7b7ec0, 8b171722624178254ba65819889b41f2, 15630701c421ca2fcfecfd91622a30b3, 07b636a8bf645b7c512be756a8b69fe2, 05ee0d9bb5b1789da51fb0c022b33268, 0e9a01b4b3cc55564426f0d296d62846, bcdf3c943e6aa549e8753c32ded15360, 573bb9ebe60a259c6e0a890a74fa5a9e, 1297fa863626ddc4c5f5d9f6c5e5cb2f"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "5f4a3d3b5b21106dc72cca87921dc2788b3c4b70935eeca58eadb63a3518063f"
      hash2 = "bb53f0db836794aaedc9bccdd044105dbaa19ccb3a8e4583b11a29d26b56ca7c"
      hash3 = "c2e3029089ee805aadddf739c0c3018e7a833760b98d26b25f45e88f15cb11b6"
      hash4 = "503a30682bed0e07f14dbaedbfa0ad56398923d31aeca6efbda85f649b2f4ecc"
      hash5 = "3a800217027270f563a4721ba7df9ec5e101aeca3f27997ebd634e71abfd634f"
      hash6 = "b2dabbc952e916996f8ab3e3b868be538e00cdd2095450a296338d37da1afbb2"
      hash7 = "f07f526f240e6f91fbe91cf6413d97d58086b4a2a30393b146d31980f9c52dd8"
      hash8 = "53cc5abba6e39f54eecb9c0e4f80bf0a3df71982b3614dbaac48325c223c24ca"
      hash9 = "2044f43871ea0b24f228f0a30760b9bdbef26056726dc918e0bc31d130a4fd28"
      hash10 = "1048876df466fc480e46db03dacf774a0df61df51d3efb2876426321c60fe8b8"
      hash11 = "d5001e36a8c10501ebc0b03d1ec750e7657e0e7f3524a11c18cfbd3b06b7d634"
      hash12 = "e85181b8b3ba26ff40b9258fefc5fb6e974cfb99474ad29f445d6275ca6f74cc"
      hash13 = "a0f204d460f124f0f59b78ac6cc5dfcb6b1ced2e142185ff194435ff4016a788"
      hash14 = "cda8030bbabb0f8780de77912c63088d10c78b99bd5d4caadc27a3f8b8ec0a53"
      hash15 = "69de46a3d1262baa013ffd1f68c7eb5da4c988841335cf53278bd9a1087639cf"
      hash16 = "cf98b7c3daf69163ba7b2dd76538a0d9e19f63cb0d5d359ad529119d4f448d67"
      hash17 = "b9727e82fb6c723b18fb7a3906b5db97c0a0fc33e4808d10cb7329875973ea1a"
      hash18 = "a79e724b8b19334d676ac488569ca70f2737065495736b322c85f5edc8867f03"
      hash19 = "d8b1007592166e012ef7f1c709d35384481ded2c670add63edbb25f8d39c1a9f"
      hash20 = "62a098d7034672832209bc3495cf8a0a461542d816058dcc690009b2d2a44e85"
      hash21 = "6e2fd44944b0b6adf608d298aa78781bfc7bf9ab29c0644132eea183ff5e58d9"
      hash22 = "06e263554cbc8aad32eeedf2ca5374f5cde628312d5b61d61bdaaddc62c2e252"
      hash23 = "06c4fd2b55e3691fca7ceee681fb4858a7afcca05d9a2da86e9d9d4315294d9c"
      hash24 = "7b183d3b61275360f6715097e51be6bd47723899ae7d6d48085b766f01f2dee4"
   strings:
      $s1 = "m64fhbbiw.dll" fullword ascii
      $s2 = "T$`3D$" fullword ascii /* Goodware String - occured 1 times */
      $s3 = "OhYL3\\" fullword ascii
      $s4 = "|$H3t$<3|$D" fullword ascii
      $s5 = "G<0|[<9" fullword ascii
      $s6 = "|$@3t$43|$<" fullword ascii
      $s7 = "~D$h3G" fullword ascii
      $s8 = "~j{Mg%" fullword ascii
      $s9 = "9VLt&W" fullword ascii
      $s10 = "t$h3T$43" fullword ascii
      $s11 = "`7Rich" fullword ascii
      $s12 = "l$(w?r" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _match_453 {
   meta:
      description = "black - from files 0f9eddc5e740edcd96e2f32d6acc3bb3, 6cfc530100079ac1f1ed0cf61bed2ca8, acd5942fee24e5bc6769bb2fb529b695, 8a490aa2517646411b6ea1383f17bbd1, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 5f52a27f400818807d2693e1a52260ad, 0086748f3a7854b3a35f69b5285c534f, e28e3404155556ecafff204356fcc5f0, 4d6dff8b2def91e85a09faa27899d9d5, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, af408f884178b56843b9f7324bcdefb4, 51f0f95501d456804707bd997c56b416, a3b4afa503657e7a327934ddd231887e, b3c0545d8bdbd5cd9c4c5cbd4d070d2a, b9280790ed58987ab2af68537ad18d6d, b1b0580af0e8fa730486561255426f38, 26fc98d7481f9b494ecbfebacdcbeab3, ae33c5c9544d63463cca74c42a556983, ee3f5f355249823f286f389ce0567002, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 86d7666073561a5d0ca494d80eae3e5e, e4c92dd63239428f0b33c7f424293687, 9b3518901fb21e67bfd3986cdcded31c, 99fe45ec1a50c0413a6dcb1d23b754f9, e97524afde7b751f6b024fa4798bdf51, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash2 = "438784b7594602da1a92d67890953b527ef6cb045e0c64ccaa4e78448576fff5"
      hash3 = "0083066406394696a0e6f26928d71785bf9fcdecdd6dcf52731a93b78f2cca0c"
      hash4 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash5 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash6 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash7 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash8 = "0693cfd2a09f5358cdec077df4cf049c88fe5fcdc606a228e389c9b2e517f965"
      hash9 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash10 = "dbc26374af31e9c81b8bc3a6c3063387f587a2596510e2a3be24aea6e025294f"
      hash11 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash12 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash13 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash14 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash15 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash16 = "c92d9638c8fb2b0556802ea87082be829f50dd7d29579a1a893ade35bd7a9256"
      hash17 = "a8efd58c2f819b96742b10bad9aa76494731295f32ccc9897d3694944017b2a4"
      hash18 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash19 = "7bf303baebaec1c10be08273dd3d1ce503c4a7e1edaefc6092778b2926ebb278"
      hash20 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash21 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash22 = "b95f40cce47499183ef95d6d56b8b5deed0d99a413a8bd7067200c5b1ae752a9"
      hash23 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash24 = "ade656b212a4bef11d70720679ec7fd91586a9507448634cd716178ed908e509"
      hash25 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash26 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash27 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash28 = "c9d6e3fa0bf1bae569a87f1526093204b2b6bbc227e8ddcd2af450c4fb5c71c3"
      hash29 = "ee7ab7d8bd4643e2f2d63bc0329b21c6d3437beea13fc379ee7fbfc0e326d0f5"
      hash30 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash31 = "b81e7c41d4c6cec4c6f99f9e577c8335c685bf09351af664d82c2a97bc12b89c"
      hash32 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash33 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = "[1;32mpermission granted" fullword ascii
      $s2 = "[1;37m%s%d%%" fullword ascii
      $s3 = "DONATE" fullword ascii
      $s4 = "[1;37m%.1f MB" fullword ascii
      $s5 = "[1;30m L3:" fullword ascii
      $s6 = "[1;30m/" fullword ascii
      $s7 = "[1;36m %zu" fullword ascii
      $s8 = "[1;37m%-13s%s (%zu)" fullword ascii
      $s9 = "[1;30mL2:" fullword ascii
      $s10 = "[1;36m%zu" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 25000KB and ( all of them )
      ) or ( all of them )
}

rule _match_454 {
   meta:
      description = "black - from files 0f9eddc5e740edcd96e2f32d6acc3bb3, 8a490aa2517646411b6ea1383f17bbd1, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 5f52a27f400818807d2693e1a52260ad, 0086748f3a7854b3a35f69b5285c534f, e28e3404155556ecafff204356fcc5f0, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, a3b4afa503657e7a327934ddd231887e, b9280790ed58987ab2af68537ad18d6d, b1b0580af0e8fa730486561255426f38, ae33c5c9544d63463cca74c42a556983, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 86d7666073561a5d0ca494d80eae3e5e, 99fe45ec1a50c0413a6dcb1d23b754f9, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash2 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash3 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash4 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash5 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash6 = "0693cfd2a09f5358cdec077df4cf049c88fe5fcdc606a228e389c9b2e517f965"
      hash7 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash8 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash9 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash10 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash11 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash12 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash13 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash14 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash15 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash16 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash17 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash18 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash19 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash20 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash21 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash22 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = "H1D$8I" fullword ascii
      $s2 = "L9/uqH" fullword ascii
      $s3 = "H1D$0I" fullword ascii
      $s4 = "8H1D$h3" fullword ascii
      $s5 = "(H1D$XI" fullword ascii
      $s6 = "H1D$@I" fullword ascii
      $s7 = "H;J snH" fullword ascii
      $s8 = "0H1D$`I" fullword ascii
      $s9 = "H1D$HI" fullword ascii
      $s10 = "t$pE;w0" fullword ascii
      $s11 = " H1D$PI" fullword ascii
      $s12 = "C@H98t$H" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 13000KB and ( 8 of them )
      ) or ( all of them )
}

rule _match_505 {
   meta:
      description = "black - from files 4396f6981923a6e702a9d18a3d76e482, 0f9eddc5e740edcd96e2f32d6acc3bb3, 6cfc530100079ac1f1ed0cf61bed2ca8, acd5942fee24e5bc6769bb2fb529b695, 8a490aa2517646411b6ea1383f17bbd1, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 5f52a27f400818807d2693e1a52260ad, 0086748f3a7854b3a35f69b5285c534f, e28e3404155556ecafff204356fcc5f0, 4d6dff8b2def91e85a09faa27899d9d5, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, 4451163751d9841553744a6f80ca0aed, fc481ae3e90d67283ce944cefb433d25, a3b4afa503657e7a327934ddd231887e, b3c0545d8bdbd5cd9c4c5cbd4d070d2a, b9280790ed58987ab2af68537ad18d6d, b1b0580af0e8fa730486561255426f38, 13ce83c5c7ea01852b0ae2e35b74949b, 63d152e378907ea71551baff27a82d7d, ae33c5c9544d63463cca74c42a556983, ee3f5f355249823f286f389ce0567002, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 15c4fc341d735f9ea8427f918d3f5422, 86d7666073561a5d0ca494d80eae3e5e, e4c92dd63239428f0b33c7f424293687, 9b3518901fb21e67bfd3986cdcded31c, 99fe45ec1a50c0413a6dcb1d23b754f9, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "4fd49a0d1574549b4f8b64c9d474417600d6ede505c3997b3b07eb9e92bd440a"
      hash2 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash3 = "438784b7594602da1a92d67890953b527ef6cb045e0c64ccaa4e78448576fff5"
      hash4 = "0083066406394696a0e6f26928d71785bf9fcdecdd6dcf52731a93b78f2cca0c"
      hash5 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash6 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash7 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash8 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash9 = "0693cfd2a09f5358cdec077df4cf049c88fe5fcdc606a228e389c9b2e517f965"
      hash10 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash11 = "dbc26374af31e9c81b8bc3a6c3063387f587a2596510e2a3be24aea6e025294f"
      hash12 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash13 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash14 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash15 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash16 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash17 = "e90a53ae1c6318e25816e74530a4c3607e55cbadf3b7eb0d0ff97fb78d6a8d96"
      hash18 = "201b177ab0fe48289ac660b899b7813ed6f276a9ea1246574c28ebacb943905d"
      hash19 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash20 = "7bf303baebaec1c10be08273dd3d1ce503c4a7e1edaefc6092778b2926ebb278"
      hash21 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash22 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash23 = "10fe50b5f6fbaad5498bdc524145e5e05719fccc308da6de5a7c30ce9c3cbba3"
      hash24 = "f275d2589f252cfd2a131a89429837de58c04322c5ced8986dfc968d37bb1d4f"
      hash25 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash26 = "ade656b212a4bef11d70720679ec7fd91586a9507448634cd716178ed908e509"
      hash27 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash28 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash29 = "242b2e8bf86f40047ed0c60607f61f81fb144a641a394ab51f4b21f1511ddca8"
      hash30 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash31 = "c9d6e3fa0bf1bae569a87f1526093204b2b6bbc227e8ddcd2af450c4fb5c71c3"
      hash32 = "ee7ab7d8bd4643e2f2d63bc0329b21c6d3437beea13fc379ee7fbfc0e326d0f5"
      hash33 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash34 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash35 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = "GPH3G@fD" fullword ascii
      $s2 = "FPH3F@f" fullword ascii
      $s3 = "NXH3NHfL" fullword ascii
      $s4 = "OXH3OHfH" fullword ascii
      $s5 = "OXH3OHfL" fullword ascii
      $s6 = "GPH3G@f" fullword ascii
      $s7 = "FPH3F@fD" fullword ascii
      $s8 = "BPH3B@I" fullword ascii
      $s9 = "FPI3F@fD" fullword ascii
      $s10 = "NXH3NHfH" fullword ascii
      $s11 = "NXI3NHfL" fullword ascii
      $s12 = "BPH3B@H" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and ( 8 of them )
      ) or ( all of them )
}

rule _match_609 {
   meta:
      description = "black - from files 905eeda0ddf717b45bb294b227e6d8ae, 6b97eabf2e7eef8ccfc36593771ebe12, 4396f6981923a6e702a9d18a3d76e482, 0f9eddc5e740edcd96e2f32d6acc3bb3, 20addcaa91c6bc5c7cc665ddb2e8c52c, 6cfc530100079ac1f1ed0cf61bed2ca8, acd5942fee24e5bc6769bb2fb529b695, 8a490aa2517646411b6ea1383f17bbd1, bab9ba3432d3255edc4f8e86f6ea6010, f957d3e479a07339edad73308c36e092, 97ee5c92d5c865ef6db67c35bc8a427a, 97ee5c92d5c865ef6db67c35bc8a427a, d220d7b9023e6bd3717edc17765fbb25, d220d7b9023e6bd3717edc17765fbb25, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, eafa15f8a4e79523f4f6288519e2d60a, 6a6858a0087de5ff6493aa76d105d6df, 0f4acbb2acfaa97b146f4949729d0ec6, 5f52a27f400818807d2693e1a52260ad, 09b0bb70c4456e39cb26cdf2667b2be7, 5846aed02e23db1af696661606cf5bfd, cd7e6a6f2e3fc3cb1049efbbf235577f, 0086748f3a7854b3a35f69b5285c534f, e0095ff4e8222e5caafe0aedce42f9d4, e28e3404155556ecafff204356fcc5f0, 4d6dff8b2def91e85a09faa27899d9d5, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, 3934d1adff337a3741fc308eb83daaba, 99bd2332ea3179db7a70a6e66d11e096, af408f884178b56843b9f7324bcdefb4, 0cf00d65acee7181d4679d2ad3da5301, 51f0f95501d456804707bd997c56b416, 51f0f95501d456804707bd997c56b416, f8a8bd5eb3b9328c007438070e0c3ca8, 2458b8fb100cb0d0c80a3f62aea0e080, 2458b8fb100cb0d0c80a3f62aea0e080, 2b3e56a15d75e4aa0327ac55733353ca, 0742b7c20e14fc0b9390fd5aafef6442, 0742b7c20e14fc0b9390fd5aafef6442, 4451163751d9841553744a6f80ca0aed, fc481ae3e90d67283ce944cefb433d25, a3b4afa503657e7a327934ddd231887e, b3c0545d8bdbd5cd9c4c5cbd4d070d2a, b9280790ed58987ab2af68537ad18d6d, 80ba21786b71bb0dba959194fa1d3f63, a746e73da04945445e385850616990c9, 6a80142ac8cf4d5534d2eb9cb0e3e08d, ddafbf9406cc26df63a32702126e3fc9, b1b0580af0e8fa730486561255426f38, 720c0967b97baeaadefdfff2d265a183, 13ce83c5c7ea01852b0ae2e35b74949b, 0304ecd571a157fbcd4723d455bb554b, b1a919e6fb009361b64d51b351a25e4c, be3781cfcf4d7b709449382184148803, 936c8489a348fbdb03c66bbf46c60d7e, 3ba79ba35b4b388fe9699e51d4c43fea, 26fc98d7481f9b494ecbfebacdcbeab3, 63d152e378907ea71551baff27a82d7d, ae33c5c9544d63463cca74c42a556983, ee3f5f355249823f286f389ce0567002, df180313543e2a1a9c31ae49a0fb16be, e74a8e9fbf1969888d78bfe6bf757759, 9a07ca40de9c85495231302023c6a74a, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 15c4fc341d735f9ea8427f918d3f5422, 2ae5db210e8c7c0c96e6bed93bce1da6, a79c869cbd44bdfa9860a858facd982e, a79c869cbd44bdfa9860a858facd982e, 2bb37adb6ed181947bbb7f4535a351c1, 9ad1d65187d0fb50941ff23676234c5d, 86d7666073561a5d0ca494d80eae3e5e, e4c92dd63239428f0b33c7f424293687, 9f8125060a075a7c7b3e8b13d630bcf9, 0cccafcbc4d1a6d50ccd8fa1df89bc0f, 9b3518901fb21e67bfd3986cdcded31c, a4d33f5f38e992c5e6d56865ff2ba1dc, 99fe45ec1a50c0413a6dcb1d23b754f9, e2ab3fc59ad63fee82456d2e42b23d2c, 74f394c609338509e94d61091a70b6f5, e97524afde7b751f6b024fa4798bdf51, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "a28878f5880b8a1c506258dd39b459cec616f79100afe006b4779525b8a937a3"
      hash2 = "d2b4b16be498e2fbe782b6f0e73515f6fc74c7a661c44891a9860cbf2b690d02"
      hash3 = "4fd49a0d1574549b4f8b64c9d474417600d6ede505c3997b3b07eb9e92bd440a"
      hash4 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash5 = "c2389593cb340e9b682e457e6bf926abf1eee594d129c237f3f87852731dba7d"
      hash6 = "438784b7594602da1a92d67890953b527ef6cb045e0c64ccaa4e78448576fff5"
      hash7 = "0083066406394696a0e6f26928d71785bf9fcdecdd6dcf52731a93b78f2cca0c"
      hash8 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash9 = "95319d0df797fdb6ceb91efe6883dbc0455c5cc1932d559b1db37454538801c7"
      hash10 = "3a3fcb2a72c7e88bb0a5e31240f73f6b401ea9f22416a65519cd0c699d665e94"
      hash11 = "e91e3d9138b2961bf0807b39ab1c0647e78ccf6985890246db1d698af498e43b"
      hash12 = "e91e3d9138b2961bf0807b39ab1c0647e78ccf6985890246db1d698af498e43b"
      hash13 = "8d887ba624e0e8f55be8deb805ec25c1a2a34e6fa137b6bc30025cfbc124dfb8"
      hash14 = "8d887ba624e0e8f55be8deb805ec25c1a2a34e6fa137b6bc30025cfbc124dfb8"
      hash15 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash16 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash17 = "7d2a58520ab1dea0d33c5866fdfbb8ccfb5a446f200c6d4c064d14ff90cdf76c"
      hash18 = "632f7efefd5383c0a53b18bb6cb327296b1b0bea50ea89ec493a4064e9df5973"
      hash19 = "4c9bf0426483d1f8f7943cb291345134964d237f1b8270f88f51cbdd1557a41e"
      hash20 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash21 = "bc2a8aa09df1303d24917145a3b41acf1b9df09c72e65273883c63b288623e2b"
      hash22 = "5d1ef3f5bc06e457945af001cad5e392eea47ae4486522ad3342f42b6e2b7436"
      hash23 = "08e6eb5d64f01d4a982bf75e4ffbec7d0f61d7ece7b7fbfe2fade7ae39ad8884"
      hash24 = "0693cfd2a09f5358cdec077df4cf049c88fe5fcdc606a228e389c9b2e517f965"
      hash25 = "ac51683da9fbe47c0d65f00d85a8b9705c4ab01a66f43c4a872b8f5407516f2b"
      hash26 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash27 = "dbc26374af31e9c81b8bc3a6c3063387f587a2596510e2a3be24aea6e025294f"
      hash28 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash29 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash30 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash31 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash32 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash33 = "2fefce5634c8b6f9e334fd6b1c34b86f6cb8278dc07558034d1ead43d1467cbb"
      hash34 = "2e999f22d7fa0d018342d235067b5bb879b4505bb0e42156f816d38ae61cd3fe"
      hash35 = "c92d9638c8fb2b0556802ea87082be829f50dd7d29579a1a893ade35bd7a9256"
      hash36 = "a0e6799ed9cb59ac3aeab73f2c10015fbabbacc850b56148778f69cc38835d27"
      hash37 = "a8efd58c2f819b96742b10bad9aa76494731295f32ccc9897d3694944017b2a4"
      hash38 = "a8efd58c2f819b96742b10bad9aa76494731295f32ccc9897d3694944017b2a4"
      hash39 = "2df4f0927f0f73ff7ca38a4edfe9406be229985fd5ae468d9b5aa19b9b0cd0ac"
      hash40 = "ba3e5e8af6d21e5fa3a78b69a87ca1cd39afd4342795f514bd651af81e9b8e47"
      hash41 = "ba3e5e8af6d21e5fa3a78b69a87ca1cd39afd4342795f514bd651af81e9b8e47"
      hash42 = "7bdb3093778ff709bac2a5e5e22960ab93fce19da7fc8e79aed29105c8d45f61"
      hash43 = "3b38ac70eac888ba76ae3c5812179863a78b4e63ce92f5108f019bb00f96b35c"
      hash44 = "3b38ac70eac888ba76ae3c5812179863a78b4e63ce92f5108f019bb00f96b35c"
      hash45 = "e90a53ae1c6318e25816e74530a4c3607e55cbadf3b7eb0d0ff97fb78d6a8d96"
      hash46 = "201b177ab0fe48289ac660b899b7813ed6f276a9ea1246574c28ebacb943905d"
      hash47 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash48 = "7bf303baebaec1c10be08273dd3d1ce503c4a7e1edaefc6092778b2926ebb278"
      hash49 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash50 = "2e4b386aa820c4a1b294274d89652098e4a78921df83b1ed101213f558f704ea"
      hash51 = "beae2bc4274deb42c452e6ad910853cfa1a60e05f0180ed43829e2a4f5281e04"
      hash52 = "c8eb9182adc12b591cbdafe27759495487a53c0cd38f83f77f575edf21e5d4b3"
      hash53 = "a35d47fde5d36de866ba7fbe638c7ea9f5860962b326484936a992cbba6fa22f"
      hash54 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash55 = "a5da66d083a3a55342caab79f28aa97728682eebad7a9b8de88b0af92e9a7c28"
      hash56 = "10fe50b5f6fbaad5498bdc524145e5e05719fccc308da6de5a7c30ce9c3cbba3"
      hash57 = "02abeb1e769c65f180a39d46e4fb04f2282de9356b891f9734ce1ab86b5b183d"
      hash58 = "72356978da0b156bae25c84189c01a47b7c8e8daf22e2be533f1e2733f8372f2"
      hash59 = "714ae3c335d8dd42c2db8fe655c433887a5e0ef1c5f49a267d91f523427b2b61"
      hash60 = "b29176abdf91577a1267f00ad74137289898c4edd08ec4e27556f439a3d406e8"
      hash61 = "d274427049b5e28fdd153a0bdbcb08445ffebd9031ed666dba23b62e44b3191a"
      hash62 = "b95f40cce47499183ef95d6d56b8b5deed0d99a413a8bd7067200c5b1ae752a9"
      hash63 = "f275d2589f252cfd2a131a89429837de58c04322c5ced8986dfc968d37bb1d4f"
      hash64 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash65 = "ade656b212a4bef11d70720679ec7fd91586a9507448634cd716178ed908e509"
      hash66 = "a7799d88b5ae3a611ca45939dbd479766fd4a3dd86e622bf95ef1189afc59f13"
      hash67 = "4c486b48b0524a9e3059f5dab86bffa9a0fa82787363c7784c624453344dc1d1"
      hash68 = "ea9d91772dd86455d5bf25c080ed859faae39c7085abb5de0b3142a397e7f131"
      hash69 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash70 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash71 = "242b2e8bf86f40047ed0c60607f61f81fb144a641a394ab51f4b21f1511ddca8"
      hash72 = "3b1a32116390ef2a821cbeb15e214f937293ee39cfde2a2e97f2eb128474bce3"
      hash73 = "58fc973c2df43431d85dd6713461e818376109c4b8f681cf9775768d45e18bf1"
      hash74 = "58fc973c2df43431d85dd6713461e818376109c4b8f681cf9775768d45e18bf1"
      hash75 = "270825598a9cede97ed8ab5b68f3a1e1ee135489de3e464b6a46e29fb0e69c3c"
      hash76 = "6b5e1968ea97bcb10a53e2754d4f33c58bc1efed2ff1533d9bb3c346d8dfe318"
      hash77 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash78 = "c9d6e3fa0bf1bae569a87f1526093204b2b6bbc227e8ddcd2af450c4fb5c71c3"
      hash79 = "a2cce624ed3e428075dedc5b4243c065baafe0a121de26d686756e487e4d7232"
      hash80 = "4a49d867bbb4e4e36b55c77f0f514fdf18a78b18b701ae853075092ac2893e2e"
      hash81 = "ee7ab7d8bd4643e2f2d63bc0329b21c6d3437beea13fc379ee7fbfc0e326d0f5"
      hash82 = "0e1b04257292042084e66b6497e1a2411a81d497dabcee84e238da35e9472b50"
      hash83 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash84 = "5fc5a50b6becf57bcc7e47f6dcbbe2efa2ce15f43739f230f889b69e642619a9"
      hash85 = "02bd77bfd0a50ae5ea7e8a6587187e84b5c4d0d5638c7559abe609fbebbacd38"
      hash86 = "b81e7c41d4c6cec4c6f99f9e577c8335c685bf09351af664d82c2a97bc12b89c"
      hash87 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash88 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = "LOGONSERVER=" fullword wide
      $s2 = "SYSTEMROOT=" fullword wide
      $s3 = "SYSTEMDRIVE=" fullword wide
      $s4 = "WINDIR=" fullword wide
      $s5 = "USERDOMAIN=" fullword wide /* Goodware String - occured 2 times */
      $s6 = "USERNAME=" fullword wide /* Goodware String - occured 2 times */
      $s7 = "USERPROFILE=" fullword wide /* Goodware String - occured 2 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 27000KB and ( all of them )
      ) or ( all of them )
}

rule _match_631 {
   meta:
      description = "black - from files 0f9eddc5e740edcd96e2f32d6acc3bb3, 6cfc530100079ac1f1ed0cf61bed2ca8, acd5942fee24e5bc6769bb2fb529b695, 8a490aa2517646411b6ea1383f17bbd1, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 5f52a27f400818807d2693e1a52260ad, 0086748f3a7854b3a35f69b5285c534f, e28e3404155556ecafff204356fcc5f0, 4d6dff8b2def91e85a09faa27899d9d5, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, 4451163751d9841553744a6f80ca0aed, fc481ae3e90d67283ce944cefb433d25, a3b4afa503657e7a327934ddd231887e, b3c0545d8bdbd5cd9c4c5cbd4d070d2a, b9280790ed58987ab2af68537ad18d6d, b1b0580af0e8fa730486561255426f38, 13ce83c5c7ea01852b0ae2e35b74949b, 63d152e378907ea71551baff27a82d7d, ae33c5c9544d63463cca74c42a556983, ee3f5f355249823f286f389ce0567002, 9a07ca40de9c85495231302023c6a74a, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 15c4fc341d735f9ea8427f918d3f5422, 86d7666073561a5d0ca494d80eae3e5e, e4c92dd63239428f0b33c7f424293687, 9b3518901fb21e67bfd3986cdcded31c, 99fe45ec1a50c0413a6dcb1d23b754f9, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash2 = "438784b7594602da1a92d67890953b527ef6cb045e0c64ccaa4e78448576fff5"
      hash3 = "0083066406394696a0e6f26928d71785bf9fcdecdd6dcf52731a93b78f2cca0c"
      hash4 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash5 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash6 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash7 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash8 = "0693cfd2a09f5358cdec077df4cf049c88fe5fcdc606a228e389c9b2e517f965"
      hash9 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash10 = "dbc26374af31e9c81b8bc3a6c3063387f587a2596510e2a3be24aea6e025294f"
      hash11 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash12 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash13 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash14 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash15 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash16 = "e90a53ae1c6318e25816e74530a4c3607e55cbadf3b7eb0d0ff97fb78d6a8d96"
      hash17 = "201b177ab0fe48289ac660b899b7813ed6f276a9ea1246574c28ebacb943905d"
      hash18 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash19 = "7bf303baebaec1c10be08273dd3d1ce503c4a7e1edaefc6092778b2926ebb278"
      hash20 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash21 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash22 = "10fe50b5f6fbaad5498bdc524145e5e05719fccc308da6de5a7c30ce9c3cbba3"
      hash23 = "f275d2589f252cfd2a131a89429837de58c04322c5ced8986dfc968d37bb1d4f"
      hash24 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash25 = "ade656b212a4bef11d70720679ec7fd91586a9507448634cd716178ed908e509"
      hash26 = "ea9d91772dd86455d5bf25c080ed859faae39c7085abb5de0b3142a397e7f131"
      hash27 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash28 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash29 = "242b2e8bf86f40047ed0c60607f61f81fb144a641a394ab51f4b21f1511ddca8"
      hash30 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash31 = "c9d6e3fa0bf1bae569a87f1526093204b2b6bbc227e8ddcd2af450c4fb5c71c3"
      hash32 = "ee7ab7d8bd4643e2f2d63bc0329b21c6d3437beea13fc379ee7fbfc0e326d0f5"
      hash33 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash34 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash35 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = ".?AVISignalListener@xmrig@@" fullword ascii
      $s2 = ".?AVIStrategyListener@xmrig@@" fullword ascii
      $s3 = ".?AVIJobResultListener@xmrig@@" fullword ascii
      $s4 = ".?AVIClientListener@xmrig@@" fullword ascii
      $s5 = ".?AVFailoverStrategy@xmrig@@" fullword ascii
      $s6 = ".?AVNetwork@xmrig@@" fullword ascii
      $s7 = ".?AVDonateStrategy@xmrig@@" fullword ascii
      $s8 = ".?AVIStrategy@xmrig@@" fullword ascii
      $s9 = ".?AVSinglePoolStrategy@xmrig@@" fullword ascii
      $s10 = ".?AVApp@xmrig@@" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and ( all of them )
      ) or ( all of them )
}

rule _match_632 {
   meta:
      description = "black - from files 0f9eddc5e740edcd96e2f32d6acc3bb3, 8a490aa2517646411b6ea1383f17bbd1, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 5f52a27f400818807d2693e1a52260ad, e28e3404155556ecafff204356fcc5f0, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, af408f884178b56843b9f7324bcdefb4, 51f0f95501d456804707bd997c56b416, a3b4afa503657e7a327934ddd231887e, b9280790ed58987ab2af68537ad18d6d, b1b0580af0e8fa730486561255426f38, 26fc98d7481f9b494ecbfebacdcbeab3, ae33c5c9544d63463cca74c42a556983, ee3f5f355249823f286f389ce0567002, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 86d7666073561a5d0ca494d80eae3e5e, e4c92dd63239428f0b33c7f424293687, 9b3518901fb21e67bfd3986cdcded31c, 99fe45ec1a50c0413a6dcb1d23b754f9, e97524afde7b751f6b024fa4798bdf51, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash2 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash3 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash4 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash5 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash6 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash7 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash8 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash9 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash10 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash11 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash12 = "c92d9638c8fb2b0556802ea87082be829f50dd7d29579a1a893ade35bd7a9256"
      hash13 = "a8efd58c2f819b96742b10bad9aa76494731295f32ccc9897d3694944017b2a4"
      hash14 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash15 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash16 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash17 = "b95f40cce47499183ef95d6d56b8b5deed0d99a413a8bd7067200c5b1ae752a9"
      hash18 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash19 = "ade656b212a4bef11d70720679ec7fd91586a9507448634cd716178ed908e509"
      hash20 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash21 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash22 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash23 = "c9d6e3fa0bf1bae569a87f1526093204b2b6bbc227e8ddcd2af450c4fb5c71c3"
      hash24 = "ee7ab7d8bd4643e2f2d63bc0329b21c6d3437beea13fc379ee7fbfc0e326d0f5"
      hash25 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash26 = "b81e7c41d4c6cec4c6f99f9e577c8335c685bf09351af664d82c2a97bc12b89c"
      hash27 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash28 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = "[%s] failed to parse field \"seed_hash\" required by RandomX" fullword ascii
      $s2 = "[1;37m threads)" fullword ascii
      $s3 = "[1;32m READY" fullword ascii
      $s4 = "%s use profile " fullword ascii
      $s5 = "cryptonight-aeonv7" fullword ascii
      $s6 = "[0;33m stopped" fullword ascii
      $s7 = "cryptonight-bittube2" fullword ascii
      $s8 = "[0m scratchpad " fullword ascii
      $s9 = "[1;37m (" fullword ascii
      $s10 = "[45;1m r " fullword ascii
      $s11 = "[1;30m (%llu ms)" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 25000KB and ( 8 of them )
      ) or ( all of them )
}

rule _match_721 {
   meta:
      description = "black - from files 4396f6981923a6e702a9d18a3d76e482, 0f9eddc5e740edcd96e2f32d6acc3bb3, 8a490aa2517646411b6ea1383f17bbd1, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 5f52a27f400818807d2693e1a52260ad, 5846aed02e23db1af696661606cf5bfd, e28e3404155556ecafff204356fcc5f0, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, af408f884178b56843b9f7324bcdefb4, 0cf00d65acee7181d4679d2ad3da5301, 51f0f95501d456804707bd997c56b416, 4451163751d9841553744a6f80ca0aed, a3b4afa503657e7a327934ddd231887e, b9280790ed58987ab2af68537ad18d6d, b1b0580af0e8fa730486561255426f38, 26fc98d7481f9b494ecbfebacdcbeab3, 63d152e378907ea71551baff27a82d7d, ae33c5c9544d63463cca74c42a556983, ee3f5f355249823f286f389ce0567002, 9a07ca40de9c85495231302023c6a74a, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 86d7666073561a5d0ca494d80eae3e5e, e4c92dd63239428f0b33c7f424293687, 9b3518901fb21e67bfd3986cdcded31c, 99fe45ec1a50c0413a6dcb1d23b754f9, e97524afde7b751f6b024fa4798bdf51, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "4fd49a0d1574549b4f8b64c9d474417600d6ede505c3997b3b07eb9e92bd440a"
      hash2 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash3 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash4 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash5 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash6 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash7 = "5d1ef3f5bc06e457945af001cad5e392eea47ae4486522ad3342f42b6e2b7436"
      hash8 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash9 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash10 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash11 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash12 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash13 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash14 = "c92d9638c8fb2b0556802ea87082be829f50dd7d29579a1a893ade35bd7a9256"
      hash15 = "a0e6799ed9cb59ac3aeab73f2c10015fbabbacc850b56148778f69cc38835d27"
      hash16 = "a8efd58c2f819b96742b10bad9aa76494731295f32ccc9897d3694944017b2a4"
      hash17 = "e90a53ae1c6318e25816e74530a4c3607e55cbadf3b7eb0d0ff97fb78d6a8d96"
      hash18 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash19 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash20 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash21 = "b95f40cce47499183ef95d6d56b8b5deed0d99a413a8bd7067200c5b1ae752a9"
      hash22 = "f275d2589f252cfd2a131a89429837de58c04322c5ced8986dfc968d37bb1d4f"
      hash23 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash24 = "ade656b212a4bef11d70720679ec7fd91586a9507448634cd716178ed908e509"
      hash25 = "ea9d91772dd86455d5bf25c080ed859faae39c7085abb5de0b3142a397e7f131"
      hash26 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash27 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash28 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash29 = "c9d6e3fa0bf1bae569a87f1526093204b2b6bbc227e8ddcd2af450c4fb5c71c3"
      hash30 = "ee7ab7d8bd4643e2f2d63bc0329b21c6d3437beea13fc379ee7fbfc0e326d0f5"
      hash31 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash32 = "b81e7c41d4c6cec4c6f99f9e577c8335c685bf09351af664d82c2a97bc12b89c"
      hash33 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash34 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = "cryptonight-turtle" fullword ascii
      $s2 = "cn-pico/trtl" fullword ascii
      $s3 = "cn-ultralite" fullword ascii
      $s4 = "cryptonight-pico/trtl" fullword ascii
      $s5 = "cryptonight-pico" fullword ascii
      $s6 = "cryptonight_turtle" fullword ascii
      $s7 = "cryptonight-ultralite" fullword ascii
      $s8 = "cn_turtle" fullword ascii
      $s9 = "cn-pico" fullword ascii
      $s10 = "cn-trtl" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 25000KB and ( all of them )
      ) or ( all of them )
}

rule _match_753 {
   meta:
      description = "black - from files 0f9eddc5e740edcd96e2f32d6acc3bb3, 8a490aa2517646411b6ea1383f17bbd1, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 5f52a27f400818807d2693e1a52260ad, e28e3404155556ecafff204356fcc5f0, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, a3b4afa503657e7a327934ddd231887e, b9280790ed58987ab2af68537ad18d6d, b1b0580af0e8fa730486561255426f38, ae33c5c9544d63463cca74c42a556983, ee3f5f355249823f286f389ce0567002, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 86d7666073561a5d0ca494d80eae3e5e, 99fe45ec1a50c0413a6dcb1d23b754f9, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash2 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash3 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash4 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash5 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash6 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash7 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash8 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash9 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash10 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash11 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash12 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash13 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash14 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash15 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash16 = "ade656b212a4bef11d70720679ec7fd91586a9507448634cd716178ed908e509"
      hash17 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash18 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash19 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash20 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash21 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash22 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = "HcC0H;" fullword ascii /* Goodware String - occured 1 times */
      $s2 = "C49G4u" fullword ascii /* Goodware String - occured 3 times */
      $s3 = "C(9G(u-" fullword ascii
      $s4 = "C$9G$u5" fullword ascii
      $s5 = "C 9G uM" fullword ascii
      $s6 = "G L;C u" fullword ascii
      $s7 = "C(f9G(u" fullword ascii
      $s8 = "C,9G,u%" fullword ascii
      $s9 = "C89G8u" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 13000KB and ( all of them )
      ) or ( all of them )
}

rule _match_754 {
   meta:
      description = "black - from files 0f9eddc5e740edcd96e2f32d6acc3bb3, 6cfc530100079ac1f1ed0cf61bed2ca8, acd5942fee24e5bc6769bb2fb529b695, 8a490aa2517646411b6ea1383f17bbd1, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 5f52a27f400818807d2693e1a52260ad, 0086748f3a7854b3a35f69b5285c534f, e28e3404155556ecafff204356fcc5f0, 4d6dff8b2def91e85a09faa27899d9d5, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, fc481ae3e90d67283ce944cefb433d25, a3b4afa503657e7a327934ddd231887e, b3c0545d8bdbd5cd9c4c5cbd4d070d2a, b9280790ed58987ab2af68537ad18d6d, b1b0580af0e8fa730486561255426f38, ae33c5c9544d63463cca74c42a556983, ee3f5f355249823f286f389ce0567002, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 86d7666073561a5d0ca494d80eae3e5e, e4c92dd63239428f0b33c7f424293687, 9b3518901fb21e67bfd3986cdcded31c, 99fe45ec1a50c0413a6dcb1d23b754f9, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash2 = "438784b7594602da1a92d67890953b527ef6cb045e0c64ccaa4e78448576fff5"
      hash3 = "0083066406394696a0e6f26928d71785bf9fcdecdd6dcf52731a93b78f2cca0c"
      hash4 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash5 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash6 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash7 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash8 = "0693cfd2a09f5358cdec077df4cf049c88fe5fcdc606a228e389c9b2e517f965"
      hash9 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash10 = "dbc26374af31e9c81b8bc3a6c3063387f587a2596510e2a3be24aea6e025294f"
      hash11 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash12 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash13 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash14 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash15 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash16 = "201b177ab0fe48289ac660b899b7813ed6f276a9ea1246574c28ebacb943905d"
      hash17 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash18 = "7bf303baebaec1c10be08273dd3d1ce503c4a7e1edaefc6092778b2926ebb278"
      hash19 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash20 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash21 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash22 = "ade656b212a4bef11d70720679ec7fd91586a9507448634cd716178ed908e509"
      hash23 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash24 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash25 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash26 = "c9d6e3fa0bf1bae569a87f1526093204b2b6bbc227e8ddcd2af450c4fb5c71c3"
      hash27 = "ee7ab7d8bd4643e2f2d63bc0329b21c6d3437beea13fc379ee7fbfc0e326d0f5"
      hash28 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash29 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash30 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = ".?AV?$CpuWorker@$04@xmrig@@" fullword ascii
      $s2 = ".?AVIBackend@xmrig@@" fullword ascii
      $s3 = ".?AV?$CpuWorker@$00@xmrig@@" fullword ascii
      $s4 = ".?AVWorker@xmrig@@" fullword ascii
      $s5 = ".?AVCpuBackend@xmrig@@" fullword ascii
      $s6 = ".?AV?$CpuWorker@$01@xmrig@@" fullword ascii
      $s7 = ".?AVMiner@xmrig@@" fullword ascii
      $s8 = ".?AV?$CpuWorker@$03@xmrig@@" fullword ascii
      $s9 = ".?AVIWorker@xmrig@@" fullword ascii
      $s10 = ".?AV?$CpuWorker@$02@xmrig@@" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and ( all of them )
      ) or ( all of them )
}

rule _match_836 {
   meta:
      description = "black - from files 905eeda0ddf717b45bb294b227e6d8ae, 6b97eabf2e7eef8ccfc36593771ebe12, 4396f6981923a6e702a9d18a3d76e482, 0f9eddc5e740edcd96e2f32d6acc3bb3, 6cfc530100079ac1f1ed0cf61bed2ca8, acd5942fee24e5bc6769bb2fb529b695, 8a490aa2517646411b6ea1383f17bbd1, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 5f52a27f400818807d2693e1a52260ad, 0086748f3a7854b3a35f69b5285c534f, e28e3404155556ecafff204356fcc5f0, 4d6dff8b2def91e85a09faa27899d9d5, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, 2458b8fb100cb0d0c80a3f62aea0e080, 4451163751d9841553744a6f80ca0aed, fc481ae3e90d67283ce944cefb433d25, a3b4afa503657e7a327934ddd231887e, b3c0545d8bdbd5cd9c4c5cbd4d070d2a, b9280790ed58987ab2af68537ad18d6d, 80ba21786b71bb0dba959194fa1d3f63, b1b0580af0e8fa730486561255426f38, 13ce83c5c7ea01852b0ae2e35b74949b, 63d152e378907ea71551baff27a82d7d, ae33c5c9544d63463cca74c42a556983, ee3f5f355249823f286f389ce0567002, 9a07ca40de9c85495231302023c6a74a, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 15c4fc341d735f9ea8427f918d3f5422, 86d7666073561a5d0ca494d80eae3e5e, e4c92dd63239428f0b33c7f424293687, 9b3518901fb21e67bfd3986cdcded31c, 99fe45ec1a50c0413a6dcb1d23b754f9, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "a28878f5880b8a1c506258dd39b459cec616f79100afe006b4779525b8a937a3"
      hash2 = "d2b4b16be498e2fbe782b6f0e73515f6fc74c7a661c44891a9860cbf2b690d02"
      hash3 = "4fd49a0d1574549b4f8b64c9d474417600d6ede505c3997b3b07eb9e92bd440a"
      hash4 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash5 = "438784b7594602da1a92d67890953b527ef6cb045e0c64ccaa4e78448576fff5"
      hash6 = "0083066406394696a0e6f26928d71785bf9fcdecdd6dcf52731a93b78f2cca0c"
      hash7 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash8 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash9 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash10 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash11 = "0693cfd2a09f5358cdec077df4cf049c88fe5fcdc606a228e389c9b2e517f965"
      hash12 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash13 = "dbc26374af31e9c81b8bc3a6c3063387f587a2596510e2a3be24aea6e025294f"
      hash14 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash15 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash16 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash17 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash18 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash19 = "ba3e5e8af6d21e5fa3a78b69a87ca1cd39afd4342795f514bd651af81e9b8e47"
      hash20 = "e90a53ae1c6318e25816e74530a4c3607e55cbadf3b7eb0d0ff97fb78d6a8d96"
      hash21 = "201b177ab0fe48289ac660b899b7813ed6f276a9ea1246574c28ebacb943905d"
      hash22 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash23 = "7bf303baebaec1c10be08273dd3d1ce503c4a7e1edaefc6092778b2926ebb278"
      hash24 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash25 = "2e4b386aa820c4a1b294274d89652098e4a78921df83b1ed101213f558f704ea"
      hash26 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash27 = "10fe50b5f6fbaad5498bdc524145e5e05719fccc308da6de5a7c30ce9c3cbba3"
      hash28 = "f275d2589f252cfd2a131a89429837de58c04322c5ced8986dfc968d37bb1d4f"
      hash29 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash30 = "ade656b212a4bef11d70720679ec7fd91586a9507448634cd716178ed908e509"
      hash31 = "ea9d91772dd86455d5bf25c080ed859faae39c7085abb5de0b3142a397e7f131"
      hash32 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash33 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash34 = "242b2e8bf86f40047ed0c60607f61f81fb144a641a394ab51f4b21f1511ddca8"
      hash35 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash36 = "c9d6e3fa0bf1bae569a87f1526093204b2b6bbc227e8ddcd2af450c4fb5c71c3"
      hash37 = "ee7ab7d8bd4643e2f2d63bc0329b21c6d3437beea13fc379ee7fbfc0e326d0f5"
      hash38 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash39 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash40 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = "A H;B r" fullword ascii
      $s2 = "taH9_`u" fullword ascii
      $s3 = "F@H9G " fullword ascii
      $s4 = "N L9cp" fullword ascii
      $s5 = "B0H9A0r" fullword ascii
      $s6 = "t3;{h|\"" fullword ascii
      $s7 = "N L9cpt" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and ( all of them )
      ) or ( all of them )
}

rule _match_837 {
   meta:
      description = "black - from files 905eeda0ddf717b45bb294b227e6d8ae, 6b97eabf2e7eef8ccfc36593771ebe12, 4396f6981923a6e702a9d18a3d76e482, 20addcaa91c6bc5c7cc665ddb2e8c52c, 97ee5c92d5c865ef6db67c35bc8a427a, 50b754688ea8b1994abc99ea58263ebb, d220d7b9023e6bd3717edc17765fbb25, 0f4acbb2acfaa97b146f4949729d0ec6, 5846aed02e23db1af696661606cf5bfd, cd7e6a6f2e3fc3cb1049efbbf235577f, a7e372d0982334302446756bf112d881, 3934d1adff337a3741fc308eb83daaba, 99bd2332ea3179db7a70a6e66d11e096, 0cf00d65acee7181d4679d2ad3da5301, f8a8bd5eb3b9328c007438070e0c3ca8, 2458b8fb100cb0d0c80a3f62aea0e080, 0742b7c20e14fc0b9390fd5aafef6442, cd9d53902ae60c8a9330b6b145cbe3bb, 80ba21786b71bb0dba959194fa1d3f63, a746e73da04945445e385850616990c9, 6a80142ac8cf4d5534d2eb9cb0e3e08d, ddafbf9406cc26df63a32702126e3fc9, b1a919e6fb009361b64d51b351a25e4c, 3ba79ba35b4b388fe9699e51d4c43fea, e74a8e9fbf1969888d78bfe6bf757759, 9a07ca40de9c85495231302023c6a74a, 2ae5db210e8c7c0c96e6bed93bce1da6, 6bd4123b8dc8281bfee4c09350545c7e, 7c2a9696e8feae3fdd4d2a71a2359019, 233cb487009705a47f32a694558deca5, 0cccafcbc4d1a6d50ccd8fa1df89bc0f, 3a69511ef880ea841a6740357901ca61, 74f394c609338509e94d61091a70b6f5"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "a28878f5880b8a1c506258dd39b459cec616f79100afe006b4779525b8a937a3"
      hash2 = "d2b4b16be498e2fbe782b6f0e73515f6fc74c7a661c44891a9860cbf2b690d02"
      hash3 = "4fd49a0d1574549b4f8b64c9d474417600d6ede505c3997b3b07eb9e92bd440a"
      hash4 = "c2389593cb340e9b682e457e6bf926abf1eee594d129c237f3f87852731dba7d"
      hash5 = "e91e3d9138b2961bf0807b39ab1c0647e78ccf6985890246db1d698af498e43b"
      hash6 = "2efbcf082019f2fe3b7b065842a6e99e0441e7166265d2021695fce00f0d4373"
      hash7 = "8d887ba624e0e8f55be8deb805ec25c1a2a34e6fa137b6bc30025cfbc124dfb8"
      hash8 = "4c9bf0426483d1f8f7943cb291345134964d237f1b8270f88f51cbdd1557a41e"
      hash9 = "5d1ef3f5bc06e457945af001cad5e392eea47ae4486522ad3342f42b6e2b7436"
      hash10 = "08e6eb5d64f01d4a982bf75e4ffbec7d0f61d7ece7b7fbfe2fade7ae39ad8884"
      hash11 = "d204dc52cd7c86013aa224f66e5631efec50edff579c78d21310c49b05910018"
      hash12 = "2fefce5634c8b6f9e334fd6b1c34b86f6cb8278dc07558034d1ead43d1467cbb"
      hash13 = "2e999f22d7fa0d018342d235067b5bb879b4505bb0e42156f816d38ae61cd3fe"
      hash14 = "a0e6799ed9cb59ac3aeab73f2c10015fbabbacc850b56148778f69cc38835d27"
      hash15 = "2df4f0927f0f73ff7ca38a4edfe9406be229985fd5ae468d9b5aa19b9b0cd0ac"
      hash16 = "ba3e5e8af6d21e5fa3a78b69a87ca1cd39afd4342795f514bd651af81e9b8e47"
      hash17 = "3b38ac70eac888ba76ae3c5812179863a78b4e63ce92f5108f019bb00f96b35c"
      hash18 = "9c62abcac2762be0e5abbb7f06ffb65c0b8fbea84d015944b6593453354303eb"
      hash19 = "2e4b386aa820c4a1b294274d89652098e4a78921df83b1ed101213f558f704ea"
      hash20 = "beae2bc4274deb42c452e6ad910853cfa1a60e05f0180ed43829e2a4f5281e04"
      hash21 = "c8eb9182adc12b591cbdafe27759495487a53c0cd38f83f77f575edf21e5d4b3"
      hash22 = "a35d47fde5d36de866ba7fbe638c7ea9f5860962b326484936a992cbba6fa22f"
      hash23 = "72356978da0b156bae25c84189c01a47b7c8e8daf22e2be533f1e2733f8372f2"
      hash24 = "d274427049b5e28fdd153a0bdbcb08445ffebd9031ed666dba23b62e44b3191a"
      hash25 = "4c486b48b0524a9e3059f5dab86bffa9a0fa82787363c7784c624453344dc1d1"
      hash26 = "ea9d91772dd86455d5bf25c080ed859faae39c7085abb5de0b3142a397e7f131"
      hash27 = "3b1a32116390ef2a821cbeb15e214f937293ee39cfde2a2e97f2eb128474bce3"
      hash28 = "12a37426a995ef84e905c85a531c2754d10926dfdec03125074f83b738fe40af"
      hash29 = "6057eeaa384d6cefe9c0917ff848da11508bc0754714446465d508a3a232fbdb"
      hash30 = "1c6eeaf450250baad8b4bbdcb4539a5ec8ad9878d1ea4c96c493e01cca02f1d2"
      hash31 = "4a49d867bbb4e4e36b55c77f0f514fdf18a78b18b701ae853075092ac2893e2e"
      hash32 = "477ff70035e7438bbb414dcaf805d93a61dc39f75acf882134097fe3be105e48"
      hash33 = "02bd77bfd0a50ae5ea7e8a6587187e84b5c4d0d5638c7559abe609fbebbacd38"
   strings:
      $s1 = "Date: %3s, %02u %3s %04u %02u:%02u:%02u GMT" fullword ascii
      $s2 = "Switch Proxy" fullword ascii
      $s3 = "Unordered Collection" fullword ascii
      $s4 = "Blocked by Windows Parental Controls" fullword ascii
      $s5 = "Bandwidth Limit Exceeded" fullword ascii
      $s6 = "No Response" fullword ascii
      $s7 = "Retry With" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 27000KB and ( all of them )
      ) or ( all of them )
}

rule _match_838 {
   meta:
      description = "black - from files 86e319d1829ff562e623f18753e2e93f, c0c47b20d4a0acf33130efd241dcecb7, 9f4d9aaa17f43e35b68909cae6e2963e, 6638373439ec194078e3e6867a68e936, 0aa72cf7f23aeb9a055d869b1352ab05, b8c541161474bdb653f90b25c266bf32, 5d7241a98f223e091f32498665b4b205, e58365a2c5cebc3ef06e3e32c7921572, 2ca8a43dc76db43db4d7af35859a770f, 5d07e7441e45078f8cbcf62fcd6dae0a, 96d989641197f46942207b72fa661820, 416610b942ffaaf0b83b20b1591a1623, e90d08f6690a46b566c3381bebdc38af, 52f16c77af20982d5a0897b7e81beff8, 04c93df4e64d5b8421c28e103b7cba43, bed4c27f271c12d2b95f72ebb46a9c78, 66532a0adab204c8239633eb49d07ce1, b74d586186adaa3cc2fe40d495263c84, cd0bbad6af58ff1e1a6dd4406c7b7ec0, 8b171722624178254ba65819889b41f2, 15630701c421ca2fcfecfd91622a30b3, 07b636a8bf645b7c512be756a8b69fe2, 05ee0d9bb5b1789da51fb0c022b33268, 0e9a01b4b3cc55564426f0d296d62846, bcdf3c943e6aa549e8753c32ded15360, 573bb9ebe60a259c6e0a890a74fa5a9e, 1297fa863626ddc4c5f5d9f6c5e5cb2f"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "6d3962c8bb8b5cd8aa7c2ffb746ea7300f26ce413ef2e51c623ae264e6aa53b6"
      hash2 = "5f4a3d3b5b21106dc72cca87921dc2788b3c4b70935eeca58eadb63a3518063f"
      hash3 = "bb53f0db836794aaedc9bccdd044105dbaa19ccb3a8e4583b11a29d26b56ca7c"
      hash4 = "c2e3029089ee805aadddf739c0c3018e7a833760b98d26b25f45e88f15cb11b6"
      hash5 = "503a30682bed0e07f14dbaedbfa0ad56398923d31aeca6efbda85f649b2f4ecc"
      hash6 = "3a800217027270f563a4721ba7df9ec5e101aeca3f27997ebd634e71abfd634f"
      hash7 = "b2dabbc952e916996f8ab3e3b868be538e00cdd2095450a296338d37da1afbb2"
      hash8 = "f07f526f240e6f91fbe91cf6413d97d58086b4a2a30393b146d31980f9c52dd8"
      hash9 = "53cc5abba6e39f54eecb9c0e4f80bf0a3df71982b3614dbaac48325c223c24ca"
      hash10 = "2044f43871ea0b24f228f0a30760b9bdbef26056726dc918e0bc31d130a4fd28"
      hash11 = "1048876df466fc480e46db03dacf774a0df61df51d3efb2876426321c60fe8b8"
      hash12 = "d5001e36a8c10501ebc0b03d1ec750e7657e0e7f3524a11c18cfbd3b06b7d634"
      hash13 = "e85181b8b3ba26ff40b9258fefc5fb6e974cfb99474ad29f445d6275ca6f74cc"
      hash14 = "a0f204d460f124f0f59b78ac6cc5dfcb6b1ced2e142185ff194435ff4016a788"
      hash15 = "2f39eda2aac8f011cd62c859ca1ed11bee46176f9e960560e9bfdd72decf6e47"
      hash16 = "8a07303b7102324fa1a6258e1ff6e5680b2c2e0020e103f656e3a72ef3c6019e"
      hash17 = "cda8030bbabb0f8780de77912c63088d10c78b99bd5d4caadc27a3f8b8ec0a53"
      hash18 = "69de46a3d1262baa013ffd1f68c7eb5da4c988841335cf53278bd9a1087639cf"
      hash19 = "cf98b7c3daf69163ba7b2dd76538a0d9e19f63cb0d5d359ad529119d4f448d67"
      hash20 = "b9727e82fb6c723b18fb7a3906b5db97c0a0fc33e4808d10cb7329875973ea1a"
      hash21 = "a79e724b8b19334d676ac488569ca70f2737065495736b322c85f5edc8867f03"
      hash22 = "d8b1007592166e012ef7f1c709d35384481ded2c670add63edbb25f8d39c1a9f"
      hash23 = "62a098d7034672832209bc3495cf8a0a461542d816058dcc690009b2d2a44e85"
      hash24 = "6e2fd44944b0b6adf608d298aa78781bfc7bf9ab29c0644132eea183ff5e58d9"
      hash25 = "06e263554cbc8aad32eeedf2ca5374f5cde628312d5b61d61bdaaddc62c2e252"
      hash26 = "06c4fd2b55e3691fca7ceee681fb4858a7afcca05d9a2da86e9d9d4315294d9c"
      hash27 = "7b183d3b61275360f6715097e51be6bd47723899ae7d6d48085b766f01f2dee4"
   strings:
      $s1 = "L$D3L$" fullword ascii /* Goodware String - occured 1 times */
      $s2 = "T$T3D$" fullword ascii /* Goodware String - occured 2 times */
      $s3 = "T$d3D$" fullword ascii
      $s4 = "D$$3t$t3|$|j" fullword ascii
      $s5 = "FT;A$w{r" fullword ascii
      $s6 = "FP;A sq" fullword ascii
      $s7 = "|$$;|$$w" fullword ascii
      $s8 = "t$P3T$x3" fullword ascii
      $s9 = "L$ $02" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and ( all of them )
      ) or ( all of them )
}

rule _match_839 {
   meta:
      description = "black - from files 6b97eabf2e7eef8ccfc36593771ebe12, 4396f6981923a6e702a9d18a3d76e482, 0f9eddc5e740edcd96e2f32d6acc3bb3, 6cfc530100079ac1f1ed0cf61bed2ca8, acd5942fee24e5bc6769bb2fb529b695, 8a490aa2517646411b6ea1383f17bbd1, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 5f52a27f400818807d2693e1a52260ad, 5846aed02e23db1af696661606cf5bfd, 0086748f3a7854b3a35f69b5285c534f, e28e3404155556ecafff204356fcc5f0, 4d6dff8b2def91e85a09faa27899d9d5, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, 51f0f95501d456804707bd997c56b416, 2458b8fb100cb0d0c80a3f62aea0e080, 4451163751d9841553744a6f80ca0aed, fc481ae3e90d67283ce944cefb433d25, a3b4afa503657e7a327934ddd231887e, b3c0545d8bdbd5cd9c4c5cbd4d070d2a, b9280790ed58987ab2af68537ad18d6d, 80ba21786b71bb0dba959194fa1d3f63, b1b0580af0e8fa730486561255426f38, 13ce83c5c7ea01852b0ae2e35b74949b, 26fc98d7481f9b494ecbfebacdcbeab3, 63d152e378907ea71551baff27a82d7d, ae33c5c9544d63463cca74c42a556983, ee3f5f355249823f286f389ce0567002, 9a07ca40de9c85495231302023c6a74a, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 15c4fc341d735f9ea8427f918d3f5422, 86d7666073561a5d0ca494d80eae3e5e, e4c92dd63239428f0b33c7f424293687, 9b3518901fb21e67bfd3986cdcded31c, 99fe45ec1a50c0413a6dcb1d23b754f9, e97524afde7b751f6b024fa4798bdf51, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "d2b4b16be498e2fbe782b6f0e73515f6fc74c7a661c44891a9860cbf2b690d02"
      hash2 = "4fd49a0d1574549b4f8b64c9d474417600d6ede505c3997b3b07eb9e92bd440a"
      hash3 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash4 = "438784b7594602da1a92d67890953b527ef6cb045e0c64ccaa4e78448576fff5"
      hash5 = "0083066406394696a0e6f26928d71785bf9fcdecdd6dcf52731a93b78f2cca0c"
      hash6 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash7 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash8 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash9 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash10 = "5d1ef3f5bc06e457945af001cad5e392eea47ae4486522ad3342f42b6e2b7436"
      hash11 = "0693cfd2a09f5358cdec077df4cf049c88fe5fcdc606a228e389c9b2e517f965"
      hash12 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash13 = "dbc26374af31e9c81b8bc3a6c3063387f587a2596510e2a3be24aea6e025294f"
      hash14 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash15 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash16 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash17 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash18 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash19 = "a8efd58c2f819b96742b10bad9aa76494731295f32ccc9897d3694944017b2a4"
      hash20 = "ba3e5e8af6d21e5fa3a78b69a87ca1cd39afd4342795f514bd651af81e9b8e47"
      hash21 = "e90a53ae1c6318e25816e74530a4c3607e55cbadf3b7eb0d0ff97fb78d6a8d96"
      hash22 = "201b177ab0fe48289ac660b899b7813ed6f276a9ea1246574c28ebacb943905d"
      hash23 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash24 = "7bf303baebaec1c10be08273dd3d1ce503c4a7e1edaefc6092778b2926ebb278"
      hash25 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash26 = "2e4b386aa820c4a1b294274d89652098e4a78921df83b1ed101213f558f704ea"
      hash27 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash28 = "10fe50b5f6fbaad5498bdc524145e5e05719fccc308da6de5a7c30ce9c3cbba3"
      hash29 = "b95f40cce47499183ef95d6d56b8b5deed0d99a413a8bd7067200c5b1ae752a9"
      hash30 = "f275d2589f252cfd2a131a89429837de58c04322c5ced8986dfc968d37bb1d4f"
      hash31 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash32 = "ade656b212a4bef11d70720679ec7fd91586a9507448634cd716178ed908e509"
      hash33 = "ea9d91772dd86455d5bf25c080ed859faae39c7085abb5de0b3142a397e7f131"
      hash34 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash35 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash36 = "242b2e8bf86f40047ed0c60607f61f81fb144a641a394ab51f4b21f1511ddca8"
      hash37 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash38 = "c9d6e3fa0bf1bae569a87f1526093204b2b6bbc227e8ddcd2af450c4fb5c71c3"
      hash39 = "ee7ab7d8bd4643e2f2d63bc0329b21c6d3437beea13fc379ee7fbfc0e326d0f5"
      hash40 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash41 = "b81e7c41d4c6cec4c6f99f9e577c8335c685bf09351af664d82c2a97bc12b89c"
      hash42 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash43 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = "API3A@f" fullword ascii
      $s2 = "y I39I" fullword ascii
      $s3 = "API3A@fH" fullword ascii
      $s4 = "IXI3IHI" fullword ascii
      $s5 = "IXI3IHfH" fullword ascii
      $s6 = "@PI3@@f" fullword ascii
      $s7 = "BPH3B@f" fullword ascii
      $s8 = "BPH3B@fD" fullword ascii
      $s9 = "JXH3JHfL" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 25000KB and ( all of them )
      ) or ( all of them )
}

rule _match_925 {
   meta:
      description = "black - from files 4396f6981923a6e702a9d18a3d76e482, 0f9eddc5e740edcd96e2f32d6acc3bb3, 6cfc530100079ac1f1ed0cf61bed2ca8, acd5942fee24e5bc6769bb2fb529b695, 8a490aa2517646411b6ea1383f17bbd1, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 5f52a27f400818807d2693e1a52260ad, 0086748f3a7854b3a35f69b5285c534f, e28e3404155556ecafff204356fcc5f0, 4d6dff8b2def91e85a09faa27899d9d5, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, a3b4afa503657e7a327934ddd231887e, b3c0545d8bdbd5cd9c4c5cbd4d070d2a, b9280790ed58987ab2af68537ad18d6d, b1b0580af0e8fa730486561255426f38, ae33c5c9544d63463cca74c42a556983, ee3f5f355249823f286f389ce0567002, 9a07ca40de9c85495231302023c6a74a, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 86d7666073561a5d0ca494d80eae3e5e, 9b3518901fb21e67bfd3986cdcded31c, 99fe45ec1a50c0413a6dcb1d23b754f9, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "4fd49a0d1574549b4f8b64c9d474417600d6ede505c3997b3b07eb9e92bd440a"
      hash2 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash3 = "438784b7594602da1a92d67890953b527ef6cb045e0c64ccaa4e78448576fff5"
      hash4 = "0083066406394696a0e6f26928d71785bf9fcdecdd6dcf52731a93b78f2cca0c"
      hash5 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash6 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash7 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash8 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash9 = "0693cfd2a09f5358cdec077df4cf049c88fe5fcdc606a228e389c9b2e517f965"
      hash10 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash11 = "dbc26374af31e9c81b8bc3a6c3063387f587a2596510e2a3be24aea6e025294f"
      hash12 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash13 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash14 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash15 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash16 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash17 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash18 = "7bf303baebaec1c10be08273dd3d1ce503c4a7e1edaefc6092778b2926ebb278"
      hash19 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash20 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash21 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash22 = "ade656b212a4bef11d70720679ec7fd91586a9507448634cd716178ed908e509"
      hash23 = "ea9d91772dd86455d5bf25c080ed859faae39c7085abb5de0b3142a397e7f131"
      hash24 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash25 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash26 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash27 = "ee7ab7d8bd4643e2f2d63bc0329b21c6d3437beea13fc379ee7fbfc0e326d0f5"
      hash28 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash29 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash30 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = "k4+kP+" fullword ascii /* Goodware String - occured 1 times */
      $s2 = "<utT@:" fullword ascii
      $s3 = "<htl<jt\\<lt4<tt$<wt" fullword ascii
      $s4 = "<StW@:" fullword ascii
      $s5 = "k(+sPL" fullword ascii
      $s6 = "D<P0@:" fullword ascii
      $s7 = "#D8d$`t" fullword ascii
      $s8 = "s(+kPH" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and ( all of them )
      ) or ( all of them )
}

rule _match_948 {
   meta:
      description = "black - from files 0f9eddc5e740edcd96e2f32d6acc3bb3, 8a490aa2517646411b6ea1383f17bbd1, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 5f52a27f400818807d2693e1a52260ad, e28e3404155556ecafff204356fcc5f0, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, af408f884178b56843b9f7324bcdefb4, 51f0f95501d456804707bd997c56b416, a3b4afa503657e7a327934ddd231887e, b9280790ed58987ab2af68537ad18d6d, b1b0580af0e8fa730486561255426f38, 26fc98d7481f9b494ecbfebacdcbeab3, ae33c5c9544d63463cca74c42a556983, ee3f5f355249823f286f389ce0567002, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 86d7666073561a5d0ca494d80eae3e5e, 9b3518901fb21e67bfd3986cdcded31c, 99fe45ec1a50c0413a6dcb1d23b754f9, e97524afde7b751f6b024fa4798bdf51, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash2 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash3 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash4 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash5 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash6 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash7 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash8 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash9 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash10 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash11 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash12 = "c92d9638c8fb2b0556802ea87082be829f50dd7d29579a1a893ade35bd7a9256"
      hash13 = "a8efd58c2f819b96742b10bad9aa76494731295f32ccc9897d3694944017b2a4"
      hash14 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash15 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash16 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash17 = "b95f40cce47499183ef95d6d56b8b5deed0d99a413a8bd7067200c5b1ae752a9"
      hash18 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash19 = "ade656b212a4bef11d70720679ec7fd91586a9507448634cd716178ed908e509"
      hash20 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash21 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash22 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash23 = "ee7ab7d8bd4643e2f2d63bc0329b21c6d3437beea13fc379ee7fbfc0e326d0f5"
      hash24 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash25 = "b81e7c41d4c6cec4c6f99f9e577c8335c685bf09351af664d82c2a97bc12b89c"
      hash26 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash27 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = "hwloc auto configuration for algorithm \"%s\" failed." fullword ascii
      $s2 = "[1;35minit dataset%s" fullword ascii
      $s3 = "[1;30m seed %s..." fullword ascii
      $s4 = "[0m %sJIT" fullword ascii
      $s5 = "[1;32m+" fullword ascii
      $s6 = "[1;36m %zu MB" fullword ascii
      $s7 = "[1;37m%s (" fullword ascii
      $s8 = "[1;36m%u" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 25000KB and ( all of them )
      ) or ( all of them )
}



rule _match_952 {
   meta:
      description = "black - from files 0f9eddc5e740edcd96e2f32d6acc3bb3, 8a490aa2517646411b6ea1383f17bbd1, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 5f52a27f400818807d2693e1a52260ad, e28e3404155556ecafff204356fcc5f0, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, a3b4afa503657e7a327934ddd231887e, b1b0580af0e8fa730486561255426f38, ae33c5c9544d63463cca74c42a556983, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 86d7666073561a5d0ca494d80eae3e5e, 99fe45ec1a50c0413a6dcb1d23b754f9, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash2 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash3 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash4 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash5 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash6 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash7 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash8 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash9 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash10 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash11 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash12 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash13 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash14 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash15 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash16 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash17 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash18 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash19 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash20 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = "\\$|D9\\$L" fullword ascii
      $s2 = "L$ H1|$ " fullword ascii
      $s3 = "9Zhv=fff" fullword ascii
      $s4 = "L$pHcA" fullword ascii /* Goodware String - occured 4 times */
      $s5 = "|$`L;u t3I" fullword ascii
      $s6 = "|$XL;u t(I" fullword ascii
      $s7 = "L;u tA3" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 13000KB and ( all of them )
      ) or ( all of them )
}

rule _match_953 {
   meta:
      description = "black - from files 0f9eddc5e740edcd96e2f32d6acc3bb3, 8a490aa2517646411b6ea1383f17bbd1, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 5f52a27f400818807d2693e1a52260ad, e28e3404155556ecafff204356fcc5f0, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, af408f884178b56843b9f7324bcdefb4, 51f0f95501d456804707bd997c56b416, 4451163751d9841553744a6f80ca0aed, a3b4afa503657e7a327934ddd231887e, b9280790ed58987ab2af68537ad18d6d, b1b0580af0e8fa730486561255426f38, 13ce83c5c7ea01852b0ae2e35b74949b, 26fc98d7481f9b494ecbfebacdcbeab3, 63d152e378907ea71551baff27a82d7d, ae33c5c9544d63463cca74c42a556983, ee3f5f355249823f286f389ce0567002, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 15c4fc341d735f9ea8427f918d3f5422, 86d7666073561a5d0ca494d80eae3e5e, e4c92dd63239428f0b33c7f424293687, 9b3518901fb21e67bfd3986cdcded31c, 99fe45ec1a50c0413a6dcb1d23b754f9, e97524afde7b751f6b024fa4798bdf51, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash2 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash3 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash4 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash5 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash6 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash7 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash8 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash9 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash10 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash11 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash12 = "c92d9638c8fb2b0556802ea87082be829f50dd7d29579a1a893ade35bd7a9256"
      hash13 = "a8efd58c2f819b96742b10bad9aa76494731295f32ccc9897d3694944017b2a4"
      hash14 = "e90a53ae1c6318e25816e74530a4c3607e55cbadf3b7eb0d0ff97fb78d6a8d96"
      hash15 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash16 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash17 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash18 = "10fe50b5f6fbaad5498bdc524145e5e05719fccc308da6de5a7c30ce9c3cbba3"
      hash19 = "b95f40cce47499183ef95d6d56b8b5deed0d99a413a8bd7067200c5b1ae752a9"
      hash20 = "f275d2589f252cfd2a131a89429837de58c04322c5ced8986dfc968d37bb1d4f"
      hash21 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash22 = "ade656b212a4bef11d70720679ec7fd91586a9507448634cd716178ed908e509"
      hash23 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash24 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash25 = "242b2e8bf86f40047ed0c60607f61f81fb144a641a394ab51f4b21f1511ddca8"
      hash26 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash27 = "c9d6e3fa0bf1bae569a87f1526093204b2b6bbc227e8ddcd2af450c4fb5c71c3"
      hash28 = "ee7ab7d8bd4643e2f2d63bc0329b21c6d3437beea13fc379ee7fbfc0e326d0f5"
      hash29 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash30 = "b81e7c41d4c6cec4c6f99f9e577c8335c685bf09351af664d82c2a97bc12b89c"
      hash31 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash32 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = "[%s] error: " fullword ascii
      $s2 = "[1;37muse %s " fullword ascii
      $s3 = "[1;31m\"%s\"" fullword ascii
      $s4 = "[0;31m, code: %d" fullword ascii
      $s5 = "[1;33mpaused" fullword ascii
      $s6 = "[1;32mresumed" fullword ascii
      $s7 = "[0;31m\"%s\"" fullword ascii
      $s8 = "[1;30m%s" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 25000KB and ( all of them )
      ) or ( all of them )
}

rule _match_954 {
   meta:
      description = "black - from files 0f9eddc5e740edcd96e2f32d6acc3bb3, 6cfc530100079ac1f1ed0cf61bed2ca8, acd5942fee24e5bc6769bb2fb529b695, 8a490aa2517646411b6ea1383f17bbd1, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 5f52a27f400818807d2693e1a52260ad, 0086748f3a7854b3a35f69b5285c534f, e28e3404155556ecafff204356fcc5f0, 4d6dff8b2def91e85a09faa27899d9d5, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, af408f884178b56843b9f7324bcdefb4, 51f0f95501d456804707bd997c56b416, fc481ae3e90d67283ce944cefb433d25, a3b4afa503657e7a327934ddd231887e, b3c0545d8bdbd5cd9c4c5cbd4d070d2a, b9280790ed58987ab2af68537ad18d6d, b1b0580af0e8fa730486561255426f38, 26fc98d7481f9b494ecbfebacdcbeab3, ae33c5c9544d63463cca74c42a556983, ee3f5f355249823f286f389ce0567002, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 86d7666073561a5d0ca494d80eae3e5e, e4c92dd63239428f0b33c7f424293687, 9b3518901fb21e67bfd3986cdcded31c, 99fe45ec1a50c0413a6dcb1d23b754f9, e97524afde7b751f6b024fa4798bdf51, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash2 = "438784b7594602da1a92d67890953b527ef6cb045e0c64ccaa4e78448576fff5"
      hash3 = "0083066406394696a0e6f26928d71785bf9fcdecdd6dcf52731a93b78f2cca0c"
      hash4 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash5 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash6 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash7 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash8 = "0693cfd2a09f5358cdec077df4cf049c88fe5fcdc606a228e389c9b2e517f965"
      hash9 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash10 = "dbc26374af31e9c81b8bc3a6c3063387f587a2596510e2a3be24aea6e025294f"
      hash11 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash12 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash13 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash14 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash15 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash16 = "c92d9638c8fb2b0556802ea87082be829f50dd7d29579a1a893ade35bd7a9256"
      hash17 = "a8efd58c2f819b96742b10bad9aa76494731295f32ccc9897d3694944017b2a4"
      hash18 = "201b177ab0fe48289ac660b899b7813ed6f276a9ea1246574c28ebacb943905d"
      hash19 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash20 = "7bf303baebaec1c10be08273dd3d1ce503c4a7e1edaefc6092778b2926ebb278"
      hash21 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash22 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash23 = "b95f40cce47499183ef95d6d56b8b5deed0d99a413a8bd7067200c5b1ae752a9"
      hash24 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash25 = "ade656b212a4bef11d70720679ec7fd91586a9507448634cd716178ed908e509"
      hash26 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash27 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash28 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash29 = "c9d6e3fa0bf1bae569a87f1526093204b2b6bbc227e8ddcd2af450c4fb5c71c3"
      hash30 = "ee7ab7d8bd4643e2f2d63bc0329b21c6d3437beea13fc379ee7fbfc0e326d0f5"
      hash31 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash32 = "b81e7c41d4c6cec4c6f99f9e577c8335c685bf09351af664d82c2a97bc12b89c"
      hash33 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash34 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = "randomx-init" fullword ascii
      $s2 = "cryptonight_alloy" fullword ascii
      $s3 = "cryptonight/fast" fullword ascii
      $s4 = "cryptonight-monerov8" fullword ascii
      $s5 = "cryptonight-monerov7" fullword ascii
      $s6 = "cryptonight_r" fullword ascii
      $s7 = "randomx-no-numa" fullword ascii
      $s8 = "cn/fast" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 25000KB and ( all of them )
      ) or ( all of them )
}

rule _match_955 {
   meta:
      description = "black - from files 0f9eddc5e740edcd96e2f32d6acc3bb3, 6cfc530100079ac1f1ed0cf61bed2ca8, acd5942fee24e5bc6769bb2fb529b695, 8a490aa2517646411b6ea1383f17bbd1, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 5f52a27f400818807d2693e1a52260ad, 0086748f3a7854b3a35f69b5285c534f, e28e3404155556ecafff204356fcc5f0, 4d6dff8b2def91e85a09faa27899d9d5, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, af408f884178b56843b9f7324bcdefb4, 51f0f95501d456804707bd997c56b416, 4451163751d9841553744a6f80ca0aed, fc481ae3e90d67283ce944cefb433d25, a3b4afa503657e7a327934ddd231887e, b3c0545d8bdbd5cd9c4c5cbd4d070d2a, b9280790ed58987ab2af68537ad18d6d, b1b0580af0e8fa730486561255426f38, 13ce83c5c7ea01852b0ae2e35b74949b, 26fc98d7481f9b494ecbfebacdcbeab3, 63d152e378907ea71551baff27a82d7d, ae33c5c9544d63463cca74c42a556983, ee3f5f355249823f286f389ce0567002, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 15c4fc341d735f9ea8427f918d3f5422, 86d7666073561a5d0ca494d80eae3e5e, e4c92dd63239428f0b33c7f424293687, 9b3518901fb21e67bfd3986cdcded31c, 99fe45ec1a50c0413a6dcb1d23b754f9, e97524afde7b751f6b024fa4798bdf51, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash2 = "438784b7594602da1a92d67890953b527ef6cb045e0c64ccaa4e78448576fff5"
      hash3 = "0083066406394696a0e6f26928d71785bf9fcdecdd6dcf52731a93b78f2cca0c"
      hash4 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash5 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash6 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash7 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash8 = "0693cfd2a09f5358cdec077df4cf049c88fe5fcdc606a228e389c9b2e517f965"
      hash9 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash10 = "dbc26374af31e9c81b8bc3a6c3063387f587a2596510e2a3be24aea6e025294f"
      hash11 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash12 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash13 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash14 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash15 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash16 = "c92d9638c8fb2b0556802ea87082be829f50dd7d29579a1a893ade35bd7a9256"
      hash17 = "a8efd58c2f819b96742b10bad9aa76494731295f32ccc9897d3694944017b2a4"
      hash18 = "e90a53ae1c6318e25816e74530a4c3607e55cbadf3b7eb0d0ff97fb78d6a8d96"
      hash19 = "201b177ab0fe48289ac660b899b7813ed6f276a9ea1246574c28ebacb943905d"
      hash20 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash21 = "7bf303baebaec1c10be08273dd3d1ce503c4a7e1edaefc6092778b2926ebb278"
      hash22 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash23 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash24 = "10fe50b5f6fbaad5498bdc524145e5e05719fccc308da6de5a7c30ce9c3cbba3"
      hash25 = "b95f40cce47499183ef95d6d56b8b5deed0d99a413a8bd7067200c5b1ae752a9"
      hash26 = "f275d2589f252cfd2a131a89429837de58c04322c5ced8986dfc968d37bb1d4f"
      hash27 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash28 = "ade656b212a4bef11d70720679ec7fd91586a9507448634cd716178ed908e509"
      hash29 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash30 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash31 = "242b2e8bf86f40047ed0c60607f61f81fb144a641a394ab51f4b21f1511ddca8"
      hash32 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash33 = "c9d6e3fa0bf1bae569a87f1526093204b2b6bbc227e8ddcd2af450c4fb5c71c3"
      hash34 = "ee7ab7d8bd4643e2f2d63bc0329b21c6d3437beea13fc379ee7fbfc0e326d0f5"
      hash35 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash36 = "b81e7c41d4c6cec4c6f99f9e577c8335c685bf09351af664d82c2a97bc12b89c"
      hash37 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash38 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = "http-access-token" fullword ascii
      $s2 = "seed_hash" fullword ascii
      $s3 = "http-no-restricted" fullword ascii
      $s4 = "donate-over-proxy" fullword ascii
      $s5 = "http-enabled" fullword ascii
      $s6 = "daemon" fullword ascii /* Goodware String - occured 23 times */
      $s7 = "daemon-poll-interval" fullword ascii
      $s8 = "http-host" fullword ascii /* Goodware String - occured 2 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 25000KB and ( all of them )
      ) or ( all of them )
}

rule _match_956 {
   meta:
      description = "black - from files 0f9eddc5e740edcd96e2f32d6acc3bb3, 8a490aa2517646411b6ea1383f17bbd1, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 5f52a27f400818807d2693e1a52260ad, e28e3404155556ecafff204356fcc5f0, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, 51f0f95501d456804707bd997c56b416, a3b4afa503657e7a327934ddd231887e, b9280790ed58987ab2af68537ad18d6d, b1b0580af0e8fa730486561255426f38, 13ce83c5c7ea01852b0ae2e35b74949b, 26fc98d7481f9b494ecbfebacdcbeab3, ae33c5c9544d63463cca74c42a556983, ee3f5f355249823f286f389ce0567002, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 15c4fc341d735f9ea8427f918d3f5422, 86d7666073561a5d0ca494d80eae3e5e, 9b3518901fb21e67bfd3986cdcded31c, 99fe45ec1a50c0413a6dcb1d23b754f9, e97524afde7b751f6b024fa4798bdf51, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash2 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash3 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash4 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash5 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash6 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash7 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash8 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash9 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash10 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash11 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash12 = "a8efd58c2f819b96742b10bad9aa76494731295f32ccc9897d3694944017b2a4"
      hash13 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash14 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash15 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash16 = "10fe50b5f6fbaad5498bdc524145e5e05719fccc308da6de5a7c30ce9c3cbba3"
      hash17 = "b95f40cce47499183ef95d6d56b8b5deed0d99a413a8bd7067200c5b1ae752a9"
      hash18 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash19 = "ade656b212a4bef11d70720679ec7fd91586a9507448634cd716178ed908e509"
      hash20 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash21 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash22 = "242b2e8bf86f40047ed0c60607f61f81fb144a641a394ab51f4b21f1511ddca8"
      hash23 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash24 = "ee7ab7d8bd4643e2f2d63bc0329b21c6d3437beea13fc379ee7fbfc0e326d0f5"
      hash25 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash26 = "b81e7c41d4c6cec4c6f99f9e577c8335c685bf09351af664d82c2a97bc12b89c"
      hash27 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash28 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = "      --http-host=HOST          bind host for HTTP API (default: 127.0.0.1)" fullword ascii
      $s2 = "      --http-no-restricted      enable full remote access to HTTP API (only if access token set)" fullword ascii
      $s3 = "      --http-port=N             bind port for HTTP API" fullword ascii
      $s4 = "      --http-access-token=T     access token for HTTP API" fullword ascii
      $s5 = "      --api-worker-id=ID        custom worker-id for API" fullword ascii
      $s6 = "      --daemon                  use daemon RPC instead of pool for solo mining" fullword ascii
      $s7 = "      --daemon-poll-interval=N  daemon poll interval in milliseconds (default: 1000)" fullword ascii
      $s8 = "      --api-id=ID               custom instance ID for API" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 25000KB and ( all of them )
      ) or ( all of them )
}

rule _match_1021 {
   meta:
      description = "black - from files 905eeda0ddf717b45bb294b227e6d8ae, 6b97eabf2e7eef8ccfc36593771ebe12, 4396f6981923a6e702a9d18a3d76e482, 0f9eddc5e740edcd96e2f32d6acc3bb3, 6cfc530100079ac1f1ed0cf61bed2ca8, acd5942fee24e5bc6769bb2fb529b695, 8a490aa2517646411b6ea1383f17bbd1, de5e6b20d9d57a8c34b9dccb2588dbf2, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 5f52a27f400818807d2693e1a52260ad, 0086748f3a7854b3a35f69b5285c534f, e28e3404155556ecafff204356fcc5f0, 4d6dff8b2def91e85a09faa27899d9d5, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, 2458b8fb100cb0d0c80a3f62aea0e080, a3b4afa503657e7a327934ddd231887e, b3c0545d8bdbd5cd9c4c5cbd4d070d2a, b9280790ed58987ab2af68537ad18d6d, 80ba21786b71bb0dba959194fa1d3f63, b1b0580af0e8fa730486561255426f38, ae33c5c9544d63463cca74c42a556983, ee3f5f355249823f286f389ce0567002, 9a07ca40de9c85495231302023c6a74a, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 86d7666073561a5d0ca494d80eae3e5e, e4c92dd63239428f0b33c7f424293687, 9b3518901fb21e67bfd3986cdcded31c, 99fe45ec1a50c0413a6dcb1d23b754f9, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "a28878f5880b8a1c506258dd39b459cec616f79100afe006b4779525b8a937a3"
      hash2 = "d2b4b16be498e2fbe782b6f0e73515f6fc74c7a661c44891a9860cbf2b690d02"
      hash3 = "4fd49a0d1574549b4f8b64c9d474417600d6ede505c3997b3b07eb9e92bd440a"
      hash4 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash5 = "438784b7594602da1a92d67890953b527ef6cb045e0c64ccaa4e78448576fff5"
      hash6 = "0083066406394696a0e6f26928d71785bf9fcdecdd6dcf52731a93b78f2cca0c"
      hash7 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash8 = "a7a273fb3a56da7b4f75f958a02d4a7a7641e8ec3701d90b786fe9fad54b7eb3"
      hash9 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash10 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash11 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash12 = "0693cfd2a09f5358cdec077df4cf049c88fe5fcdc606a228e389c9b2e517f965"
      hash13 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash14 = "dbc26374af31e9c81b8bc3a6c3063387f587a2596510e2a3be24aea6e025294f"
      hash15 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash16 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash17 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash18 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash19 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash20 = "ba3e5e8af6d21e5fa3a78b69a87ca1cd39afd4342795f514bd651af81e9b8e47"
      hash21 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash22 = "7bf303baebaec1c10be08273dd3d1ce503c4a7e1edaefc6092778b2926ebb278"
      hash23 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash24 = "2e4b386aa820c4a1b294274d89652098e4a78921df83b1ed101213f558f704ea"
      hash25 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash26 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash27 = "ade656b212a4bef11d70720679ec7fd91586a9507448634cd716178ed908e509"
      hash28 = "ea9d91772dd86455d5bf25c080ed859faae39c7085abb5de0b3142a397e7f131"
      hash29 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash30 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash31 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash32 = "c9d6e3fa0bf1bae569a87f1526093204b2b6bbc227e8ddcd2af450c4fb5c71c3"
      hash33 = "ee7ab7d8bd4643e2f2d63bc0329b21c6d3437beea13fc379ee7fbfc0e326d0f5"
      hash34 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash35 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash36 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = "ue!T$(H!T$ " fullword ascii
      $s2 = "t'D8d$8t" fullword ascii
      $s3 = "L$&8\\$&t,8Y" fullword ascii
      $s4 = "T$ D)s" fullword ascii
      $s5 = "D!l$xA" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 21000KB and ( all of them )
      ) or ( all of them )
}

rule _match_1023 {
   meta:
      description = "black - from files 905eeda0ddf717b45bb294b227e6d8ae, 6b97eabf2e7eef8ccfc36593771ebe12, 4396f6981923a6e702a9d18a3d76e482, 0f9eddc5e740edcd96e2f32d6acc3bb3, 6cfc530100079ac1f1ed0cf61bed2ca8, acd5942fee24e5bc6769bb2fb529b695, 8a490aa2517646411b6ea1383f17bbd1, bab9ba3432d3255edc4f8e86f6ea6010, f957d3e479a07339edad73308c36e092, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 6a6858a0087de5ff6493aa76d105d6df, 5f52a27f400818807d2693e1a52260ad, 5846aed02e23db1af696661606cf5bfd, 0086748f3a7854b3a35f69b5285c534f, e0095ff4e8222e5caafe0aedce42f9d4, e28e3404155556ecafff204356fcc5f0, 4d6dff8b2def91e85a09faa27899d9d5, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, 3934d1adff337a3741fc308eb83daaba, 99bd2332ea3179db7a70a6e66d11e096, af408f884178b56843b9f7324bcdefb4, 0cf00d65acee7181d4679d2ad3da5301, 51f0f95501d456804707bd997c56b416, 2458b8fb100cb0d0c80a3f62aea0e080, 2b3e56a15d75e4aa0327ac55733353ca, 4451163751d9841553744a6f80ca0aed, a3b4afa503657e7a327934ddd231887e, b3c0545d8bdbd5cd9c4c5cbd4d070d2a, b9280790ed58987ab2af68537ad18d6d, 80ba21786b71bb0dba959194fa1d3f63, b1b0580af0e8fa730486561255426f38, 720c0967b97baeaadefdfff2d265a183, 13ce83c5c7ea01852b0ae2e35b74949b, 0304ecd571a157fbcd4723d455bb554b, be3781cfcf4d7b709449382184148803, 26fc98d7481f9b494ecbfebacdcbeab3, 63d152e378907ea71551baff27a82d7d, ae33c5c9544d63463cca74c42a556983, ee3f5f355249823f286f389ce0567002, 9a07ca40de9c85495231302023c6a74a, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 15c4fc341d735f9ea8427f918d3f5422, 9ad1d65187d0fb50941ff23676234c5d, 86d7666073561a5d0ca494d80eae3e5e, e4c92dd63239428f0b33c7f424293687, 9b3518901fb21e67bfd3986cdcded31c, 99fe45ec1a50c0413a6dcb1d23b754f9, e97524afde7b751f6b024fa4798bdf51, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "a28878f5880b8a1c506258dd39b459cec616f79100afe006b4779525b8a937a3"
      hash2 = "d2b4b16be498e2fbe782b6f0e73515f6fc74c7a661c44891a9860cbf2b690d02"
      hash3 = "4fd49a0d1574549b4f8b64c9d474417600d6ede505c3997b3b07eb9e92bd440a"
      hash4 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash5 = "438784b7594602da1a92d67890953b527ef6cb045e0c64ccaa4e78448576fff5"
      hash6 = "0083066406394696a0e6f26928d71785bf9fcdecdd6dcf52731a93b78f2cca0c"
      hash7 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash8 = "95319d0df797fdb6ceb91efe6883dbc0455c5cc1932d559b1db37454538801c7"
      hash9 = "3a3fcb2a72c7e88bb0a5e31240f73f6b401ea9f22416a65519cd0c699d665e94"
      hash10 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash11 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash12 = "632f7efefd5383c0a53b18bb6cb327296b1b0bea50ea89ec493a4064e9df5973"
      hash13 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash14 = "5d1ef3f5bc06e457945af001cad5e392eea47ae4486522ad3342f42b6e2b7436"
      hash15 = "0693cfd2a09f5358cdec077df4cf049c88fe5fcdc606a228e389c9b2e517f965"
      hash16 = "ac51683da9fbe47c0d65f00d85a8b9705c4ab01a66f43c4a872b8f5407516f2b"
      hash17 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash18 = "dbc26374af31e9c81b8bc3a6c3063387f587a2596510e2a3be24aea6e025294f"
      hash19 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash20 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash21 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash22 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash23 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash24 = "2fefce5634c8b6f9e334fd6b1c34b86f6cb8278dc07558034d1ead43d1467cbb"
      hash25 = "2e999f22d7fa0d018342d235067b5bb879b4505bb0e42156f816d38ae61cd3fe"
      hash26 = "c92d9638c8fb2b0556802ea87082be829f50dd7d29579a1a893ade35bd7a9256"
      hash27 = "a0e6799ed9cb59ac3aeab73f2c10015fbabbacc850b56148778f69cc38835d27"
      hash28 = "a8efd58c2f819b96742b10bad9aa76494731295f32ccc9897d3694944017b2a4"
      hash29 = "ba3e5e8af6d21e5fa3a78b69a87ca1cd39afd4342795f514bd651af81e9b8e47"
      hash30 = "7bdb3093778ff709bac2a5e5e22960ab93fce19da7fc8e79aed29105c8d45f61"
      hash31 = "e90a53ae1c6318e25816e74530a4c3607e55cbadf3b7eb0d0ff97fb78d6a8d96"
      hash32 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash33 = "7bf303baebaec1c10be08273dd3d1ce503c4a7e1edaefc6092778b2926ebb278"
      hash34 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash35 = "2e4b386aa820c4a1b294274d89652098e4a78921df83b1ed101213f558f704ea"
      hash36 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash37 = "a5da66d083a3a55342caab79f28aa97728682eebad7a9b8de88b0af92e9a7c28"
      hash38 = "10fe50b5f6fbaad5498bdc524145e5e05719fccc308da6de5a7c30ce9c3cbba3"
      hash39 = "02abeb1e769c65f180a39d46e4fb04f2282de9356b891f9734ce1ab86b5b183d"
      hash40 = "714ae3c335d8dd42c2db8fe655c433887a5e0ef1c5f49a267d91f523427b2b61"
      hash41 = "b95f40cce47499183ef95d6d56b8b5deed0d99a413a8bd7067200c5b1ae752a9"
      hash42 = "f275d2589f252cfd2a131a89429837de58c04322c5ced8986dfc968d37bb1d4f"
      hash43 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash44 = "ade656b212a4bef11d70720679ec7fd91586a9507448634cd716178ed908e509"
      hash45 = "ea9d91772dd86455d5bf25c080ed859faae39c7085abb5de0b3142a397e7f131"
      hash46 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash47 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash48 = "242b2e8bf86f40047ed0c60607f61f81fb144a641a394ab51f4b21f1511ddca8"
      hash49 = "6b5e1968ea97bcb10a53e2754d4f33c58bc1efed2ff1533d9bb3c346d8dfe318"
      hash50 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash51 = "c9d6e3fa0bf1bae569a87f1526093204b2b6bbc227e8ddcd2af450c4fb5c71c3"
      hash52 = "ee7ab7d8bd4643e2f2d63bc0329b21c6d3437beea13fc379ee7fbfc0e326d0f5"
      hash53 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash54 = "b81e7c41d4c6cec4c6f99f9e577c8335c685bf09351af664d82c2a97bc12b89c"
      hash55 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash56 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = "[1;37mCOMMANDS     " fullword ascii
      $s2 = "[1;37mause, " fullword ascii
      $s3 = "[1;37mesume" fullword ascii
      $s4 = "[1;36m%s/%s" fullword ascii
      $s5 = "[1;31m-" fullword ascii
      $s6 = "[1;37m%-13s" fullword ascii
      $s7 = "[1;32m" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 25000KB and ( all of them )
      ) or ( all of them )
}

rule _match_1027 {
   meta:
      description = "black - from files f6ae12377ac77bd2b27c5977a7a01f6e, b04996ef7a113bf1f00888c4549afa93, 478e84180c19dc6e3f8aa6e6ebb2c7d0, 4ef7a01ccf898a2a139112fc82dc6daa, f46e9d4d3a936d3b85f5bd7b57dc2a3f, d64b3c6bcfa051b4725f4e991dc69b2c, 2578ba1d40ae41f63401af64cfc96803, 3f915707b453bd1cb84172b243dfc4e9, a2bde96e2d58cbb462b119380229d7f1, f65c66a0018c3026eacc92dafde90a0c, d38ac75f463b0517666bc171a3857b02, 30eb70ff293c54191675850d488c8edf, 75d0d94f087a9e8db3c88cbb5a6a8581, 184a71bd3054df5debb180933daf2dc8, 2489fcdbc397f255d261314d0e8f6cec, 5f1cc00a759fbaf72f02e9a37e6facb3, 90ab577f39b0ac8507e040117936efc1, 7fcfc4a9bbf477fe3e60b3dc2973f2bd, 5bf5e758581dbe00659d7e33065b7995, 2da8b883993ad19ccc8d4037ba904146, 38dc5cda072ae24cbbc42951da82ca9e, daa493a267811288fa42e31a2bee5c03, fa7fe9e295f9f6c4fe68572077790c62, 9e7afd009e1fc67700825548ccfd5db6, 5e88545848b639cbcd20f0b91a6a9d6a, 9a03e726e17750485746d9b4221c3c43"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "d03177393a733bc582065ea4331b6f5143c30c8c080502990158022f5670656b"
      hash2 = "1c6878417802864542aaecf710f8d150bf86fc3c1e3efe125465ae7097e2a841"
      hash3 = "f5387d3900b664d91bb64e2fbd4cba6798ae4453110230cff8574235a4da2d57"
      hash4 = "d2546fc94b5e707620311d42ffb5d357cb0f4bb9232844d1443ce6bdca48695e"
      hash5 = "22b7e4063b65d0ff6d1123afab92486a63c4001ad20f46912098a2b8dd2765fd"
      hash6 = "0ba38581fffb9dc1e839698215a3d0cecec70617401eff3ff137f1a2c993555d"
      hash7 = "28faaf21893e7050f72f2ebc625c9b277838af082f8802334ac644ba2a7e3817"
      hash8 = "07ce5434b4351184ecfbceb07656bef9b9fd86ad24944383c11849936c86ef15"
      hash9 = "603772dc820d896156cfb6b5f3a063dcf5679f8498159da333eac75619811abc"
      hash10 = "3115857f4f3637f4caeff807bf060a875d75c67b551420f99e6800569ea1e375"
      hash11 = "76a579b7137df1875b1bcf0fe76842648d47b02c6355f6ad2bbeebe3b2874ba3"
      hash12 = "b4272b4c37af4ca5cdd6cd88d130cfbe543046ad18e03d6e17ab65db04da2325"
      hash13 = "0010dd78b832f3c63555286846ceec9f45218766ada59f366f08abcf6284549a"
      hash14 = "5b2d32a75fa7212d10ea6cbfc02a623ca4b3b824444fdf07220d468b00e50aeb"
      hash15 = "a980557bc3319653eb8a58ccfa9084a630a3c8c2db5cd65fb41d97689ea916ba"
      hash16 = "43c2f983cfdcae1f5f808b84c985bacbf5ed2eabed0ee3d91e61d86658f27909"
      hash17 = "0fb9d466e83cbab992088b5ee79db56f9c87bb2362abfe0568f5fc6388371ac3"
      hash18 = "7bccfe4068a5a9d531b262a48755485c2586932fa448f2b23098b21b92bb1252"
      hash19 = "ccf07834ff02e45f76ad2c0fc953ffd22c5064c717f32ff7343948ae14855c97"
      hash20 = "de6a1b84e4b0b00e322cb031c68209e3b2769b656dec8dd6d07c8848e6ae1552"
      hash21 = "cda1657bf6eee7c53253ea6d5391515a61058d8ba8076a31ef7dba33bf70db4c"
      hash22 = "6a9e5cbe50e96087d5b5fa480f3182911a5f1b549e27d3c3c3ec8406d2518d6b"
      hash23 = "e8a522970e58eb47433067c6a0f2044135a9248a614aea2ccfe148821fa7f024"
      hash24 = "9fe39e3c738da59a6fa83bf0998fe0419d0da51cb0796fe28f13bb73905fc582"
      hash25 = "3ff4ed2042ba6b6e5b949a88766e57033636873c8bd4d704ebec61a209528f86"
      hash26 = "6783fa21bdd16b94156b3855f3104f4d9e534ac806f7afa0b681b0e68127126d"
   strings:
      $s1 = "T$,3T$<" fullword ascii /* Goodware String - occured 1 times */
      $s2 = "T$43T$<" fullword ascii /* Goodware String - occured 1 times */
      $s3 = "T$(;D$$" fullword ascii /* Goodware String - occured 1 times */
      $s4 = ";D$$sY" fullword ascii
      $s5 = ";\\$$s(" fullword ascii
      $s6 = "FD;G$w[r" fullword ascii
      $s7 = "F@;G wQ" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and ( all of them )
      ) or ( all of them )
}

rule _match_1028 {
   meta:
      description = "black - from files f6ae12377ac77bd2b27c5977a7a01f6e, b04996ef7a113bf1f00888c4549afa93, 478e84180c19dc6e3f8aa6e6ebb2c7d0, 4ef7a01ccf898a2a139112fc82dc6daa, f46e9d4d3a936d3b85f5bd7b57dc2a3f, a746e73da04945445e385850616990c9, 2578ba1d40ae41f63401af64cfc96803, 3f915707b453bd1cb84172b243dfc4e9, a2bde96e2d58cbb462b119380229d7f1, f65c66a0018c3026eacc92dafde90a0c, d38ac75f463b0517666bc171a3857b02, 75d0d94f087a9e8db3c88cbb5a6a8581, 2489fcdbc397f255d261314d0e8f6cec, 5f1cc00a759fbaf72f02e9a37e6facb3, 90ab577f39b0ac8507e040117936efc1, 5bf5e758581dbe00659d7e33065b7995, 38dc5cda072ae24cbbc42951da82ca9e, a4d33f5f38e992c5e6d56865ff2ba1dc, fa7fe9e295f9f6c4fe68572077790c62, 9e7afd009e1fc67700825548ccfd5db6, 5e88545848b639cbcd20f0b91a6a9d6a"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "d03177393a733bc582065ea4331b6f5143c30c8c080502990158022f5670656b"
      hash2 = "1c6878417802864542aaecf710f8d150bf86fc3c1e3efe125465ae7097e2a841"
      hash3 = "f5387d3900b664d91bb64e2fbd4cba6798ae4453110230cff8574235a4da2d57"
      hash4 = "d2546fc94b5e707620311d42ffb5d357cb0f4bb9232844d1443ce6bdca48695e"
      hash5 = "22b7e4063b65d0ff6d1123afab92486a63c4001ad20f46912098a2b8dd2765fd"
      hash6 = "beae2bc4274deb42c452e6ad910853cfa1a60e05f0180ed43829e2a4f5281e04"
      hash7 = "28faaf21893e7050f72f2ebc625c9b277838af082f8802334ac644ba2a7e3817"
      hash8 = "07ce5434b4351184ecfbceb07656bef9b9fd86ad24944383c11849936c86ef15"
      hash9 = "603772dc820d896156cfb6b5f3a063dcf5679f8498159da333eac75619811abc"
      hash10 = "3115857f4f3637f4caeff807bf060a875d75c67b551420f99e6800569ea1e375"
      hash11 = "76a579b7137df1875b1bcf0fe76842648d47b02c6355f6ad2bbeebe3b2874ba3"
      hash12 = "0010dd78b832f3c63555286846ceec9f45218766ada59f366f08abcf6284549a"
      hash13 = "a980557bc3319653eb8a58ccfa9084a630a3c8c2db5cd65fb41d97689ea916ba"
      hash14 = "43c2f983cfdcae1f5f808b84c985bacbf5ed2eabed0ee3d91e61d86658f27909"
      hash15 = "0fb9d466e83cbab992088b5ee79db56f9c87bb2362abfe0568f5fc6388371ac3"
      hash16 = "ccf07834ff02e45f76ad2c0fc953ffd22c5064c717f32ff7343948ae14855c97"
      hash17 = "cda1657bf6eee7c53253ea6d5391515a61058d8ba8076a31ef7dba33bf70db4c"
      hash18 = "0e1b04257292042084e66b6497e1a2411a81d497dabcee84e238da35e9472b50"
      hash19 = "e8a522970e58eb47433067c6a0f2044135a9248a614aea2ccfe148821fa7f024"
      hash20 = "9fe39e3c738da59a6fa83bf0998fe0419d0da51cb0796fe28f13bb73905fc582"
      hash21 = "3ff4ed2042ba6b6e5b949a88766e57033636873c8bd4d704ebec61a209528f86"
   strings:
      $s1 = "G,_^][" fullword ascii /* Goodware String - occured 4 times */
      $s2 = "@tG9{<u" fullword ascii
      $s3 = "@tG9{8u" fullword ascii
      $s4 = "C89{Du" fullword ascii
      $s5 = "C<9{Hu" fullword ascii
      $s6 = "C49{@u" fullword ascii
      $s7 = "@tG9{4u" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 5000KB and ( all of them )
      ) or ( all of them )
}

rule _match_1033 {
   meta:
      description = "black - from files 4396f6981923a6e702a9d18a3d76e482, 0f9eddc5e740edcd96e2f32d6acc3bb3, 6cfc530100079ac1f1ed0cf61bed2ca8, acd5942fee24e5bc6769bb2fb529b695, 8a490aa2517646411b6ea1383f17bbd1, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 5f52a27f400818807d2693e1a52260ad, 5846aed02e23db1af696661606cf5bfd, 0086748f3a7854b3a35f69b5285c534f, e28e3404155556ecafff204356fcc5f0, 4d6dff8b2def91e85a09faa27899d9d5, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, 51f0f95501d456804707bd997c56b416, 4451163751d9841553744a6f80ca0aed, fc481ae3e90d67283ce944cefb433d25, a3b4afa503657e7a327934ddd231887e, b3c0545d8bdbd5cd9c4c5cbd4d070d2a, b9280790ed58987ab2af68537ad18d6d, b1b0580af0e8fa730486561255426f38, 13ce83c5c7ea01852b0ae2e35b74949b, 26fc98d7481f9b494ecbfebacdcbeab3, 63d152e378907ea71551baff27a82d7d, ae33c5c9544d63463cca74c42a556983, ee3f5f355249823f286f389ce0567002, 9a07ca40de9c85495231302023c6a74a, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 15c4fc341d735f9ea8427f918d3f5422, 86d7666073561a5d0ca494d80eae3e5e, e4c92dd63239428f0b33c7f424293687, 9b3518901fb21e67bfd3986cdcded31c, 99fe45ec1a50c0413a6dcb1d23b754f9, e97524afde7b751f6b024fa4798bdf51, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "4fd49a0d1574549b4f8b64c9d474417600d6ede505c3997b3b07eb9e92bd440a"
      hash2 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash3 = "438784b7594602da1a92d67890953b527ef6cb045e0c64ccaa4e78448576fff5"
      hash4 = "0083066406394696a0e6f26928d71785bf9fcdecdd6dcf52731a93b78f2cca0c"
      hash5 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash6 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash7 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash8 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash9 = "5d1ef3f5bc06e457945af001cad5e392eea47ae4486522ad3342f42b6e2b7436"
      hash10 = "0693cfd2a09f5358cdec077df4cf049c88fe5fcdc606a228e389c9b2e517f965"
      hash11 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash12 = "dbc26374af31e9c81b8bc3a6c3063387f587a2596510e2a3be24aea6e025294f"
      hash13 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash14 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash15 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash16 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash17 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash18 = "a8efd58c2f819b96742b10bad9aa76494731295f32ccc9897d3694944017b2a4"
      hash19 = "e90a53ae1c6318e25816e74530a4c3607e55cbadf3b7eb0d0ff97fb78d6a8d96"
      hash20 = "201b177ab0fe48289ac660b899b7813ed6f276a9ea1246574c28ebacb943905d"
      hash21 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash22 = "7bf303baebaec1c10be08273dd3d1ce503c4a7e1edaefc6092778b2926ebb278"
      hash23 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash24 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash25 = "10fe50b5f6fbaad5498bdc524145e5e05719fccc308da6de5a7c30ce9c3cbba3"
      hash26 = "b95f40cce47499183ef95d6d56b8b5deed0d99a413a8bd7067200c5b1ae752a9"
      hash27 = "f275d2589f252cfd2a131a89429837de58c04322c5ced8986dfc968d37bb1d4f"
      hash28 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash29 = "ade656b212a4bef11d70720679ec7fd91586a9507448634cd716178ed908e509"
      hash30 = "ea9d91772dd86455d5bf25c080ed859faae39c7085abb5de0b3142a397e7f131"
      hash31 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash32 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash33 = "242b2e8bf86f40047ed0c60607f61f81fb144a641a394ab51f4b21f1511ddca8"
      hash34 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash35 = "c9d6e3fa0bf1bae569a87f1526093204b2b6bbc227e8ddcd2af450c4fb5c71c3"
      hash36 = "ee7ab7d8bd4643e2f2d63bc0329b21c6d3437beea13fc379ee7fbfc0e326d0f5"
      hash37 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash38 = "b81e7c41d4c6cec4c6f99f9e577c8335c685bf09351af664d82c2a97bc12b89c"
      hash39 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash40 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = "t$ ARASATAUAVAWWH" fullword ascii
      $s2 = "z L3:fH" fullword ascii
      $s3 = "@PI3@@" fullword ascii
      $s4 = "HXI3HHL" fullword ascii
      $s5 = "@_A_A^A]A\\A[AZ" fullword ascii
      $s6 = ")t$0fI" fullword ascii
      $s7 = "bXL3bHfH" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 25000KB and ( all of them )
      ) or ( all of them )
}

rule _match_1055 {
   meta:
      description = "black - from files 20addcaa91c6bc5c7cc665ddb2e8c52c, 97ee5c92d5c865ef6db67c35bc8a427a, d220d7b9023e6bd3717edc17765fbb25, eafa15f8a4e79523f4f6288519e2d60a, 0f4acbb2acfaa97b146f4949729d0ec6, 09b0bb70c4456e39cb26cdf2667b2be7, cd7e6a6f2e3fc3cb1049efbbf235577f, f8a8bd5eb3b9328c007438070e0c3ca8, 0742b7c20e14fc0b9390fd5aafef6442, a746e73da04945445e385850616990c9, 6a80142ac8cf4d5534d2eb9cb0e3e08d, b1a919e6fb009361b64d51b351a25e4c, 936c8489a348fbdb03c66bbf46c60d7e, 3ba79ba35b4b388fe9699e51d4c43fea, df180313543e2a1a9c31ae49a0fb16be, e74a8e9fbf1969888d78bfe6bf757759, a79c869cbd44bdfa9860a858facd982e, 9f8125060a075a7c7b3e8b13d630bcf9, 0cccafcbc4d1a6d50ccd8fa1df89bc0f, a4d33f5f38e992c5e6d56865ff2ba1dc, e2ab3fc59ad63fee82456d2e42b23d2c"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "c2389593cb340e9b682e457e6bf926abf1eee594d129c237f3f87852731dba7d"
      hash2 = "e91e3d9138b2961bf0807b39ab1c0647e78ccf6985890246db1d698af498e43b"
      hash3 = "8d887ba624e0e8f55be8deb805ec25c1a2a34e6fa137b6bc30025cfbc124dfb8"
      hash4 = "7d2a58520ab1dea0d33c5866fdfbb8ccfb5a446f200c6d4c064d14ff90cdf76c"
      hash5 = "4c9bf0426483d1f8f7943cb291345134964d237f1b8270f88f51cbdd1557a41e"
      hash6 = "bc2a8aa09df1303d24917145a3b41acf1b9df09c72e65273883c63b288623e2b"
      hash7 = "08e6eb5d64f01d4a982bf75e4ffbec7d0f61d7ece7b7fbfe2fade7ae39ad8884"
      hash8 = "2df4f0927f0f73ff7ca38a4edfe9406be229985fd5ae468d9b5aa19b9b0cd0ac"
      hash9 = "3b38ac70eac888ba76ae3c5812179863a78b4e63ce92f5108f019bb00f96b35c"
      hash10 = "beae2bc4274deb42c452e6ad910853cfa1a60e05f0180ed43829e2a4f5281e04"
      hash11 = "c8eb9182adc12b591cbdafe27759495487a53c0cd38f83f77f575edf21e5d4b3"
      hash12 = "72356978da0b156bae25c84189c01a47b7c8e8daf22e2be533f1e2733f8372f2"
      hash13 = "b29176abdf91577a1267f00ad74137289898c4edd08ec4e27556f439a3d406e8"
      hash14 = "d274427049b5e28fdd153a0bdbcb08445ffebd9031ed666dba23b62e44b3191a"
      hash15 = "a7799d88b5ae3a611ca45939dbd479766fd4a3dd86e622bf95ef1189afc59f13"
      hash16 = "4c486b48b0524a9e3059f5dab86bffa9a0fa82787363c7784c624453344dc1d1"
      hash17 = "58fc973c2df43431d85dd6713461e818376109c4b8f681cf9775768d45e18bf1"
      hash18 = "a2cce624ed3e428075dedc5b4243c065baafe0a121de26d686756e487e4d7232"
      hash19 = "4a49d867bbb4e4e36b55c77f0f514fdf18a78b18b701ae853075092ac2893e2e"
      hash20 = "0e1b04257292042084e66b6497e1a2411a81d497dabcee84e238da35e9472b50"
      hash21 = "5fc5a50b6becf57bcc7e47f6dcbbe2efa2ce15f43739f230f889b69e642619a9"
   strings:
      $s1 = "[22;36m%s %s " fullword ascii
      $s2 = "[01;35mnew job" fullword ascii
      $s3 = "[01;36m%s H/s" fullword ascii
      $s4 = "[01;37mspeed" fullword ascii
      $s5 = "[01;36m%s " fullword ascii
      $s6 = "[01;36mH/s" fullword ascii
      $s7 = "[0m 2.5s/60s/15m " fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 27000KB and ( all of them )
      ) or ( all of them )
}

rule _match_1061 {
   meta:
      description = "black - from files 97ee5c92d5c865ef6db67c35bc8a427a, d220d7b9023e6bd3717edc17765fbb25, 0f4acbb2acfaa97b146f4949729d0ec6, 5846aed02e23db1af696661606cf5bfd, cd7e6a6f2e3fc3cb1049efbbf235577f, 3934d1adff337a3741fc308eb83daaba, 99bd2332ea3179db7a70a6e66d11e096, 0cf00d65acee7181d4679d2ad3da5301, f8a8bd5eb3b9328c007438070e0c3ca8, 2458b8fb100cb0d0c80a3f62aea0e080, 0742b7c20e14fc0b9390fd5aafef6442, 6a80142ac8cf4d5534d2eb9cb0e3e08d, ddafbf9406cc26df63a32702126e3fc9, b1a919e6fb009361b64d51b351a25e4c, 3ba79ba35b4b388fe9699e51d4c43fea, c2f7a2599c9dea0e04d9d20a4eb2c0f0, e88d37df942ac9ab1432c686ef346a6c, fa52279e88d5510ea6c4eaec3b100c00, e74a8e9fbf1969888d78bfe6bf757759, 47a32262fbe86e120fd5d69e295b9fc3"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "e91e3d9138b2961bf0807b39ab1c0647e78ccf6985890246db1d698af498e43b"
      hash2 = "8d887ba624e0e8f55be8deb805ec25c1a2a34e6fa137b6bc30025cfbc124dfb8"
      hash3 = "4c9bf0426483d1f8f7943cb291345134964d237f1b8270f88f51cbdd1557a41e"
      hash4 = "5d1ef3f5bc06e457945af001cad5e392eea47ae4486522ad3342f42b6e2b7436"
      hash5 = "08e6eb5d64f01d4a982bf75e4ffbec7d0f61d7ece7b7fbfe2fade7ae39ad8884"
      hash6 = "2fefce5634c8b6f9e334fd6b1c34b86f6cb8278dc07558034d1ead43d1467cbb"
      hash7 = "2e999f22d7fa0d018342d235067b5bb879b4505bb0e42156f816d38ae61cd3fe"
      hash8 = "a0e6799ed9cb59ac3aeab73f2c10015fbabbacc850b56148778f69cc38835d27"
      hash9 = "2df4f0927f0f73ff7ca38a4edfe9406be229985fd5ae468d9b5aa19b9b0cd0ac"
      hash10 = "ba3e5e8af6d21e5fa3a78b69a87ca1cd39afd4342795f514bd651af81e9b8e47"
      hash11 = "3b38ac70eac888ba76ae3c5812179863a78b4e63ce92f5108f019bb00f96b35c"
      hash12 = "c8eb9182adc12b591cbdafe27759495487a53c0cd38f83f77f575edf21e5d4b3"
      hash13 = "a35d47fde5d36de866ba7fbe638c7ea9f5860962b326484936a992cbba6fa22f"
      hash14 = "72356978da0b156bae25c84189c01a47b7c8e8daf22e2be533f1e2733f8372f2"
      hash15 = "d274427049b5e28fdd153a0bdbcb08445ffebd9031ed666dba23b62e44b3191a"
      hash16 = "6c9ad0cbcb8156f327526451c3452837d5256283239a77f931b1a3f542e61b82"
      hash17 = "9741357a1d61e8777cbb9234b46369df7752b9950f069fef7154a8ce748619e3"
      hash18 = "be1c04b7dc32a549668dc96f6f14c1e70f552f119864a0e467418455ec6f62a5"
      hash19 = "4c486b48b0524a9e3059f5dab86bffa9a0fa82787363c7784c624453344dc1d1"
      hash20 = "1b435cd0e002358d4ca191463d0fb54ea1136b53b74de8db93d61f935203392e"
   strings:
      $s1 = "MHD_is_feature_supported" fullword ascii
      $s2 = "MHD_resume_connection" fullword ascii
      $s3 = "MHD_suspend_connection" fullword ascii
      $s4 = "MHD_get_fdset2" fullword ascii
      $s5 = "MHD_set_response_options" fullword ascii
      $s6 = "MHD_create_response_from_fd64" fullword ascii
      $s7 = "MHD_create_response_from_fd_at_offset64" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 27000KB and ( all of them )
      ) or ( all of them )
}

rule _match_1105 {
   meta:
      description = "black - from files 905eeda0ddf717b45bb294b227e6d8ae, 6b97eabf2e7eef8ccfc36593771ebe12, 4396f6981923a6e702a9d18a3d76e482, 0f9eddc5e740edcd96e2f32d6acc3bb3, 6cfc530100079ac1f1ed0cf61bed2ca8, acd5942fee24e5bc6769bb2fb529b695, 8a490aa2517646411b6ea1383f17bbd1, bab9ba3432d3255edc4f8e86f6ea6010, f957d3e479a07339edad73308c36e092, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 6a6858a0087de5ff6493aa76d105d6df, 5f52a27f400818807d2693e1a52260ad, 5846aed02e23db1af696661606cf5bfd, 0086748f3a7854b3a35f69b5285c534f, e0095ff4e8222e5caafe0aedce42f9d4, e28e3404155556ecafff204356fcc5f0, 4d6dff8b2def91e85a09faa27899d9d5, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, 3934d1adff337a3741fc308eb83daaba, 99bd2332ea3179db7a70a6e66d11e096, af408f884178b56843b9f7324bcdefb4, 0cf00d65acee7181d4679d2ad3da5301, 51f0f95501d456804707bd997c56b416, 2458b8fb100cb0d0c80a3f62aea0e080, 2b3e56a15d75e4aa0327ac55733353ca, 4451163751d9841553744a6f80ca0aed, fc481ae3e90d67283ce944cefb433d25, a3b4afa503657e7a327934ddd231887e, b3c0545d8bdbd5cd9c4c5cbd4d070d2a, b9280790ed58987ab2af68537ad18d6d, 80ba21786b71bb0dba959194fa1d3f63, b1b0580af0e8fa730486561255426f38, 720c0967b97baeaadefdfff2d265a183, 13ce83c5c7ea01852b0ae2e35b74949b, 0304ecd571a157fbcd4723d455bb554b, be3781cfcf4d7b709449382184148803, 26fc98d7481f9b494ecbfebacdcbeab3, 63d152e378907ea71551baff27a82d7d, ae33c5c9544d63463cca74c42a556983, ee3f5f355249823f286f389ce0567002, 9a07ca40de9c85495231302023c6a74a, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 15c4fc341d735f9ea8427f918d3f5422, 9ad1d65187d0fb50941ff23676234c5d, 86d7666073561a5d0ca494d80eae3e5e, e4c92dd63239428f0b33c7f424293687, 9b3518901fb21e67bfd3986cdcded31c, 99fe45ec1a50c0413a6dcb1d23b754f9, e97524afde7b751f6b024fa4798bdf51, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "a28878f5880b8a1c506258dd39b459cec616f79100afe006b4779525b8a937a3"
      hash2 = "d2b4b16be498e2fbe782b6f0e73515f6fc74c7a661c44891a9860cbf2b690d02"
      hash3 = "4fd49a0d1574549b4f8b64c9d474417600d6ede505c3997b3b07eb9e92bd440a"
      hash4 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash5 = "438784b7594602da1a92d67890953b527ef6cb045e0c64ccaa4e78448576fff5"
      hash6 = "0083066406394696a0e6f26928d71785bf9fcdecdd6dcf52731a93b78f2cca0c"
      hash7 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash8 = "95319d0df797fdb6ceb91efe6883dbc0455c5cc1932d559b1db37454538801c7"
      hash9 = "3a3fcb2a72c7e88bb0a5e31240f73f6b401ea9f22416a65519cd0c699d665e94"
      hash10 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash11 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash12 = "632f7efefd5383c0a53b18bb6cb327296b1b0bea50ea89ec493a4064e9df5973"
      hash13 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash14 = "5d1ef3f5bc06e457945af001cad5e392eea47ae4486522ad3342f42b6e2b7436"
      hash15 = "0693cfd2a09f5358cdec077df4cf049c88fe5fcdc606a228e389c9b2e517f965"
      hash16 = "ac51683da9fbe47c0d65f00d85a8b9705c4ab01a66f43c4a872b8f5407516f2b"
      hash17 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash18 = "dbc26374af31e9c81b8bc3a6c3063387f587a2596510e2a3be24aea6e025294f"
      hash19 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash20 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash21 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash22 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash23 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash24 = "2fefce5634c8b6f9e334fd6b1c34b86f6cb8278dc07558034d1ead43d1467cbb"
      hash25 = "2e999f22d7fa0d018342d235067b5bb879b4505bb0e42156f816d38ae61cd3fe"
      hash26 = "c92d9638c8fb2b0556802ea87082be829f50dd7d29579a1a893ade35bd7a9256"
      hash27 = "a0e6799ed9cb59ac3aeab73f2c10015fbabbacc850b56148778f69cc38835d27"
      hash28 = "a8efd58c2f819b96742b10bad9aa76494731295f32ccc9897d3694944017b2a4"
      hash29 = "ba3e5e8af6d21e5fa3a78b69a87ca1cd39afd4342795f514bd651af81e9b8e47"
      hash30 = "7bdb3093778ff709bac2a5e5e22960ab93fce19da7fc8e79aed29105c8d45f61"
      hash31 = "e90a53ae1c6318e25816e74530a4c3607e55cbadf3b7eb0d0ff97fb78d6a8d96"
      hash32 = "201b177ab0fe48289ac660b899b7813ed6f276a9ea1246574c28ebacb943905d"
      hash33 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash34 = "7bf303baebaec1c10be08273dd3d1ce503c4a7e1edaefc6092778b2926ebb278"
      hash35 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash36 = "2e4b386aa820c4a1b294274d89652098e4a78921df83b1ed101213f558f704ea"
      hash37 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash38 = "a5da66d083a3a55342caab79f28aa97728682eebad7a9b8de88b0af92e9a7c28"
      hash39 = "10fe50b5f6fbaad5498bdc524145e5e05719fccc308da6de5a7c30ce9c3cbba3"
      hash40 = "02abeb1e769c65f180a39d46e4fb04f2282de9356b891f9734ce1ab86b5b183d"
      hash41 = "714ae3c335d8dd42c2db8fe655c433887a5e0ef1c5f49a267d91f523427b2b61"
      hash42 = "b95f40cce47499183ef95d6d56b8b5deed0d99a413a8bd7067200c5b1ae752a9"
      hash43 = "f275d2589f252cfd2a131a89429837de58c04322c5ced8986dfc968d37bb1d4f"
      hash44 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash45 = "ade656b212a4bef11d70720679ec7fd91586a9507448634cd716178ed908e509"
      hash46 = "ea9d91772dd86455d5bf25c080ed859faae39c7085abb5de0b3142a397e7f131"
      hash47 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash48 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash49 = "242b2e8bf86f40047ed0c60607f61f81fb144a641a394ab51f4b21f1511ddca8"
      hash50 = "6b5e1968ea97bcb10a53e2754d4f33c58bc1efed2ff1533d9bb3c346d8dfe318"
      hash51 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash52 = "c9d6e3fa0bf1bae569a87f1526093204b2b6bbc227e8ddcd2af450c4fb5c71c3"
      hash53 = "ee7ab7d8bd4643e2f2d63bc0329b21c6d3437beea13fc379ee7fbfc0e326d0f5"
      hash54 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash55 = "b81e7c41d4c6cec4c6f99f9e577c8335c685bf09351af664d82c2a97bc12b89c"
      hash56 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash57 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = "[1;32m * " fullword ascii
      $s2 = "[0;31m" fullword ascii
      $s3 = "[1;30m" fullword ascii
      $s4 = "[1;37m%s" fullword ascii
      $s5 = "[0;33m" fullword ascii
      $s6 = "[1;37m" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 25000KB and ( all of them )
      ) or ( all of them )
}

rule _match_1107 {
   meta:
      description = "black - from files 6b97eabf2e7eef8ccfc36593771ebe12, 4396f6981923a6e702a9d18a3d76e482, 0f9eddc5e740edcd96e2f32d6acc3bb3, 6cfc530100079ac1f1ed0cf61bed2ca8, acd5942fee24e5bc6769bb2fb529b695, 8a490aa2517646411b6ea1383f17bbd1, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 5f52a27f400818807d2693e1a52260ad, 5846aed02e23db1af696661606cf5bfd, 0086748f3a7854b3a35f69b5285c534f, e28e3404155556ecafff204356fcc5f0, 4d6dff8b2def91e85a09faa27899d9d5, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, 51f0f95501d456804707bd997c56b416, 2458b8fb100cb0d0c80a3f62aea0e080, 4451163751d9841553744a6f80ca0aed, a3b4afa503657e7a327934ddd231887e, b3c0545d8bdbd5cd9c4c5cbd4d070d2a, b9280790ed58987ab2af68537ad18d6d, 80ba21786b71bb0dba959194fa1d3f63, b1b0580af0e8fa730486561255426f38, 13ce83c5c7ea01852b0ae2e35b74949b, 26fc98d7481f9b494ecbfebacdcbeab3, 63d152e378907ea71551baff27a82d7d, ae33c5c9544d63463cca74c42a556983, ee3f5f355249823f286f389ce0567002, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 15c4fc341d735f9ea8427f918d3f5422, 86d7666073561a5d0ca494d80eae3e5e, e4c92dd63239428f0b33c7f424293687, 9b3518901fb21e67bfd3986cdcded31c, 99fe45ec1a50c0413a6dcb1d23b754f9, e97524afde7b751f6b024fa4798bdf51, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "d2b4b16be498e2fbe782b6f0e73515f6fc74c7a661c44891a9860cbf2b690d02"
      hash2 = "4fd49a0d1574549b4f8b64c9d474417600d6ede505c3997b3b07eb9e92bd440a"
      hash3 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash4 = "438784b7594602da1a92d67890953b527ef6cb045e0c64ccaa4e78448576fff5"
      hash5 = "0083066406394696a0e6f26928d71785bf9fcdecdd6dcf52731a93b78f2cca0c"
      hash6 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash7 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash8 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash9 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash10 = "5d1ef3f5bc06e457945af001cad5e392eea47ae4486522ad3342f42b6e2b7436"
      hash11 = "0693cfd2a09f5358cdec077df4cf049c88fe5fcdc606a228e389c9b2e517f965"
      hash12 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash13 = "dbc26374af31e9c81b8bc3a6c3063387f587a2596510e2a3be24aea6e025294f"
      hash14 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash15 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash16 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash17 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash18 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash19 = "a8efd58c2f819b96742b10bad9aa76494731295f32ccc9897d3694944017b2a4"
      hash20 = "ba3e5e8af6d21e5fa3a78b69a87ca1cd39afd4342795f514bd651af81e9b8e47"
      hash21 = "e90a53ae1c6318e25816e74530a4c3607e55cbadf3b7eb0d0ff97fb78d6a8d96"
      hash22 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash23 = "7bf303baebaec1c10be08273dd3d1ce503c4a7e1edaefc6092778b2926ebb278"
      hash24 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash25 = "2e4b386aa820c4a1b294274d89652098e4a78921df83b1ed101213f558f704ea"
      hash26 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash27 = "10fe50b5f6fbaad5498bdc524145e5e05719fccc308da6de5a7c30ce9c3cbba3"
      hash28 = "b95f40cce47499183ef95d6d56b8b5deed0d99a413a8bd7067200c5b1ae752a9"
      hash29 = "f275d2589f252cfd2a131a89429837de58c04322c5ced8986dfc968d37bb1d4f"
      hash30 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash31 = "ade656b212a4bef11d70720679ec7fd91586a9507448634cd716178ed908e509"
      hash32 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash33 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash34 = "242b2e8bf86f40047ed0c60607f61f81fb144a641a394ab51f4b21f1511ddca8"
      hash35 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash36 = "c9d6e3fa0bf1bae569a87f1526093204b2b6bbc227e8ddcd2af450c4fb5c71c3"
      hash37 = "ee7ab7d8bd4643e2f2d63bc0329b21c6d3437beea13fc379ee7fbfc0e326d0f5"
      hash38 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash39 = "b81e7c41d4c6cec4c6f99f9e577c8335c685bf09351af664d82c2a97bc12b89c"
      hash40 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash41 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = "[1;37m%-13sauto:%s" fullword ascii
      $s2 = "[1;37m%-13s%s" fullword ascii
      $s3 = "[1;31mnone" fullword ascii
      $s4 = "[1;32mintel" fullword ascii
      $s5 = "[1;32mryzen" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 25000KB and ( all of them )
      ) or ( all of them )
}

rule _match_1108 {
   meta:
      description = "black - from files 6b97eabf2e7eef8ccfc36593771ebe12, 0f9eddc5e740edcd96e2f32d6acc3bb3, 8a490aa2517646411b6ea1383f17bbd1, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 5f52a27f400818807d2693e1a52260ad, e28e3404155556ecafff204356fcc5f0, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, 2458b8fb100cb0d0c80a3f62aea0e080, a3b4afa503657e7a327934ddd231887e, b9280790ed58987ab2af68537ad18d6d, 80ba21786b71bb0dba959194fa1d3f63, b1b0580af0e8fa730486561255426f38, ae33c5c9544d63463cca74c42a556983, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 86d7666073561a5d0ca494d80eae3e5e, 99fe45ec1a50c0413a6dcb1d23b754f9, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "d2b4b16be498e2fbe782b6f0e73515f6fc74c7a661c44891a9860cbf2b690d02"
      hash2 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash3 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash4 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash5 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash6 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash7 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash8 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash9 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash10 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash11 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash12 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash13 = "ba3e5e8af6d21e5fa3a78b69a87ca1cd39afd4342795f514bd651af81e9b8e47"
      hash14 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash15 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash16 = "2e4b386aa820c4a1b294274d89652098e4a78921df83b1ed101213f558f704ea"
      hash17 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash18 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash19 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash20 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash21 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash22 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash23 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash24 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = "T$@McJ" fullword ascii
      $s2 = "T$0McJ" fullword ascii
      $s3 = "L$@McQ" fullword ascii
      $s4 = "L$PMcQ" fullword ascii
      $s5 = "T$PMcJ" fullword ascii
      $s6 = "~D$xfD" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 13000KB and ( all of them )
      ) or ( all of them )
}

rule _match_1111 {
   meta:
      description = "black - from files 568c6b1b3531ebd169c2a0ed65e62ef2, 945c640a20136010a058c9b4585ee47d, 4cc2fe8853b10d5f0b3149197d6663e4, ddcb5a9db519905658d881fa4103aa9a, bab9ba3432d3255edc4f8e86f6ea6010, 8a0d9d21af0356ddb2c82938f44e76d6, bed6e71336cb5309922a8cc3703ae7bd, 28281dec5a549c89ed55cc716069880c, 2ec73fee140c557a280e903dca386d4c, 45666ebea0ee088eb73616ad7eb16bb8, 0cc9fc7f24baf15588f438668d1eb27b, 3563aa2973ecef6681fb05e8b8d3eb13, ebef3b340f36cadf104a4a4630c15e2a, 6ac3b36f512b8f24cf6b52968d1243db, 06bc107a1237a49172bcc05fa64b3c72, 664d97ce12fe1690a5577ff601450a2f, 974c78abe08937557dd3f76ddda86c6e, c6f26ae8372c6b5550268ea143f6a6b2, 866a36906d5a0bf307e5424e67d55855, 00e69728719213a306c42e2abc8960ab, 032f9521303b5f0290d454ace3b74092, 31977b7f611099363326b3b5f10cdc16, 138650bdcf49b37f28ba9442aee758e1, 001e98ad444991d549d32ccda6d0f163, 578701d99783505703e6c79edf03de38, caab1031e15330c70aae8eb59e9e990c, c5d0fb9299c61e0e4c4811a7d3adec0e, b3a7cac730bc9c86f93be1b9e19e8ef2, c2e6e8c7c69afc5dc3bfdf4584df0e26, d669cf0445190e3b99678f6117c10f44, 495e6dae9afeb153886008d2c2f8e904, 86fe125eb293f34f113ac369dd82ad8e, b64fc678f1ffee948e1467bea12b5151, b821ac143b1ef6255ec26927b513721f, 8089bfe80c3950ab2c3aa9cea4da897c, 438dfb539ffb2275e5cde2557c9fafc4, f77112868bc3c7548136fe3ba98173bb, 26f5653be871bbf96ae6b14a9d90e16a, 6ceec8b6bc987c3944f85d585298fcb4, c4beabd1eed6215f933417c6c71a8c38, bf5c98c53c232481dea1c844adb260c2, 6d5f2f5b87b36569402723eff364fb3b, fd15788b6f10fd2b40b490de031036e8, 63ec990cf6b2d2dd9993f534b72f363e, 68006d734fa1ff1112cdcb1980c2045f, c75488f8a3f9c68cb4595c93aa198ba6, 05a33d00fbe7015caa1dec3a032db941, bf6a20945af16f099345b8996e4c3105, cf02f19e6e3db88f5165808cef0ff18f, 0553b99673cec4aae84126595799d04b, 61f0f4ec78a00d0b0f90c9ddec70c882, 0a4ea2bc69d0f743172a94d9c5d44d10, cc068a79d76a8fd587ccbdf0457500a4, d5ad9957fda245d5b443ac0ef29fac36, ca6fdcfa15dfd53fd86e106f02954b2e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "d8bb9838164d5239c7865fb0d647fd7690aa88e20afc6e64f3571501f8cdaeed"
      hash2 = "94f14fd7f48959be578b0a8eb1665ad7bca238dcbaa5dde93166cd812d30117a"
      hash3 = "e3889d79eb9b2eb5cfe48bf7890c131f5f78bdfa07f9b6b1c1be68b0f34f5469"
      hash4 = "5f3f2312d38f6661ab6a2cbfa62aa69aa1c654560baee42aeb11acd7975c5404"
      hash5 = "95319d0df797fdb6ceb91efe6883dbc0455c5cc1932d559b1db37454538801c7"
      hash6 = "13318a5072747bbea5274cbeffa70a4b54a846227b522b2305fa9084e50eedfe"
      hash7 = "7e94c91042d2bb54fa4799916995531f5e8e60a4006b454b7efc3b41114e9997"
      hash8 = "027193e7e65434cc2cb02ccb9630adef451836ff749ac53567425df89d554dbd"
      hash9 = "9d9577f969b681660485deaa86d98a3eac91c40183274e441a1430ea9df3704a"
      hash10 = "3f7f4d46bc6a80eefd05ae0a68790a91cd9793f9c9610fa35f52334cae7588ed"
      hash11 = "a56b3fd3adb9b82aeb6fbe87d6f3c3abab99b2ed66e39dc919caf1f3a41ec39a"
      hash12 = "80cdeb8403a52b68b2111fa82eeccebc348ade40d3c310c885558ae239f9191b"
      hash13 = "d14a8879d6f5494fcde844418ae12942d10d68cf1251e53b8bf32a7e32c1c3ca"
      hash14 = "328b16103c3e45530336c8f8fed73270f3978825856186dd8b762a25cd2d66f2"
      hash15 = "ad2761ceae4efbdf61fa1e3b14eb63e9e7be18aa653fe81b48ae47f3720f5e77"
      hash16 = "2782d85b803ddd1e2f6f669bdc63e04be83df42aada87f95642c102f3634fc98"
      hash17 = "0251908b98972dfc0f4be031a52d727b3a2ec61dec11b714c69e9dc43859c227"
      hash18 = "393d1196202090c0fa7b91d9cba1e0813c10cc5b9a9ddc95f94f73f24d42bf85"
      hash19 = "0c7cae8a6dfda31f1301117cfcb35718c8dc339d3ecc8b59bfd6d352462be306"
      hash20 = "d8ebd67551e9b8e484716a3db342de47b755ce14787ad64e1be2a3c35f866449"
      hash21 = "42c5e48280453ae905f0225a26bb46696fe6137edad53a71292572dd0e29d453"
      hash22 = "ada2cdb11b677dc930aa8efaddd64b76fcc13237be75678fc22d3ee07a1b01c6"
      hash23 = "c1ac650fc52b93f29917b3f8e31ae5fbc454e4db5393a43a80289e6e73b1cef6"
      hash24 = "fffb60f3530e2d8ead6ba2e7af33e1d4ccf7374f6cfedf29b31be200f3d35d85"
      hash25 = "5fb55c1ea3228126438d5adf84bda429f7b34c6f2fd1ba13bf28998b0290a984"
      hash26 = "4f4ccc67dfd75b5b6381ca103fb59db0993074fdf47c6207ffcf3445b157705d"
      hash27 = "14ea784bb6f0eb3d4d02671333c6ce6017313af3ae6b7bf34a9014be601ce811"
      hash28 = "1a806c8ce5d8739af51ae29f6bd0ebfa81bc2902defe839c180e580d529d76cf"
      hash29 = "8e3ebdd236e5d5f86901e622a44722a337bcae4c407b6788180e6ba9d45da1b4"
      hash30 = "ec0c435c5b028ec2a5032b55093b2d58eaa4d1b6c3393fb3c86bc4d62e98ed4f"
      hash31 = "75716bdc15998b47f345c329f67dcdba69cbb3307185223a5b3aadf6a7a111d3"
      hash32 = "0ceff53c08811cd2beb63a05540983ac66990e73035d6def77e45746c54c64b1"
      hash33 = "9d56b44a7d661f4f19407e3a1cbd3894b676084dd13f04bddcf705aacc4a25c8"
      hash34 = "97dfbe369a4443f6fdb3cc5baf94297a9390bc9477a8bb40a593fc34bda8dd99"
      hash35 = "c849aaf6ffc518407bc3fdbe6a799717cd8b7ab9c311a157dc9c6fa0b92b731e"
      hash36 = "ad441eb91d8c1a9e3ab9236ad5aa21f6921b9d17bcd53f8f6ba7f71f142fe371"
      hash37 = "d164adbcc75129eac9e51801634f8c24659e8f19a3d8dfb5ee09bfe57b802d6c"
      hash38 = "59cf778386c70416b41727d8b3350f65e9a2161959d6a3bbf67ec3257988cd61"
      hash39 = "70b4b95db10476f42efe0bd9ca6f330adebd3c781f9d3085523023c4656a1f8d"
      hash40 = "f915e58bac90e89a2a9c5809363131d881be6b09f0a1ad8602a8075246b22898"
      hash41 = "93d60abf15b2c5ef5847c70af31bad188db2eaa7cc6f1eb46bb851de71a3b9b7"
      hash42 = "5928d3cbe2c423aa672423b72608d2b609f4a24758d42c782ba3e25c85bca595"
      hash43 = "e9ea35b72b2b66680bc0ca9cd0f93c4934bbb0263fda63c19202d698976aaf54"
      hash44 = "3f31b4d2ca54b90c109f9a4444d080d40351769ea6354e817cf43ba5e44eb190"
      hash45 = "ea7b50030a83f64a9acbf6732567de2f155a762db8dacca4ad00e5e971403f04"
      hash46 = "ce386e19019fbd1edb3ebd5379a74e7c3dd1b18525cb7f8a8c8883b6663c218f"
      hash47 = "f6ba827dbf74c8cc8614f10298f7ee2ffd39d24367dad0cf09ef515c14785da4"
      hash48 = "5547725b534420b1a6ea435f756f4c6d35588b1cd811f14ae091721f2594e856"
      hash49 = "07c6661d8d1b4bdc3da5074e6e9739db100be2037c75f9c390df3174f4ae38c8"
      hash50 = "29899e0ead4381d8b560799d595b38d12520f07512639aeca7ee636d469ba3ab"
      hash51 = "2c17365876f6ad394b63f2b08115bc967f24ff304cf4ea6d5697e557ebd1716c"
      hash52 = "c82140ef3c150e830843707005802e2f201935e4cf315949b9f2410c6ed4446e"
      hash53 = "74b87ab37c24f819570e8c418535d3c03235661c764ecbb968571b7a49323bec"
      hash54 = "05db9268b60613003145246001646d12396a9becea41a15bb88dc2a283cf081c"
      hash55 = "97c689f7732beb1180b70bf6536a4037990459600175d49ab14734239c77b4d6"
   strings:
      $s1 = "|$83|$ " fullword ascii
      $s2 = "D$x3D$T" fullword ascii
      $s3 = "D$h121J" fullword ascii
      $s4 = "T$p3T$@" fullword ascii
      $s5 = "D$t3D$|" fullword ascii /* Goodware String - occured 5 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and ( all of them )
      ) or ( all of them )
}


rule _match_1121 {
   meta:
      description = "black - from files 0f9eddc5e740edcd96e2f32d6acc3bb3, 6cfc530100079ac1f1ed0cf61bed2ca8, acd5942fee24e5bc6769bb2fb529b695, 8a490aa2517646411b6ea1383f17bbd1, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 5f52a27f400818807d2693e1a52260ad, 0086748f3a7854b3a35f69b5285c534f, e28e3404155556ecafff204356fcc5f0, 4d6dff8b2def91e85a09faa27899d9d5, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, fc481ae3e90d67283ce944cefb433d25, a3b4afa503657e7a327934ddd231887e, b3c0545d8bdbd5cd9c4c5cbd4d070d2a, b9280790ed58987ab2af68537ad18d6d, b1b0580af0e8fa730486561255426f38, ae33c5c9544d63463cca74c42a556983, ee3f5f355249823f286f389ce0567002, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 86d7666073561a5d0ca494d80eae3e5e, 9b3518901fb21e67bfd3986cdcded31c, 99fe45ec1a50c0413a6dcb1d23b754f9, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash2 = "438784b7594602da1a92d67890953b527ef6cb045e0c64ccaa4e78448576fff5"
      hash3 = "0083066406394696a0e6f26928d71785bf9fcdecdd6dcf52731a93b78f2cca0c"
      hash4 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash5 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash6 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash7 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash8 = "0693cfd2a09f5358cdec077df4cf049c88fe5fcdc606a228e389c9b2e517f965"
      hash9 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash10 = "dbc26374af31e9c81b8bc3a6c3063387f587a2596510e2a3be24aea6e025294f"
      hash11 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash12 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash13 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash14 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash15 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash16 = "201b177ab0fe48289ac660b899b7813ed6f276a9ea1246574c28ebacb943905d"
      hash17 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash18 = "7bf303baebaec1c10be08273dd3d1ce503c4a7e1edaefc6092778b2926ebb278"
      hash19 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash20 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash21 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash22 = "ade656b212a4bef11d70720679ec7fd91586a9507448634cd716178ed908e509"
      hash23 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash24 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash25 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash26 = "ee7ab7d8bd4643e2f2d63bc0329b21c6d3437beea13fc379ee7fbfc0e326d0f5"
      hash27 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash28 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash29 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = "removed parent level %s at depth %u" fullword ascii
      $s2 = "may merge levels #%u=%s and #%u=%s" fullword ascii
      $s3 = "removed child level %s at depth %u" fullword ascii
      $s4 = "from plugin " fullword ascii
      $s5 = ".?AVHwlocCpuInfo@xmrig@@" fullword ascii
      $s6 = "%s#%u mask %llx" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and ( all of them )
      ) or ( all of them )
}

rule _match_1126 {
   meta:
      description = "black - from files 20addcaa91c6bc5c7cc665ddb2e8c52c, 97ee5c92d5c865ef6db67c35bc8a427a, 50b754688ea8b1994abc99ea58263ebb, d220d7b9023e6bd3717edc17765fbb25, 0f4acbb2acfaa97b146f4949729d0ec6, 5846aed02e23db1af696661606cf5bfd, cd7e6a6f2e3fc3cb1049efbbf235577f, 3934d1adff337a3741fc308eb83daaba, 99bd2332ea3179db7a70a6e66d11e096, 0cf00d65acee7181d4679d2ad3da5301, f8a8bd5eb3b9328c007438070e0c3ca8, 2458b8fb100cb0d0c80a3f62aea0e080, 0742b7c20e14fc0b9390fd5aafef6442, cd9d53902ae60c8a9330b6b145cbe3bb, a746e73da04945445e385850616990c9, 6a80142ac8cf4d5534d2eb9cb0e3e08d, ddafbf9406cc26df63a32702126e3fc9, b1a919e6fb009361b64d51b351a25e4c, 3ba79ba35b4b388fe9699e51d4c43fea, e74a8e9fbf1969888d78bfe6bf757759, 2ae5db210e8c7c0c96e6bed93bce1da6, 233cb487009705a47f32a694558deca5, 0cccafcbc4d1a6d50ccd8fa1df89bc0f, 3a69511ef880ea841a6740357901ca61, 74f394c609338509e94d61091a70b6f5"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "c2389593cb340e9b682e457e6bf926abf1eee594d129c237f3f87852731dba7d"
      hash2 = "e91e3d9138b2961bf0807b39ab1c0647e78ccf6985890246db1d698af498e43b"
      hash3 = "2efbcf082019f2fe3b7b065842a6e99e0441e7166265d2021695fce00f0d4373"
      hash4 = "8d887ba624e0e8f55be8deb805ec25c1a2a34e6fa137b6bc30025cfbc124dfb8"
      hash5 = "4c9bf0426483d1f8f7943cb291345134964d237f1b8270f88f51cbdd1557a41e"
      hash6 = "5d1ef3f5bc06e457945af001cad5e392eea47ae4486522ad3342f42b6e2b7436"
      hash7 = "08e6eb5d64f01d4a982bf75e4ffbec7d0f61d7ece7b7fbfe2fade7ae39ad8884"
      hash8 = "2fefce5634c8b6f9e334fd6b1c34b86f6cb8278dc07558034d1ead43d1467cbb"
      hash9 = "2e999f22d7fa0d018342d235067b5bb879b4505bb0e42156f816d38ae61cd3fe"
      hash10 = "a0e6799ed9cb59ac3aeab73f2c10015fbabbacc850b56148778f69cc38835d27"
      hash11 = "2df4f0927f0f73ff7ca38a4edfe9406be229985fd5ae468d9b5aa19b9b0cd0ac"
      hash12 = "ba3e5e8af6d21e5fa3a78b69a87ca1cd39afd4342795f514bd651af81e9b8e47"
      hash13 = "3b38ac70eac888ba76ae3c5812179863a78b4e63ce92f5108f019bb00f96b35c"
      hash14 = "9c62abcac2762be0e5abbb7f06ffb65c0b8fbea84d015944b6593453354303eb"
      hash15 = "beae2bc4274deb42c452e6ad910853cfa1a60e05f0180ed43829e2a4f5281e04"
      hash16 = "c8eb9182adc12b591cbdafe27759495487a53c0cd38f83f77f575edf21e5d4b3"
      hash17 = "a35d47fde5d36de866ba7fbe638c7ea9f5860962b326484936a992cbba6fa22f"
      hash18 = "72356978da0b156bae25c84189c01a47b7c8e8daf22e2be533f1e2733f8372f2"
      hash19 = "d274427049b5e28fdd153a0bdbcb08445ffebd9031ed666dba23b62e44b3191a"
      hash20 = "4c486b48b0524a9e3059f5dab86bffa9a0fa82787363c7784c624453344dc1d1"
      hash21 = "3b1a32116390ef2a821cbeb15e214f937293ee39cfde2a2e97f2eb128474bce3"
      hash22 = "1c6eeaf450250baad8b4bbdcb4539a5ec8ad9878d1ea4c96c493e01cca02f1d2"
      hash23 = "4a49d867bbb4e4e36b55c77f0f514fdf18a78b18b701ae853075092ac2893e2e"
      hash24 = "477ff70035e7438bbb414dcaf805d93a61dc39f75acf882134097fe3be105e48"
      hash25 = "02bd77bfd0a50ae5ea7e8a6587187e84b5c4d0d5638c7559abe609fbebbacd38"
   strings:
      $s1 = "Failed to signal quiesce via inter-thread communication channel" fullword ascii
      $s2 = "failed to signal quiesce via inter-thread communication channel" fullword ascii
      $s3 = "MHD_get_fdset2() called with except_fd_set set to NULL. Such behavior is unsupported." fullword ascii
      $s4 = "Using MHD_quiesce_daemon in this mode requires MHD_USE_ITC" fullword ascii
      $s5 = "Cannot suspend connections without enabling MHD_ALLOW_SUSPEND_RESUME!" fullword ascii
      $s6 = "MHD_run_from_select() called with except_fd_set set to NULL. Such behavior is deprecated." fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 27000KB and ( all of them )
      ) or ( all of them )
}

rule _match_1127 {
   meta:
      description = "black - from files 20addcaa91c6bc5c7cc665ddb2e8c52c, 97ee5c92d5c865ef6db67c35bc8a427a, d220d7b9023e6bd3717edc17765fbb25, eafa15f8a4e79523f4f6288519e2d60a, 0f4acbb2acfaa97b146f4949729d0ec6, 09b0bb70c4456e39cb26cdf2667b2be7, cd7e6a6f2e3fc3cb1049efbbf235577f, f8a8bd5eb3b9328c007438070e0c3ca8, 0742b7c20e14fc0b9390fd5aafef6442, a746e73da04945445e385850616990c9, 6a80142ac8cf4d5534d2eb9cb0e3e08d, b1a919e6fb009361b64d51b351a25e4c, 936c8489a348fbdb03c66bbf46c60d7e, 3ba79ba35b4b388fe9699e51d4c43fea, e74a8e9fbf1969888d78bfe6bf757759, a79c869cbd44bdfa9860a858facd982e, 9f8125060a075a7c7b3e8b13d630bcf9, 0cccafcbc4d1a6d50ccd8fa1df89bc0f, a4d33f5f38e992c5e6d56865ff2ba1dc, e2ab3fc59ad63fee82456d2e42b23d2c"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "c2389593cb340e9b682e457e6bf926abf1eee594d129c237f3f87852731dba7d"
      hash2 = "e91e3d9138b2961bf0807b39ab1c0647e78ccf6985890246db1d698af498e43b"
      hash3 = "8d887ba624e0e8f55be8deb805ec25c1a2a34e6fa137b6bc30025cfbc124dfb8"
      hash4 = "7d2a58520ab1dea0d33c5866fdfbb8ccfb5a446f200c6d4c064d14ff90cdf76c"
      hash5 = "4c9bf0426483d1f8f7943cb291345134964d237f1b8270f88f51cbdd1557a41e"
      hash6 = "bc2a8aa09df1303d24917145a3b41acf1b9df09c72e65273883c63b288623e2b"
      hash7 = "08e6eb5d64f01d4a982bf75e4ffbec7d0f61d7ece7b7fbfe2fade7ae39ad8884"
      hash8 = "2df4f0927f0f73ff7ca38a4edfe9406be229985fd5ae468d9b5aa19b9b0cd0ac"
      hash9 = "3b38ac70eac888ba76ae3c5812179863a78b4e63ce92f5108f019bb00f96b35c"
      hash10 = "beae2bc4274deb42c452e6ad910853cfa1a60e05f0180ed43829e2a4f5281e04"
      hash11 = "c8eb9182adc12b591cbdafe27759495487a53c0cd38f83f77f575edf21e5d4b3"
      hash12 = "72356978da0b156bae25c84189c01a47b7c8e8daf22e2be533f1e2733f8372f2"
      hash13 = "b29176abdf91577a1267f00ad74137289898c4edd08ec4e27556f439a3d406e8"
      hash14 = "d274427049b5e28fdd153a0bdbcb08445ffebd9031ed666dba23b62e44b3191a"
      hash15 = "4c486b48b0524a9e3059f5dab86bffa9a0fa82787363c7784c624453344dc1d1"
      hash16 = "58fc973c2df43431d85dd6713461e818376109c4b8f681cf9775768d45e18bf1"
      hash17 = "a2cce624ed3e428075dedc5b4243c065baafe0a121de26d686756e487e4d7232"
      hash18 = "4a49d867bbb4e4e36b55c77f0f514fdf18a78b18b701ae853075092ac2893e2e"
      hash19 = "0e1b04257292042084e66b6497e1a2411a81d497dabcee84e238da35e9472b50"
      hash20 = "5fc5a50b6becf57bcc7e47f6dcbbe2efa2ce15f43739f230f889b69e642619a9"
   strings:
      $s1 = "[%s:%u] login error code: %d" fullword ascii
      $s2 = "[%s:%u] connect error: \"%s\"" fullword ascii
      $s3 = "[%s:%u] read error: \"%s\"" fullword ascii
      $s4 = "[%s:%u] JSON decode failed: \"%s\"" fullword ascii
      $s5 = "[%s:%u] unsupported method: \"%s\"" fullword ascii
      $s6 = "[%s:%u] DNS error: \"%s\"" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 27000KB and ( all of them )
      ) or ( all of them )
}

rule _match_1177 {
   meta:
      description = "black - from files 905eeda0ddf717b45bb294b227e6d8ae, 6b97eabf2e7eef8ccfc36593771ebe12, 4396f6981923a6e702a9d18a3d76e482, 0f9eddc5e740edcd96e2f32d6acc3bb3, 20addcaa91c6bc5c7cc665ddb2e8c52c, 8a490aa2517646411b6ea1383f17bbd1, 97ee5c92d5c865ef6db67c35bc8a427a, d220d7b9023e6bd3717edc17765fbb25, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 0f4acbb2acfaa97b146f4949729d0ec6, 5f52a27f400818807d2693e1a52260ad, 09b0bb70c4456e39cb26cdf2667b2be7, 5846aed02e23db1af696661606cf5bfd, cd7e6a6f2e3fc3cb1049efbbf235577f, 0086748f3a7854b3a35f69b5285c534f, e28e3404155556ecafff204356fcc5f0, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, 3934d1adff337a3741fc308eb83daaba, 99bd2332ea3179db7a70a6e66d11e096, af408f884178b56843b9f7324bcdefb4, 0cf00d65acee7181d4679d2ad3da5301, 51f0f95501d456804707bd997c56b416, f8a8bd5eb3b9328c007438070e0c3ca8, 2458b8fb100cb0d0c80a3f62aea0e080, 0742b7c20e14fc0b9390fd5aafef6442, a3b4afa503657e7a327934ddd231887e, b9280790ed58987ab2af68537ad18d6d, 80ba21786b71bb0dba959194fa1d3f63, a746e73da04945445e385850616990c9, 6a80142ac8cf4d5534d2eb9cb0e3e08d, ddafbf9406cc26df63a32702126e3fc9, b1b0580af0e8fa730486561255426f38, 13ce83c5c7ea01852b0ae2e35b74949b, 0304ecd571a157fbcd4723d455bb554b, b1a919e6fb009361b64d51b351a25e4c, 3ba79ba35b4b388fe9699e51d4c43fea, 26fc98d7481f9b494ecbfebacdcbeab3, ae33c5c9544d63463cca74c42a556983, ee3f5f355249823f286f389ce0567002, df180313543e2a1a9c31ae49a0fb16be, e74a8e9fbf1969888d78bfe6bf757759, 9a07ca40de9c85495231302023c6a74a, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 15c4fc341d735f9ea8427f918d3f5422, 2ae5db210e8c7c0c96e6bed93bce1da6, a79c869cbd44bdfa9860a858facd982e, 2bb37adb6ed181947bbb7f4535a351c1, 9ad1d65187d0fb50941ff23676234c5d, 86d7666073561a5d0ca494d80eae3e5e, 0cccafcbc4d1a6d50ccd8fa1df89bc0f, 9b3518901fb21e67bfd3986cdcded31c, a4d33f5f38e992c5e6d56865ff2ba1dc, 99fe45ec1a50c0413a6dcb1d23b754f9, 74f394c609338509e94d61091a70b6f5, e97524afde7b751f6b024fa4798bdf51, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "a28878f5880b8a1c506258dd39b459cec616f79100afe006b4779525b8a937a3"
      hash2 = "d2b4b16be498e2fbe782b6f0e73515f6fc74c7a661c44891a9860cbf2b690d02"
      hash3 = "4fd49a0d1574549b4f8b64c9d474417600d6ede505c3997b3b07eb9e92bd440a"
      hash4 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash5 = "c2389593cb340e9b682e457e6bf926abf1eee594d129c237f3f87852731dba7d"
      hash6 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash7 = "e91e3d9138b2961bf0807b39ab1c0647e78ccf6985890246db1d698af498e43b"
      hash8 = "8d887ba624e0e8f55be8deb805ec25c1a2a34e6fa137b6bc30025cfbc124dfb8"
      hash9 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash10 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash11 = "4c9bf0426483d1f8f7943cb291345134964d237f1b8270f88f51cbdd1557a41e"
      hash12 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash13 = "bc2a8aa09df1303d24917145a3b41acf1b9df09c72e65273883c63b288623e2b"
      hash14 = "5d1ef3f5bc06e457945af001cad5e392eea47ae4486522ad3342f42b6e2b7436"
      hash15 = "08e6eb5d64f01d4a982bf75e4ffbec7d0f61d7ece7b7fbfe2fade7ae39ad8884"
      hash16 = "0693cfd2a09f5358cdec077df4cf049c88fe5fcdc606a228e389c9b2e517f965"
      hash17 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash18 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash19 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash20 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash21 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash22 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash23 = "2fefce5634c8b6f9e334fd6b1c34b86f6cb8278dc07558034d1ead43d1467cbb"
      hash24 = "2e999f22d7fa0d018342d235067b5bb879b4505bb0e42156f816d38ae61cd3fe"
      hash25 = "c92d9638c8fb2b0556802ea87082be829f50dd7d29579a1a893ade35bd7a9256"
      hash26 = "a0e6799ed9cb59ac3aeab73f2c10015fbabbacc850b56148778f69cc38835d27"
      hash27 = "a8efd58c2f819b96742b10bad9aa76494731295f32ccc9897d3694944017b2a4"
      hash28 = "2df4f0927f0f73ff7ca38a4edfe9406be229985fd5ae468d9b5aa19b9b0cd0ac"
      hash29 = "ba3e5e8af6d21e5fa3a78b69a87ca1cd39afd4342795f514bd651af81e9b8e47"
      hash30 = "3b38ac70eac888ba76ae3c5812179863a78b4e63ce92f5108f019bb00f96b35c"
      hash31 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash32 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash33 = "2e4b386aa820c4a1b294274d89652098e4a78921df83b1ed101213f558f704ea"
      hash34 = "beae2bc4274deb42c452e6ad910853cfa1a60e05f0180ed43829e2a4f5281e04"
      hash35 = "c8eb9182adc12b591cbdafe27759495487a53c0cd38f83f77f575edf21e5d4b3"
      hash36 = "a35d47fde5d36de866ba7fbe638c7ea9f5860962b326484936a992cbba6fa22f"
      hash37 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash38 = "10fe50b5f6fbaad5498bdc524145e5e05719fccc308da6de5a7c30ce9c3cbba3"
      hash39 = "02abeb1e769c65f180a39d46e4fb04f2282de9356b891f9734ce1ab86b5b183d"
      hash40 = "72356978da0b156bae25c84189c01a47b7c8e8daf22e2be533f1e2733f8372f2"
      hash41 = "d274427049b5e28fdd153a0bdbcb08445ffebd9031ed666dba23b62e44b3191a"
      hash42 = "b95f40cce47499183ef95d6d56b8b5deed0d99a413a8bd7067200c5b1ae752a9"
      hash43 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash44 = "ade656b212a4bef11d70720679ec7fd91586a9507448634cd716178ed908e509"
      hash45 = "a7799d88b5ae3a611ca45939dbd479766fd4a3dd86e622bf95ef1189afc59f13"
      hash46 = "4c486b48b0524a9e3059f5dab86bffa9a0fa82787363c7784c624453344dc1d1"
      hash47 = "ea9d91772dd86455d5bf25c080ed859faae39c7085abb5de0b3142a397e7f131"
      hash48 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash49 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash50 = "242b2e8bf86f40047ed0c60607f61f81fb144a641a394ab51f4b21f1511ddca8"
      hash51 = "3b1a32116390ef2a821cbeb15e214f937293ee39cfde2a2e97f2eb128474bce3"
      hash52 = "58fc973c2df43431d85dd6713461e818376109c4b8f681cf9775768d45e18bf1"
      hash53 = "270825598a9cede97ed8ab5b68f3a1e1ee135489de3e464b6a46e29fb0e69c3c"
      hash54 = "6b5e1968ea97bcb10a53e2754d4f33c58bc1efed2ff1533d9bb3c346d8dfe318"
      hash55 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash56 = "4a49d867bbb4e4e36b55c77f0f514fdf18a78b18b701ae853075092ac2893e2e"
      hash57 = "ee7ab7d8bd4643e2f2d63bc0329b21c6d3437beea13fc379ee7fbfc0e326d0f5"
      hash58 = "0e1b04257292042084e66b6497e1a2411a81d497dabcee84e238da35e9472b50"
      hash59 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash60 = "02bd77bfd0a50ae5ea7e8a6587187e84b5c4d0d5638c7559abe609fbebbacd38"
      hash61 = "b81e7c41d4c6cec4c6f99f9e577c8335c685bf09351af664d82c2a97bc12b89c"
      hash62 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash63 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = "hugepages" fullword ascii
      $s2 = "hashes_total" fullword ascii
      $s3 = "shares_total" fullword ascii
      $s4 = "donate_level" fullword ascii
      $s5 = "worker_id" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 27000KB and ( all of them )
      ) or ( all of them )
}

rule _match_1178 {
   meta:
      description = "black - from files 905eeda0ddf717b45bb294b227e6d8ae, 6b97eabf2e7eef8ccfc36593771ebe12, 4396f6981923a6e702a9d18a3d76e482, bab9ba3432d3255edc4f8e86f6ea6010, f957d3e479a07339edad73308c36e092, 5846aed02e23db1af696661606cf5bfd, e0095ff4e8222e5caafe0aedce42f9d4, 3934d1adff337a3741fc308eb83daaba, 99bd2332ea3179db7a70a6e66d11e096, 0cf00d65acee7181d4679d2ad3da5301, 2458b8fb100cb0d0c80a3f62aea0e080, 2b3e56a15d75e4aa0327ac55733353ca, 4451163751d9841553744a6f80ca0aed, 80ba21786b71bb0dba959194fa1d3f63, 720c0967b97baeaadefdfff2d265a183, 13ce83c5c7ea01852b0ae2e35b74949b, 0304ecd571a157fbcd4723d455bb554b, be3781cfcf4d7b709449382184148803, 63d152e378907ea71551baff27a82d7d, 9a07ca40de9c85495231302023c6a74a, 15c4fc341d735f9ea8427f918d3f5422, 9ad1d65187d0fb50941ff23676234c5d"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "a28878f5880b8a1c506258dd39b459cec616f79100afe006b4779525b8a937a3"
      hash2 = "d2b4b16be498e2fbe782b6f0e73515f6fc74c7a661c44891a9860cbf2b690d02"
      hash3 = "4fd49a0d1574549b4f8b64c9d474417600d6ede505c3997b3b07eb9e92bd440a"
      hash4 = "95319d0df797fdb6ceb91efe6883dbc0455c5cc1932d559b1db37454538801c7"
      hash5 = "3a3fcb2a72c7e88bb0a5e31240f73f6b401ea9f22416a65519cd0c699d665e94"
      hash6 = "5d1ef3f5bc06e457945af001cad5e392eea47ae4486522ad3342f42b6e2b7436"
      hash7 = "ac51683da9fbe47c0d65f00d85a8b9705c4ab01a66f43c4a872b8f5407516f2b"
      hash8 = "2fefce5634c8b6f9e334fd6b1c34b86f6cb8278dc07558034d1ead43d1467cbb"
      hash9 = "2e999f22d7fa0d018342d235067b5bb879b4505bb0e42156f816d38ae61cd3fe"
      hash10 = "a0e6799ed9cb59ac3aeab73f2c10015fbabbacc850b56148778f69cc38835d27"
      hash11 = "ba3e5e8af6d21e5fa3a78b69a87ca1cd39afd4342795f514bd651af81e9b8e47"
      hash12 = "7bdb3093778ff709bac2a5e5e22960ab93fce19da7fc8e79aed29105c8d45f61"
      hash13 = "e90a53ae1c6318e25816e74530a4c3607e55cbadf3b7eb0d0ff97fb78d6a8d96"
      hash14 = "2e4b386aa820c4a1b294274d89652098e4a78921df83b1ed101213f558f704ea"
      hash15 = "a5da66d083a3a55342caab79f28aa97728682eebad7a9b8de88b0af92e9a7c28"
      hash16 = "10fe50b5f6fbaad5498bdc524145e5e05719fccc308da6de5a7c30ce9c3cbba3"
      hash17 = "02abeb1e769c65f180a39d46e4fb04f2282de9356b891f9734ce1ab86b5b183d"
      hash18 = "714ae3c335d8dd42c2db8fe655c433887a5e0ef1c5f49a267d91f523427b2b61"
      hash19 = "f275d2589f252cfd2a131a89429837de58c04322c5ced8986dfc968d37bb1d4f"
      hash20 = "ea9d91772dd86455d5bf25c080ed859faae39c7085abb5de0b3142a397e7f131"
      hash21 = "242b2e8bf86f40047ed0c60607f61f81fb144a641a394ab51f4b21f1511ddca8"
      hash22 = "6b5e1968ea97bcb10a53e2754d4f33c58bc1efed2ff1533d9bb3c346d8dfe318"
   strings:
      $s1 = "Incompatible algorithm \"%s\" detected, reconnect" fullword ascii
      $s2 = "Unknown/unsupported algorithm detected, reconnect" fullword ascii
      $s3 = "cryptonight/xtl" fullword ascii
      $s4 = "api-no-restricted" fullword ascii
      $s5 = "api-ipv6" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 13000KB and ( all of them )
      ) or ( all of them )
}

rule _match_1194 {
   meta:
      description = "black - from files 4396f6981923a6e702a9d18a3d76e482, 0f9eddc5e740edcd96e2f32d6acc3bb3, 8a490aa2517646411b6ea1383f17bbd1, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 5f52a27f400818807d2693e1a52260ad, 5846aed02e23db1af696661606cf5bfd, e28e3404155556ecafff204356fcc5f0, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, af408f884178b56843b9f7324bcdefb4, 0cf00d65acee7181d4679d2ad3da5301, 51f0f95501d456804707bd997c56b416, 4451163751d9841553744a6f80ca0aed, a3b4afa503657e7a327934ddd231887e, b9280790ed58987ab2af68537ad18d6d, b1b0580af0e8fa730486561255426f38, 13ce83c5c7ea01852b0ae2e35b74949b, 26fc98d7481f9b494ecbfebacdcbeab3, 63d152e378907ea71551baff27a82d7d, ae33c5c9544d63463cca74c42a556983, ee3f5f355249823f286f389ce0567002, 9a07ca40de9c85495231302023c6a74a, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 15c4fc341d735f9ea8427f918d3f5422, 86d7666073561a5d0ca494d80eae3e5e, e4c92dd63239428f0b33c7f424293687, 9b3518901fb21e67bfd3986cdcded31c, 99fe45ec1a50c0413a6dcb1d23b754f9, e97524afde7b751f6b024fa4798bdf51, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "4fd49a0d1574549b4f8b64c9d474417600d6ede505c3997b3b07eb9e92bd440a"
      hash2 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash3 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash4 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash5 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash6 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash7 = "5d1ef3f5bc06e457945af001cad5e392eea47ae4486522ad3342f42b6e2b7436"
      hash8 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash9 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash10 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash11 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash12 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash13 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash14 = "c92d9638c8fb2b0556802ea87082be829f50dd7d29579a1a893ade35bd7a9256"
      hash15 = "a0e6799ed9cb59ac3aeab73f2c10015fbabbacc850b56148778f69cc38835d27"
      hash16 = "a8efd58c2f819b96742b10bad9aa76494731295f32ccc9897d3694944017b2a4"
      hash17 = "e90a53ae1c6318e25816e74530a4c3607e55cbadf3b7eb0d0ff97fb78d6a8d96"
      hash18 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash19 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash20 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash21 = "10fe50b5f6fbaad5498bdc524145e5e05719fccc308da6de5a7c30ce9c3cbba3"
      hash22 = "b95f40cce47499183ef95d6d56b8b5deed0d99a413a8bd7067200c5b1ae752a9"
      hash23 = "f275d2589f252cfd2a131a89429837de58c04322c5ced8986dfc968d37bb1d4f"
      hash24 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash25 = "ade656b212a4bef11d70720679ec7fd91586a9507448634cd716178ed908e509"
      hash26 = "ea9d91772dd86455d5bf25c080ed859faae39c7085abb5de0b3142a397e7f131"
      hash27 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash28 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash29 = "242b2e8bf86f40047ed0c60607f61f81fb144a641a394ab51f4b21f1511ddca8"
      hash30 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash31 = "c9d6e3fa0bf1bae569a87f1526093204b2b6bbc227e8ddcd2af450c4fb5c71c3"
      hash32 = "ee7ab7d8bd4643e2f2d63bc0329b21c6d3437beea13fc379ee7fbfc0e326d0f5"
      hash33 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash34 = "b81e7c41d4c6cec4c6f99f9e577c8335c685bf09351af664d82c2a97bc12b89c"
      hash35 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash36 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = "[0m height " fullword ascii
      $s2 = "[1;32maccepted" fullword ascii
      $s3 = "[1;31mrejected" fullword ascii
      $s4 = "[1;37m%llu" fullword ascii
      $s5 = "[1;30m(%llu ms)" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 25000KB and ( all of them )
      ) or ( all of them )
}

rule _match_1233 {
   meta:
      description = "black - from files 0f9eddc5e740edcd96e2f32d6acc3bb3, 8a490aa2517646411b6ea1383f17bbd1, 162a7b063003403841e98dc02aaa6b76, b0bba51294493c6aa40adeba3c70a371, 5f52a27f400818807d2693e1a52260ad, 0086748f3a7854b3a35f69b5285c534f, e28e3404155556ecafff204356fcc5f0, df28944c7a1569a49e64529cbd739aac, b02c64a2e6f556a3088281bed53180a5, 2c4bcb03ce02b34dcaccf12f768e0e55, 503abad89154afa5dc155168c423a404, ef760347014ebf86b83a544b32997fe4, 51f0f95501d456804707bd997c56b416, a3b4afa503657e7a327934ddd231887e, b9280790ed58987ab2af68537ad18d6d, b1b0580af0e8fa730486561255426f38, 26fc98d7481f9b494ecbfebacdcbeab3, ae33c5c9544d63463cca74c42a556983, ee3f5f355249823f286f389ce0567002, 62092d967bf0ef931ee7206b3a54b2b8, b85ce83adb5b61a8fb353509f945ec3b, 86d7666073561a5d0ca494d80eae3e5e, 9b3518901fb21e67bfd3986cdcded31c, 99fe45ec1a50c0413a6dcb1d23b754f9, e97524afde7b751f6b024fa4798bdf51, 7a4a5e709646970e205e40f33b1eeecf, aa70ae1a4464eebee96dda065ebdf41e"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "0b3bb29a7523a5ad6a80504d305a7e2b2219089d7c7884fd447d09fe665e456f"
      hash2 = "1205b6420a940016fbbf2848a7e53b3840780d943d5e1cf5ac7c1df46f0cac49"
      hash3 = "49882a647d1ea3d91880e879b582d9f71b5c4c146f957d76c7e38f2089ddd415"
      hash4 = "9b56871e8d0366c5c53283d5f75d6ad69245548a2ba963011002401a51b8fcd9"
      hash5 = "9f989edd442d4e2167c35e5eb7d94b82bd537ab0af7dc3c4e38dccbe32c8f7ea"
      hash6 = "0693cfd2a09f5358cdec077df4cf049c88fe5fcdc606a228e389c9b2e517f965"
      hash7 = "45979695a2ae3d4376849ee004ee5fd7f61e04b2cf7f417fb06d9b5cfc7c46e4"
      hash8 = "d0aba3f1fad79fad7f6cf85b87d62b248f8e364c327d8c307aa494cf7358c830"
      hash9 = "d1882410ced24e9d59a7030d5f6fb1e6b10770f76a949b49050017cbef791bb1"
      hash10 = "c57ef432bbd52ce46a57969378d2e60823a4fbeef91184c18f65ace42c4afa03"
      hash11 = "8cd3296624a8d68374514831ec48e50833bb74674daa1c774320f158347e6e7b"
      hash12 = "702385ae971271eb8402b916152741a9fe15a06f4e221bf2b7b42db69c10ffb5"
      hash13 = "a8efd58c2f819b96742b10bad9aa76494731295f32ccc9897d3694944017b2a4"
      hash14 = "ac7bfed9fa8f834cbb5c7c5ab1ddb322887ca8d70527938f2b27cb0dab42906b"
      hash15 = "0a51f478127b8bcf5dcee926e76bf75ff9f3647c361a23a6683a45778a0594ea"
      hash16 = "aaa916440af3cef8808d70c299328379d7186d7590689e5613f24c3da29e9a1c"
      hash17 = "b95f40cce47499183ef95d6d56b8b5deed0d99a413a8bd7067200c5b1ae752a9"
      hash18 = "71d448f276e9ec612c908db68bba33c753404e507694900ab48dcb402f62e365"
      hash19 = "ade656b212a4bef11d70720679ec7fd91586a9507448634cd716178ed908e509"
      hash20 = "48d14096f82f837c4fd18fcff6a9d7947b45e8d092ff99a959cf9d2571205c37"
      hash21 = "98d5651f2aea6682d0723074228b3a33c7d71dcabf52fd3e254fc4fd777f5804"
      hash22 = "bab19ccd766acbc66644fdd4a2ad6f91c6c0cd850d6bd57c66f86d6e2e99322c"
      hash23 = "ee7ab7d8bd4643e2f2d63bc0329b21c6d3437beea13fc379ee7fbfc0e326d0f5"
      hash24 = "15bb87399fcfab98e8c527d08882e1c643dd3b99c4213a266b8b0e92bf0c9ade"
      hash25 = "b81e7c41d4c6cec4c6f99f9e577c8335c685bf09351af664d82c2a97bc12b89c"
      hash26 = "3a8f5d98115a3c88eb63ba0cc368dba4e81adae9e72a34b5c714b656211e3f60"
      hash27 = "e060fba2f2b159cf1464e76eb995d1443cab68b2f99aa376681a091d3051aaa8"
   strings:
      $s1 = "SUWVATAUAVAWH" fullword ascii
      $s2 = "\\$@L3D$8L3L$0L3T$(L3\\$ L3d$" fullword ascii
      $s3 = "L3a L3i(L3q0L3y8H" fullword ascii
      $s4 = "L3c L3k(L3s0L3{8H" fullword ascii
      $s5 = "PA_A^A]A\\^_][" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 25000KB and ( all of them )
      ) or ( all of them )
}

rule _match_1242 {
   meta:
      description = "black - from files 20addcaa91c6bc5c7cc665ddb2e8c52c, 97ee5c92d5c865ef6db67c35bc8a427a, d220d7b9023e6bd3717edc17765fbb25, eafa15f8a4e79523f4f6288519e2d60a, 0f4acbb2acfaa97b146f4949729d0ec6, 09b0bb70c4456e39cb26cdf2667b2be7, cd7e6a6f2e3fc3cb1049efbbf235577f, f8a8bd5eb3b9328c007438070e0c3ca8, 0742b7c20e14fc0b9390fd5aafef6442, a746e73da04945445e385850616990c9, 6a80142ac8cf4d5534d2eb9cb0e3e08d, ddafbf9406cc26df63a32702126e3fc9, b1a919e6fb009361b64d51b351a25e4c, 3ba79ba35b4b388fe9699e51d4c43fea, e74a8e9fbf1969888d78bfe6bf757759, 2ae5db210e8c7c0c96e6bed93bce1da6, a79c869cbd44bdfa9860a858facd982e, 0cccafcbc4d1a6d50ccd8fa1df89bc0f, a4d33f5f38e992c5e6d56865ff2ba1dc, e2ab3fc59ad63fee82456d2e42b23d2c, 74f394c609338509e94d61091a70b6f5"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "c2389593cb340e9b682e457e6bf926abf1eee594d129c237f3f87852731dba7d"
      hash2 = "e91e3d9138b2961bf0807b39ab1c0647e78ccf6985890246db1d698af498e43b"
      hash3 = "8d887ba624e0e8f55be8deb805ec25c1a2a34e6fa137b6bc30025cfbc124dfb8"
      hash4 = "7d2a58520ab1dea0d33c5866fdfbb8ccfb5a446f200c6d4c064d14ff90cdf76c"
      hash5 = "4c9bf0426483d1f8f7943cb291345134964d237f1b8270f88f51cbdd1557a41e"
      hash6 = "bc2a8aa09df1303d24917145a3b41acf1b9df09c72e65273883c63b288623e2b"
      hash7 = "08e6eb5d64f01d4a982bf75e4ffbec7d0f61d7ece7b7fbfe2fade7ae39ad8884"
      hash8 = "2df4f0927f0f73ff7ca38a4edfe9406be229985fd5ae468d9b5aa19b9b0cd0ac"
      hash9 = "3b38ac70eac888ba76ae3c5812179863a78b4e63ce92f5108f019bb00f96b35c"
      hash10 = "beae2bc4274deb42c452e6ad910853cfa1a60e05f0180ed43829e2a4f5281e04"
      hash11 = "c8eb9182adc12b591cbdafe27759495487a53c0cd38f83f77f575edf21e5d4b3"
      hash12 = "a35d47fde5d36de866ba7fbe638c7ea9f5860962b326484936a992cbba6fa22f"
      hash13 = "72356978da0b156bae25c84189c01a47b7c8e8daf22e2be533f1e2733f8372f2"
      hash14 = "d274427049b5e28fdd153a0bdbcb08445ffebd9031ed666dba23b62e44b3191a"
      hash15 = "4c486b48b0524a9e3059f5dab86bffa9a0fa82787363c7784c624453344dc1d1"
      hash16 = "3b1a32116390ef2a821cbeb15e214f937293ee39cfde2a2e97f2eb128474bce3"
      hash17 = "58fc973c2df43431d85dd6713461e818376109c4b8f681cf9775768d45e18bf1"
      hash18 = "4a49d867bbb4e4e36b55c77f0f514fdf18a78b18b701ae853075092ac2893e2e"
      hash19 = "0e1b04257292042084e66b6497e1a2411a81d497dabcee84e238da35e9472b50"
      hash20 = "5fc5a50b6becf57bcc7e47f6dcbbe2efa2ce15f43739f230f889b69e642619a9"
      hash21 = "02bd77bfd0a50ae5ea7e8a6587187e84b5c4d0d5638c7559abe609fbebbacd38"
   strings:
      $s1 = "[01;37mCOMMANDS:     " fullword ascii
      $s2 = "[01;37mause, " fullword ascii
      $s3 = "[01;37mashrate, " fullword ascii
      $s4 = "[01;35mh" fullword ascii
      $s5 = "[01;35mp" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 27000KB and ( all of them )
      ) or ( all of them )
}

rule _match_1271 {
   meta:
      description = "black - from files 97ee5c92d5c865ef6db67c35bc8a427a, d220d7b9023e6bd3717edc17765fbb25, eafa15f8a4e79523f4f6288519e2d60a, 0f4acbb2acfaa97b146f4949729d0ec6, 09b0bb70c4456e39cb26cdf2667b2be7, 5846aed02e23db1af696661606cf5bfd, 7d98df10c15276bb856b370bd95910fc, 3934d1adff337a3741fc308eb83daaba, 99bd2332ea3179db7a70a6e66d11e096, 0cf00d65acee7181d4679d2ad3da5301, 51f0f95501d456804707bd997c56b416, 2458b8fb100cb0d0c80a3f62aea0e080, 0742b7c20e14fc0b9390fd5aafef6442, 0cbf09e41d0c3c13e499be3b704e0037, 6a80142ac8cf4d5534d2eb9cb0e3e08d, b1a919e6fb009361b64d51b351a25e4c, 3ba79ba35b4b388fe9699e51d4c43fea, 26fc98d7481f9b494ecbfebacdcbeab3, c2f7a2599c9dea0e04d9d20a4eb2c0f0, e88d37df942ac9ab1432c686ef346a6c, f88c498d67b63c23ccab437d132be322, 9f8125060a075a7c7b3e8b13d630bcf9, 47a32262fbe86e120fd5d69e295b9fc3, e97524afde7b751f6b024fa4798bdf51"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2020-08-08"
      hash1 = "e91e3d9138b2961bf0807b39ab1c0647e78ccf6985890246db1d698af498e43b"
      hash2 = "8d887ba624e0e8f55be8deb805ec25c1a2a34e6fa137b6bc30025cfbc124dfb8"
      hash3 = "7d2a58520ab1dea0d33c5866fdfbb8ccfb5a446f200c6d4c064d14ff90cdf76c"
      hash4 = "4c9bf0426483d1f8f7943cb291345134964d237f1b8270f88f51cbdd1557a41e"
      hash5 = "bc2a8aa09df1303d24917145a3b41acf1b9df09c72e65273883c63b288623e2b"
      hash6 = "5d1ef3f5bc06e457945af001cad5e392eea47ae4486522ad3342f42b6e2b7436"
      hash7 = "cc38d385ce50ead01e56b0039e31c044d65ffd683a031c2a9bf8031a2a77bf17"
      hash8 = "2fefce5634c8b6f9e334fd6b1c34b86f6cb8278dc07558034d1ead43d1467cbb"
      hash9 = "2e999f22d7fa0d018342d235067b5bb879b4505bb0e42156f816d38ae61cd3fe"
      hash10 = "a0e6799ed9cb59ac3aeab73f2c10015fbabbacc850b56148778f69cc38835d27"
      hash11 = "a8efd58c2f819b96742b10bad9aa76494731295f32ccc9897d3694944017b2a4"
      hash12 = "ba3e5e8af6d21e5fa3a78b69a87ca1cd39afd4342795f514bd651af81e9b8e47"
      hash13 = "3b38ac70eac888ba76ae3c5812179863a78b4e63ce92f5108f019bb00f96b35c"
      hash14 = "66f0823a9d423952e39f087e2aeaad95ff9e03d45f1493fedc460d3adb1d2537"
      hash15 = "c8eb9182adc12b591cbdafe27759495487a53c0cd38f83f77f575edf21e5d4b3"
      hash16 = "72356978da0b156bae25c84189c01a47b7c8e8daf22e2be533f1e2733f8372f2"
      hash17 = "d274427049b5e28fdd153a0bdbcb08445ffebd9031ed666dba23b62e44b3191a"
      hash18 = "b95f40cce47499183ef95d6d56b8b5deed0d99a413a8bd7067200c5b1ae752a9"
      hash19 = "6c9ad0cbcb8156f327526451c3452837d5256283239a77f931b1a3f542e61b82"
      hash20 = "9741357a1d61e8777cbb9234b46369df7752b9950f069fef7154a8ce748619e3"
      hash21 = "5cb85aa8140676e879dfbf7d8811ee090d3e5f3de319918684ac6cc562f47450"
      hash22 = "a2cce624ed3e428075dedc5b4243c065baafe0a121de26d686756e487e4d7232"
      hash23 = "1b435cd0e002358d4ca191463d0fb54ea1136b53b74de8db93d61f935203392e"
      hash24 = "b81e7c41d4c6cec4c6f99f9e577c8335c685bf09351af664d82c2a97bc12b89c"
   strings:
      $s1 = "      <!--The ID below indicates application support for Windows 10 -->" fullword ascii
      $s2 = "      <!--The ID below indicates application support for Windows 8.1 -->" fullword ascii
      $s3 = "      <!--The ID below indicates application support for Windows 7 -->" fullword ascii
      $s4 = "      <!--The ID below indicates application support for Windows 8 -->" fullword ascii
      $s5 = "      <!--The ID below indicates application support for Windows Vista -->" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 27000KB and ( all of them )
      ) or ( all of them )
}

