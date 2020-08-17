/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2020-08-06
   Identifier: 1_2000_black
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _match_1623 {
   strings:
      $s1 = "m64j___hw.dll" fullword ascii
      $s2 = "K0U0b0l0p" fullword ascii /* base64 encoded string '+E4oIt' */
      $s3 = "4 4$4(4,4044484<4@" fullword ascii /* hex encoded string 'DD@DHD' */
      $s4 = "\"=5=<=B=" fullword ascii /* hex encoded string '[' */
      $s5 = ">#>)>/>5>0" fullword ascii /* hex encoded string 'P' */
      $s6 = ": :(:,:0:4:8:<:@:D:L:P:T:X:\\:`:d:h:t:|:" fullword ascii
      $s7 = "Q\"DZ:\"?" fullword ascii
      $s8 = "D:L:T:\\:" fullword ascii
      $s9 = "?#?i?{?" fullword ascii /* Goodware String - occured 1 times */
      $s10 = "EDcdn)I" fullword ascii
      $s11 = "VWgB''r" fullword ascii
      $s12 = ".fafyxijfhkdanfrzz" fullword ascii
      $s13 = "HlGD|Bh" fullword ascii
      $s14 = "D4H4L4P4" fullword ascii /* Goodware String - occured 1 times */
      $s15 = "4'4E4S4" fullword ascii /* Goodware String - occured 1 times */
      $s16 = "T=`=l=" fullword ascii /* Goodware String - occured 1 times */
      $s17 = "YNhe$ rs@" fullword ascii
      $s18 = "80<0@0D0H0X0\\0" fullword ascii /* Goodware String - occured 1 times */
      $s19 = "4 9$9(9,9094989<9@9D9H9L9P9T9X9\\9`9d9h9l9p9t9x9|9" fullword ascii /* Goodware String - occured 1 times */
      $s20 = "7.8:8[8" fullword ascii /* Goodware String - occured 1 times */
   condition:
      ( uint16(0) == 0x0000 and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule _match_63{
   
   strings:
      $s1 = "Variant Also Negotiates" fullword ascii
      $s2 = "Unavailable For Legal Reasons" fullword ascii
      $s3 = "Not Extended" fullword ascii /* Goodware String - occured 1 times */
      $s4 = "Insufficient Storage" fullword ascii /* Goodware String - occured 2 times */
      $s5 = "Failed Dependency" fullword ascii /* Goodware String - occured 2 times */
      $s6 = "Unprocessable Entity" fullword ascii /* Goodware String - occured 2 times */
      $s7 = "Upgrade Required" fullword ascii /* Goodware String - occured 4 times */
   condition:
      ( uint16(0) == 0x0000 and filesize < 27000KB and ( all of them )
      ) or ( all of them )
}

rule _match_80 {
   
   strings:
      $s1 = "The document root must not be followed by other values." fullword ascii
      $s2 = "Missing a comma or ']' after an array element." fullword ascii
      $s3 = "Unspecific syntax error." fullword ascii
      $s4 = "Missing a comma or '}' after an object member." fullword ascii
      $s5 = "Terminate parsing due to Handler error." fullword ascii
      $s6 = "Missing a closing quotation mark in string." fullword ascii
      $s7 = "Miss exponent in number." fullword ascii
      $s8 = "The surrogate pair in string is invalid." fullword ascii
      $s9 = "Invalid encoding in string." fullword ascii
      $s10 = "The document is empty." fullword ascii
      $s11 = "Number too big to be stored in double." fullword ascii
      $s12 = "Invalid value." fullword ascii
      $s13 = "Missing a name for object member." fullword ascii
      $s14 = "Miss fraction part in number." fullword ascii
      $s15 = "Missing a colon after a name of object member." fullword ascii
      $s16 = "Incorrect hex digit after \\u escape in string." fullword ascii
      $s17 = "Invalid escape character in string." fullword ascii
   condition:
      ( uint16(0) == 0x0000 and filesize < 27000KB and ( 8 of them )
      ) or ( all of them )
}

rule _match_51 {

   strings:
      $s1 = "[%s] login error code: %d" fullword ascii
      $s2 = "[%s] connect error: \"%s\"" fullword ascii
      $s3 = "[%s] read error: \"%s\"" fullword ascii
      $s4 = "[%s] JSON decode failed: \"%s\"" fullword ascii
      $s5 = "[%s] JSON decode failed" fullword ascii
      $s6 = "[%s] DNS error: \"%s\"" fullword ascii
      $s7 = "[%s] error: \"%s\", code: %d" fullword ascii
      $s8 = "[%s] unsupported method: \"%s\"" fullword ascii
      $s9 = "[0;36m %s %s " fullword ascii
      $s10 = "[1;37m%s:%d" fullword ascii
      $s11 = "[1;36m%s H/s" fullword ascii
      $s12 = "[1;37mspeed" fullword ascii
      $s13 = "[1;36mH/s" fullword ascii
      $s14 = "[0m max " fullword ascii
      $s15 = "[0m 10s/60s/15m " fullword ascii
      $s16 = "[1;36m%s" fullword ascii
   condition:
      ( uint16(0) == 0x0000 and filesize < 25000KB and ( 8 of them )
      ) or ( all of them )
}

rule _match_40 {
   
   strings:
      $s1 = "elit, sed do eiusmod tempor incididunt ut labore" fullword ascii
      $s2 = "sunt in culpa qui officia deserunt mollit anim id est laborum." fullword ascii
      $s3 = "ut aliquip ex ea commodo consequat. Duis aute" fullword ascii
      $s4 = "irure dolor in reprehenderit in voluptate velit" fullword ascii
      $s5 = "quis nostrud exercitation ullamco laboris nisi" fullword ascii
      $s6 = "esse cillum dolore eu fugiat nulla pariatur." fullword ascii
      $s7 = "cryptonight/double" fullword ascii
      $s8 = "cryptonight/zls" fullword ascii
      $s9 = "Lorem ipsum dolor sit amet, consectetur adipiscing" fullword ascii
      $s10 = "cryptonight/rwz" fullword ascii
      $s11 = "et dolore magna aliqua. Ut enim ad minim veniam," fullword ascii
      $s12 = "This is a test This is a test This is a test" fullword ascii
      $s13 = "cn/rwz" fullword ascii
      $s14 = "cn/zls" fullword ascii
      $s15 = "cn/double" fullword ascii
      $s16 = "Excepteur sint occaecat cupidatat non proident," fullword ascii
   condition:
      ( uint16(0) == 0x0000 and filesize < 25000KB and ( 8 of them )
      ) or ( all of them )
}

rule _match_60 {

   strings:
      $s1 = "Payload Too Large" fullword ascii
      $s2 = "Already Reported" fullword ascii
      $s3 = "Range Not Satisfiable" fullword ascii
      $s4 = "Misdirected Request" fullword ascii
      $s5 = "Multi-Status" fullword ascii /* Goodware String - occured 1 times */
      $s6 = "Loop Detected" fullword ascii /* Goodware String - occured 2 times */
      $s7 = "IM Used" fullword ascii
      $s8 = "URI Too Long" fullword ascii
      $s9 = "Too Many Requests" fullword ascii /* Goodware String - occured 5 times */
      $s10 = "Precondition Required" fullword ascii /* Goodware String - occured 5 times */
      $s11 = "Network Authentication Required" fullword ascii /* Goodware String - occured 5 times */
   condition:
      ( uint16(0) == 0x0000 and filesize < 27000KB and ( 8 of them )
      ) or ( all of them )
}

rule _match_43 {

   strings:
      $s1 = "cryptonight-heavy/tube" fullword ascii
      $s2 = "cryptonight-heavy" fullword ascii
      $s3 = "cn-heavy/tube" fullword ascii
      $s4 = "cryptonight-lite/0" fullword ascii
      $s5 = "cryptonight-heavy/0" fullword ascii
      $s6 = "cryptonight-heavy/xhv" fullword ascii
      $s7 = "cn-heavy/0" fullword ascii
      $s8 = "cn-heavy/xhv" fullword ascii
      $s9 = "cryptonight-lite/1" fullword ascii
      $s10 = "recW~|" fullword ascii
      $s11 = "cn-light" fullword ascii
      $s12 = "cn-lite" fullword ascii
      $s13 = "cn-lite/1" fullword ascii
      $s14 = "cn-lite/0" fullword ascii
      $s15 = "cn-heavy" fullword ascii
   condition:
      ( uint16(0) == 0x0000 and filesize < 25000KB and ( 8 of them )
      ) or ( all of them )
}

rule _match_88 {
   
   strings:
      $s1 = "LOGONSERVER=" fullword wide
      $s2 = "SYSTEMROOT=" fullword wide
      $s3 = "SYSTEMDRIVE=" fullword wide
      $s4 = "WINDIR=" fullword wide
      $s5 = "USERDOMAIN=" fullword wide /* Goodware String - occured 2 times */
      $s6 = "USERNAME=" fullword wide /* Goodware String - occured 2 times */
      $s7 = "USERPROFILE=" fullword wide /* Goodware String - occured 2 times */
   condition:
      ( uint16(0) == 0x0000 and filesize < 27000KB and ( all of them )
      ) or ( all of them )
}

rule _match_40_1 {

   strings:
      $s1 = "B0H9A0r" fullword ascii
      $s2 = "N L9cp" fullword ascii
      $s3 = "t3;{h|\"" fullword ascii
      $s4 = "taH9_`u" fullword ascii
      $s5 = "N L9cpt" fullword ascii
      $s6 = "F@H9G " fullword ascii
      $s7 = "A H;B r" fullword ascii
   condition:
      ( uint16(0) == 0x0000 and filesize < 17000KB and ( all of them )) or ( all of them )
}

rule _match_43_1 {
  
   strings:
      $s1 = "@PI3@@f" fullword ascii
      $s2 = "BPH3B@fD" fullword ascii
      $s3 = "API3A@f" fullword ascii
      $s4 = "API3A@fH" fullword ascii
      $s5 = "y I39I" fullword ascii
      $s6 = "JXH3JHfL" fullword ascii
      $s7 = "IXI3IHI" fullword ascii
      $s8 = "IXI3IHfH" fullword ascii
      $s9 = "BPH3B@f" fullword ascii
   condition:
      ( uint16(0) == 0x0000 and filesize < 25000KB and ( all of them )) or ( all of them )
}

rule _match_57 {

   strings:
      $s1 = "[1;32m * " fullword ascii
      $s2 = "[0;31m" fullword ascii
      $s3 = "[1;37m%s" fullword ascii
      $s4 = "[1;37m" fullword ascii
      $s5 = "[1;30m" fullword ascii
      $s6 = "[0;33m" fullword ascii
   condition:
      ( uint16(0) == 0x0000 and filesize < 25000KB and ( all of them )
      ) or ( all of them )
}



rule _match_41 {

   strings:
      $s1 = "[1;37m%-13sauto:%s" fullword ascii
      $s2 = "[1;32mintel" fullword ascii
      $s3 = "[1;37m%-13s%s" fullword ascii
      $s4 = "[1;31mnone" fullword ascii
      $s5 = "[1;32mryzen" fullword ascii
   condition:
      ( uint16(0) == 0x0000 and filesize < 25000KB and ( all of them )
      ) or ( all of them )
}

rule _match_55 {

   strings:
      $s1 = "T$p3T$@" fullword ascii
      $s2 = "D$h121J" fullword ascii
      $s3 = "D$x3D$T" fullword ascii
      $s4 = "|$83|$ " fullword ascii
      $s5 = "D$t3D$|" fullword ascii /* Goodware String - occured 5 times */
   condition:
      ( uint16(0) == 0x0000 and filesize < 4000KB and ( all of them )
      ) or ( all of them )
}

rule _match_63_1 {

   strings:
      $s1 = "hugepages" fullword ascii
      $s2 = "shares_total" fullword ascii
      $s3 = "hashes_total" fullword ascii
      $s4 = "worker_id" fullword ascii
      $s5 = "donate_level" fullword ascii
   condition:
      ( uint16(0) == 0x0000 and filesize < 27000KB and ( all of them )
      ) or ( all of them )
}


rule _match_56 {

   strings:
      $s1 = "[1;37mCOMMANDS" fullword ascii
      $s2 = "[1;37mause, " fullword ascii
      $s3 = "[1;36m%s/%s" fullword ascii
      $s4 = "[1;37m%-13s" fullword ascii
      $s5 = "[1;31m-" fullword ascii
      $s6 = "[1;37mesume" fullword ascii
      $s7 = "[1;32m" fullword ascii
   condition:
      ( uint16(0) == 0x0000 and filesize < 25000KB and ( all of them )
      ) or ( all of them )
}

