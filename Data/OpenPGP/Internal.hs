module Data.OpenPGP.Internal where

import Data.Word
import Data.Bits

decode_s2k_count :: Word8 -> Word32
decode_s2k_count c =  (16 + (fromIntegral c .&. 15)) `shiftL`
	((fromIntegral c `shiftR` 4) + 6)

encode_s2k_count :: Word32 -> Word8
encode_s2k_count iterations
	| iterations >= 65011712 = 255
	| decode_s2k_count result < iterations = result+1
	| otherwise = result
	where
	result = fromIntegral $ (fromIntegral c `shiftL` 4) .|. (count - 16)
	(count, c) = encode_s2k_count' (iterations `shiftR` 6) (0::Word8)
	encode_s2k_count' count c
		| count < 32 = (count, c)
		| otherwise = encode_s2k_count' (count `shiftR` 1) (c+1)
