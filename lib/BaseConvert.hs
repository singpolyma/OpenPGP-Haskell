module BaseConvert (toString, toAlphaDigit) where

import Data.Char

toBase :: (Integral a) => a -> a -> [a]
toBase b v = (toBase' [] v)
	where
	toBase' a 0 = a
	toBase' a v = toBase' (r:a) q
		where (q,r) = v `divMod` b

toAlphaDigit :: (Integral a) => a -> Char
toAlphaDigit n | n < 10    = chr ((fromIntegral n) + ord '0')
               | otherwise = chr ((fromIntegral n) + ord 'A' - 10)

toString :: (Integral a) => a -> a -> String
toString b v = map toAlphaDigit (toBase b v)
