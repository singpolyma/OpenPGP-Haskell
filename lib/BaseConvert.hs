module BaseConvert (toString, toAlphaDigit) where

import Data.List

toBase :: (Integral a) => a -> a -> [a]
toBase _ 0 = [0]
toBase b v = reverse $
	unfoldr (\n -> if n == 0 then Nothing else Just (m n)) v
	where m n = let (q, r) = n `divMod` b in (r, q)

toAlphaDigit :: (Integral a) => a -> Char
toAlphaDigit n = (['0'..'9'] ++ ['A'..]) !! fromIntegral n

toString :: (Integral a) => a -> a -> String
toString b v = map toAlphaDigit (toBase b v)
