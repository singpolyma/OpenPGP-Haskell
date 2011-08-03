module BaseConvert (toString, toAlphaDigit) where

import Data.Sequence
import Data.Foldable

toBase :: (Integral a) => a -> a -> [a]
toBase _ 0 = [0]
toBase b v = toList $
	unfoldl (\n -> if n == 0 then Nothing else Just (n `divMod` b)) v

toAlphaDigit :: (Integral a) => a -> Char
toAlphaDigit = ((!!) (['0'..'9'] ++ ['A'..])) . fromIntegral

toString :: (Integral a) => a -> a -> String
toString b v = map toAlphaDigit (toBase b v)
