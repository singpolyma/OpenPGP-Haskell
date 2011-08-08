module BaseConvert (toString, toNum, toAlphaDigit, fromAlphaDigit) where

import Data.Sequence
import Data.Foldable (toList)
import Data.List
import Data.Char

digit_alphabet = ['0'..'9'] ++ ['A'..]

toBase :: (Integral a) => a -> a -> [a]
toBase _ 0 = [0]
toBase b v = toList $
	unfoldl (\n -> if n == 0 then Nothing else Just (n `divMod` b)) v

toAlphaDigit :: (Integral a) => a -> Char
toAlphaDigit = (digit_alphabet !!) . fromIntegral

toString :: (Integral a) => a -> a -> String
toString b v = map toAlphaDigit (toBase b v)

fromAlphaDigit :: (Num a) => Char -> a
fromAlphaDigit v = fromIntegral n
	where Just n = elemIndex (toUpper v) digit_alphabet

fromBase :: (Num a) => a -> [a] -> a
fromBase b = foldl (\n k -> n * b + k) 0

toNum :: (Num a) => a -> String -> a
toNum b v = fromBase b (map fromAlphaDigit v)
