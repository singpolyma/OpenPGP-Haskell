module OpenPGP.Crypto (verify, fingerprint) where

import Data.Word
import Data.Map (Map, (!))
import qualified Data.ByteString.Lazy as LZ

import Data.Binary
import qualified Codec.Encryption.RSA as RSA
import qualified Data.Digest.MD5 as MD5
import qualified Data.Digest.SHA1 as SHA1
import qualified Data.Digest.SHA256 as SHA256
import qualified Data.Digest.SHA384 as SHA384
import qualified Data.Digest.SHA512 as SHA512

import qualified OpenPGP as OpenPGP
import qualified BaseConvert as BaseConvert

-- http://tools.ietf.org/html/rfc4880#section-12.2
fingerprint :: OpenPGP.Packet -> String
fingerprint p | OpenPGP.version p == 4 =
	BaseConvert.toString 16 $ SHA1.toInteger $ SHA1.hash $
		LZ.unpack (LZ.concat (OpenPGP.fingerprint_material p))
fingerprint p | (OpenPGP.version p) `elem` [2, 3] =
	concat $ map (BaseConvert.toString 16) $
		MD5.hash $ LZ.unpack (LZ.concat (OpenPGP.fingerprint_material p))

find_key :: OpenPGP.Message -> String -> Maybe OpenPGP.Packet
find_key (OpenPGP.Message (x@(OpenPGP.PublicKeyPacket {}):xs)) keyid =
	find_key_ x xs keyid
find_key (OpenPGP.Message (x@(OpenPGP.SecretKeyPacket {}):xs)) keyid =
	find_key_ x xs keyid
find_key _ _ = Nothing

find_key_ :: OpenPGP.Packet -> [OpenPGP.Packet] -> String -> Maybe OpenPGP.Packet
find_key_ x xs keyid =
	if thisid == keyid then Just x else find_key (OpenPGP.Message xs) keyid
	where thisid = reverse $
		take (length keyid) (reverse (fingerprint x))

keyfield_as_octets :: OpenPGP.Packet -> Char -> [Word8]
keyfield_as_octets k f =
	LZ.unpack $ LZ.drop 2 (encode (k' ! f))
	where k' = OpenPGP.key k

-- http://tools.ietf.org/html/rfc3447#page-43
emsa_pkcs1_v1_5_hash_padding :: OpenPGP.HashAlgorithm -> [Word8]
emsa_pkcs1_v1_5_hash_padding OpenPGP.MD5 = [0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10]
emsa_pkcs1_v1_5_hash_padding OpenPGP.SHA1 = [0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14]
emsa_pkcs1_v1_5_hash_padding OpenPGP.SHA256 = [0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20]
emsa_pkcs1_v1_5_hash_padding OpenPGP.SHA384 = [0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30]
emsa_pkcs1_v1_5_hash_padding OpenPGP.SHA512 = [0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40]

hash :: OpenPGP.HashAlgorithm -> [Word8] -> [Word8]
hash OpenPGP.MD5 = MD5.hash
hash OpenPGP.SHA1 = reverse . drop 2 . LZ.unpack . encode . OpenPGP.MPI . SHA1.toInteger . SHA1.hash
hash OpenPGP.SHA256 = SHA256.hash
hash OpenPGP.SHA384 = SHA384.hash
hash OpenPGP.SHA512 = SHA512.hash

emsa_pkcs1_v1_5_encode :: [Word8] -> Int -> OpenPGP.HashAlgorithm -> [Word8]
emsa_pkcs1_v1_5_encode m emLen algo =
	[0, 1] ++ (replicate (emLen - (length t) - 3) 0xff) ++ [0] ++ t
	where t = (emsa_pkcs1_v1_5_hash_padding algo) ++ (hash algo m)

verify :: OpenPGP.Message -> OpenPGP.Message -> Int -> Bool
verify keys packet sigidx =
	encoded == (RSA.encrypt (n, e) raw_sig)
	where
	raw_sig = LZ.unpack $ LZ.drop 2 $ encode (OpenPGP.signature sig)
	encoded = emsa_pkcs1_v1_5_encode signature_over
		(length n) (OpenPGP.hash_algorithm sig)
	signature_over = LZ.unpack $ dta `LZ.append` (OpenPGP.trailer sig)
	(n, e) = (keyfield_as_octets k 'n', keyfield_as_octets k 'e')
	Just k = find_key keys issuer
	Just issuer = OpenPGP.signature_issuer sig
	sig = (sigs !! sigidx)
	(sigs, (OpenPGP.LiteralDataPacket {OpenPGP.content = dta}):_) =
		OpenPGP.signatures_and_data packet
