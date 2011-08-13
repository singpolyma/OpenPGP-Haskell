-- | This is a wrapper around <http://hackage.haskell.org/package/Crypto>
-- that currently does fingerprint generation and signature verification.
--
-- The recommended way to import this module is:
--
-- > import qualified Data.OpenPGP.Crypto as OpenPGP
module Data.OpenPGP.Crypto (sign, verify, fingerprint) where

import Data.Word
import Data.List (find)
import Data.Map ((!))
import qualified Data.ByteString.Lazy as LZ
import qualified Data.ByteString.Lazy.UTF8 as LZ (fromString)

import Data.Binary
import Codec.Utils (fromOctets)
import qualified Codec.Encryption.RSA as RSA
import qualified Data.Digest.MD5 as MD5
import qualified Data.Digest.SHA1 as SHA1
import qualified Data.Digest.SHA256 as SHA256
import qualified Data.Digest.SHA384 as SHA384
import qualified Data.Digest.SHA512 as SHA512

import qualified Data.OpenPGP as OpenPGP
import qualified Data.BaseConvert as BaseConvert

-- | Generate a key fingerprint from a PublicKeyPacket or SecretKeyPacket
-- <http://tools.ietf.org/html/rfc4880#section-12.2>
fingerprint :: OpenPGP.Packet -> String
fingerprint p | OpenPGP.version p == 4 =
	BaseConvert.toString 16 $ SHA1.toInteger $ SHA1.hash $
		LZ.unpack (LZ.concat (OpenPGP.fingerprint_material p))
fingerprint p | OpenPGP.version p `elem` [2, 3] =
	concatMap (BaseConvert.toString 16) $
		MD5.hash $ LZ.unpack (LZ.concat (OpenPGP.fingerprint_material p))
fingerprint _ = error "Unsupported Packet version or type in fingerprint."

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
emsa_pkcs1_v1_5_hash_padding _ =
	error "Unsupported HashAlgorithm in emsa_pkcs1_v1_5_hash_padding."

hash :: OpenPGP.HashAlgorithm -> [Word8] -> [Word8]
hash OpenPGP.MD5 = MD5.hash
hash OpenPGP.SHA1 = reverse . drop 2 . LZ.unpack . encode . OpenPGP.MPI . SHA1.toInteger . SHA1.hash
hash OpenPGP.SHA256 = SHA256.hash
hash OpenPGP.SHA384 = SHA384.hash
hash OpenPGP.SHA512 = SHA512.hash
hash _ = error "Unsupported HashAlgorithm in hash."

emsa_pkcs1_v1_5_encode :: [Word8] -> Int -> OpenPGP.HashAlgorithm -> [Word8]
emsa_pkcs1_v1_5_encode m emLen algo =
	[0, 1] ++ replicate (emLen - length t - 3) 0xff ++ [0] ++ t
	where t = emsa_pkcs1_v1_5_hash_padding algo ++ hash algo m

-- | Verify a message signature.  Only supports RSA keys for now.
verify :: OpenPGP.Message    -- ^ Keys that may have made the signature
          -> OpenPGP.Message -- ^ LiteralData message to verify
          -> Int             -- ^ Index of signature to verify (0th, 1st, etc)
          -> Bool
verify keys message sigidx =
	encoded == RSA.encrypt (n, e) raw_sig
	where
	raw_sig = LZ.unpack $ LZ.drop 2 $ encode (OpenPGP.signature sig)
	encoded = emsa_pkcs1_v1_5_encode signature_over
		(length n) (OpenPGP.hash_algorithm sig)
	signature_over = LZ.unpack $ dta `LZ.append` OpenPGP.trailer sig
	(n, e) = (keyfield_as_octets k 'n', keyfield_as_octets k 'e')
	Just k = find_key keys issuer
	Just issuer = OpenPGP.signature_issuer sig
	sig = sigs !! sigidx
	(sigs, (OpenPGP.LiteralDataPacket {OpenPGP.content = dta}):_) =
		OpenPGP.signatures_and_data message

-- | Sign data or key/userID pair.  Only supports RSA keys for now.
sign :: OpenPGP.Message    -- ^ SecretKeys, one of which will be used
        -> OpenPGP.Message -- ^ Message containing data or key to sign, and optional signature packet
        -> OpenPGP.HashAlgorithm -- ^ HashAlgorithm to use is signature
        -> String  -- ^ KeyID of key to choose or @[]@ for first
        -> Integer -- ^ Timestamp for signature (unless sig supplied)
        -> OpenPGP.Packet
sign keys message hsh keyid timestamp =
	sig {
		OpenPGP.signature = OpenPGP.MPI $ toNum final,
		OpenPGP.hash_head = toNum $ take 2 final
	}
	where
	-- toNum has explicit param so that it can remain polymorphic
	toNum l = fromOctets (256::Integer) l
	final   = dropWhile (==0) $ RSA.decrypt (n, d) encoded
	encoded = emsa_pkcs1_v1_5_encode dta (length n) hsh
	(n, d)  = (keyfield_as_octets k 'n', keyfield_as_octets k 'd')
	dta     = LZ.unpack $ case signOver of {
		OpenPGP.LiteralDataPacket {OpenPGP.content = c} -> c;
		_ -> LZ.concat $ OpenPGP.fingerprint_material signOver ++ [
			LZ.singleton 0xB4,
			encode (fromIntegral (length firstUserID) :: Word32),
			LZ.fromString firstUserID
		]
	} `LZ.append` OpenPGP.trailer sig
	-- Always force key and hash algorithm
	sig     = let s = (findSigOrDefault (find isSignature m)) {
		OpenPGP.key_algorithm = OpenPGP.RSA,
		OpenPGP.hash_algorithm = hsh
	} in s { OpenPGP.trailer = OpenPGP.calculate_signature_trailer s }

	-- Either a SignaturePacket was found, or we need to make one
	findSigOrDefault (Just s) = s
	findSigOrDefault Nothing  = OpenPGP.SignaturePacket {
		OpenPGP.version = 4,
		OpenPGP.key_algorithm = undefined,
		OpenPGP.hash_algorithm = undefined,
		OpenPGP.signature_type = defaultStype,
		OpenPGP.hashed_subpackets = [
			-- Do we really need to pass in timestamp just for the default?
			OpenPGP.SignatureCreationTimePacket $ fromIntegral timestamp,
			OpenPGP.IssuerPacket keyid'
		] ++ (case signOver of
			OpenPGP.LiteralDataPacket {} -> []
			_ -> [] -- TODO: OpenPGP.KeyFlagsPacket [0x01, 0x02]
		),
		OpenPGP.unhashed_subpackets = [],
		OpenPGP.signature = undefined,
		OpenPGP.trailer = undefined,
		OpenPGP.hash_head = undefined
	}

	keyid'  = reverse $ take 16 $ reverse $ fingerprint k
	Just k  = find_key keys keyid

	Just (OpenPGP.UserIDPacket firstUserID) = find isUserID m

	defaultStype = case signOver of
		OpenPGP.LiteralDataPacket {OpenPGP.format = f} ->
			if f == 'b' then 0x00 else 0x01
		_ -> 0x13

	Just signOver = find isSignable m
	OpenPGP.Message m = message

	isSignable (OpenPGP.LiteralDataPacket {}) = True
	isSignable (OpenPGP.PublicKeyPacket {})   = True
	isSignable (OpenPGP.SecretKeyPacket {})   = True
	isSignable _                              = False

	isSignature (OpenPGP.SignaturePacket {})  = True
	isSignature _                             = False

	isUserID (OpenPGP.UserIDPacket {})        = True
	isUserID _                                = False
