-- | Main implementation of the OpenPGP message format <http://tools.ietf.org/html/rfc4880>
--
-- The recommended way to import this module is:
--
-- > import qualified Data.OpenPGP as OpenPGP
module Data.OpenPGP (Message(..), Packet(..), SignatureSubpacket(..), HashAlgorithm(..), KeyAlgorithm(..), CompressionAlgorithm(..), MPI(..), fingerprint_material, signatures_and_data, signature_issuer, calculate_signature_trailer, decode_s2k_count, encode_s2k_count) where

import Control.Monad
import Data.Bits
import Data.Word
import Data.Map (Map, (!))
import qualified Data.Map as Map
import qualified Data.ByteString.Lazy as LZ
import qualified Data.ByteString.Lazy.UTF8 as LZ (toString, fromString)

import Data.Binary
import Data.Binary.Get
import Data.Binary.Put
import qualified Codec.Compression.Zlib.Raw as Zip
import qualified Codec.Compression.Zlib as Zlib
import qualified Codec.Compression.BZip as BZip2

import qualified Data.BaseConvert as BaseConvert

data Packet =
	SignaturePacket {
		version::Word8,
		signature_type::Word8,
		key_algorithm::KeyAlgorithm,
		hash_algorithm::HashAlgorithm,
		hashed_subpackets::[SignatureSubpacket],
		unhashed_subpackets::[SignatureSubpacket],
		hash_head::Word16,
		signature::MPI,
		trailer::LZ.ByteString
	} |
	OnePassSignaturePacket {
		version::Word8,
		signature_type::Word8,
		hash_algorithm::HashAlgorithm,
		key_algorithm::KeyAlgorithm,
		key_id::String,
		nested::Word8
	} |
	PublicKeyPacket {
		version::Word8,
		timestamp::Word32,
		key_algorithm::KeyAlgorithm,
		key::Map Char MPI
	} |
	SecretKeyPacket {
		version::Word8,
		timestamp::Word32,
		key_algorithm::KeyAlgorithm,
		key::Map Char MPI,
		s2k_useage::Word8,
		symmetric_type::Word8,
		s2k_type::Word8,
		s2k_hash_algorithm::HashAlgorithm,
		s2k_salt::Word64,
		s2k_count::Word32,
		encrypted_data::LZ.ByteString,
		private_hash::Maybe LZ.ByteString -- the hash may be in the encrypted data
	} |
	CompressedDataPacket {
		compression_algorithm::CompressionAlgorithm,
		message::Message
	} |
	LiteralDataPacket {
		format::Char,
		filename::String,
		timestamp::Word32,
		content::LZ.ByteString
	} |
	UserIDPacket String
	deriving (Show, Read, Eq)

instance Binary Packet where
	put p = do
		-- First two bits are 1 for new packet format
		put ((tag .|. 0xC0) :: Word8)
		-- Use 5-octet lengths
		put (255 :: Word8)
		put ((fromIntegral $ LZ.length body) :: Word32)
		putLazyByteString body
		where
		(body, tag) = put_packet p
	get = do
		tag <- get :: Get Word8
		let (t, l) =
			if (tag .&. 64) /= 0 then
				(tag .&. 63, parse_new_length)
			else
				((tag `shiftR` 2) .&. 15, parse_old_length tag)
		len <- l
		-- This forces the whole packet to be consumed
		packet <- getLazyByteString (fromIntegral len)
		return $ runGet (parse_packet t) packet

-- http://tools.ietf.org/html/rfc4880#section-4.2.2
parse_new_length :: Get Word32
parse_new_length = do
	len <- fmap fromIntegral (get :: Get Word8)
	case len of
		-- One octet length
		_ | len < 192 -> return len
		-- Two octet length
		_ | len > 191 && len < 224 -> do
			second <- fmap fromIntegral (get :: Get Word8)
			return $ ((len - 192) `shiftL` 8) + second + 192
		-- Five octet length
		255 -> get :: Get Word32
		-- TODO: Partial body lengths. 1 << (len & 0x1F)
		_ -> fail "Unsupported new packet length."

-- http://tools.ietf.org/html/rfc4880#section-4.2.1
parse_old_length :: Word8 -> Get Word32
parse_old_length tag =
	case tag .&. 3 of
		-- One octet length
		0 -> fmap fromIntegral (get :: Get Word8)
		-- Two octet length
		1 -> fmap fromIntegral (get :: Get Word16)
		-- Four octet length
		2 -> get
		-- Indeterminate length
		3 -> fmap fromIntegral remaining
		-- Error
		_ -> fail "Unsupported old packet length."

-- http://tools.ietf.org/html/rfc4880#section-5.5.2
public_key_fields :: KeyAlgorithm -> [Char]
public_key_fields RSA     = ['n', 'e']
public_key_fields RSA_E   = public_key_fields RSA
public_key_fields RSA_S   = public_key_fields RSA
public_key_fields ELGAMAL = ['p', 'g', 'y']
public_key_fields DSA     = ['p', 'q', 'g', 'y']
public_key_fields _       = undefined -- Nothing in the spec. Maybe empty

-- http://tools.ietf.org/html/rfc4880#section-5.5.3
secret_key_fields :: KeyAlgorithm -> [Char]
secret_key_fields RSA     = ['d', 'p', 'q', 'u']
secret_key_fields RSA_E   = secret_key_fields RSA
secret_key_fields RSA_S   = secret_key_fields RSA
secret_key_fields ELGAMAL = ['x']
secret_key_fields DSA     = ['x']
secret_key_fields _       = undefined -- Nothing in the spec. Maybe empty

-- Need this seperate for trailer calculation
signature_packet_start :: Packet -> LZ.ByteString
signature_packet_start (SignaturePacket {
	version = 4,
	signature_type = signature_type,
	key_algorithm = key_algorithm,
	hash_algorithm = hash_algorithm,
	hashed_subpackets = hashed_subpackets
}) =
	LZ.concat [
		encode (0x04 :: Word8),
		encode signature_type,
		encode key_algorithm,
		encode hash_algorithm,
		encode ((fromIntegral $ LZ.length hashed_subs) :: Word16),
		hashed_subs
	]
	where
	hashed_subs = LZ.concat $ map encode hashed_subpackets
signature_packet_start _ =
	error "Trying to get start of signature packet for non signature packet."

-- The trailer is just the top of the body plus some crap
calculate_signature_trailer :: Packet -> LZ.ByteString
calculate_signature_trailer p =
	LZ.concat [
		signature_packet_start p,
		encode (0x04 :: Word8),
		encode (0xff :: Word8),
		encode (fromIntegral (LZ.length $ signature_packet_start p) :: Word32)
	]

put_packet :: (Num a) => Packet -> (LZ.ByteString, a)
put_packet (SignaturePacket { version = 4,
                              signature_type = signature_type,
                              key_algorithm = key_algorithm,
                              hash_algorithm = hash_algorithm,
                              hashed_subpackets = hashed_subpackets,
                              unhashed_subpackets = unhashed_subpackets,
                              hash_head = hash_head,
                              signature = signature }) =
	(LZ.concat [ LZ.singleton 4, encode signature_type,
	            encode key_algorithm, encode hash_algorithm,
	            encode (fromIntegral $ LZ.length hashed :: Word16),
	            hashed,
	            encode (fromIntegral $ LZ.length unhashed :: Word16),
	            unhashed,
	            encode hash_head, encode signature ], 2)
	where
	hashed   = LZ.concat $ map encode hashed_subpackets
	unhashed = LZ.concat $ map encode unhashed_subpackets
put_packet (OnePassSignaturePacket { version = version,
                                     signature_type = signature_type,
                                     hash_algorithm = hash_algorithm,
                                     key_algorithm = key_algorithm,
                                     key_id = key_id,
                                     nested = nested }) =
	(LZ.concat [ encode version, encode signature_type,
	             encode hash_algorithm, encode key_algorithm,
	             encode (BaseConvert.toNum 16 key_id :: Word64),
	             encode nested ], 4)
put_packet (SecretKeyPacket { version = version, timestamp = timestamp,
                              key_algorithm = algorithm, key = key,
                              s2k_useage = s2k_useage,
                              symmetric_type = symmetric_type,
                              s2k_type = s2k_type,
                              s2k_hash_algorithm = s2k_hash_algo,
                              s2k_salt = s2k_salt,
                              s2k_count = s2k_count,
                              encrypted_data = encrypted_data }) =
	(LZ.concat $ [p, encode s2k_useage] ++
	(if s2k_useage `elem` [255, 254] then
		[encode symmetric_type, encode s2k_type, encode s2k_hash_algo] ++
		(if s2k_type `elem` [1, 3] then [encode s2k_salt] else []) ++
		if s2k_type == 3 then [encode $ encode_s2k_count s2k_count] else []
	else []) ++
	(if s2k_useage > 0 then
		[encrypted_data]
	else s ++
		-- XXX: Checksum is part of encrypted_data for V4 ONLY
		if s2k_useage == 254 then
			[LZ.replicate 20 0] -- TODO SHA1 Checksum
		else
			[encode (fromIntegral $
				LZ.foldl (\c i -> (c + fromIntegral i) `mod` 65536)
				(0::Integer) (LZ.concat s) :: Word16)]), 5)
	where
	p = fst (put_packet $ PublicKeyPacket version timestamp algorithm key
		:: (LZ.ByteString, Integer)) -- Supress warning
	s = map (encode . (key !)) (secret_key_fields algorithm)
put_packet (PublicKeyPacket { version = 4, timestamp = timestamp,
                              key_algorithm = algorithm, key = key }) =
	(LZ.concat $ [LZ.singleton 4, encode timestamp, encode algorithm] ++
		map (encode . (key !)) (public_key_fields algorithm), 6)
put_packet (CompressedDataPacket { compression_algorithm = algorithm,
                                   message = message }) =
	(LZ.append (encode algorithm) $ compress $ encode message, 8)
	where
	compress = case algorithm of
		Uncompressed -> id
		ZIP          -> Zip.compress
		ZLIB         -> Zlib.compress
		BZip2        -> BZip2.compress
		x            -> error ("No implementation for " ++ show x)
put_packet (LiteralDataPacket { format = format, filename = filename,
                                timestamp = timestamp, content = content
                              }) =
	(LZ.concat [encode format, encode filename_l, lz_filename,
	            encode timestamp, content], 11)
	where
	filename_l  = (fromIntegral $ LZ.length lz_filename) :: Word8
	lz_filename = LZ.fromString filename
put_packet (UserIDPacket txt) = (LZ.fromString txt, 13)
put_packet _ = error "Unsupported Packet version or type in put_packet."

parse_packet :: Word8 -> Get Packet
-- SignaturePacket, http://tools.ietf.org/html/rfc4880#section-5.2
parse_packet  2 = do
	version <- get
	case version of
		3 -> undefined -- TODO: V3 sigs
		4 -> do
			signature_type <- get
			key_algorithm <- get
			hash_algorithm <- get
			hashed_size <- fmap fromIntegral (get :: Get Word16)
			hashed_data <- getLazyByteString hashed_size
			let hashed = runGet get_signature_subpackets hashed_data
			unhashed_size <- fmap fromIntegral (get :: Get Word16)
			unhashed_data <- getLazyByteString unhashed_size
			let unhashed = runGet get_signature_subpackets unhashed_data
			hash_head <- get
			signature <- get
			return SignaturePacket {
				version = version,
				signature_type = signature_type,
				key_algorithm = key_algorithm,
				hash_algorithm = hash_algorithm,
				hashed_subpackets = hashed,
				unhashed_subpackets = unhashed,
				hash_head = hash_head,
				signature = signature,
				trailer = LZ.concat [encode version, encode signature_type, encode key_algorithm, encode hash_algorithm, encode (fromIntegral hashed_size :: Word16), hashed_data, LZ.pack [4, 0xff], encode ((6 + fromIntegral hashed_size) :: Word32)]
			}
		x -> fail $ "Unknown SignaturePacket version " ++ show x ++ "."
-- OnePassSignaturePacket, http://tools.ietf.org/html/rfc4880#section-5.4
parse_packet  4 = do
	version <- get
	signature_type <- get
	hash_algo <- get
	key_algo <- get
	key_id <- get :: Get Word64
	nested <- get
	return OnePassSignaturePacket {
		version = version,
		signature_type = signature_type,
		hash_algorithm = hash_algo,
		key_algorithm = key_algo,
		key_id = BaseConvert.toString 16 key_id,
		nested = nested
	}
-- SecretKeyPacket, http://tools.ietf.org/html/rfc4880#section-5.5.3
parse_packet  5 = do
	-- Parse PublicKey part
	(PublicKeyPacket {
		version = version,
		timestamp = timestamp,
		key_algorithm = algorithm,
		key = key
	}) <- parse_packet 6
	s2k_useage <- get :: Get Word8
	let k = SecretKeyPacket version timestamp algorithm key s2k_useage
	k' <- case s2k_useage of
		_ | s2k_useage `elem` [255, 254] -> do
			symmetric_type <- get
			s2k_type <- get
			s2k_hash_algorithm <- get
			s2k_salt <- if s2k_type `elem` [1, 3] then get
				else return undefined
			s2k_count <- if s2k_type == 3 then fmap decode_s2k_count get else
				return undefined
			return (k symmetric_type s2k_type s2k_hash_algorithm
				s2k_salt s2k_count)
		_ | s2k_useage > 0 ->
			-- s2k_useage is symmetric_type in this case
			return (k s2k_useage undefined undefined undefined undefined)
		_ ->
			return (k undefined undefined undefined undefined undefined)
	if s2k_useage > 0 then do {
		encrypted <- getRemainingLazyByteString;
		return (k' encrypted Nothing)
	} else do
		key <- foldM (\m f -> do
			mpi <- get :: Get MPI
			return $ Map.insert f mpi m) key (secret_key_fields algorithm)
		private_hash <- getRemainingLazyByteString
		return ((k' undefined (Just private_hash)) {key = key})
-- PublicKeyPacket, http://tools.ietf.org/html/rfc4880#section-5.5.2
parse_packet  6 = do
	version <- get :: Get Word8
	case version of
		4 -> do
			timestamp <- get
			algorithm <- get
			key <- mapM (\f -> do
				mpi <- get :: Get MPI
				return (f, mpi)) (public_key_fields algorithm)
			return PublicKeyPacket {
				version = 4,
				timestamp = timestamp,
				key_algorithm = algorithm,
				key = Map.fromList key
			}
		x -> fail $ "Unsupported PublicKeyPacket version " ++ show x ++ "."
-- CompressedDataPacket, http://tools.ietf.org/html/rfc4880#section-5.6
parse_packet  8 = do
	algorithm <- get
	message <- getRemainingLazyByteString
	let decompress = case algorithm of
		Uncompressed -> id
		ZIP          -> Zip.decompress
		ZLIB         -> Zlib.decompress
		BZip2        -> BZip2.decompress
		x            -> error ("No implementation for " ++ show x)
	return CompressedDataPacket {
		compression_algorithm = algorithm,
		message = runGet (get :: Get Message) (decompress message)
	}
-- LiteralDataPacket, http://tools.ietf.org/html/rfc4880#section-5.9
parse_packet 11 = do
	format <- get
	filenameLength <- get :: Get Word8
	filename <- getLazyByteString (fromIntegral filenameLength)
	timestamp <- get
	content <- getRemainingLazyByteString
	return LiteralDataPacket {
		format = format,
		filename = LZ.toString filename,
		timestamp = timestamp,
		content = content
	}
-- UserIDPacket, http://tools.ietf.org/html/rfc4880#section-5.11
parse_packet 13 =
	fmap (UserIDPacket . LZ.toString) getRemainingLazyByteString
-- Fail nicely for unimplemented packets
parse_packet x = fail $ "Unimplemented OpenPGP packet tag " ++ show x ++ "."

-- | Helper method for fingerprints and such
fingerprint_material :: Packet -> [LZ.ByteString]
fingerprint_material (PublicKeyPacket {version = 4,
                      timestamp = timestamp,
                      key_algorithm = algorithm,
                      key = key}) =
	[
		LZ.singleton 0x99,
		encode (6 + fromIntegral (LZ.length material) :: Word16),
		LZ.singleton 4, encode timestamp, encode algorithm,
		material
	]
	where
	material =
		LZ.concat $ map (encode . (key !)) (public_key_fields algorithm)
-- Proxy to make SecretKeyPacket work
fingerprint_material (SecretKeyPacket {version = 4,
                      timestamp = timestamp,
                      key_algorithm = algorithm,
                      key = key}) =
	fingerprint_material PublicKeyPacket {version = 4,
                      timestamp = timestamp,
                      key_algorithm = algorithm,
                      key = key}
fingerprint_material p | version p `elem` [2, 3] = [n, e]
	where
	n = LZ.drop 2 (encode (key p ! 'n'))
	e = LZ.drop 2 (encode (key p ! 'e'))
fingerprint_material _ =
	error "Unsupported Packet version or type in fingerprint_material."

enum_to_word8 :: (Enum a) => a -> Word8
enum_to_word8 = fromIntegral . fromEnum

enum_from_word8 :: (Enum a) => Word8 -> a
enum_from_word8 = toEnum . fromIntegral

data HashAlgorithm = MD5 | SHA1 | RIPEMD160 | SHA256 | SHA384 | SHA512 | SHA224 | HashAlgorithm Word8
	deriving (Show, Read, Eq)

instance Enum HashAlgorithm where
	toEnum 01 = MD5
	toEnum 02 = SHA1
	toEnum 03 = RIPEMD160
	toEnum 08 = SHA256
	toEnum 09 = SHA384
	toEnum 10 = SHA512
	toEnum 11 = SHA224
	toEnum x  = HashAlgorithm $ fromIntegral x
	fromEnum MD5       = 01
	fromEnum SHA1      = 02
	fromEnum RIPEMD160 = 03
	fromEnum SHA256    = 08
	fromEnum SHA384    = 09
	fromEnum SHA512    = 10
	fromEnum SHA224    = 11
	fromEnum (HashAlgorithm x) = fromIntegral x

instance Binary HashAlgorithm where
	put = put . enum_to_word8
	get = fmap enum_from_word8 get

data KeyAlgorithm = RSA | RSA_E | RSA_S | ELGAMAL | DSA | ECC | ECDSA | DH | KeyAlgorithm Word8
	deriving (Show, Read, Eq)

instance Enum KeyAlgorithm where
	toEnum 01 = RSA
	toEnum 02 = RSA_E
	toEnum 03 = RSA_S
	toEnum 16 = ELGAMAL
	toEnum 17 = DSA
	toEnum 18 = ECC
	toEnum 19 = ECDSA
	toEnum 21 = DH
	toEnum x  = KeyAlgorithm $ fromIntegral x
	fromEnum RSA     = 01
	fromEnum RSA_E   = 02
	fromEnum RSA_S   = 03
	fromEnum ELGAMAL = 16
	fromEnum DSA     = 17
	fromEnum ECC     = 18
	fromEnum ECDSA   = 19
	fromEnum DH      = 21
	fromEnum (KeyAlgorithm x) = fromIntegral x

instance Binary KeyAlgorithm where
	put = put . enum_to_word8
	get = fmap enum_from_word8 get

data CompressionAlgorithm = Uncompressed | ZIP | ZLIB | BZip2 | CompressionAlgorithm Word8
	deriving (Show, Read, Eq)

instance Enum CompressionAlgorithm where
	toEnum 0 = Uncompressed
	toEnum 1 = ZIP
	toEnum 2 = ZLIB
	toEnum 3 = BZip2
	toEnum x = CompressionAlgorithm $ fromIntegral x
	fromEnum Uncompressed = 0
	fromEnum ZIP          = 1
	fromEnum ZLIB         = 2
	fromEnum BZip2        = 3
	fromEnum (CompressionAlgorithm x) = fromIntegral x

instance Binary CompressionAlgorithm where
	put = put . enum_to_word8
	get = fmap enum_from_word8 get

-- A message is encoded as a list that takes the entire file
newtype Message = Message [Packet] deriving (Show, Read, Eq)
instance Binary Message where
	put (Message []) = return ()
	put (Message (x:xs)) = do
		put x
		put (Message xs)
	get = do
		done <- isEmpty
		if done then return (Message []) else do
			next_packet <- get
			(Message tail) <- get
			return $ Message (next_packet:tail)

-- | Extract all signature and data packets from a 'Message'
signatures_and_data :: Message -> ([Packet], [Packet])
signatures_and_data (Message ((CompressedDataPacket {message = m}):_)) =
	signatures_and_data m
signatures_and_data (Message lst) =
	(filter isSig lst, filter isDta lst)
	where
	isSig (SignaturePacket {}) = True
	isSig _ = False
	isDta (LiteralDataPacket {}) = True
	isDta _ = False

newtype MPI = MPI Integer deriving (Show, Read, Eq, Ord)
instance Binary MPI where
	put (MPI i) = do
		put (((fromIntegral . LZ.length $ bytes) - 1) * 8
			+ floor (logBase (2::Double) $ fromIntegral (bytes `LZ.index` 0))
			+ 1 :: Word16)
		putLazyByteString bytes
		where
		bytes = LZ.reverse $ LZ.unfoldr (\x ->
				if x == 0 then Nothing else
					Just (fromIntegral x, x `shiftR` 8)
			) i
	get = do
		length <- fmap fromIntegral (get :: Get Word16)
		bytes <- getLazyByteString ((length + 7) `div` 8)
		return (MPI (LZ.foldl (\a b ->
			a `shiftL` 8 .|. fromIntegral b) 0 bytes))

data SignatureSubpacket =
	SignatureCreationTimePacket Word32 |
	IssuerPacket String
	deriving (Show, Read, Eq)

instance Binary SignatureSubpacket where
	put p = do
		-- Use 5-octet-length + 1 for tag as the first packet body octet
		put (255 :: Word8)
		put (fromIntegral (LZ.length body) + 1 :: Word32)
		put tag
		putLazyByteString body
		where
		(body, tag) = put_signature_subpacket p
	get = do
		len <- fmap fromIntegral (get :: Get Word8)
		len <- case len of
			_ | len > 190 && len < 255 -> do -- Two octet length
				second <- fmap fromIntegral (get :: Get Word8)
				return $ ((len - 192) `shiftR` 8) + second + 192
			255 -> -- Five octet length
				fmap fromIntegral (get :: Get Word32)
			_ -> -- One octet length, no furthur processing
				return len
		tag <- get :: Get Word8
		-- This forces the whole packet to be consumed
		packet <- getLazyByteString (len-1)
		return $ runGet (parse_signature_subpacket tag) packet

-- | Find the keyid that issued a SignaturePacket
signature_issuer :: Packet -> Maybe String
signature_issuer (SignaturePacket {hashed_subpackets = hashed,
                                   unhashed_subpackets = unhashed}) =
	if length issuers > 0 then Just issuer else Nothing
	where IssuerPacket issuer = issuers !! 0
	      issuers = filter isIssuer hashed ++ filter isIssuer unhashed
	      isIssuer (IssuerPacket {}) = True
	      isIssuer _ = False
signature_issuer _ = Nothing

put_signature_subpacket :: SignatureSubpacket -> (LZ.ByteString, Word8)
put_signature_subpacket (SignatureCreationTimePacket time) =
	(encode time, 2)
put_signature_subpacket (IssuerPacket keyid) =
	(encode (BaseConvert.toNum 16 keyid :: Word64), 16)

get_signature_subpackets :: Get [SignatureSubpacket]
get_signature_subpackets = do
	done <- isEmpty
	if done then return [] else do {
		next_packet <- get :: Get SignatureSubpacket;
		tail <- get_signature_subpackets;
		return (next_packet:tail);
	}

parse_signature_subpacket :: Word8 -> Get SignatureSubpacket
-- SignatureCreationTimePacket, http://tools.ietf.org/html/rfc4880#section-5.2.3.4
parse_signature_subpacket  2 = fmap SignatureCreationTimePacket get
-- IssuerPacket, http://tools.ietf.org/html/rfc4880#section-5.2.3.5
parse_signature_subpacket 16 = do
	keyid <- get :: Get Word64
	return $ IssuerPacket (BaseConvert.toString 16 keyid)
-- Fail nicely for unimplemented packets
parse_signature_subpacket x =
	fail $ "Unimplemented OpenPGP signature subpacket tag " ++ show x ++ "."

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
