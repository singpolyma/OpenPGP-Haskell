{-# LANGUAGE CPP #-}
-- | Main implementation of the OpenPGP message format <http://tools.ietf.org/html/rfc4880>
--
-- The recommended way to import this module is:
--
-- > import qualified Data.OpenPGP as OpenPGP
module Data.OpenPGP (
	Packet(
		AsymmetricSessionKeyPacket,
		OnePassSignaturePacket,
		PublicKeyPacket,
		SecretKeyPacket,
		CompressedDataPacket,
		MarkerPacket,
		LiteralDataPacket,
		UserIDPacket,
		ModificationDetectionCodePacket,
		UnsupportedPacket,
		compression_algorithm,
		content,
		encrypted_data,
		filename,
		format,
		hash_algorithm,
		hashed_subpackets,
		hash_head,
		key,
		is_subkey,
		v3_days_of_validity,
		key_algorithm,
		key_id,
		message,
		nested,
		private_hash,
		s2k_count,
		s2k_hash_algorithm,
		s2k_salt,
		s2k_type,
		s2k_useage,
		signature,
		signature_type,
		symmetric_type,
		timestamp,
		trailer,
		unhashed_subpackets,
		version
	),
	isSignaturePacket,
	signaturePacket,
	Message(..),
	SignatureSubpacket(..),
	HashAlgorithm(..),
	KeyAlgorithm(..),
	SymmetricAlgorithm(..),
	CompressionAlgorithm(..),
	RevocationCode(..),
	MPI(..),
	find_key,
	fingerprint_material,
	signatures_and_data,
	signature_issuer
) where

import Numeric
import Control.Monad
import Control.Arrow
import Control.Applicative
import Control.Exception (assert)
import Data.Bits
import Data.Word
import Data.Char
import Data.Maybe
import Data.List
import Data.OpenPGP.Internal
import qualified Data.ByteString.Lazy as LZ

#ifdef CEREAL
import Data.Serialize
import qualified Data.ByteString as B
import qualified Data.ByteString.UTF8 as B (toString, fromString)
#define BINARY_CLASS Serialize
#else
import Data.Binary
import Data.Binary.Get
import Data.Binary.Put
import qualified Data.ByteString.Lazy as B
import qualified Data.ByteString.Lazy.UTF8 as B (toString, fromString)
#define BINARY_CLASS Binary
#endif

import qualified Codec.Compression.Zlib.Raw as Zip
import qualified Codec.Compression.Zlib as Zlib
import qualified Codec.Compression.BZip as BZip2

#ifdef CEREAL
getRemainingByteString :: Get B.ByteString
getRemainingByteString = remaining >>= getByteString

getSomeByteString :: Word64 -> Get B.ByteString
getSomeByteString = getByteString . fromIntegral

putSomeByteString :: B.ByteString -> Put
putSomeByteString = putByteString

unsafeRunGet :: Get a -> B.ByteString -> a
unsafeRunGet g bs = let Right v = runGet g bs in v

compress :: CompressionAlgorithm -> B.ByteString -> B.ByteString
compress algo = toStrictBS . lazyCompress algo . toLazyBS

decompress :: CompressionAlgorithm -> B.ByteString -> B.ByteString
decompress algo = toStrictBS . lazyDecompress algo . toLazyBS

toStrictBS :: LZ.ByteString -> B.ByteString
toStrictBS = B.concat . LZ.toChunks

toLazyBS :: B.ByteString -> LZ.ByteString
toLazyBS = LZ.fromChunks . (:[])
#else
getRemainingByteString :: Get B.ByteString
getRemainingByteString = getRemainingLazyByteString

getSomeByteString :: Word64 -> Get B.ByteString
getSomeByteString = getLazyByteString . fromIntegral

putSomeByteString :: B.ByteString -> Put
putSomeByteString = putLazyByteString

unsafeRunGet :: Get a -> B.ByteString -> a
unsafeRunGet = runGet

compress :: CompressionAlgorithm -> B.ByteString -> B.ByteString
compress = lazyCompress

decompress :: CompressionAlgorithm -> B.ByteString -> B.ByteString
decompress = lazyDecompress
#endif

lazyCompress :: CompressionAlgorithm -> LZ.ByteString -> LZ.ByteString
lazyCompress Uncompressed = id
lazyCompress ZIP          = Zip.compress
lazyCompress ZLIB         = Zlib.compress
lazyCompress BZip2        = BZip2.compress
lazyCompress x            = error ("No implementation for " ++ show x)

lazyDecompress :: CompressionAlgorithm -> LZ.ByteString -> LZ.ByteString
lazyDecompress Uncompressed = id
lazyDecompress ZIP          = Zip.decompress
lazyDecompress ZLIB         = Zlib.decompress
lazyDecompress BZip2        = BZip2.decompress
lazyDecompress x            = error ("No implementation for " ++ show x)

assertProp :: (a -> Bool) -> a -> a
assertProp f x = assert (f x) x

pad :: Int -> String -> String
pad l s = replicate (l - length s) '0' ++ s

data Packet =
	AsymmetricSessionKeyPacket {
		version::Word8,
		key_id::String,
		key_algorithm::KeyAlgorithm,
		encrypted_data::B.ByteString
	} |
	SignaturePacket {
		version::Word8,
		signature_type::Word8,
		key_algorithm::KeyAlgorithm,
		hash_algorithm::HashAlgorithm,
		hashed_subpackets::[SignatureSubpacket],
		unhashed_subpackets::[SignatureSubpacket],
		hash_head::Word16,
		signature::[MPI],
		trailer::B.ByteString
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
		key::[(Char,MPI)],
		is_subkey::Bool,
		v3_days_of_validity::Maybe Word16
	} |
	SecretKeyPacket {
		version::Word8,
		timestamp::Word32,
		key_algorithm::KeyAlgorithm,
		key::[(Char,MPI)],
		s2k_useage::Word8, -- determines if the Maybes are Just or Nothing
		symmetric_type::Maybe Word8,
		s2k_type::Maybe Word8,
		s2k_hash_algorithm::Maybe HashAlgorithm,
		s2k_salt::Maybe Word64,
		s2k_count::Maybe Word32,
		encrypted_data::B.ByteString,
		private_hash::Maybe B.ByteString, -- the hash may be in the encrypted data
		is_subkey::Bool
	} |
	CompressedDataPacket {
		compression_algorithm::CompressionAlgorithm,
		message::Message
	} |
	MarkerPacket |
	LiteralDataPacket {
		format::Char,
		filename::String,
		timestamp::Word32,
		content::B.ByteString
	} |
	UserIDPacket String |
	ModificationDetectionCodePacket B.ByteString |
	UnsupportedPacket Word8 B.ByteString
	deriving (Show, Read, Eq)

instance BINARY_CLASS Packet where
	put p = do
		-- First two bits are 1 for new packet format
		put ((tag .|. 0xC0) :: Word8)
		case tag of
			19 -> put (assertProp (<192) blen :: Word8)
			_  -> do
				-- Use 5-octet lengths
				put (255 :: Word8)
				put (blen :: Word32)
				putSomeByteString body
		where
		blen :: (Num a) => a
		blen = fromIntegral $ B.length body
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
		packet <- getSomeByteString (fromIntegral len)
		return $ unsafeRunGet (parse_packet t) packet

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

(!) :: (Eq k) => [(k,v)] -> k -> v
(!) xs = fromJust . (`lookup` xs)

-- Need this seperate for trailer calculation
signature_packet_start :: Packet -> B.ByteString
signature_packet_start (SignaturePacket {
	version = 4,
	signature_type = signature_type,
	key_algorithm = key_algorithm,
	hash_algorithm = hash_algorithm,
	hashed_subpackets = hashed_subpackets
}) =
	B.concat [
		encode (0x04 :: Word8),
		encode signature_type,
		encode key_algorithm,
		encode hash_algorithm,
		encode ((fromIntegral $ B.length hashed_subs) :: Word16),
		hashed_subs
	]
	where
	hashed_subs = B.concat $ map encode hashed_subpackets
signature_packet_start x =
	error ("Trying to get start of signature packet for: " ++ show x)

-- The trailer is just the top of the body plus some crap
calculate_signature_trailer :: Packet -> B.ByteString
calculate_signature_trailer (SignaturePacket { version = v,
                                               signature_type = signature_type,
                                               unhashed_subpackets = unhashed_subpackets
                                             }) | v `elem` [2,3] =
	B.concat [
		encode signature_type,
		encode creation_time
	]
	where
	Just (SignatureCreationTimePacket creation_time) = find isCreation unhashed_subpackets
	isCreation (SignatureCreationTimePacket {}) = True
	isCreation _ = False
calculate_signature_trailer p@(SignaturePacket {version = 4}) =
	B.concat [
		signature_packet_start p,
		encode (0x04 :: Word8),
		encode (0xff :: Word8),
		encode (fromIntegral (B.length $ signature_packet_start p) :: Word32)
	]
calculate_signature_trailer x =
	error ("Trying to calculate signature trailer for: " ++ show x)

put_packet :: Packet -> (B.ByteString, Word8)
put_packet (AsymmetricSessionKeyPacket version key_id key_algorithm dta) =
	(B.concat [
		encode version,
		encode (fst $ head $ readHex key_id :: Word64),
		encode key_algorithm,
		dta
	], 1)
put_packet (SignaturePacket { version = v,
                              unhashed_subpackets = unhashed_subpackets,
                              key_algorithm = key_algorithm,
                              hash_algorithm = hash_algorithm,
                              hash_head = hash_head,
                              signature = signature,
                              trailer = trailer }) | v `elem` [2,3] =
	-- TODO: Assert that there are no subpackets we cannot encode?
	(B.concat $ [
		B.singleton v,
		B.singleton 0x05,
		trailer, -- signature_type and creation_time
		encode keyid,
		encode key_algorithm,
		encode hash_algorithm,
		encode hash_head
	] ++ map encode signature, 2)
	where
	keyid = fst $ head $ readHex keyidS :: Word64
	Just (IssuerPacket keyidS) = find isIssuer unhashed_subpackets
	isIssuer (IssuerPacket {}) = True
	isIssuer _ = False
put_packet (SignaturePacket { version = 4,
                              unhashed_subpackets = unhashed_subpackets,
                              hash_head = hash_head,
                              signature = signature,
                              trailer = trailer }) =
	(B.concat $ [
		trailer_top,
		encode (fromIntegral $ B.length unhashed :: Word16),
		unhashed, encode hash_head
	] ++ map encode signature, 2)
	where
	trailer_top = B.reverse $ B.drop 6 $ B.reverse trailer
	unhashed = B.concat $ map encode unhashed_subpackets
put_packet (OnePassSignaturePacket { version = version,
                                     signature_type = signature_type,
                                     hash_algorithm = hash_algorithm,
                                     key_algorithm = key_algorithm,
                                     key_id = key_id,
                                     nested = nested }) =
	(B.concat [
		encode version, encode signature_type,
		encode hash_algorithm, encode key_algorithm,
		encode (fst $ head $ readHex key_id :: Word64),
		encode nested
	], 4)
put_packet (SecretKeyPacket { version = version, timestamp = timestamp,
                              key_algorithm = algorithm, key = key,
                              s2k_useage = s2k_useage,
                              symmetric_type = symmetric_type,
                              s2k_type = s2k_type,
                              s2k_hash_algorithm = s2k_hash_algo,
                              s2k_salt = s2k_salt,
                              s2k_count = s2k_count,
                              encrypted_data = encrypted_data,
                              is_subkey = is_subkey }) =
	(B.concat $ [p, encode s2k_useage] ++
	(if s2k_useage `elem` [255, 254] then
		[encode $ fromJust symmetric_type, encode s2k_t,
		 encode $ fromJust s2k_hash_algo] ++
		(if s2k_t `elem` [1,3] then [encode $ fromJust s2k_salt] else []) ++
		if s2k_t == 3 then
			[encode $ encode_s2k_count $ fromJust s2k_count] else []
	else []) ++
	(if s2k_useage > 0 then
		[encrypted_data]
	else s ++
		-- XXX: Checksum is part of encrypted_data for V4 ONLY
		if s2k_useage == 254 then
			[B.replicate 20 0] -- TODO SHA1 Checksum
		else
			[encode (fromIntegral $
				B.foldl (\c i -> (c + fromIntegral i) `mod` 65536)
				(0::Integer) (B.concat s) :: Word16)]),
	if is_subkey then 7 else 5)
	where
	(Just s2k_t) = s2k_type
	p = fst (put_packet $
		PublicKeyPacket version timestamp algorithm key False Nothing)
	s = map (encode . (key !)) (secret_key_fields algorithm)
put_packet p@(PublicKeyPacket { version = v, timestamp = timestamp,
                              key_algorithm = algorithm, key = key,
                              is_subkey = is_subkey })
	| v == 3 =
		final (B.concat $ [
			B.singleton 3, encode timestamp,
			encode (fromJust $ v3_days_of_validity p),
			encode algorithm
		] ++ material)
	| v == 4 =
		final (B.concat $ [
			B.singleton 4, encode timestamp, encode algorithm
		] ++ material)
	where
	final x = (x, if is_subkey then 14 else 6)
	material = map (encode . (key !)) (public_key_fields algorithm)
put_packet (CompressedDataPacket { compression_algorithm = algorithm,
                                   message = message }) =
	(B.append (encode algorithm) $ compress algorithm $ encode message, 8)
put_packet MarkerPacket = (B.fromString "PGP", 10)
put_packet (LiteralDataPacket { format = format, filename = filename,
                                timestamp = timestamp, content = content
                              }) =
	(B.concat [
		encode format, encode filename_l, lz_filename,
		encode timestamp, content
	], 11)
	where
	filename_l  = (fromIntegral $ B.length lz_filename) :: Word8
	lz_filename = B.fromString filename
put_packet (UserIDPacket txt) = (B.fromString txt, 13)
put_packet (ModificationDetectionCodePacket bstr) = (bstr, 19)
put_packet (UnsupportedPacket tag bytes) = (bytes, fromIntegral tag)
put_packet x = error ("Unsupported Packet version or type in put_packet: " ++ show x)

parse_packet :: Word8 -> Get Packet
-- AsymmetricSessionKeyPacket, http://tools.ietf.org/html/rfc4880#section-5.1
parse_packet  1 = AsymmetricSessionKeyPacket
	<$> fmap (assertProp (==3)) get
	<*> fmap (pad 16 . map toUpper . flip showHex "") (get :: Get Word64)
	<*> get
	<*> getRemainingByteString
-- SignaturePacket, http://tools.ietf.org/html/rfc4880#section-5.2
parse_packet  2 = do
	version <- get
	case version of
		_ | version `elem` [2,3] -> do
			_ <- fmap (assertProp (==5)) (get :: Get Word8)
			signature_type <- get
			creation_time <- get :: Get Word32
			keyid <- get :: Get Word64
			key_algorithm <- get
			hash_algorithm <- get
			hash_head <- get
			signature <- listUntilEnd
			return SignaturePacket {
				version = version,
				signature_type = signature_type,
				key_algorithm = key_algorithm,
				hash_algorithm = hash_algorithm,
				hashed_subpackets = [],
				unhashed_subpackets = [
					SignatureCreationTimePacket creation_time,
					IssuerPacket $ pad 16 $ map toUpper $ showHex keyid ""
				],
				hash_head = hash_head,
				signature = signature,
				trailer = B.concat [encode signature_type, encode creation_time]
			}
		4 -> do
			signature_type <- get
			key_algorithm <- get
			hash_algorithm <- get
			hashed_size <- fmap fromIntegral (get :: Get Word16)
			hashed_data <- getSomeByteString hashed_size
			let hashed = unsafeRunGet listUntilEnd hashed_data
			unhashed_size <- fmap fromIntegral (get :: Get Word16)
			unhashed_data <- getSomeByteString unhashed_size
			let unhashed = unsafeRunGet listUntilEnd unhashed_data
			hash_head <- get
			signature <- listUntilEnd
			return SignaturePacket {
				version = version,
				signature_type = signature_type,
				key_algorithm = key_algorithm,
				hash_algorithm = hash_algorithm,
				hashed_subpackets = hashed,
				unhashed_subpackets = unhashed,
				hash_head = hash_head,
				signature = signature,
				trailer = B.concat [encode version, encode signature_type, encode key_algorithm, encode hash_algorithm, encode (fromIntegral hashed_size :: Word16), hashed_data, B.pack [4, 0xff], encode ((6 + fromIntegral hashed_size) :: Word32)]
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
		key_id = pad 16 $ map toUpper $ showHex key_id "",
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
			return (k (Just symmetric_type) (Just s2k_type)
				(Just s2k_hash_algorithm) (Just s2k_salt) (Just s2k_count))
		_ | s2k_useage > 0 ->
			-- s2k_useage is symmetric_type in this case
			return (k (Just s2k_useage) Nothing Nothing Nothing Nothing)
		_ ->
			return (k Nothing Nothing Nothing Nothing Nothing)
	if s2k_useage > 0 then do {
		encrypted <- getRemainingByteString;
		return (k' encrypted Nothing False)
	} else do
		key <- foldM (\m f -> do
			mpi <- get :: Get MPI
			return $ (f,mpi):m) key (secret_key_fields algorithm)
		private_hash <- getRemainingByteString
		return ((k' B.empty (Just private_hash) False) {key = key})
-- PublicKeyPacket, http://tools.ietf.org/html/rfc4880#section-5.5.2
parse_packet  6 = do
	version <- get :: Get Word8
	case version of
		3 -> do
			timestamp <- get
			days <- get
			algorithm <- get
			key <- mapM (\f -> fmap ((,)f) get) (public_key_fields algorithm)
			return PublicKeyPacket {
				version = version,
				timestamp = timestamp,
				key_algorithm = algorithm,
				key = key,
				is_subkey = False,
				v3_days_of_validity = Just days
			}
		4 -> do
			timestamp <- get
			algorithm <- get
			key <- mapM (\f -> fmap ((,)f) get) (public_key_fields algorithm)
			return PublicKeyPacket {
				version = 4,
				timestamp = timestamp,
				key_algorithm = algorithm,
				key = key,
				is_subkey = False,
				v3_days_of_validity = Nothing
			}
		x -> fail $ "Unsupported PublicKeyPacket version " ++ show x ++ "."
-- Secret-SubKey Packet, http://tools.ietf.org/html/rfc4880#section-5.5.1.4
parse_packet  7 = do
	p <- parse_packet 5
	return p {is_subkey = True}
-- CompressedDataPacket, http://tools.ietf.org/html/rfc4880#section-5.6
parse_packet  8 = do
	algorithm <- get
	message <- getRemainingByteString
	return CompressedDataPacket {
		compression_algorithm = algorithm,
		message = unsafeRunGet get (decompress algorithm message)
	}
-- MarkerPacket, http://tools.ietf.org/html/rfc4880#section-5.8
parse_packet 10 = return MarkerPacket
-- LiteralDataPacket, http://tools.ietf.org/html/rfc4880#section-5.9
parse_packet 11 = do
	format <- get
	filenameLength <- get :: Get Word8
	filename <- getSomeByteString (fromIntegral filenameLength)
	timestamp <- get
	content <- getRemainingByteString
	return LiteralDataPacket {
		format = format,
		filename = B.toString filename,
		timestamp = timestamp,
		content = content
	}
-- UserIDPacket, http://tools.ietf.org/html/rfc4880#section-5.11
parse_packet 13 =
	fmap (UserIDPacket . B.toString) getRemainingByteString
-- Public-Subkey Packet, http://tools.ietf.org/html/rfc4880#section-5.5.1.2
parse_packet 14 = do
	p <- parse_packet 6
	return p {is_subkey = True}
-- ModificationDetectionCodePacket, http://tools.ietf.org/html/rfc4880#section-5.14
parse_packet 19 =
	fmap ModificationDetectionCodePacket getRemainingByteString
-- Represent unsupported packets as their tag and literal bytes
parse_packet tag = fmap (UnsupportedPacket tag) getRemainingByteString

-- | Helper method for fingerprints and such
fingerprint_material :: Packet -> [B.ByteString]
fingerprint_material p | version p == 4 =
	[
		B.singleton 0x99,
		encode (6 + fromIntegral (B.length material) :: Word16),
		B.singleton 4, encode (timestamp p), encode (key_algorithm p),
		material
	]
	where
	material = B.concat $ map (encode . (key p !))
		(public_key_fields $ key_algorithm p)
fingerprint_material p | version p `elem` [2, 3] = [n, e]
	where
	n = B.drop 2 (encode (key p ! 'n'))
	e = B.drop 2 (encode (key p ! 'e'))
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

instance BINARY_CLASS HashAlgorithm where
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

instance BINARY_CLASS KeyAlgorithm where
	put = put . enum_to_word8
	get = fmap enum_from_word8 get

data SymmetricAlgorithm = Unencrypted | IDEA | TripleDES | CAST5 | Blowfish | AES128 | AES192 | AES256 | Twofish | SymmetricAlgorithm Word8
	deriving (Show, Read, Eq)

instance Enum SymmetricAlgorithm where
	toEnum 00 = Unencrypted
	toEnum 01 = IDEA
	toEnum 02 = TripleDES
	toEnum 03 = CAST5
	toEnum 04 = Blowfish
	toEnum 07 = AES128
	toEnum 08 = AES192
	toEnum 09 = AES256
	toEnum 10 = Twofish
	toEnum x  = SymmetricAlgorithm $ fromIntegral x
	fromEnum Unencrypted = 00
	fromEnum IDEA        = 01
	fromEnum TripleDES   = 02
	fromEnum CAST5       = 03
	fromEnum Blowfish    = 04
	fromEnum AES128      = 07
	fromEnum AES192      = 08
	fromEnum AES256      = 09
	fromEnum Twofish     = 10
	fromEnum (SymmetricAlgorithm x) = fromIntegral x

instance BINARY_CLASS SymmetricAlgorithm where
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

instance BINARY_CLASS CompressionAlgorithm where
	put = put . enum_to_word8
	get = fmap enum_from_word8 get

data RevocationCode = NoReason | KeySuperseded | KeyCompromised | KeyRetired | UserIDInvalid | RevocationCode Word8 deriving (Show, Read, Eq)

instance Enum RevocationCode where
	toEnum 00 = NoReason
	toEnum 01 = KeySuperseded
	toEnum 02 = KeyCompromised
	toEnum 03 = KeyRetired
	toEnum 32 = UserIDInvalid
	toEnum  x = RevocationCode $ fromIntegral x
	fromEnum NoReason       = 00
	fromEnum KeySuperseded  = 01
	fromEnum KeyCompromised = 02
	fromEnum KeyRetired     = 03
	fromEnum UserIDInvalid  = 32
	fromEnum (RevocationCode x) = fromIntegral x

instance BINARY_CLASS RevocationCode where
	put = put . enum_to_word8
	get = fmap enum_from_word8 get

-- A message is encoded as a list that takes the entire file
newtype Message = Message [Packet] deriving (Show, Read, Eq)
instance BINARY_CLASS Message where
	put (Message xs) = mapM_ put xs
	get = fmap Message listUntilEnd

-- | Extract all signature and data packets from a 'Message'
signatures_and_data :: Message -> ([Packet], [Packet])
signatures_and_data (Message ((CompressedDataPacket {message = m}):_)) =
	signatures_and_data m
signatures_and_data (Message lst) =
	(filter isSignaturePacket lst, filter isDta lst)
	where
	isDta (LiteralDataPacket {}) = True
	isDta _ = False

newtype MPI = MPI Integer deriving (Show, Read, Eq, Ord)
instance BINARY_CLASS MPI where
	put (MPI i) = do
		put (bitl :: Word16)
		putSomeByteString bytes
		where
		(bytes, bitl)
			| B.null bytes' = (B.singleton 0, 1)
			| otherwise     =
				(bytes', (fromIntegral (B.length bytes') - 1) * 8 + sigBit)

		sigBit = fst $ until ((==0) . snd)
			(first (+1) . second (`shiftR` 1)) (0,B.index bytes 0)
		bytes' = B.reverse $ B.unfoldr (\x ->
				if x == 0 then Nothing else
					Just (fromIntegral x, x `shiftR` 8)
			) (assertProp (>=0) i)
	get = do
		length <- fmap fromIntegral (get :: Get Word16)
		bytes <- getSomeByteString (assertProp (>0) $ (length + 7) `div` 8)
		return (MPI (B.foldl (\a b ->
			a `shiftL` 8 .|. fromIntegral b) 0 bytes))

listUntilEnd :: (BINARY_CLASS a) => Get [a]
listUntilEnd = do
	done <- isEmpty
	if done then return [] else do
		next <- get
		rest <- listUntilEnd
		return (next:rest)

-- http://tools.ietf.org/html/rfc4880#section-5.2.3.1
data SignatureSubpacket =
	SignatureCreationTimePacket Word32 |
	SignatureExpirationTimePacket Word32 | -- seconds after CreationTime
	ExportableCertificationPacket Bool |
	TrustSignaturePacket {depth::Word8, trust::Word8} |
	RegularExpressionPacket String |
	RevocablePacket Bool |
	KeyExpirationTimePacket Word32 | -- seconds after key CreationTime
	PreferredSymmetricAlgorithmsPacket [SymmetricAlgorithm] |
	RevocationKeyPacket {
		sensitive::Bool,
		revocation_key_algorithm::KeyAlgorithm,
		revocation_key_fingerprint::String
	} |
	IssuerPacket String |
	NotationDataPacket {
		human_readable::Bool,
		notation_name::String,
		notation_value::String
	} |
	PreferredHashAlgorithmsPacket [HashAlgorithm] |
	PreferredCompressionAlgorithmsPacket [CompressionAlgorithm] |
	KeyServerPreferencesPacket {keyserver_no_modify::Bool} |
	PreferredKeyServerPacket String |
	PrimaryUserIDPacket Bool |
	PolicyURIPacket String |
	KeyFlagsPacket {
		certify_keys::Bool,
		sign_data::Bool,
		encrypt_communication::Bool,
		encrypt_storage::Bool,
		split_key::Bool,
		authentication::Bool,
		group_key::Bool
	} |
	SignerUserIDPacket String |
	ReasonForRevocationPacket RevocationCode String |
	FeaturesPacket {supports_mdc::Bool} |
	SignatureTargetPacket {
		target_key_algorithm::KeyAlgorithm,
		target_hash_algorithm::HashAlgorithm,
		hash::B.ByteString
	} |
	EmbeddedSignaturePacket Packet |
	UnsupportedSignatureSubpacket Word8 B.ByteString
	deriving (Show, Read, Eq)

instance BINARY_CLASS SignatureSubpacket where
	put p = do
		-- Use 5-octet-length + 1 for tag as the first packet body octet
		put (255 :: Word8)
		put (fromIntegral (B.length body) + 1 :: Word32)
		put tag
		putSomeByteString body
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
		tag <- fmap stripCrit get :: Get Word8
		-- This forces the whole packet to be consumed
		packet <- getSomeByteString (len-1)
		return $ unsafeRunGet (parse_signature_subpacket tag) packet
		where
		-- TODO: Decide how to actually encode the "is critical" data
		-- instead of just ignoring it
		stripCrit tag = if tag .&. 0x80 == 0x80 then tag .&. 0x7f else tag

put_signature_subpacket :: SignatureSubpacket -> (B.ByteString, Word8)
put_signature_subpacket (SignatureCreationTimePacket time) =
	(encode time, 2)
put_signature_subpacket (SignatureExpirationTimePacket time) =
	(encode time, 3)
put_signature_subpacket (ExportableCertificationPacket exportable) =
	(encode $ enum_to_word8 exportable, 4)
put_signature_subpacket (TrustSignaturePacket depth trust) =
	(B.concat [encode depth, encode trust], 5)
put_signature_subpacket (RegularExpressionPacket regex) =
	(B.concat [B.fromString regex, B.singleton 0], 6)
put_signature_subpacket (RevocablePacket exportable) =
	(encode $ enum_to_word8 exportable, 7)
put_signature_subpacket (KeyExpirationTimePacket time) =
	(encode time, 9)
put_signature_subpacket (PreferredSymmetricAlgorithmsPacket algos) =
	(B.concat $ map encode algos, 11)
put_signature_subpacket (RevocationKeyPacket sensitive kalgo fpr) =
	(B.concat [encode bitfield, encode kalgo, fprb], 12)
	where
	bitfield = 0x80 .|. (if sensitive then 0x40 else 0x0) :: Word8
	fprb = B.drop 2 $ encode (MPI fpri)
	fpri = fst $ head $ readHex fpr
put_signature_subpacket (IssuerPacket keyid) =
	(encode (fst $ head $ readHex keyid :: Word64), 16)
put_signature_subpacket (NotationDataPacket human_readable name value) =
	(B.concat [
		B.pack [flag1,0,0,0],
		encode (fromIntegral (B.length namebs) :: Word16),
		encode (fromIntegral (B.length valuebs) :: Word16),
		namebs,
		valuebs
	], 20)
	where
	valuebs = B.fromString value
	namebs = B.fromString name
	flag1 = if human_readable then 0x80 else 0x0
put_signature_subpacket (PreferredHashAlgorithmsPacket algos) =
	(B.concat $ map encode algos, 21)
put_signature_subpacket (PreferredCompressionAlgorithmsPacket algos) =
	(B.concat $ map encode algos, 22)
put_signature_subpacket (KeyServerPreferencesPacket no_modify) =
	(B.singleton (if no_modify then 0x80 else 0x0), 23)
put_signature_subpacket (PreferredKeyServerPacket uri) =
	(B.fromString uri, 24)
put_signature_subpacket (PrimaryUserIDPacket isprimary) =
	(encode $ enum_to_word8 isprimary, 25)
put_signature_subpacket (PolicyURIPacket uri) =
	(B.fromString uri, 26)
put_signature_subpacket (KeyFlagsPacket certify sign encryptC encryptS split auth group) =
	(B.singleton $
		flag 0x01 certify  .|.
		flag 0x02 sign     .|.
		flag 0x04 encryptC .|.
		flag 0x08 encryptS .|.
		flag 0x10 split    .|.
		flag 0x20 auth     .|.
		flag 0x80 group
	, 27)
	where
	flag x True = x
	flag _ False = 0x0
put_signature_subpacket (SignerUserIDPacket userid) =
	(B.fromString userid, 28)
put_signature_subpacket (ReasonForRevocationPacket code string) =
	(B.concat [encode code, B.fromString string], 29)
put_signature_subpacket (FeaturesPacket supports_mdc) =
	(B.singleton $ if supports_mdc then 0x01 else 0x00, 30)
put_signature_subpacket (SignatureTargetPacket kalgo halgo hash) =
	(B.concat [encode kalgo, encode halgo, hash], 31)
put_signature_subpacket (EmbeddedSignaturePacket packet) =
	(fst $ put_packet (assertProp isSignaturePacket packet), 32)
put_signature_subpacket (UnsupportedSignatureSubpacket tag bytes) =
	(bytes, tag)

parse_signature_subpacket :: Word8 -> Get SignatureSubpacket
-- SignatureCreationTimePacket, http://tools.ietf.org/html/rfc4880#section-5.2.3.4
parse_signature_subpacket  2 = fmap SignatureCreationTimePacket get
-- SignatureExpirationTimePacket, http://tools.ietf.org/html/rfc4880#section-5.2.3.10
parse_signature_subpacket  3 = fmap SignatureExpirationTimePacket get
-- ExportableCertificationPacket, http://tools.ietf.org/html/rfc4880#section-5.2.3.11
parse_signature_subpacket  4 =
	fmap (ExportableCertificationPacket . enum_from_word8) get
-- TrustSignaturePacket, http://tools.ietf.org/html/rfc4880#section-5.2.3.13
parse_signature_subpacket  5 = liftM2 TrustSignaturePacket get get
-- TrustSignaturePacket, http://tools.ietf.org/html/rfc4880#section-5.2.3.14
parse_signature_subpacket  6 = fmap
	(RegularExpressionPacket . B.toString . B.init) getRemainingByteString
-- RevocablePacket, http://tools.ietf.org/html/rfc4880#section-5.2.3.12
parse_signature_subpacket  7 =
	fmap (RevocablePacket . enum_from_word8) get
-- KeyExpirationTimePacket, http://tools.ietf.org/html/rfc4880#section-5.2.3.6
parse_signature_subpacket  9 = fmap KeyExpirationTimePacket get
-- PreferredSymmetricAlgorithms, http://tools.ietf.org/html/rfc4880#section-5.2.3.7
parse_signature_subpacket 11 =
	fmap PreferredSymmetricAlgorithmsPacket listUntilEnd
-- RevocationKeyPacket, http://tools.ietf.org/html/rfc4880#section-5.2.3.15
parse_signature_subpacket 12 = do
	bitfield <- get :: Get Word8
	kalgo <- get
	fpr <- getSomeByteString 20
	-- bitfield must have bit 0x80 set, says the spec
	return RevocationKeyPacket {
		sensitive = bitfield .&. 0x40 == 0x40,
		revocation_key_algorithm = kalgo,
		revocation_key_fingerprint =
			pad 40 $ map toUpper $ foldr (padB `oo` showHex) "" (B.unpack fpr)
	}
	where
	oo = (.) . (.)
	padB s | odd $ length s = '0':s
	       | otherwise = s
-- IssuerPacket, http://tools.ietf.org/html/rfc4880#section-5.2.3.5
parse_signature_subpacket 16 = do
	keyid <- get :: Get Word64
	return $ IssuerPacket (pad 16 $ map toUpper $ showHex keyid "")
-- NotationDataPacket, http://tools.ietf.org/html/rfc4880#section-5.2.3.16
parse_signature_subpacket 20 = do
	(flag1,_,_,_) <- get4word8
	(m,n) <- liftM2 (,) get get :: Get (Word16,Word16)
	name <- fmap B.toString $ getSomeByteString $ fromIntegral m
	value <- fmap B.toString $ getSomeByteString $ fromIntegral n
	return NotationDataPacket {
		human_readable = flag1 .&. 0x80 == 0x80,
		notation_name = name,
		notation_value = value
	}
	where
	get4word8 :: Get (Word8,Word8,Word8,Word8)
	get4word8 = liftM4 (,,,) get get get get
-- PreferredHashAlgorithmsPacket, http://tools.ietf.org/html/rfc4880#section-5.2.3.8
parse_signature_subpacket 21 =
	fmap PreferredHashAlgorithmsPacket listUntilEnd
-- PreferredCompressionAlgorithmsPacket, http://tools.ietf.org/html/rfc4880#section-5.2.3.9
parse_signature_subpacket 22 =
	fmap PreferredCompressionAlgorithmsPacket listUntilEnd
-- KeyServerPreferencesPacket, http://tools.ietf.org/html/rfc4880#section-5.2.3.17
parse_signature_subpacket 23 = do
	empty <- isEmpty
	flag1 <- if empty then return 0 else get :: Get Word8
	return KeyServerPreferencesPacket {
		keyserver_no_modify = flag1 .&. 0x80 == 0x80
	}
-- PreferredKeyServerPacket, http://tools.ietf.org/html/rfc4880#section-5.2.3.18
parse_signature_subpacket 24 =
	fmap (PreferredKeyServerPacket . B.toString) getRemainingByteString
-- PrimaryUserIDPacket, http://tools.ietf.org/html/rfc4880#section-5.2.3.19
parse_signature_subpacket 25 =
	fmap (PrimaryUserIDPacket . enum_from_word8) get
-- PolicyURIPacket, http://tools.ietf.org/html/rfc4880#section-5.2.3.20
parse_signature_subpacket 26 =
	fmap (PolicyURIPacket . B.toString) getRemainingByteString
-- KeyFlagsPacket, http://tools.ietf.org/html/rfc4880#section-5.2.3.21
parse_signature_subpacket 27 = do
	empty <- isEmpty
	flag1 <- if empty then return 0 else get :: Get Word8
	return KeyFlagsPacket {
		certify_keys          = flag1 .&. 0x01 == 0x01,
		sign_data             = flag1 .&. 0x02 == 0x02,
		encrypt_communication = flag1 .&. 0x04 == 0x04,
		encrypt_storage       = flag1 .&. 0x08 == 0x08,
		split_key             = flag1 .&. 0x10 == 0x10,
		authentication        = flag1 .&. 0x20 == 0x20,
		group_key             = flag1 .&. 0x80 == 0x80
	}
-- SignerUserIDPacket, http://tools.ietf.org/html/rfc4880#section-5.2.3.22
parse_signature_subpacket 28 =
	fmap (SignerUserIDPacket . B.toString) getRemainingByteString
-- ReasonForRevocationPacket, http://tools.ietf.org/html/rfc4880#section-5.2.3.23
parse_signature_subpacket 29 = liftM2 ReasonForRevocationPacket get
	(fmap B.toString getRemainingByteString)
-- FeaturesPacket, http://tools.ietf.org/html/rfc4880#section-5.2.3.24
parse_signature_subpacket 30 = do
	empty <- isEmpty
	flag1 <- if empty then return 0 else get :: Get Word8
	return FeaturesPacket {
		supports_mdc = flag1 .&. 0x01 == 0x01
	}
-- SignatureTargetPacket, http://tools.ietf.org/html/rfc4880#section-5.2.3.25
parse_signature_subpacket 31 =
	liftM3 SignatureTargetPacket get get getRemainingByteString
-- EmbeddedSignaturePacket, http://tools.ietf.org/html/rfc4880#section-5.2.3.26
parse_signature_subpacket 32 =
	fmap (EmbeddedSignaturePacket . forceSignature) (parse_packet 2)
	where
	forceSignature x@(SignaturePacket {}) = x
	forceSignature _ = error "EmbeddedSignature must contain signature"
-- Represent unsupported packets as their tag and literal bytes
parse_signature_subpacket tag =
	fmap (UnsupportedSignatureSubpacket tag) getRemainingByteString

-- | Find the keyid that issued a SignaturePacket
signature_issuer :: Packet -> Maybe String
signature_issuer (SignaturePacket {hashed_subpackets = hashed,
                                   unhashed_subpackets = unhashed}) =
	case issuers of
		IssuerPacket issuer : _ -> Just issuer
		_                       -> Nothing
	where
	issuers = filter isIssuer hashed ++ filter isIssuer unhashed
	isIssuer (IssuerPacket {}) = True
	isIssuer _ = False
signature_issuer _ = Nothing

find_key :: (Packet -> String) -> Message -> String -> Maybe Packet
find_key fpr (Message (x@(PublicKeyPacket {}):xs)) keyid =
	find_key' fpr x xs keyid
find_key fpr (Message (x@(SecretKeyPacket {}):xs)) keyid =
	find_key' fpr x xs keyid
find_key fpr (Message (_:xs)) keyid =
	find_key fpr (Message xs) keyid
find_key _ _ _ = Nothing

find_key' :: (Packet -> String) -> Packet -> [Packet] -> String -> Maybe Packet
find_key' fpr x xs keyid
	| thisid == keyid = Just x
	| otherwise = find_key fpr (Message xs) keyid
	where
	thisid = reverse $ take (length keyid) (reverse (fpr x))

-- | SignaturePacket smart constructor
signaturePacket :: Word8 -> Word8 -> KeyAlgorithm -> HashAlgorithm -> [SignatureSubpacket] -> [SignatureSubpacket] -> Word16 -> [MPI] -> Packet
signaturePacket version signature_type key_algorithm hash_algorithm hashed_subpackets unhashed_subpackets hash_head signature =
	let p = SignaturePacket {
		version = version,
		signature_type = signature_type,
		key_algorithm = key_algorithm,
		hash_algorithm = hash_algorithm,
		hashed_subpackets = hashed_subpackets,
		unhashed_subpackets = unhashed_subpackets,
		hash_head = hash_head,
		signature = signature,
		trailer = undefined
	} in p { trailer = calculate_signature_trailer p }

isSignaturePacket :: Packet -> Bool
isSignaturePacket (SignaturePacket {})  = True
isSignaturePacket _                     = False
