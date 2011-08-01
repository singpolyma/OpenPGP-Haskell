module OpenPGP (Message(..), Packet(..), HashAlgorithm, KeyAlgorithm, CompressionAlgorithm) where

import Data.Binary
import Data.Binary.Get
import Data.Bits
import Data.Word
import Data.Map (Map)
import qualified Data.Map as Map
import qualified Data.ByteString.Lazy as LZ
import qualified Data.ByteString.Lazy.UTF8 as LZ (toString)
import qualified Codec.Compression.Zlib.Raw as Zip
import qualified Codec.Compression.Zlib as Zlib
import qualified Codec.Compression.BZip as BZip2

import qualified BaseConvert as BaseConvert

data Packet =
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
		public_key_algorithm::KeyAlgorithm,
		key::Map Char MPI
	} |
	CompressedDataPacket {
		compressed_data_algorithm::CompressionAlgorithm,
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

data HashAlgorithm = MD5 | SHA1 | RIPEMD160 | SHA256 | SHA384 | SHA512 | SHA224
	deriving (Show, Read, Eq)
instance Binary HashAlgorithm where
	get = do
		tag <- get :: Get Word8
		case tag of
			01 -> return MD5
			02 -> return SHA1
			03 -> return RIPEMD160
			08 -> return SHA256
			09 -> return SHA384
			10 -> return SHA512
			11 -> return SHA224

data KeyAlgorithm = RSA | RSA_E | RSA_S | ELGAMAL | DSA | ECC | ECDSA | DH
	deriving (Show, Read, Eq)
instance Binary KeyAlgorithm where
	put RSA     = put (01 :: Word8)
	put RSA_E   = put (02 :: Word8)
	put RSA_S   = put (03 :: Word8)
	put ELGAMAL = put (16 :: Word8)
	put DSA     = put (17 :: Word8)
	put ECC     = put (18 :: Word8)
	put ECDSA   = put (19 :: Word8)
	put DH      = put (21 :: Word8)
	get = do
		tag <- get :: Get Word8
		case tag of
			01 -> return RSA
			02 -> return RSA_E
			03 -> return RSA_S
			16 -> return ELGAMAL
			17 -> return DSA
			18 -> return ECC
			19 -> return ECDSA
			21 -> return DH

data CompressionAlgorithm = Uncompressed | ZIP | ZLIB | BZip2
	deriving (Show, Read, Eq)
instance Binary CompressionAlgorithm where
	get = do
		tag <- get :: Get Word8
		case tag of
			0 -> return Uncompressed
			1 -> return ZIP
			2 -> return ZLIB
			3 -> return BZip2

-- A message is encoded as a list that takes the entire file
newtype Message = Message [Packet] deriving (Show, Read, Eq)
instance Binary Message where
	put (Message []) = return ()
	put (Message (x:xs)) = do
		put x
		put (Message xs)
	get = do
		done <- isEmpty
		if done then do
			return (Message [])
		else do
			next_packet <- get :: Get Packet
			(Message tail) <- get :: Get Message
			return (Message (next_packet:tail))

newtype MPI = MPI Integer deriving (Show, Read, Eq, Ord)
instance Binary MPI where
	put (MPI i) = do
		put ((((fromIntegral (LZ.length bytes)) - 1) * 8) + (floor (logBase 2 (fromIntegral (bytes `LZ.index` 1)))) + 1 :: Word16)
		mapM (\x -> putWord8 x) (LZ.unpack bytes)
		put ()
		where bytes = LZ.unfoldr (\x -> if x == 0 then Nothing else Just (fromIntegral x, x `shiftR` 8)) i
	get = do
		length <- fmap fromIntegral (get :: Get Word16)
		bytes <- getLazyByteString (floor ((length + 7) / 8))
		return (MPI (LZ.foldr (\b a ->
			a `shiftL` 8 .|. fromIntegral b) 0 bytes))

instance Binary Packet where
	get = do
		tag <- get :: Get Word8
		if (tag .&. 64) /= 0 then do
			len <- fmap fromIntegral parse_new_length
			-- This forces the whole packet to be consumed
			packet <- getLazyByteString len
			return $ runGet (parse_packet (tag .&. 63)) packet
		else do
			len <- fmap fromIntegral (parse_old_length tag)
			-- This forces the whole packet to be consumed
			packet <- getLazyByteString len
			return $ runGet (parse_packet ((tag `shiftR` 2) .&. 15)) packet

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
		_ | len == 255 -> get :: Get Word32
		-- TODO: Partial body lengths. 1 << (len & 0x1F)

-- http://tools.ietf.org/html/rfc4880#section-4.2.1
parse_old_length :: Word8 -> Get Word32
parse_old_length tag =
	case (tag .&. 3) of
		-- One octet length
		0 -> fmap fromIntegral (get :: Get Word8)
		-- Two octet length
		1 -> fmap fromIntegral (get :: Get Word16)
		-- Four octet length
		2 -> get
		-- Indeterminate length
		3 -> fmap fromIntegral remaining

parse_packet :: Word8 -> Get Packet
-- OnePassSignaturePacket, http://tools.ietf.org/html/rfc4880#section-5.4
parse_packet  4 = do
	version <- get
	signature_type <- get
	hash_algo <- get
	key_algo <- get
	key_id <- get :: Get Word64
	nested <- get
	return (OnePassSignaturePacket {
		version = version,
		signature_type = signature_type,
		hash_algorithm = hash_algo,
		key_algorithm = key_algo,
		key_id = (BaseConvert.toString 16 key_id),
		nested = nested
	})
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
			return (PublicKeyPacket {
				version = 4,
				timestamp = timestamp,
				public_key_algorithm = algorithm,
				key = Map.fromList key
			})
-- CompressedDataPacket, http://tools.ietf.org/html/rfc4880#section-5.6
parse_packet  8 = do
	algorithm <- get
	message <- getRemainingLazyByteString
	case algorithm of
		Uncompressed ->
			return (CompressedDataPacket {
				compressed_data_algorithm = algorithm,
				message = runGet (get :: Get Message) message
			})
		ZIP ->
			return (CompressedDataPacket {
				compressed_data_algorithm = algorithm,
				message = runGet (get :: Get Message) (Zip.decompress message)
			})
		ZLIB ->
			return (CompressedDataPacket {
				compressed_data_algorithm = algorithm,
				message = runGet (get :: Get Message) (Zlib.decompress message)
			})
		BZip2 ->
			return (CompressedDataPacket {
				compressed_data_algorithm = algorithm,
				message = runGet (get :: Get Message) (BZip2.decompress message)
			})
-- LiteralDataPacket, http://tools.ietf.org/html/rfc4880#section-5.9
parse_packet 11 = do
	format <- get
	filenameLength <- get :: Get Word8
	filename <- getLazyByteString (fromIntegral filenameLength)
	timestamp <- get
	content <- getRemainingLazyByteString
	return (LiteralDataPacket {
		format = format,
		filename = LZ.toString filename,
		timestamp = timestamp,
		content = content
	})
-- UserIDPacket, http://tools.ietf.org/html/rfc4880#section-5.11
parse_packet 13 =
	fmap UserIDPacket (fmap LZ.toString getRemainingLazyByteString)
parse_packet _ = fail "Unimplemented OpenPGP packet tag"
