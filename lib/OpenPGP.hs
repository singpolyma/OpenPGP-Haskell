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

newtype Message = Message [Packet] deriving (Show, Read, Eq)
newtype MPI = MPI Integer deriving (Show, Read, Eq, Ord)

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

data HashAlgorithm = MD5 | SHA1 | RIPEMD160 | SHA256 | SHA384 | SHA512 | SHA224 deriving (Show, Read, Eq)
data KeyAlgorithm = RSA | ELGAMAL | DSA | ECC | ECDSA | DH deriving (Show, Read, Eq)
data CompressionAlgorithm = Uncompressed | ZIP | ZLIB | BZip2 deriving (Show, Read, Eq)

hash_algorithms :: (Num a) => a -> HashAlgorithm
hash_algorithms  1 = MD5
hash_algorithms  2 = SHA1
hash_algorithms  3 = RIPEMD160
hash_algorithms  8 = SHA256
hash_algorithms  9 = SHA384
hash_algorithms 10 = SHA512
hash_algorithms 11 = SHA224

key_algorithms :: (Num a) => a -> KeyAlgorithm
key_algorithms  1 = RSA
key_algorithms  2 = RSA
key_algorithms  3 = RSA
key_algorithms 16 = ELGAMAL
key_algorithms 17 = DSA
key_algorithms 18 = ECC
key_algorithms 19 = ECDSA
key_algorithms 21 = DH

public_key_fields :: KeyAlgorithm -> [Char]
public_key_fields RSA     = ['n', 'e']
public_key_fields ELGAMAL = ['p', 'g', 'y']
public_key_fields DSA     = ['p', 'q', 'g', 'y']

-- A message is encoded as a list that takes the entire file
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
	hash_algo <- get :: Get Word8
	key_algo <- get :: Get Word8
	key_id <- get :: Get Word64
	nested <- get
	return (OnePassSignaturePacket {
		version = version,
		signature_type = signature_type,
		hash_algorithm = (hash_algorithms hash_algo),
		key_algorithm = (key_algorithms key_algo),
		key_id = (BaseConvert.toString 16 key_id),
		nested = nested
	})
-- PublicKeyPacket, http://tools.ietf.org/html/rfc4880#section-5.5.2
parse_packet  6 = do
	version <- get :: Get Word8
	case version of
		4 -> do
			timestamp <- get
			algorithm <- fmap key_algorithms (get :: Get Word8)
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
	algorithm <- get :: Get Word8
	message <- getRemainingLazyByteString
	case algorithm of
		0 ->
			return (CompressedDataPacket {
				compressed_data_algorithm = Uncompressed,
				message = runGet (get :: Get Message) message
			})
		1 ->
			return (CompressedDataPacket {
				compressed_data_algorithm = ZIP,
				message = runGet (get :: Get Message) (Zip.decompress message)
			})
		2 ->
			return (CompressedDataPacket {
				compressed_data_algorithm = ZLIB,
				message = runGet (get :: Get Message) (Zlib.decompress message)
			})
		3 ->
			return (CompressedDataPacket {
				compressed_data_algorithm = BZip2,
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
