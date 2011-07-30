import Data.Binary
import Data.Binary.Get
import Data.Bits
import Data.Word
import qualified Data.ByteString.Lazy as LZ
import qualified Data.ByteString.Lazy.UTF8 as LZ
import qualified Codec.Compression.Zlib.Raw as Zip
import qualified Codec.Compression.Zlib as Zlib
import qualified Codec.Compression.BZip as BZip2

newtype Message = Message [Packet] deriving Show

data Packet =
	CompressedDataPacket {
		algorithm::CompressionAlgorithm,
		message::Message
	} |
	LiteralDataPacket {
		format::Char,
		filename::String,
		timestamp::Word32,
		content::LZ.ByteString
	} |
	UserIDPacket String
	deriving Show

data CompressionAlgorithm = Uncompressed | ZIP | ZLIB | BZip2 deriving Show

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

instance Binary Packet where
	get = do
		tag <- get :: Get Word8
		if (tag .&. 64) /= 0 then do
			len <- parse_new_length
			let l = fromIntegral len in do
				-- This forces the whole packet to be consumed
				packet <- getLazyByteString l
				return $ runGet (parse_packet (tag .&. 63)) packet
		else do
			len <- parse_old_length tag
			let l = fromIntegral len in do
				-- This forces the whole packet to be consumed
				packet <- getLazyByteString l
				return $ runGet (parse_packet ((tag `shiftR` 2) .&. 15)) packet

-- http://tools.ietf.org/html/rfc4880#section-4.2.2
parse_new_length :: Get Word32
parse_new_length = do
	len <- get :: Get Word8
	let l = fromIntegral len in
		case len of
			-- One octet length
			_ | len < 192 -> return l
			-- Two octet length
			_ | len > 191 && len < 224 -> do
				second <- get :: Get Word8
				let s = fromIntegral second in
					return $ ((l - 192) `shiftL` 8) + s + 192
			-- Five octet length
			_ | len == 255 -> get :: Get Word32
			-- TODO: Partial body lengths. 1 << (len & 0x1F)

-- http://tools.ietf.org/html/rfc4880#section-4.2.1
parse_old_length :: Word8 -> Get Word32
parse_old_length tag =
	case (tag .&. 3) of
		-- One octet length
		0 -> do
			len <- get :: Get Word8
			return (fromIntegral len)
		-- Two octet length
		1 -> do
			len <- get :: Get Word16
			return (fromIntegral len)
		-- Four octet length
		2 -> get :: Get Word32
		-- Indeterminate length
		3 -> do
			len <- remaining
			return (fromIntegral len)

parse_packet :: Word8 -> Get Packet
-- CompressedDataPacket, http://tools.ietf.org/html/rfc4880#section-5.6
parse_packet  8 = do
	algorithm <- get :: Get Word8
	message <- getRemainingLazyByteString
	case algorithm of
		0 ->
			return (CompressedDataPacket {
				algorithm = Uncompressed,
				message = runGet (get :: Get Message) message
			})
		1 ->
			return (CompressedDataPacket {
				algorithm = ZIP,
				message = runGet (get :: Get Message) (Zip.decompress message)
			})
		2 ->
			return (CompressedDataPacket {
				algorithm = ZLIB,
				message = runGet (get :: Get Message) (Zlib.decompress message)
			})
		3 ->
			return (CompressedDataPacket {
				algorithm = BZip2,
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
parse_packet 13 = do
	text <- getRemainingLazyByteString
	return (UserIDPacket (LZ.toString text))
parse_packet _ = fail "Unimplemented OpenPGP packet tag"
