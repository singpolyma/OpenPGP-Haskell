import Data.Binary
import Data.Binary.Get
import Data.Bits
import Data.Word

newtype Message = Message [Packet] deriving Show
data Packet = EmptyPacket | Len Word8 Word32 deriving Show

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
			return (Len (tag .&. 63) len)
		else do
			len <- parse_old_length tag
			let l = fromIntegral len in
				return (Len ((tag `shiftR` 2) .&. 15) l)

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
