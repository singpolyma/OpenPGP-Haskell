import System (getArgs)
import System.Time (getClockTime, ClockTime(..))

import Data.Binary

import qualified Data.OpenPGP as OpenPGP
import qualified Data.OpenPGP.Crypto as OpenPGP
import qualified Data.ByteString.Lazy as LZ
import qualified Data.ByteString.Lazy.UTF8 as LZ

main :: IO ()
main = do
	argv <- getArgs
	time <- getClockTime
	let TOD t _ = time
	keys <- decodeFile (argv !! 0)
	let dataPacket = OpenPGP.LiteralDataPacket 'u' "t.txt"
			(fromIntegral t) (LZ.fromString "This is a message.")
	let message = OpenPGP.Message [
		OpenPGP.sign keys (OpenPGP.Message [dataPacket])
			OpenPGP.SHA256 [] (fromIntegral t),
		dataPacket]
	LZ.putStr $ encode message
