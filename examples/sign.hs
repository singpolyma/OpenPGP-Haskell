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
	let message = OpenPGP.Message [
		OpenPGP.LiteralDataPacket 'u' "t.txt" (fromIntegral t)
			(LZ.fromString "This is a message.") ]
	LZ.putStr $ encode $
		OpenPGP.sign keys message OpenPGP.SHA256 [] (fromIntegral t)
