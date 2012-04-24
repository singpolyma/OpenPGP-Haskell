import Test.Framework (defaultMain, testGroup, Test)
import Test.Framework.Providers.HUnit
import Test.Framework.Providers.QuickCheck2
import Test.QuickCheck ()
import Test.HUnit hiding (Test)

import Data.Word
import Data.Binary
import qualified Data.OpenPGP as OpenPGP
import qualified Data.OpenPGP.Crypto as OpenPGP
import qualified Data.ByteString.Lazy as LZ

testSerialization :: FilePath -> Assertion
testSerialization fp = do
	bs <- LZ.readFile $ "tests/data/" ++ fp
	nullShield "First" (decode bs) (\firstpass ->
			nullShield "Second" (decode $ encode firstpass) (\secondpass ->
				assertEqual ("for " ++ fp) firstpass secondpass
			)
		)
	where
	nullShield pass (OpenPGP.Message []) _ =
		assertFailure $ pass ++ " pass of " ++ fp ++ " decoded to nothing."
	nullShield _ m f = f m

testFingerprint :: FilePath -> String -> Assertion
testFingerprint fp kf = do
	bs <- LZ.readFile $ "tests/data/" ++ fp
	let (OpenPGP.Message [packet]) = decode bs
	assertEqual ("for " ++ fp) kf (OpenPGP.fingerprint packet)

testVerifyMessage :: FilePath -> FilePath -> Assertion
testVerifyMessage keyring message = do
	keys <- fmap decode $ LZ.readFile $ "tests/data/" ++ keyring
	m <- fmap decode $ LZ.readFile $ "tests/data/" ++ message
	let verification = OpenPGP.verify keys m 0
	assertEqual (keyring ++ " for " ++ message) True verification

prop_s2k_count :: Word8 -> Bool
prop_s2k_count c =
	c == OpenPGP.encode_s2k_count (OpenPGP.decode_s2k_count c)

tests :: [Test]
tests =
	[
		testGroup "Serialization group" [
			testCase "000001-006.public_key" (testSerialization "000001-006.public_key"),
			testCase "000002-013.user_id" (testSerialization "000002-013.user_id"),
			-- Issue #11 -- testCase "000003-002.sig" (testSerialization "000003-002.sig"),
			testCase "000004-012.ring_trust" (testSerialization "000004-012.ring_trust"),
			-- Issue #11 -- testCase "000005-002.sig" (testSerialization "000005-002.sig"),
			testCase "000006-012.ring_trust" (testSerialization "000006-012.ring_trust"),
			-- Issue #11 -- testCase "000007-002.sig" (testSerialization "000007-002.sig"),
			testCase "000008-012.ring_trust" (testSerialization "000008-012.ring_trust"),
			-- Issue #11 -- testCase "000009-002.sig" (testSerialization "000009-002.sig"),
			testCase "000010-012.ring_trust" (testSerialization "000010-012.ring_trust"),
			-- Issue #11 -- testCase "000011-002.sig" (testSerialization "000011-002.sig"),
			testCase "000012-012.ring_trust" (testSerialization "000012-012.ring_trust"),
			testCase "000013-014.public_subkey" (testSerialization "000013-014.public_subkey"),
			-- Issue #11 -- testCase "000014-002.sig" (testSerialization "000014-002.sig"),
			testCase "000015-012.ring_trust" (testSerialization "000015-012.ring_trust"),
			testCase "000016-006.public_key" (testSerialization "000016-006.public_key"),
			-- Issue #11 -- testCase "000017-002.sig" (testSerialization "000017-002.sig"),
			testCase "000018-012.ring_trust" (testSerialization "000018-012.ring_trust"),
			testCase "000019-013.user_id" (testSerialization "000019-013.user_id"),
			-- Issue #11 -- testCase "000020-002.sig" (testSerialization "000020-002.sig"),
			testCase "000021-012.ring_trust" (testSerialization "000021-012.ring_trust"),
			-- Issue #11 -- testCase "000022-002.sig" (testSerialization "000022-002.sig"),
			testCase "000023-012.ring_trust" (testSerialization "000023-012.ring_trust"),
			testCase "000024-014.public_subkey" (testSerialization "000024-014.public_subkey"),
			-- Issue #11 -- testCase "000025-002.sig" (testSerialization "000025-002.sig"),
			testCase "000026-012.ring_trust" (testSerialization "000026-012.ring_trust"),
			testCase "000027-006.public_key" (testSerialization "000027-006.public_key"),
			-- Issue #11 -- testCase "000028-002.sig" (testSerialization "000028-002.sig"),
			testCase "000029-012.ring_trust" (testSerialization "000029-012.ring_trust"),
			testCase "000030-013.user_id" (testSerialization "000030-013.user_id"),
			-- Issue #11 -- testCase "000031-002.sig" (testSerialization "000031-002.sig"),
			testCase "000032-012.ring_trust" (testSerialization "000032-012.ring_trust"),
			-- Issue #11 -- testCase "000033-002.sig" (testSerialization "000033-002.sig"),
			testCase "000034-012.ring_trust" (testSerialization "000034-012.ring_trust"),
			testCase "000035-006.public_key" (testSerialization "000035-006.public_key"),
			testCase "000036-013.user_id" (testSerialization "000036-013.user_id"),
			-- Issue #11 -- testCase "000037-002.sig" (testSerialization "000037-002.sig"),
			testCase "000038-012.ring_trust" (testSerialization "000038-012.ring_trust"),
			-- Issue #11 -- testCase "000039-002.sig" (testSerialization "000039-002.sig"),
			testCase "000040-012.ring_trust" (testSerialization "000040-012.ring_trust"),
			testCase "000041-017.attribute" (testSerialization "000041-017.attribute"),
			-- Issue #11 -- testCase "000042-002.sig" (testSerialization "000042-002.sig"),
			testCase "000043-012.ring_trust" (testSerialization "000043-012.ring_trust"),
			testCase "000044-014.public_subkey" (testSerialization "000044-014.public_subkey"),
			-- Issue #11 -- testCase "000045-002.sig" (testSerialization "000045-002.sig"),
			testCase "000046-012.ring_trust" (testSerialization "000046-012.ring_trust"),
			testCase "000047-005.secret_key" (testSerialization "000047-005.secret_key"),
			testCase "000048-013.user_id" (testSerialization "000048-013.user_id"),
			-- Issue #11 -- testCase "000049-002.sig" (testSerialization "000049-002.sig"),
			testCase "000050-012.ring_trust" (testSerialization "000050-012.ring_trust"),
			testCase "000051-007.secret_subkey" (testSerialization "000051-007.secret_subkey"),
			-- Issue #11 -- testCase "000052-002.sig" (testSerialization "000052-002.sig"),
			testCase "000053-012.ring_trust" (testSerialization "000053-012.ring_trust"),
			testCase "000054-005.secret_key" (testSerialization "000054-005.secret_key"),
			-- Issue #11 -- testCase "000055-002.sig" (testSerialization "000055-002.sig"),
			testCase "000056-012.ring_trust" (testSerialization "000056-012.ring_trust"),
			testCase "000057-013.user_id" (testSerialization "000057-013.user_id"),
			-- Issue #11 -- testCase "000058-002.sig" (testSerialization "000058-002.sig"),
			testCase "000059-012.ring_trust" (testSerialization "000059-012.ring_trust"),
			testCase "000060-007.secret_subkey" (testSerialization "000060-007.secret_subkey"),
			-- Issue #11 -- testCase "000061-002.sig" (testSerialization "000061-002.sig"),
			testCase "000062-012.ring_trust" (testSerialization "000062-012.ring_trust"),
			testCase "000063-005.secret_key" (testSerialization "000063-005.secret_key"),
			-- Issue #11 -- testCase "000064-002.sig" (testSerialization "000064-002.sig"),
			testCase "000065-012.ring_trust" (testSerialization "000065-012.ring_trust"),
			testCase "000066-013.user_id" (testSerialization "000066-013.user_id"),
			-- Issue #11 -- testCase "000067-002.sig" (testSerialization "000067-002.sig"),
			testCase "000068-012.ring_trust" (testSerialization "000068-012.ring_trust"),
			testCase "000069-005.secret_key" (testSerialization "000069-005.secret_key"),
			testCase "000070-013.user_id" (testSerialization "000070-013.user_id"),
			-- Issue #11 -- testCase "000071-002.sig" (testSerialization "000071-002.sig"),
			testCase "000072-012.ring_trust" (testSerialization "000072-012.ring_trust"),
			testCase "000073-017.attribute" (testSerialization "000073-017.attribute"),
			-- Issue #11 -- testCase "000074-002.sig" (testSerialization "000074-002.sig"),
			testCase "000075-012.ring_trust" (testSerialization "000075-012.ring_trust"),
			testCase "000076-007.secret_subkey" (testSerialization "000076-007.secret_subkey"),
			-- Issue #11 -- testCase "000077-002.sig" (testSerialization "000077-002.sig"),
			testCase "000078-012.ring_trust" (testSerialization "000078-012.ring_trust"),
			-- Issue #11 -- testCase "pubring.gpg" (testSerialization "pubring.gpg"),
			-- Issue #11 -- testCase "secring.gpg" (testSerialization "secring.gpg"),
			-- Issue #11 -- testCase "compressedsig.gpg" (testSerialization "compressedsig.gpg"),
			-- Issue #11 -- testCase "compressedsig-zlib.gpg" (testSerialization "compressedsig-zlib.gpg"),
			-- Issue #11 -- testCase "compressedsig-bzip2.gpg" (testSerialization "compressedsig-bzip2.gpg"),
			testCase "onepass_sig" (testSerialization "onepass_sig")
			-- Issue #11 -- testCase "uncompressed-ops-dsa.gpg" (testSerialization "uncompressed-ops-dsa.gpg"),
			-- Issue #11 -- testCase "uncompressed-ops-rsa.gpg" (testSerialization "uncompressed-ops-rsa.gpg"),
		],
		testGroup "Fingerprint group" [
			testCase "000001-006.public_key" (testFingerprint "000001-006.public_key" "421F28FEAAD222F856C8FFD5D4D54EA16F87040E"),
			testCase "000016-006.public_key" (testFingerprint "000016-006.public_key" "AF95E4D7BAC521EE9740BED75E9F1523413262DC"),
			testCase "000027-006.public_key" (testFingerprint "000027-006.public_key" "1EB20B2F5A5CC3BEAFD6E5CB7732CF988A63EA86"),
			testCase "000035-006.public_key" (testFingerprint "000035-006.public_key" "CB7933459F59C70DF1C3FBEEDEDC3ECF689AF56D")
		],
		testGroup "Message verification group" [
			--testCase "uncompressed-ops-dsa" (testVerifyMessage "pubring.gpg" "uncompressed-ops-dsa.gpg"),
			--testCase "uncompressed-ops-dsa-sha384" (testVerifyMessage "pubring.gpg" "uncompressed-ops-dsa-sha384.txt.gpg"),
			testCase "uncompressed-ops-rsa" (testVerifyMessage "pubring.gpg" "uncompressed-ops-rsa.gpg"),
			testCase "compressedsig" (testVerifyMessage "pubring.gpg" "compressedsig.gpg"),
			testCase "compressedsig-zlib" (testVerifyMessage "pubring.gpg" "compressedsig-zlib.gpg"),
			testCase "compressedsig-bzip2" (testVerifyMessage "pubring.gpg" "compressedsig-bzip2.gpg")
		],
		testGroup "S2K count" [
			testProperty "S2K count encode reverses decode" prop_s2k_count
		]
	]

main :: IO ()
main = defaultMain tests
