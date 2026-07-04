import qualified Crypto.SRPSpec
import Test.Hspec (hspec)


main :: IO ()
main = hspec Crypto.SRPSpec.spec
