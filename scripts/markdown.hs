import  		 Data.KeyStore.Types.Schema
import           Data.API.Markdown
import           Data.API.Types


main :: IO ()
main =
	writeFile "schema.md" $ markdown markdownMethods keystoreSchema


markdownMethods :: MarkdownMethods
markdownMethods =
    MDM
        { mdmSummaryPostfix = _TypeName
        , mdmLink           = _TypeName
        , mdmPp             = const id
        , mdmFieldDefault   = const $ const Nothing
        }
