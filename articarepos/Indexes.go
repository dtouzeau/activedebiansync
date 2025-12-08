package articarepos

import (
	"activedebiansync/utils"
	"fmt"
	"github.com/leeqvip/gophp"
)

func ParseArticaMainVers(Base64String string) (error, Repos) {
	var Rep Repos
	Unserialized := Base64Decode(Base64String)
	if len(Unserialized) == 0 {
		return fmt.Errorf("%v Base64Decode failed"), Rep
	}
	phpData, err := gophp.Unserialize([]byte(Unserialized))
	if err != nil {
		return err, Rep
	}
	array, _ := phpData.(map[string]interface{})

	for Masterkey, ValueToParse := range array {
		//fmt.Println(utils.GetCalleRuntime(), "---->", Masterkey)
		array2, _ := ValueToParse.(map[string]interface{})
		for VersioArtica, ValueToParse2 := range array2 {
			if Masterkey == "HOTFIX" {
				array3, _ := ValueToParse2.(map[string]interface{})
				for ServicePack, ValueToParse3 := range array3 {
					array4, _ := ValueToParse3.(map[string]interface{})
					for HotFixBin, ValueToParse4 := range array4 {
						var c HotfixesRecords
						c.ArticaVersion = VersioArtica
						c.ServicePack = utils.StrToInt(ServicePack)
						array5, _ := ValueToParse4.(map[string]interface{})
						for Key, val := range array5 {
							if Key == "VERSION" {
								c.Version = fmt.Sprintf("%v", val)
								c.VersionBin = utils.StrToInt(HotFixBin)
							}
							if Key == "URL" {
								c.URL = fmt.Sprintf("%v", val)
								c.Url = fmt.Sprintf("%v", val)
							}
							if Key == "MD5" {
								c.Md5 = fmt.Sprintf("%v", val)
							}
							if Key == "SIZE" {
								c.Size = fmt.Sprintf("%v", val)
							}
						}
						Rep.HotfixesOfficials = append(Rep.HotfixesOfficials, c)
					}
				}
				continue
			}
			array3, _ := ValueToParse2.(map[string]interface{})
			var Rec ReposVers
			for zKey, ValueToParse3 := range array3 {
				if zKey == "VERSION" {
					Rec.VERSION = fmt.Sprintf("%v", ValueToParse3)
				}
				if zKey == "FILENAME" {
					Rec.FILENAME = fmt.Sprintf("%v", ValueToParse3)
				}
				if zKey == "FILESIZE" {
					Rec.FILESIZE = utils.StrToInt64(fmt.Sprintf("%v", ValueToParse3))
				}
				if zKey == "FILEDATE" {
					Rec.FILEDATE = utils.StrToInt64(fmt.Sprintf("%v", ValueToParse3))
				}
				if zKey == "URL" {
					Rec.URL = fmt.Sprintf("%v", ValueToParse3)
				}

			}
			Rec.VERSIONBIN = utils.StrToInt(VersioArtica)
			if Masterkey == "OFF" {
				Rep.OFF = append(Rep.OFF, Rec)
				continue
			}
			if Masterkey == "NIGHT" {
				Rep.NIGHT = append(Rep.NIGHT, Rec)
				continue
			}
			if Masterkey == "LTS" {
				Rep.LTS = append(Rep.NIGHT, Rec)
				continue
			}

		}
	}
	return nil, Rep
}
