package articarepos

import (
	"activedebiansync/config"
	"activedebiansync/utils"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/leeqvip/gophp"
)

type HotfixesRecords struct {
	Version       string `json:"version"`
	VersionBin    int    `json:"versionBin"`
	Size          string `json:"size"`
	Md5           string `json:"md5"`
	Url           string `json:"url"`
	Time          int    `json:"time"`
	ArticaVersion string `json:"main_version"`
	ServicePack   int    `json:"service_pack"`
	URL           string `json:"URL"`
}

type HotFixesDevs struct {
	Hotfixes             []HotfixesRecords `json:"Hotfixes"`
	CurrentHotFix        string            `json:"CurrentHotFix"`
	HotfixBinAvailable   int               `json:"HotfixBinAvailable"`
	HotFixStringAvailabe string            `json:"HotFixStringAvailabe"`
}
type ArticaDownloader struct {
	Url                  string `json:"url"`
	DestinationDirectory string `json:"destinationDirectory"`
	DestinationFile      string `json:"destinationFile"`
	Md5                  string `json:"md5"`
	Size                 int64  `json:"size"`
	TempDir              string `json:"temp_dir"`
}

type ArticaSoft struct {
	Url         string `json:"url"`
	Version     string `json:"version"`
	Size        int64  `json:"size"`
	Md5         string `json:"md5"`
	ProductCode string `json:"product_code"`
	BinaryVer   int    `json:"binary_ver"`
	TempDir     string `json:"temp_dir"`
	Tempfile    string `json:"temp_file"`
}
type ReposVers struct {
	URL        string `json:"URL"`
	MD5        string `json:"MD5"`
	VERSION    string `json:"VERSION"`
	VERSIONBIN int    `json:"VERSION_BIN"`
	FILENAME   string `json:"FILENAME"`
	FILEDATE   int64  `json:"FILEDATE"`
	FILESIZE   int64  `json:"FILESIZE"`
	TIME       int64  `json:"TIME,omitempty"`
}
type Hotfixes struct {
	MainVersion string `json:"main_version"`
	ServicePack int    `json:"service_pack"`
	Version     int    `json:"version"`
	URL         string `json:"URL"`
}

type Repos struct {
	OFF               []ReposVers                  `json:"Officials"`
	NIGHT             []ReposVers                  `json:"Nightlys"`
	HotfixesOfficials []HotfixesRecords            `json:"Hotfixs"`
	ServicePacks      map[string]map[int]ReposVers `json:"ServicePacks"`
	LTS               []ReposVers                  `json:"LongTermSupport"`
	HotfixesDev       []HotfixesRecords            `json:"HotfixesDev"`
	HotfixesUrls      []Hotfixes                   `json:"HotfixesUrls"`
	Error             bool                         `json:"ERROR"`
}

type ArticaRepo struct {
	Softs []ArticaSoft `json:"softs"`
}

func ListArticaReposSrc(cfg *config.Config, DebianDistri string, EncodedBase64Index string) (error, ArticaRepo) {

	logger := utils.GetLogger()
	defer func(logger *utils.Logger) {
		_ = logger.Close()
	}(logger)

	var Message string
	DecodedStr := Base64Decode(EncodedBase64Index)
	if len(DecodedStr) < 50 {
		Message = fmt.Sprintf("%v Software repositories index file corrupted (after decoding)", utils.GetCalleRuntime())
		return fmt.Errorf(Message), ArticaRepo{}

	}
	phpData, err := gophp.Unserialize([]byte(DecodedStr))
	if err != nil {
		Message = fmt.Sprintf("%v Unable to unserialize Software repositories indexes %v", utils.GetCalleRuntime(), err.Error())
		return fmt.Errorf(Message), ArticaRepo{}
	}
	array, _ := phpData.(map[string]interface{})
	var repos ArticaRepo
	for AppCode, _ := range array {
		err, structure := getAppCodeInfo(cfg, DecodedStr, AppCode, DebianDistri)
		if err != nil {
			logger.LogError("%v %v", utils.GetCalleRuntime(), err.Error())
			continue
		}
		repos.Softs = append(repos.Softs, structure)
	}
	return nil, repos
}

// récupère l'url en fonction du repo Debian
func GetArticaRepoUrls(cfg *config.Config) map[string]string {

	HTTPsurls := make(map[string]string)
	HTTPsurls["bookworm"] = "http://articatech.net/v4softs-debian12.php"
	HTTPsurls["trixie"] = "http://articatech.net/v4softs-debian13.php"

	if cfg.ArticaRepositorySSL {
		HTTPsurls["bookworm"] = "https://articatech.com/v4softs-debian12.php"
		HTTPsurls["trixie"] = "https://articatech.net/v4softs-debian13.php"
	}
	return HTTPsurls
}
func Base64Decode(content string) string {
	decodedBytes, err := base64.StdEncoding.DecodeString(content)
	if err != nil {

		return ""
	}
	return string(decodedBytes)
}
func getAppCodeInfo(cfg *config.Config, Decoded string, AppCode string, DebianDistri string) (error, ArticaSoft) {

	Message := ""

	if len(Decoded) < 50 {
		Message = fmt.Sprintf("%v Software repositories index file corrupted (after decoding)", utils.GetCalleRuntime())
		return fmt.Errorf(Message), ArticaSoft{}

	}
	phpData, err := gophp.Unserialize([]byte(Decoded))
	if err != nil {
		Message = fmt.Sprintf("%v Unable to unserialize Software repositories indexes %v", utils.GetCalleRuntime(), err.Error())
		return fmt.Errorf(Message), ArticaSoft{}
	}
	array, _ := phpData.(map[string]interface{})

	_, ok := array["APP_NGINX"]
	if !ok {
		Message = fmt.Sprintf("%v Unable to obtain master key from indexes %v", utils.GetCalleRuntime(), AppCode)
		return fmt.Errorf(Message), ArticaSoft{}
	}
	var Latest ArticaSoft
	Latest.ProductCode = AppCode
	BinaryVerInt := 0
	array2, _ := array[AppCode].(map[string]interface{})
	for key2, ValueToParse2 := range array2 {
		BinaryVer := utils.StrToInt(key2)
		if BinaryVer > BinaryVerInt {
			array3, _ := ValueToParse2.(map[string]interface{})
			Latest.Url = fmt.Sprintf("%v", array3["URI"])
			Latest.Version = fmt.Sprintf("%v", array3["VERSION"])
			Latest.Size = utils.StrToInt64(fmt.Sprintf("%v", array3["SIZE"]))
			Latest.Md5 = fmt.Sprintf("%v", array3["MD5"])
			Latest.BinaryVer = BinaryVer
			Latest.TempDir = fmt.Sprintf("%v/artica-src/%v/%v", cfg.RepositoryPath, DebianDistri, AppCode)
			Latest.Tempfile = fmt.Sprintf("%v/%v.tar.gz", Latest.TempDir, Latest.Version)
			BinaryVerInt = BinaryVer
		}
	}

	return nil, Latest
}

func ParseArticaCoreServicePacks(Rep Repos, Base64String string) (error, Repos) {

	Rep.ServicePacks = make(map[string]map[int]ReposVers)

	if len(Base64String) < 20 {
		return fmt.Errorf("%v [%v] doesn't seems an index content", utils.GetCalleRuntime(), Base64String), Rep
	}

	Unserialized := Base64Decode(Base64String)
	if len(Unserialized) == 0 {
		return fmt.Errorf("%v unseralize failed", utils.GetCalleRuntime()), Rep
	}
	phpData, err := gophp.Unserialize([]byte(Unserialized))
	if err != nil {
		Rep.Error = true
		return fmt.Errorf("%v %v", utils.GetCalleRuntime(), err.Error()), Rep
	}
	array, _ := phpData.(map[string]interface{})

	for Masterkey, ValueToParse := range array {
		if Rep.ServicePacks[Masterkey] == nil {
			Rep.ServicePacks[Masterkey] = make(map[int]ReposVers)
		}
		array2, _ := ValueToParse.(map[string]interface{})
		var f ReposVers

		for VersioArtica, ValueToParse2 := range array2 {
			switch VersioArtica {
			case "TIME":
				f.FILEDATE = utils.StrToInt64(fmt.Sprintf("%v", ValueToParse2))
			case "VERSION":
				f.VERSION = fmt.Sprintf("%v", ValueToParse2)
			case "SIZE":
				f.FILESIZE = utils.StrToInt64(fmt.Sprintf("%v", ValueToParse2))
			case "MD5":
				f.MD5 = fmt.Sprintf("%v", ValueToParse2)
			case "URI":
				f.URL = fmt.Sprintf("%v", ValueToParse2)

			}
			if utils.StrToInt(f.VERSION) == 0 {
				continue
			}
			Rep.ServicePacks[Masterkey][utils.StrToInt(f.VERSION)] = f
		}
	}

	return nil, Rep
}
func ArticaCoreMainVer(cfg *config.Config) string {
	return UpdateRepoBaseURI(cfg) + "/artica.update4.php"

}
func ArticaCoreUrlIndex(cfg *config.Config) string {
	return UpdateRepoBaseURI(cfg) + "/servicepack2.php" + "?" + utils.TimeStampToString()
}
func ArticaUrlHotfixes(cfg *config.Config, repo Repos) Repos {
	if len(cfg.SystemID) < 5 {
		cfg.SystemID = uuid.New().String()
		_ = cfg.Save(cfg.ConfigPath)
	}

	Base := UpdateRepoBaseURI(cfg)
	for _, vers := range repo.OFF {
		MainVersion := vers.VERSION
		if repo.ServicePacks[MainVersion] == nil {
			continue
		}
		SPs := repo.ServicePacks[MainVersion]
		for BinVer, _ := range SPs {
			var xhot Hotfixes
			xhot.MainVersion = MainVersion
			xhot.ServicePack = BinVer
			xhot.URL = fmt.Sprintf("%v/hotfixdev.php?main=%v&sp=%d&uuid=%v-%v", Base, MainVersion, BinVer, "activeupdate", cfg.SystemID)
			repo.HotfixesUrls = append(repo.HotfixesUrls, xhot)
		}

	}
	return repo
}
func ArticaHotfixes(cfg *config.Config, p Hotfixes, DataEnc string) (error, []HotfixesRecords) {

	BaseUri := UpdateRepoBaseURI(cfg)
	serializedData := Base64Decode(DataEnc)
	phpData, err := gophp.Unserialize([]byte(serializedData))
	if err != nil {
		return fmt.Errorf("[ERROR]: ArticaHotfixes unserialize failed %v", err.Error()), []HotfixesRecords{}
	}
	var d []HotfixesRecords
	xarray, _ := phpData.(map[string]interface{})
	//	log.Debug().Msg(fmt.Sprintf("aupdate.GetHotfixDev: Parsing: %v", xarray))
	for TimeStr, xarray1 := range xarray {
		var c HotfixesRecords
		c.ServicePack = p.ServicePack
		c.ArticaVersion = p.MainVersion
		c.Time = utils.StrToInt(TimeStr)

		xarray2, _ := xarray1.(map[string]interface{})
		for xKey, Val := range xarray2 {
			switch xKey {
			case "URI":
				c.Url = fmt.Sprintf("%v/%v", BaseUri, Val)
				c.URL = fmt.Sprintf("%v/%v", BaseUri, Val)
			case "VERSION":
				c.Version = fmt.Sprintf("%v", Val)
				c.VersionBin = utils.StrToInt(strings.ReplaceAll(c.Version, "-", ""))
			case "SIZE":
				c.Size = fmt.Sprintf("%v", Val)
			}

		}
		d = append(d, c)
	}
	return nil, d
}
func UpdateRepoBaseURI(cfg *config.Config) string {

	uri := "http://articatech.net"
	if cfg.ArticaRepositorySSL {
		uri = "https://www.articatech.com"
	}
	return uri
}
