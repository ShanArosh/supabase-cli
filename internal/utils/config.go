package utils

import (
	_ "embed"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"os"
	"strconv"

	"github.com/go-errors/errors"
	"github.com/spf13/afero"
	"github.com/spf13/viper"
	"github.com/supabase/cli/pkg/config"
)

var (
	NetId         string
	DbId          string
	ConfigId      string
	KongId        string
	GotrueId      string
	InbucketId    string
	RealtimeId    string
	RestId        string
	StorageId     string
	ImgProxyId    string
	DifferId      string
	PgmetaId      string
	StudioId      string
	EdgeRuntimeId string
	LogflareId    string
	VectorId      string
	PoolerId      string

	DbAliases          = []string{"db", "db.supabase.internal"}
	KongAliases        = []string{"kong", "api.supabase.internal"}
	GotrueAliases      = []string{"auth"}
	InbucketAliases    = []string{"inbucket"}
	RealtimeAliases    = []string{"realtime", Config.Realtime.TenantId}
	RestAliases        = []string{"rest"}
	StorageAliases     = []string{"storage"}
	ImgProxyAliases    = []string{"imgproxy"}
	PgmetaAliases      = []string{"pg_meta"}
	StudioAliases      = []string{"studio"}
	EdgeRuntimeAliases = []string{"edge_runtime"}
	LogflareAliases    = []string{"analytics"}
	VectorAliases      = []string{"vector"}
	PoolerAliases      = []string{"pooler"}

	//go:embed templates/initial_schemas/13.sql
	InitialSchemaPg13Sql string
	//go:embed templates/initial_schemas/14.sql
	InitialSchemaPg14Sql string
)

func GetId(name string) string {
	return "supabase_" + name + "_" + Config.ProjectId
}

func UpdateDockerIds() {
	if NetId = viper.GetString("network-id"); len(NetId) == 0 {
		NetId = GetId("network")
	}
	DbId = GetId(DbAliases[0])
	ConfigId = GetId("config")
	KongId = GetId(KongAliases[0])
	GotrueId = GetId(GotrueAliases[0])
	InbucketId = GetId(InbucketAliases[0])
	RealtimeId = GetId(RealtimeAliases[0])
	RestId = GetId(RestAliases[0])
	StorageId = GetId(StorageAliases[0])
	ImgProxyId = GetId(ImgProxyAliases[0])
	DifferId = GetId("differ")
	PgmetaId = GetId(PgmetaAliases[0])
	StudioId = GetId(StudioAliases[0])
	EdgeRuntimeId = GetId(EdgeRuntimeAliases[0])
	LogflareId = GetId(LogflareAliases[0])
	VectorId = GetId(VectorAliases[0])
	PoolerId = GetId(PoolerAliases[0])
}

func GetDockerIds() []string {
	return []string{
		KongId,
		GotrueId,
		InbucketId,
		RealtimeId,
		RestId,
		StorageId,
		ImgProxyId,
		PgmetaId,
		StudioId,
		EdgeRuntimeId,
		LogflareId,
		VectorId,
		PoolerId,
	}
}

var Config = config.NewConfig(config.WithHostname(GetHostname()))

func LoadConfigFS(fsys afero.Fs) error {
	// Load default values
	var buf bytes.Buffer
	if err := initConfigTemplate.Execute(&buf, nil); err != nil {
		return errors.Errorf("failed to initialise config template: %w", err)
	}
	dec := toml.NewDecoder(&buf)
	if _, err := dec.Decode(&Config); err != nil {
		return errors.Errorf("failed to decode config template: %w", err)
	}
	// Load user defined config
	if metadata, err := toml.DecodeFS(afero.NewIOFS(fsys), ConfigPath, &Config); err != nil {
		CmdSuggestion = fmt.Sprintf("Have you set up the project with %s?", Aqua("supabase init"))
		cwd, osErr := os.Getwd()
		if osErr != nil {
			cwd = "current directory"
		}
		return errors.Errorf("cannot read config in %s: %w", Bold(cwd), err)
	} else if undecoded := metadata.Undecoded(); len(undecoded) > 0 {
		fmt.Fprintf(os.Stderr, "Unknown config fields: %+v\n", undecoded)
	}
	// Load secrets from .env file
	if err := godotenv.Load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.Errorf("failed to load %s: %w", Bold(".env"), err)
	}
	if err := viper.Unmarshal(&Config); err != nil {
		return errors.Errorf("failed to parse env to config: %w", err)
	}

	// Generate JWT tokens
	if len(Config.Auth.AnonKey) == 0 {
		anonToken := CustomClaims{Role: "anon"}.NewToken()
		if signed, err := anonToken.SignedString([]byte(Config.Auth.JwtSecret)); err != nil {
			return errors.Errorf("failed to generate anon key: %w", err)
		} else {
			Config.Auth.AnonKey = signed
		}
	}
	if len(Config.Auth.ServiceRoleKey) == 0 {
		anonToken := CustomClaims{Role: "service_role"}.NewToken()
		if signed, err := anonToken.SignedString([]byte(Config.Auth.JwtSecret)); err != nil {
			return errors.Errorf("failed to generate service_role key: %w", err)
		} else {
			Config.Auth.ServiceRoleKey = signed
		}
	}

	// Process decoded TOML.
	{
		if Config.ProjectId == "" {
			return errors.New("Missing required field in config: project_id")
		}
		UpdateDockerIds()
		// Validate api config
		if Config.Api.Port == 0 {
			return errors.New("Missing required field in config: api.port")
		}
		if Config.Api.Enabled {
			if version, err := afero.ReadFile(fsys, RestVersionPath); err == nil && len(version) > 0 && Config.Db.MajorVersion > 14 {
				index := strings.IndexByte(PostgrestImage, ':')
				Config.Api.Image = PostgrestImage[:index+1] + string(version)
			}
		}
		// Append required schemas if they are missing
		Config.Api.Schemas = removeDuplicates(append([]string{"public", "storage"}, Config.Api.Schemas...))
		Config.Api.ExtraSearchPath = removeDuplicates(append([]string{"public"}, Config.Api.ExtraSearchPath...))
		// Validate db config
		if Config.Db.Port == 0 {
			return errors.New("Missing required field in config: db.port")
		}
		switch Config.Db.MajorVersion {
		case 0:
			return errors.New("Missing required field in config: db.major_version")
		case 12:
			return errors.New("Postgres version 12.x is unsupported. To use the CLI, either start a new project or follow project migration steps here: https://supabase.com/docs/guides/database#migrating-between-projects.")
		case 13:
			Config.Db.Image = Pg13Image
			InitialSchemaSql = InitialSchemaPg13Sql
		case 14:
			Config.Db.Image = Pg14Image
			InitialSchemaSql = InitialSchemaPg14Sql
		case 15:
			if len(Config.Experimental.OrioleDBVersion) > 0 {
				Config.Db.Image = "supabase/postgres:orioledb-" + Config.Experimental.OrioleDBVersion
				var err error
				if Config.Experimental.S3Host, err = maybeLoadEnv(Config.Experimental.S3Host); err != nil {
					return err
				}
				if Config.Experimental.S3Region, err = maybeLoadEnv(Config.Experimental.S3Region); err != nil {
					return err
				}
				if Config.Experimental.S3AccessKey, err = maybeLoadEnv(Config.Experimental.S3AccessKey); err != nil {
					return err
				}
				if Config.Experimental.S3SecretKey, err = maybeLoadEnv(Config.Experimental.S3SecretKey); err != nil {
					return err
				}
			} else if version, err := afero.ReadFile(fsys, PostgresVersionPath); err == nil && len(version) > 0 {
				viper.Set("INTERNAL_IMAGE_REGISTRY", "docker.io")
				Config.Db.Image = string(version)
			}
		default:
			return errors.Errorf("Failed reading config: Invalid %s: %v.", Aqua("db.major_version"), Config.Db.MajorVersion)
		}
		// Validate pooler config
		if Config.Db.Pooler.Enabled {
			allowed := []PoolMode{TransactionMode, SessionMode}
			if !SliceContains(allowed, Config.Db.Pooler.PoolMode) {
				return errors.Errorf("Invalid config for db.pooler.pool_mode. Must be one of: %v", allowed)
			}
		}
		if connString, err := afero.ReadFile(fsys, PoolerUrlPath); err == nil && len(connString) > 0 {
			Config.Db.Pooler.ConnectionString = string(connString)
		}
		// Validate realtime config
		if Config.Realtime.Enabled {
			allowed := []AddressFamily{AddressIPv6, AddressIPv4}
			if !SliceContains(allowed, Config.Realtime.IpVersion) {
				return errors.Errorf("Invalid config for realtime.ip_version. Must be one of: %v", allowed)
			}
		}
		// Validate storage config
		if Config.Storage.Enabled {
			if version, err := afero.ReadFile(fsys, StorageVersionPath); err == nil && len(version) > 0 && Config.Db.MajorVersion > 14 {
				index := strings.IndexByte(StorageImage, ':')
				Config.Storage.Image = StorageImage[:index+1] + string(version)
			}
		}
		// Validate studio config
		if Config.Studio.Enabled {
			if Config.Studio.Port == 0 {
				return errors.New("Missing required field in config: studio.port")
			}
		}
		// Validate email config
		if Config.Inbucket.Enabled {
			if Config.Inbucket.Port == 0 {
				return errors.New("Missing required field in config: inbucket.port")
			}
		}
		// Validate auth config
		if Config.Auth.Enabled {
			if Config.Auth.SiteUrl == "" {
				return errors.New("Missing required field in config: auth.site_url")
			}
			if version, err := afero.ReadFile(fsys, GotrueVersionPath); err == nil && len(version) > 0 && Config.Db.MajorVersion > 14 {
				index := strings.IndexByte(GotrueImage, ':')
				Config.Auth.Image = GotrueImage[:index+1] + string(version)
			}
			// Validate email template
			for _, tmpl := range Config.Auth.Email.Template {
				if len(tmpl.ContentPath) > 0 {
					if _, err := fsys.Stat(tmpl.ContentPath); err != nil {
						return errors.Errorf("failed to read file info: %w", err)
					}
				}
			}
			// Validate sms config
			var err error
			if Config.Auth.Sms.Twilio.Enabled {
				if len(Config.Auth.Sms.Twilio.AccountSid) == 0 {
					return errors.New("Missing required field in config: auth.sms.twilio.account_sid")
				}
				if len(Config.Auth.Sms.Twilio.MessageServiceSid) == 0 {
					return errors.New("Missing required field in config: auth.sms.twilio.message_service_sid")
				}
				if len(Config.Auth.Sms.Twilio.AuthToken) == 0 {
					return errors.New("Missing required field in config: auth.sms.twilio.auth_token")
				}
				if Config.Auth.Sms.Twilio.AuthToken, err = maybeLoadEnv(Config.Auth.Sms.Twilio.AuthToken); err != nil {
					return err
				}
			}
			if Config.Auth.Sms.TwilioVerify.Enabled {
				if len(Config.Auth.Sms.TwilioVerify.AccountSid) == 0 {
					return errors.New("Missing required field in config: auth.sms.twilio_verify.account_sid")
				}
				if len(Config.Auth.Sms.TwilioVerify.MessageServiceSid) == 0 {
					return errors.New("Missing required field in config: auth.sms.twilio_verify.message_service_sid")
				}
				if len(Config.Auth.Sms.TwilioVerify.AuthToken) == 0 {
					return errors.New("Missing required field in config: auth.sms.twilio_verify.auth_token")
				}
				if Config.Auth.Sms.TwilioVerify.AuthToken, err = maybeLoadEnv(Config.Auth.Sms.TwilioVerify.AuthToken); err != nil {
					return err
				}
			}
			if Config.Auth.Sms.Messagebird.Enabled {
				if len(Config.Auth.Sms.Messagebird.Originator) == 0 {
					return errors.New("Missing required field in config: auth.sms.messagebird.originator")
				}
				if len(Config.Auth.Sms.Messagebird.AccessKey) == 0 {
					return errors.New("Missing required field in config: auth.sms.messagebird.access_key")
				}
				if Config.Auth.Sms.Messagebird.AccessKey, err = maybeLoadEnv(Config.Auth.Sms.Messagebird.AccessKey); err != nil {
					return err
				}
			}
			if Config.Auth.Sms.Textlocal.Enabled {
				if len(Config.Auth.Sms.Textlocal.Sender) == 0 {
					return errors.New("Missing required field in config: auth.sms.textlocal.sender")
				}
				if len(Config.Auth.Sms.Textlocal.ApiKey) == 0 {
					return errors.New("Missing required field in config: auth.sms.textlocal.api_key")
				}
				if Config.Auth.Sms.Textlocal.ApiKey, err = maybeLoadEnv(Config.Auth.Sms.Textlocal.ApiKey); err != nil {
					return err
				}
			}
			if Config.Auth.Sms.Vonage.Enabled {
				if len(Config.Auth.Sms.Vonage.From) == 0 {
					return errors.New("Missing required field in config: auth.sms.vonage.from")
				}
				if len(Config.Auth.Sms.Vonage.ApiKey) == 0 {
					return errors.New("Missing required field in config: auth.sms.vonage.api_key")
				}
				if len(Config.Auth.Sms.Vonage.ApiSecret) == 0 {
					return errors.New("Missing required field in config: auth.sms.vonage.api_secret")
				}
				if Config.Auth.Sms.Vonage.ApiKey, err = maybeLoadEnv(Config.Auth.Sms.Vonage.ApiKey); err != nil {
					return err
				}
				if Config.Auth.Sms.Vonage.ApiSecret, err = maybeLoadEnv(Config.Auth.Sms.Vonage.ApiSecret); err != nil {
					return err
				}
			}
			// Validate oauth config
			for ext, provider := range Config.Auth.External {
				if !provider.Enabled {
					continue
				}
				if provider.ClientId == "" {
					return errors.Errorf("Missing required field in config: auth.external.%s.client_id", ext)
				}
				if provider.Secret == "" {
					return errors.Errorf("Missing required field in config: auth.external.%s.secret", ext)
				}
				if provider.ClientId, err = maybeLoadEnv(provider.ClientId); err != nil {
					return err
				}
				if provider.Secret, err = maybeLoadEnv(provider.Secret); err != nil {
					return err
				}
				if provider.RedirectUri, err = maybeLoadEnv(provider.RedirectUri); err != nil {
					return err
				}
				if provider.Url, err = maybeLoadEnv(provider.Url); err != nil {
					return err
				}
				Config.Auth.External[ext] = provider
			}
		}
	}
	// Validate functions config
	for name, functionConfig := range Config.Functions {
		if functionConfig.VerifyJWT == nil {
			verifyJWT := true
			functionConfig.VerifyJWT = &verifyJWT
			Config.Functions[name] = functionConfig
		}
	}
	// Validate logflare config
	if Config.Analytics.Enabled {
		switch Config.Analytics.Backend {
		case LogflareBigQuery:
			if len(Config.Analytics.GcpProjectId) == 0 {
				return errors.New("Missing required field in config: analytics.gcp_project_id")
			}
			if len(Config.Analytics.GcpProjectNumber) == 0 {
				return errors.New("Missing required field in config: analytics.gcp_project_number")
			}
			if len(Config.Analytics.GcpJwtPath) == 0 {
				return errors.New("Path to GCP Service Account Key must be provided in config, relative to config.toml: analytics.gcp_jwt_path")
			}
		case LogflarePostgres:
			break
		default:
			allowed := []LogflareBackend{LogflarePostgres, LogflareBigQuery}
			return errors.Errorf("Invalid config for analytics.backend. Must be one of: %v", allowed)
		}
	}
	return nil
}

// Adapts fs.FS to support absolute paths
type rootFS struct {
	fsys afero.Fs
}

func (f *rootFS) Open(name string) (fs.File, error) {
	return f.fsys.Open(name)
}

func NewRootFS(fsys afero.Fs) fs.FS {
	return &rootFS{fsys: fsys}
}

func ToRealtimeEnv(addr config.AddressFamily) string {
	if addr == config.AddressIPv6 {
		return "-proto_dist inet6_tcp"
	}
	return "-proto_dist inet_tcp"
}

type InitParams struct {
	ProjectId   string
	UseOrioleDB bool
	Overwrite   bool
}

func InitConfig(params InitParams, fsys afero.Fs) error {
	c := config.NewConfig()
	c.ProjectId = params.ProjectId
	if params.UseOrioleDB {
		c.Experimental.OrioleDBVersion = "15.1.0.150"
	}
	// Create config file
	if err := MkdirIfNotExistFS(fsys, SupabaseDirPath); err != nil {
		return err
	}
	flag := os.O_WRONLY | os.O_CREATE
	if params.Overwrite {
		flag |= os.O_TRUNC
	} else {
		flag |= os.O_EXCL
	}
	f, err := fsys.OpenFile(ConfigPath, flag, 0644)
	if err != nil {
		return errors.Errorf("failed to create config file: %w", err)
	}
	defer f.Close()
	return c.Eject(f)
}

func WriteConfig(fsys afero.Fs, _test bool) error {
	return InitConfig(InitParams{}, fsys)
}

func GetApiUrl(path string) string {
	if len(Config.Api.ExternalUrl) > 0 {
		return Config.Api.ExternalUrl + path
	}
	hostPort := net.JoinHostPort(Config.Hostname,
		strconv.FormatUint(uint64(Config.Api.Port), 10),
	)
	apiUrl := url.URL{
		Scheme: "http",
		Host:   hostPort,
		Path:   path,
	}
	return apiUrl.String()
}
