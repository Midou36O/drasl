package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/jxskiss/base62"
	"github.com/labstack/echo/v4"
	"image/png"
	"io"
	"log"
	"lukechampine.com/blake3"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"
)

type ConstantsType struct {
	ConfigDirectory     string
	MaxPlayerNameLength int
	MaxUsernameLength   int
	Version             string
}

var Constants = &ConstantsType{
	MaxUsernameLength:   16,
	MaxPlayerNameLength: 16,
	ConfigDirectory:     "/etc/drasl",
	Version:             "0.1.0",
}

type CachedResponse struct {
	StatusCode int
	BodyBytes  []byte
}

func (app *App) CachedGet(url string, ttl int) (CachedResponse, error) {
	if ttl > 0 {
		cachedResponse, found := app.RequestCache.Get(url)
		if found {
			return cachedResponse.(CachedResponse), nil
		}
	}

	res, err := http.Get(url)
	if err != nil {
		return CachedResponse{}, err
	}
	defer res.Body.Close()

	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(res.Body)

	response := CachedResponse{
		StatusCode: res.StatusCode,
		BodyBytes:  buf.Bytes(),
	}

	if ttl > 0 {
		app.RequestCache.SetWithTTL(url, response, 0, time.Duration(ttl)*time.Second)
	}

	return response, nil
}

// Wrap string s to lines of at most n bytes
func Wrap(s string, n int) string {
	var builder strings.Builder
	for {
		end := n
		if end > len(s) {
			end = len(s)
		}
		builder.WriteString(s[:end])
		s = s[end:]
		if len(s) > 0 {
			builder.WriteString("\n")
		} else {
			break
		}
	}
	return builder.String()
}

func Check(e error) {
	if e != nil {
		log.Fatal(e)
	}
}

func Unwrap[T any](value T, e error) T {
	if e != nil {
		log.Fatal(e)
	}
	return value
}

func Truncate(data []byte, length int) []byte {
	if len(data) < length {
		newData := make([]byte, length)
		copy(newData, data)
		return newData
	}
	return data[:16]
}

func RandomHex(n uint) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func RandomBase62(n uint) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base62.EncodeToString(bytes), nil
}

type Error error

func IsErrorUniqueFailed(err error) bool {
	if err == nil {
		return false
	}
	// Work around https://stackoverflow.com/questions/75489773/why-do-i-get-second-argument-to-errors-as-should-not-be-error-build-error-in
	e := (errors.New("UNIQUE constraint failed")).(Error)
	return errors.As(err, &e)
}

func IsErrorUniqueFailedField(err error, field string) bool {
	if err == nil {
		return false
	}

	// The Go programming language 😎
	return err.Error() == "UNIQUE constraint failed: "+field
}

func GetSkinPath(app *App, hash string) string {
	dir := path.Join(app.Config.StateDirectory, "skin")
	return path.Join(dir, fmt.Sprintf("%s.png", hash))
}

func GetCapePath(app *App, hash string) string {
	dir := path.Join(app.Config.StateDirectory, "cape")
	return path.Join(dir, fmt.Sprintf("%s.png", hash))
}

func SignSHA256(app *App, plaintext []byte) ([]byte, error) {
	hash := sha256.New()
	hash.Write(plaintext)
	sum := hash.Sum(nil)

	return rsa.SignPKCS1v15(rand.Reader, app.Key, crypto.SHA256, sum)
}

func SignSHA1(app *App, plaintext []byte) ([]byte, error) {
	hash := sha1.New()
	hash.Write(plaintext)
	sum := hash.Sum(nil)

	return rsa.SignPKCS1v15(rand.Reader, app.Key, crypto.SHA1, sum)
}

type Profile struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Agent struct {
	Name    string `json:"name"`
	Version uint   `json:"version"`
}

type ErrorResponse struct {
	Error        string `json:"error"`
	ErrorMessage string `json:"errorMessage"`
}

func ValidateSkin(app *App, reader io.Reader) (io.Reader, error) {
	var header bytes.Buffer
	config, err := png.DecodeConfig(io.TeeReader(reader, &header))
	if err != nil {
		return nil, err
	}

	if config.Width != config.Height {
		return nil, errors.New("texture must be square")
	}

	if app.Config.SkinSizeLimit > 0 && config.Width > app.Config.SkinSizeLimit {
		return nil, fmt.Errorf("texture must not be greater than %d pixels wide", app.Config.SkinSizeLimit)
	}

	return io.MultiReader(&header, reader), nil
}

func ValidateCape(app *App, reader io.Reader) (io.Reader, error) {
	var header bytes.Buffer
	config, err := png.DecodeConfig(io.TeeReader(reader, &header))
	if err != nil {
		return nil, err
	}

	if config.Width != 2*config.Height {
		return nil, errors.New("cape's width must be twice its height")
	}

	if app.Config.SkinSizeLimit > 0 && config.Width > app.Config.SkinSizeLimit {
		return nil, fmt.Errorf("texture must not be greater than %d pixels wide", app.Config.SkinSizeLimit)
	}

	return io.MultiReader(&header, reader), nil
}

func SetSkin(app *App, user *User, reader io.Reader) error {
	oldSkinHash := UnmakeNullString(&user.SkinHash)

	if reader == nil {
		// handle resetting skin to "no skin"
		user.SkinHash = MakeNullString(nil)
	} else {
		limitedReader := io.LimitReader(reader, 10e6)

		// It's fine to read the whole skin into memory here; they will almost
		// always be <1MiB, and it's nice to know the filename before writing it to
		// disk anyways.
		buf := new(bytes.Buffer)
		_, err := buf.ReadFrom(limitedReader)
		if err != nil {
			return err
		}
		sum := blake3.Sum256(buf.Bytes())
		hash := hex.EncodeToString(sum[:])

		skinPath := GetSkinPath(app, hash)
		err = os.MkdirAll(path.Dir(skinPath), os.ModePerm)
		if err != nil {
			return err
		}

		user.SkinHash = MakeNullString(&hash)

		// TODO deal with race conditions here
		// https://stackoverflow.com/questions/64564781/golang-lock-per-value
		dest, err := os.Create(skinPath)
		if err != nil {
			return err
		}
		defer dest.Close()

		_, err = buf.WriteTo(dest)
		if err != nil {
			return err
		}
	}

	err := app.DB.Save(&user).Error
	if err != nil {
		return err
	}

	if oldSkinHash != nil {
		err = DeleteSkinIfUnused(app, *oldSkinHash)
		if err != nil {
			return err
		}
	}

	return nil
}

func SetCape(app *App, user *User, reader io.Reader) error {
	oldCapeHash := UnmakeNullString(&user.CapeHash)

	if reader == nil {
		// handle resetting cape to "no cape"
		user.CapeHash = MakeNullString(nil)
	} else {
		limitedReader := io.LimitReader(reader, 10e6)

		buf := new(bytes.Buffer)
		_, err := buf.ReadFrom(limitedReader)
		if err != nil {
			return err
		}

		sum := blake3.Sum256(buf.Bytes())
		hash := hex.EncodeToString(sum[:])

		capePath := GetCapePath(app, hash)
		err = os.MkdirAll(path.Dir(capePath), os.ModePerm)
		if err != nil {
			return err
		}

		user.CapeHash = MakeNullString(&hash)

		// TODO deal with race conditions here
		// https://stackoverflow.com/questions/64564781/golang-lock-per-value
		dest, err := os.Create(capePath)
		if err != nil {
			return err
		}
		defer dest.Close()

		_, err = buf.WriteTo(dest)
		if err != nil {
			return err
		}
	}

	err := app.DB.Save(&user).Error
	if err != nil {
		return err
	}

	if oldCapeHash != nil {
		err = DeleteCapeIfUnused(app, *oldCapeHash)
		if err != nil {
			return err
		}
	}

	return nil
}

// Delete skin if not in use
func DeleteSkinIfUnused(app *App, hash string) error {
	var inUse bool
	err := app.DB.Model(User{}).
		Select("count(*) > 0").
		Where("skin_hash = ?", hash).
		Find(&inUse).
		Error
	if err != nil {
		return err
	}

	if !inUse {
		os.Remove(GetSkinPath(app, hash))
	}

	return nil
}

// Delete cape if not in use
func DeleteCapeIfUnused(app *App, hash string) error {
	var inUse bool
	err := app.DB.Model(User{}).
		Select("count(*) > 0").
		Where("cape_hash = ?", hash).
		Find(&inUse).
		Error
	if err != nil {
		return err
	}

	if !inUse {
		os.Remove(GetCapePath(app, hash))
	}

	return nil
}

func DeleteUser(app *App, user *User) error {
	oldSkinHash := UnmakeNullString(&user.SkinHash)
	oldCapeHash := UnmakeNullString(&user.CapeHash)
	app.DB.Delete(&user)

	if oldSkinHash != nil {
		err := DeleteSkinIfUnused(app, *oldSkinHash)
		if err != nil {
			return err
		}
	}

	if oldCapeHash != nil {
		err := DeleteCapeIfUnused(app, *oldCapeHash)
		if err != nil {
			return err
		}
	}
	return nil
}

func StripQueryParam(urlString string, param string) (string, error) {
	parsedURL, err := url.Parse(urlString)
	if err != nil {
		return "", err
	}

	query := parsedURL.Query()
	query.Del(param)

	parsedURL.RawQuery = query.Encode()

	return parsedURL.String(), nil
}

func SetIsLocked(app *App, user *User, isLocked bool) error {
	user.IsLocked = isLocked
	if isLocked {
		user.BrowserToken = MakeNullString(nil)
		result := app.DB.Table("token_pairs").Where("user_uuid = ?", user.UUID).Updates(map[string]interface{}{"Valid": false})
		if result.Error != nil {
			return result.Error
		}
	}
	return nil
}

type textureMetadata struct {
	Model string `json:"string"`
}

type texture struct {
	URL      string           `json:"url"`
	Metadata *textureMetadata `json:"model,omitempty"`
}

type textureMap struct {
	Skin *texture `json:"SKIN,omitempty"`
	Cape *texture `json:"CAPE,omitempty"`
}

type texturesValue struct {
	Timestamp   int64      `json:"timestamp"`
	ProfileID   string     `json:"profileId"`
	ProfileName string     `json:"profileName"`
	Textures    textureMap `json:"textures"`
}

type SessionProfileProperty struct {
	Name      string  `json:"name"`
	Value     string  `json:"value"`
	Signature *string `json:"signature,omitempty"`
}

type SessionProfileResponse struct {
	ID         string                   `json:"id"`
	Name       string                   `json:"name"`
	Properties []SessionProfileProperty `json:"properties"`
}

func GetFallbackSkinTexturesProperty(app *App, user *User) (*SessionProfileProperty, error) {
	/// Forward a skin for `user` from the fallback API servers

	// If user does not have a FallbackPlayer set, don't get any skin.
	if user.FallbackPlayer == "" {
		return nil, nil
	}

	// Check whether the user's `FallbackPlayer` is a UUID or a player name.
	// If it's a UUID, remove the hyphens.
	var fallbackPlayer string
	var fallbackPlayerIsUUID bool
	_, err := uuid.Parse(user.FallbackPlayer)
	if err == nil {
		fallbackPlayerIsUUID = true
		if len(user.FallbackPlayer) == 36 {
			// user.FallbackPlayer is a UUID with hyphens
			fallbackPlayer, err = UUIDToID(user.FallbackPlayer)
			if err != nil {
				return nil, err
			}
		} else {
			// user.FallbackPlayer is a UUID without hyphens
			fallbackPlayer = user.FallbackPlayer
		}
	} else {
		// user.FallbackPlayer is a player name
		fallbackPlayerIsUUID = false
		fallbackPlayer = user.FallbackPlayer
	}

	for _, fallbackAPIServer := range app.Config.FallbackAPIServers {
		var id string
		if fallbackPlayerIsUUID {
			// If we have the UUID already, use it
			id = fallbackPlayer
		} else {
			// Otherwise, we only know the player name. Query the fallback API
			// server to get the fallback player's UUID
			reqURL, err := url.JoinPath(fallbackAPIServer.AccountURL, "/users/profiles/minecraft/", fallbackPlayer)
			if err != nil {
				log.Println(err)
				continue
			}
			res, err := app.CachedGet(reqURL, fallbackAPIServer.CacheTTL)
			if err != nil {
				log.Println(err)
				continue
			}

			var playerResponse playerNameToUUIDResponse
			err = json.Unmarshal(res.BodyBytes, &playerResponse)
			if err != nil {
				log.Println(err)
				continue
			}
			id = playerResponse.ID
		}
		reqURL, err := url.JoinPath(fallbackAPIServer.SessionURL, "session/minecraft/profile", id)
		if err != nil {
			log.Println(err)
			continue
		}
		res, err := app.CachedGet(reqURL, fallbackAPIServer.CacheTTL)
		if err != nil {
			log.Println(err)
			continue
		}

		if res.StatusCode == http.StatusOK {
			var profileRes SessionProfileResponse
			err = json.Unmarshal(res.BodyBytes, &profileRes)
			if err != nil {
				log.Println(err)
				continue
			}

			var texturesProperty *SessionProfileProperty
			for _, property := range profileRes.Properties {
				if property.Name == "textures" {
					texturesProperty = &property
					break
				}
			}
			if texturesProperty == nil {
				continue
			}
			return texturesProperty, nil
		}
	}

	return nil, nil
}

func GetSkinTexturesProperty(app *App, user *User, sign bool) (SessionProfileProperty, error) {
	id, err := UUIDToID(user.UUID)
	if err != nil {
		return SessionProfileProperty{}, err
	}
	if !user.SkinHash.Valid && !user.CapeHash.Valid && app.Config.ForwardSkins {
		// If the user has neither a skin nor a cape, try getting a skin from
		// Fallback API servers
		fallbackProperty, err := GetFallbackSkinTexturesProperty(app, user)
		if err != nil {
			return SessionProfileProperty{}, nil
		}
		if fallbackProperty != nil {
			if !sign {
				fallbackProperty.Signature = nil
			}
			return *fallbackProperty, nil
		}
	}

	var skinTexture *texture
	if user.SkinHash.Valid {
		skinTexture = &texture{
			URL: SkinURL(app, user.SkinHash.String),
			Metadata: &textureMetadata{
				Model: user.SkinModel,
			},
		}
	}

	var capeTexture *texture
	if user.CapeHash.Valid {
		capeTexture = &texture{
			URL: CapeURL(app, user.CapeHash.String),
		}
	}

	texturesValue := texturesValue{
		Timestamp:   time.Now().UnixNano(),
		ProfileID:   id,
		ProfileName: user.PlayerName,
		Textures: textureMap{
			Skin: skinTexture,
			Cape: capeTexture,
		},
	}
	texturesValueBlob, err := json.Marshal(texturesValue)
	if err != nil {
		return SessionProfileProperty{}, err
	}

	texturesValueBase64 := base64.StdEncoding.EncodeToString(texturesValueBlob)

	var texturesSignature *string
	if sign {
		signature, err := SignSHA1(app, []byte(texturesValueBase64))
		if err != nil {
			return SessionProfileProperty{}, err
		}
		signatureBase64 := base64.StdEncoding.EncodeToString(signature)
		texturesSignature = &signatureBase64
	}

	return SessionProfileProperty{
		Name:      "textures",
		Value:     texturesValueBase64,
		Signature: texturesSignature,
	}, nil
}

func AddAuthlibInjectorHeader(app *App, c *echo.Context) {
	(*c).Response().Header().Set("X-Authlib-Injector-API-Location", app.AuthlibInjectorURL)
}
