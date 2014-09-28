package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"time"

	"strconv"
	"sync"

	"crypto/sha256"

	"airdispat.ch/crypto"
	"airdispat.ch/identity"
	"airdispat.ch/message"
	"airdispat.ch/server"
	"airdispat.ch/tracker"
	"code.google.com/p/go-uuid/uuid"
)

// Start the Dispatcher
func main() {
	var (
		me      = flag.String("me", "", "Location of the server.")
		keyFile = flag.String("keyfile", "", "Location of file to get keys from.")
		apiKey  = flag.String("apikey", "", "NYTimes Newswire API Key.")

		port = flag.Int("port", 1024, "Port to run server on.")

		registerAt = flag.String("registerAt", "", "Tracker to Register Server At.")
		registerAs = flag.String("registerAs", "", "Alais for tracker.")
	)
	flag.Parse()

	mel := &NewsDispatcher{
		Me:         *me,
		KeyFile:    *keyFile,
		APIKey:     *apiKey,
		TrackerURL: *registerAt,
		Alias:      *registerAs,
	}
	err := mel.Run(*port)
	if err != nil {
		fmt.Println("Error Starting Server", err)
	}
}

type NewsDispatcher struct {
	// Basic Properties
	Me      string
	KeyFile string
	Key     *identity.Identity

	APIKey string

	// Tracker Properties
	TrackerURL string
	Alias      string

	Fetcher *newsFetcher

	// Import Logging and Such
	server.BasicServer
}

// Run will start the server with the specified database model.
func (m *NewsDispatcher) Run(port int) error {
	// Load the Server Keys
	loadedKey, err := identity.LoadKeyFromFile(m.KeyFile)
	if err != nil {
		loadedKey, err = identity.CreateIdentity()
		if err != nil {
			return err
		}
		if m.KeyFile != "" {
			err = loadedKey.SaveKeyToFile(m.KeyFile)
			if err != nil {
				return err
			}
		}
	}
	m.LogMessage("Loaded Address", loadedKey.Address.String())
	m.LogMessage("Loaded Encryption Key", hex.EncodeToString(crypto.RSAToBytes(loadedKey.Address.EncryptionKey)))

	loadedKey.SetLocation(m.Me)
	err = (&tracker.Router{
		URL:    m.TrackerURL,
		Origin: loadedKey,
	}).Register(loadedKey, m.Alias, nil)
	if err != nil {
		return err
	}

	m.Key = loadedKey

	m.Fetcher = &newsFetcher{
		News:      make(map[string]*newsItem),
		Images:    make(map[string]*newsImage),
		API:       m.APIKey,
		Alias:     fmt.Sprintf("%s@%s", m.Alias, m.TrackerURL),
		newsLock:  &sync.RWMutex{},
		imageLock: &sync.RWMutex{},
	}
	m.Fetcher.FetchNews()
	go m.Fetcher.StartFetch()

	// Create the AirDispatch Server
	adServer := server.Server{
		LocationName: m.Me,
		Key:          loadedKey,
		Delegate:     m,
		Handlers:     nil,
	}

	return adServer.StartServer(fmt.Sprintf("%d", port))
}

type newsFetcher struct {
	Latest *newsItem
	News   map[string]*newsItem
	Images map[string]*newsImage
	API    string
	Alias  string

	newsLock  *sync.RWMutex
	imageLock *sync.RWMutex
}

type newsItem struct {
	ID        string
	Headline  string
	Image     string
	URL       string
	Published time.Time
}

func (n *newsItem) ToDispatch(from *identity.Identity, to *identity.Address, latest bool) (*message.EncryptedMessage, error) {
	name := n.ID
	if latest {
		name = "latest"
	}

	mail := message.CreateMail(from.Address, n.Published, name, to)
	mail.Components.AddComponent(message.CreateStringComponent("airdispat.ch/news/headline", n.Headline))
	mail.Components.AddComponent(message.CreateStringComponent("airdispat.ch/news/image", n.Image))
	mail.Components.AddComponent(message.CreateStringComponent("airdispat.ch/news/url", n.URL))
	mail.Components.AddComponent(message.CreateStringComponent("airdispat.ch/news/source", "nytimes"))

	signed, err := message.SignMessage(mail, from)
	if err != nil {
		return nil, err
	}

	return signed.UnencryptedMessage(to)
}

type newsImage struct {
	ID   string
	URL  string
	Hash []byte
}

type fakeCloser struct{ io.Reader }

func (f fakeCloser) Close() error { return nil }

func (n *newsImage) ToDispatch(from *identity.Identity, to *identity.Address) (*message.EncryptedMessage, io.ReadCloser, error) {
	if n == nil {
		return nil, nil, nil
	}

	resp, err := http.Get(string(n.URL))
	if err != nil {
		return nil, nil, err
	}

	length, err := strconv.Atoi(resp.Header.Get("Content-Length"))
	if err != nil {
		return nil, nil, err
	}

	reader := resp.Body
	hash := n.Hash

	if hash == nil {
		fmt.Println("Getting hash.")
		if length > 1e7 {
			return nil, nil, errors.New("Not setup to handle large images yet.")
		}

		b := &bytes.Buffer{}
		hasher := sha256.New()

		_, err = io.Copy(
			io.MultiWriter(b, hasher),
			resp.Body,
		)
		if err != nil {
			return nil, nil, err
		}

		hash = hasher.Sum(nil)
		reader = fakeCloser{
			Reader: b,
		}

		n.Hash = hash
	}

	dataMsg, encReader, err := message.CreateDataMessage(
		hash,
		uint64(length),
		"airdispat.ch/news/image",
		n.ID,
		"news",
		reader,
		message.CreateHeader(from.Address, to),
	)
	if err != nil {
		return nil, nil, err
	}

	signed, err := message.SignMessage(dataMsg, from)
	if err != nil {
		return nil, nil, err
	}

	encMsg, err := signed.UnencryptedMessage(to)
	if err != nil {
		return nil, nil, err
	}

	return encMsg, encReader, nil
}

type jsonTimes struct {
	Results []*jsonNews `json:"results"`
}

type jsonNews struct {
	Section           string           `json:"section"`
	Subsection        string           `json:"subsection"`
	Title             string           `json:"title"`
	URL               string           `json:"url"`
	ThumbnailStandard string           `json:"thumbnail_standard"`
	ItemType          string           `json:"item_type"`
	PublishedDate     time.Time        `json:"published_date"`
	Multimedia        []jsonMultimedia `json:"multimedia"`
}

type jsonMultimedia struct {
	URL    string `json:"url"`
	Format string `json:"format"`
}

func (m *newsFetcher) StartFetch() {
	fetchChan := time.Tick(time.Minute)

	for {
		t := <-fetchChan
		fmt.Println("Fetching News", t)
		m.FetchNews()
	}
}

func (m *newsFetcher) FetchNews() {
	resp, err := http.Get("http://api.nytimes.com/svc/news/v3/content/all/all/.json?api-key=" + m.API)
	if err != nil {
		fmt.Println("Got error getting news", err)
		return
	}
	defer resp.Body.Close()

	dec := json.NewDecoder(resp.Body)

	// j := make([]*jsonNews, 0)
	t := &jsonTimes{}
	err = dec.Decode(t)
	if err != nil && err.Error() != "json: cannot unmarshal string into Go value of type []main.jsonMultimedia" {
		fmt.Println("Got error translating news", err)
		return
	}
	j := t.Results

	var latestDate time.Time

	if m.Latest != nil {
		m.newsLock.RLock()
		latestDate = m.Latest.Published
		m.newsLock.RUnlock()
	}

	populatedLatest := false
	for _, v := range j {
		// Check to see if we can add it.
		// fmt.Println(v)
		if v.Section != "Sports" && v.ItemType == "Article" && v.Multimedia != nil && v.PublishedDate.After(latestDate) {
			fmt.Println("Found a news story!")
			// Create the News Item

			imageId := uuid.NewRandom().String()
			n := &newsItem{
				ID:        uuid.NewRandom().String(),
				Headline:  v.Title,
				URL:       v.URL,
				Image:     fmt.Sprintf("%s/%s", m.Alias, imageId),
				Published: v.PublishedDate,
			}

			bigThumb := v.ThumbnailStandard
			for _, v := range v.Multimedia {
				// if v.Format == "thumbLarge" || v.Format == "Normal" {
				if v.Format == "Normal" {
					bigThumb = v.URL
					break
				}
			}
			// Create the News Image
			i := &newsImage{
				ID:  imageId,
				URL: bigThumb,
			}

			m.newsLock.Lock()
			// Populate Fields!
			m.News[n.ID] = n

			// Populate Latest!
			if !populatedLatest {
				m.Latest = n
				populatedLatest = true
			}

			m.newsLock.Unlock()

			m.imageLock.Lock()
			m.Images[imageId] = i
			m.imageLock.Unlock()
		}
	}

	fmt.Println("Finished Fetching News.")
}

func (m *newsFetcher) GetNewsItem(name string, from *identity.Identity, to *identity.Address) *message.EncryptedMessage {
	m.newsLock.RLock()
	defer m.newsLock.RUnlock()

	data, ok := m.News[name]

	if !ok {
		return nil
	}

	msg, err := data.ToDispatch(from, to, false)
	if err != nil {
		fmt.Println("Error marshalling News Story to Dispatch", err)
		return nil
	}

	return msg
}

func (m *newsFetcher) GetLatestNewsItem(from *identity.Identity, to *identity.Address) *message.EncryptedMessage {
	m.newsLock.RLock()
	defer m.newsLock.RUnlock()

	data := m.Latest

	if data == nil {
		fmt.Println("No latest news yet.")
		return nil
	}

	msg, err := data.ToDispatch(from, to, true)
	if err != nil {
		fmt.Println("Error marshalling News Story to Dispatch", err)
		return nil
	}

	return msg
}

func (m *newsFetcher) GetData(name string, from *identity.Identity, to *identity.Address) (*message.EncryptedMessage, io.ReadCloser) {
	m.imageLock.RLock()
	defer m.imageLock.RUnlock()

	data, ok := m.Images[name]

	if !ok {
		return nil, nil
	}

	msg, r, err := data.ToDispatch(from, to)
	if err != nil {
		fmt.Println("Error marshalling News Story to Dispatch", err)
		return nil, nil
	}

	return msg, r
}

// SaveMessageDescription is not implemented on this server.
func (m *NewsDispatcher) SaveMessageDescription(desc *message.EncryptedMessage) {}

// RetrieveMessageListForUser is not implemented on this server.
func (m *NewsDispatcher) RetrieveMessageListForUser(since uint64, author *identity.Address, forAddr *identity.Address) []*message.EncryptedMessage {
	return nil
}

func (m *NewsDispatcher) RetrieveDataForUser(id string, author *identity.Address, forAddr *identity.Address) (*message.EncryptedMessage, io.ReadCloser) {
	return m.Fetcher.GetData(id, m.Key, forAddr)
}

func (m *NewsDispatcher) RetrieveMessageForUser(id string, author *identity.Address, forAddr *identity.Address) *message.EncryptedMessage {
	if id == "latest" {
		return m.Fetcher.GetLatestNewsItem(m.Key, forAddr)
	}

	return m.Fetcher.GetNewsItem(id, m.Key, forAddr)
}
