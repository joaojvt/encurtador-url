package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strings"
	"sync"
)

var (
	urlStore   = make(map[string]string)
	mu         sync.Mutex
	secretKey  = []byte("secretaeskey12345678901234567890")
	letterRune = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXY1234567890")
)

func encrypt(originalURL string) string {
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		log.Fatal(err)
	}

	plainText := []byte(originalURL)

	cipherText := make([]byte, aes.BlockSize+len(plainText))

	iv := cipherText[:aes.BlockSize]

	if _, err := rand.Read(iv); err != nil {
		log.Fatal(err)
	}

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)

	return hex.EncodeToString(cipherText)
}

func decrypt(encryptedURL string) string {
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		log.Fatal(err)
	}

	cipherText, err := hex.DecodeString(encryptedURL)
	if err != nil {
		log.Fatal(err)
	}

	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(cipherText, cipherText)

	return string(cipherText)
}

func generatedShortId() string {
	b := make([]rune, 6)

	for i := range b {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letterRune))))
		if err != nil {
			log.Fatal(err)
		}

		b[i] = letterRune[num.Int64()]
	}

	return string(b)
}

func redirectHandler(w http.ResponseWriter, r *http.Request) {
	shortId := r.URL.Path[1:]

	mu.Lock()
	encryptedURl, ok := urlStore[shortId]
	mu.Unlock()

	if !ok {
		http.Error(w, "Esta URL não existe no nosso projeto", http.StatusNotFound)
		return
	}

	decryptedURL := decrypt(encryptedURl)
	fmt.Println(decryptedURL)
	http.Redirect(w, r, decryptedURL, http.StatusFound)

}

func shortenURL(w http.ResponseWriter, r *http.Request) {
	originalUrl := r.URL.Query().Get("url")

	if originalUrl == "" {
		http.Error(w, "Parâmetro URL no query é obrigatório", http.StatusBadRequest)
		return
	}

	if !(strings.HasPrefix(originalUrl, "https://") || strings.HasPrefix(originalUrl, "http://")) {
		http.Error(w, "Parametro URL no query precisa de comecar com http:// ou https://", http.StatusBadRequest)
	}

	encryptedURl := encrypt(originalUrl)
	shortId := generatedShortId()

	mu.Lock()
	urlStore[shortId] = encryptedURl
	mu.Unlock()

	shortUrl := fmt.Sprintf("http://localhost:8080/%s", shortId)
	fmt.Fprintln(w, "A URL encurtada desta url original  é: %s", shortUrl)
}

func main() {
	http.HandleFunc("/shorten", shortenURL)
	http.HandleFunc("/", redirectHandler)

	fmt.Println("Projeto iniciando na porta 8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
